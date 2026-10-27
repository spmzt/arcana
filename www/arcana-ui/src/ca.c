/*-
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Settings, Certificate authority: the console's own CA, the one each
 * host trusts the console by and that signs the hosts' certificates,
 * changed for another without a host left behind.  The next one is
 * made here, imported with its chain (the console then an intermediate
 * CA under another), or asked for by a request another CA signs; then
 * rolled out to the hosts, and finished.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "app.h"

#define	CA_POLL_MS	1000

static struct {
	ucl_object_t	*o;
	bool		 loading;
	char		 error[300];
	double		 fetched;
} ca;

static void
ca_cb(int status, const ucl_object_t *o, const char *err, void *arg)
{
	bool	post;

	post = arg != NULL;
	ca.loading = false;
	if (status != 200) {
		snprintf(ca.error, sizeof(ca.error), "%s", jstr(o,
		    "error.message") != NULL ? jstr(o, "error.message") : err !=
		    NULL ? err : "no answer");
		if (post)
			toast(true, "%s", ca.error);
		return;
	}
	ca.error[0] = '\0';
	if (ca.o != NULL)
		ucl_object_unref(ca.o);
	ca.o = ucl_object_ref((ucl_object_t *)(uintptr_t)o);
	ca.fetched = arc_now();
}

void
ca_load(void)
{

	if (ca.loading || !app.online)
		return;
	ca.loading = true;
	api("GET", "/api/ca", NULL, ca_cb, NULL);
}

/* While a change runs, what it has done is read again. */
void
ca_tick(double now)
{

	if (app.node != NODE_SETTINGS || app.settab != SET_CA || !app.visible)
		return;
	if (ca.o == NULL || (jbool(ca.o, "state.running") && now -
	    ca.fetched > CA_POLL_MS))
		ca_load();
}

static void
ca_post(const char *json)
{

	ca.loading = true;
	api("POST", "/api/ca", json, ca_cb, (void *)1);
}

/* A time as its day, UTC: 2026-10-27. */
void
day_text(char *buf, size_t len, int64_t t)
{
	struct tm	tm;
	time_t		tt;

	tt = (time_t)t;
	gmtime_r(&tt, &tm);
	strftime(buf, len, "%Y-%m-%d", &tm);
}

static void
certs_table(struct html *h, const char *id, const ucl_object_t *arr)
{
	static const struct tcol cols[] = {
		{ "Subject", "subject", false }, { "Issuer", "issuer", false },
		{ "Root", "root", false }, { "Valid to", "not_after", true },
		{ "SHA-256", "sha256", false },
	};
	const ucl_object_t	**rows, *r;
	char			  d[16];
	int			  n;

	h_fmt(h, "<table class=\"net ca-certs\" id=\"%s\">", id);
	tbl_head(h, id, cols, 5, 0);
	h_raw(h, "<tbody>");
	rows = tbl_rows(id, arr, cols, 5, NULL);
	for (n = 0; (r = rows[n]) != NULL; n++) {
		h_raw(h, "<tr><td class=\"mono\">");
		h_txt(h, jstr(r, "subject"));
		h_raw(h, "</td><td class=\"mono\">");
		h_txt(h, jstr(r, "issuer"));
		h_fmt(h, "</td><td>%s</td>", jbool(r, "root") ? "yes" : "");
		day_text(d, sizeof(d), jint(r, "not_after", 0));
		h_fmt(h, "<td>%s</td><td class=\"mono fp\"", d);
		h_attr(h, "title", jstr(r, "sha256"));
		h_raw(h, ">");
		if (jstr(r, "sha256") != NULL)
			h_fmt(h, "%.23s…", jstr(r, "sha256"));
		h_raw(h, "</td></tr>");
	}
	free(rows);
	h_raw(h, "</tbody></table>");
}

void
set_ca(struct html *h)
{
	const ucl_object_t	*st, *hs, *x;
	ucl_object_iter_t	 it;
	const char		*phase;
	bool			 running, staged;

	if (ca.o == NULL)
		ca_load();
	h_raw(h, "<p class=\"dim\">The console's own CA: each host trusts the "
	    "console by it, and it signs each host's certificate. It is "
	    "changed for another without a host left behind: the next one is "
	    "made here, imported with its chain up to its root (the console "
	    "is then an intermediate CA under another), or asked for by a "
	    "request another CA signs. <b>Roll out</b> has the console trust "
	    "both, gives each host both to trust and a certificate from the "
	    "next one, and then the console takes the next one's certificate "
	    "for its own, only once every host has the new one. <b>Finish</b> "
	    "has each host, and the console, trust the next one alone.</p>");
	if (ca.error[0] != '\0') {
		h_raw(h, "<div class=\"notice bad\">");
		h_txt(h, ca.error);
		h_raw(h, "</div>");
	}
	if (ca.o == NULL) {
		h_raw(h, "<p class=\"dim\">Reading…</p>");
		return;
	}
	h_raw(h, "<h3>Trusted now</h3>");
	certs_table(h, "ca-now", jget(ca.o, "trusted"));
	if (jget(ca.o, "console") != NULL) {
		h_raw(h, "<p class=\"dim\">The console's own certificate: <span "
		    "class=\"mono\">");
		h_txt(h, jstr(ca.o, "console.subject"));
		h_raw(h, "</span>, from <span class=\"mono\">");
		h_txt(h, jstr(ca.o, "console.issuer"));
		h_raw(h, "</span>.</p>");
	}
	if (!jbool(ca.o, "own")) {
		h_raw(h, "<div class=\"notice info\">web.conf's <code>tls</code> "
		    "block names this CA: it is changed there.</div>");
		return;
	}
	st = jget(ca.o, "state");
	phase = jstr(st, "phase") != NULL ? jstr(st, "phase") : "";
	running = jbool(st, "running");
	staged = jget(ca.o, "next") != NULL;
	if (staged) {
		h_raw(h, "<h3>Next</h3>");
		certs_table(h, "ca-next", jget(ca.o, "next.chain"));
	}
	if (phase[0] != '\0' || running) {
		h_fmt(h, "<p>The change: <span class=\"chip%s\">%s</span>",
		    running ? " warn" : strcmp(phase, "finished") == 0 ? " ok" :
		    "", running ? "running…" : phase);
		if (jstr(st, "error") != NULL && jstr(st, "error")[0] != '\0') {
			h_raw(h, " <span class=\"err\">");
			h_txt(h, jstr(st, "error"));
			h_raw(h, "</span>");
		}
		h_raw(h, "</p>");
	}
	it = NULL;
	if ((hs = jget(st, "hosts")) != NULL && ucl_object_iterate(hs, &it,
	    true) != NULL) {
		h_raw(h, "<table class=\"net ca-hosts\"><thead><tr><th>Host</th>"
		    "<th>Step</th><th></th></tr></thead><tbody>");
		it = NULL;
		while ((x = ucl_object_iterate(hs, &it, true)) != NULL) {
			h_raw(h, "<tr><td>");
			h_txt(h, jstr(x, "name"));
			h_fmt(h, "</td><td><span class=\"chip%s\">", strcmp(jstr(x,
			    "step"), "failed") == 0 ? " bad" : " ok");
			h_txt(h, jstr(x, "step"));
			h_raw(h, "</span></td><td class=\"dim\">");
			h_txt(h, jstr(x, "error") != NULL ? jstr(x, "error") : "");
			h_raw(h, "</td></tr>");
		}
		h_raw(h, "</tbody></table>");
	}
	if (running)
		return;
	h_raw(h, "<div class=\"toolbar ca-acts\">");
	if (staged && strcmp(phase, "switched") != 0) {
		h_raw(h, "<button class=\"primary small\" data-act=\"ca-rollout\">"
		    "Roll out</button>");
		if (strcmp(phase, "rolling") == 0)
			h_raw(h, "<button class=\"ghost small danger\" data-act=\""
			    "ca-rollout-force\" title=\"Switch even with hosts "
			    "not renewed: they are lost to the console\">Roll out "
			    "with force</button>");
		else
			h_raw(h, "<button class=\"ghost small\" data-act=\""
			    "ca-discard\">Discard</button>");
	}
	if (strcmp(phase, "switched") == 0) {
		h_raw(h, "<button class=\"primary small\" data-act=\"ca-finish\">"
		    "Finish</button><button class=\"ghost small danger\" "
		    "data-act=\"ca-finish-force\" title=\"Even hosts not renewed: "
		    "they are lost to the console\">Finish with force</button>");
	}
	h_raw(h, "</div>");
	if (strcmp(phase, "rolling") == 0 || strcmp(phase, "switched") == 0)
		return;
	/* A next one to stage. */
	h_raw(h, "<h3>Another CA</h3><form data-form=\"ca-make\" class=\""
	    "toolbar\"><label>Name <input name=\"cn\" placeholder=\"arcana CA\" "
	    "maxlength=\"64\"></label><button class=\"ghost small\">Make one"
	    "</button><button type=\"button\" class=\"ghost small\" data-act=\""
	    "ca-request\" title=\"A key here and a request for another CA to "
	    "sign, as an intermediate CA\">Make a request</button></form>");
	if (jstr(ca.o, "request") != NULL) {
		h_raw(h, "<p class=\"dim\">The request, for your CA to sign as an "
		    "intermediate CA (<code>CA:TRUE</code>); its key stays here. "
		    "Import what it signs, its chain up to the root after it.</p>"
		    "<pre class=\"diff ca-csr\">");
		h_txt(h, jstr(ca.o, "request"));
		h_raw(h, "</pre>");
	}
	h_raw(h, "<form data-form=\"ca-import\"><label>Import a CA <small "
	    "class=\"dim\">its certificate, then the CAs above it up to the "
	    "root, as PEM</small><textarea name=\"cert\" rows=\"5\" class=\""
	    "mono\" spellcheck=\"false\"></textarea></label><label>Its key "
	    "<small class=\"dim\">PEM; none for the request made here"
	    "</small><textarea name=\"key\" rows=\"3\" class=\"mono\" "
	    "spellcheck=\"false\"></textarea></label><div class=\"row\">"
	    "<button class=\"ghost small\">Import</button></div></form>");
}

bool
ca_form(const char *form, const ucl_object_t *f)
{
	char	*q1, *q2, *json;

	if (strcmp(form, "ca-make") == 0) {
		q1 = json_quote(jstr(f, "cn") != NULL ? jstr(f, "cn") : "");
		if (asprintf(&json, "{\"action\":\"make\",\"cn\":%s}", q1) == -1)
			abort();
		ca_post(json);
		free(q1);
		free(json);
		return (true);
	}
	if (strcmp(form, "ca-import") == 0) {
		q1 = json_quote(jstr(f, "cert") != NULL ? jstr(f, "cert") : "");
		q2 = json_quote(jstr(f, "key") != NULL ? jstr(f, "key") : "");
		if (asprintf(&json, "{\"action\":\"import\",\"cert\":%s,\"key\":"
		    "%s}", q1, q2) == -1)
			abort();
		ca_post(json);
		/* The key is in no copy kept by the page. */
		explicit_bzero(q2, strlen(q2));
		explicit_bzero(json, strlen(json));
		free(q1);
		free(q2);
		free(json);
		return (true);
	}
	return (false);
}

bool
ca_action(const char *act, const char *arg, const char *value)
{

	(void)arg;
	(void)value;
	if (strncmp(act, "ca-", 3) != 0 && strncmp(act, "do-ca-", 6) != 0)
		return (false);
	if (strcmp(act, "ca-request") == 0)
		ca_post("{\"action\":\"request\",\"cn\":\"arcana CA\"}");
	else if (strcmp(act, "ca-discard") == 0)
		ca_post("{\"action\":\"discard\"}");
	else if (strcmp(act, "ca-rollout") == 0)
		confirm("Roll out the next CA", "Each host is given both CAs to "
		    "trust and a certificate from the next one; once every host "
		    "has it, the console takes the next one's certificate for "
		    "its own. A host that does not answer holds the console "
		    "back: roll out again when it does.", "Roll out", false, "",
		    "do-ca-rollout", "", "");
	else if (strcmp(act, "ca-rollout-force") == 0)
		confirm("Roll out with force", "The console takes the next one's "
		    "certificate although some hosts were not renewed: they do "
		    "not trust it, and are lost to the console until enrolled "
		    "again.", "Roll out", true, "", "do-ca-rollout-force", "",
		    "");
	else if (strcmp(act, "ca-finish") == 0)
		confirm("Finish the change", "Each host, and then the console, "
		    "trusts the next CA alone: the one before is trusted no "
		    "more.", "Finish", false, "", "do-ca-finish", "", "");
	else if (strcmp(act, "ca-finish-force") == 0)
		confirm("Finish with force", "Hosts not renewed keep a "
		    "certificate the console no longer trusts: they are lost to "
		    "it until enrolled again.", "Finish", true, "",
		    "do-ca-finish-force", "", "");
	else if (strcmp(act, "do-ca-rollout") == 0)
		ca_post("{\"action\":\"rollout\"}");
	else if (strcmp(act, "do-ca-rollout-force") == 0)
		ca_post("{\"action\":\"rollout\",\"force\":true}");
	else if (strcmp(act, "do-ca-finish") == 0)
		ca_post("{\"action\":\"finish\"}");
	else if (strcmp(act, "do-ca-finish-force") == 0)
		ca_post("{\"action\":\"finish\",\"force\":true}");
	return (true);
}
