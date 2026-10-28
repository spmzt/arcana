/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Configuration drift, on a host's Summary: what the host has otherwise
 * than its running configuration says (RFC 8342's intended against
 * operational, the console's /drift): a node running has that is not
 * in effect, one that differs, and one the host has beyond running,
 * with where it came from (its origin, section 5.3.4): set by hand
 * since the files were written, learned (DHCP, SLAAC, a neighbour), or
 * the kernel's own.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "app.h"

static struct {
	char		 sid[9];	/* the host it was read for */
	bool		 loading;
	ucl_object_t	*o;		/* the rows */
	char		 error[256];
} dr;

static void
drift_cb(int status, const ucl_object_t *o, const char *err, void *arg)
{
	char	*sid = arg;

	if (strcmp(sid, dr.sid) != 0) {
		free(sid);
		return;
	}
	free(sid);
	dr.loading = false;
	if (status != 200 || !jbool(o, "ok") || jget(o, "drift") == NULL) {
		snprintf(dr.error, sizeof(dr.error), "%s", jstr(o, "error") !=
		    NULL ? jstr(o, "error") : jstr(o, "error.message") != NULL ?
		    jstr(o, "error.message") : err != NULL ? err : "no answer");
		return;
	}
	dr.error[0] = '\0';
	if (dr.o != NULL)
		ucl_object_unref(dr.o);
	dr.o = ucl_object_copy(jget(o, "drift"));
}

static void
drift_fetch(struct server *s)
{
	char	url[96], *arg;

	if (dr.loading && strcmp(dr.sid, s->id) == 0)
		return;
	if (strcmp(dr.sid, s->id) != 0) {
		if (dr.o != NULL)
			ucl_object_unref(dr.o);
		dr.o = NULL;
		dr.error[0] = '\0';
	}
	snprintf(dr.sid, sizeof(dr.sid), "%s", s->id);
	dr.loading = true;
	snprintf(url, sizeof(url), "/api/servers/%s/drift", s->id);
	if ((arg = strdup(s->id)) == NULL)
		abort();
	api("GET", url, NULL, drift_cb, arg);
}

/* A row's kind and origin as the table says them. */
static const char *
kind_text(const ucl_object_t *r)
{
	const char	*k = jstr(r, "kind"), *o = jstr(r, "origin");

	if (k != NULL && strcmp(k, "unapplied") == 0)
		return ("configured, not in effect");
	if (k != NULL && strcmp(k, "differs") == 0)
		return ("differs from running");
	if (o != NULL && strcmp(o, "unknown") == 0)
		return ("set by hand");
	if (o != NULL && strcmp(o, "learned") == 0)
		return ("learned by the host");
	if (o != NULL && strcmp(o, "system") == 0)
		return ("the kernel's own");
	return ("beyond running");
}

void
view_drift(struct html *h, struct server *s)
{
	static const struct tcol	 cols[] = {
		{ "What", "kind", false },
		{ "Node", "path", false },
		{ "Origin", "origin", false },
	};
	const ucl_object_t		**rows, *r;
	char				*json;
	unsigned			 hand = 0, learned = 0, unapplied = 0,
					 differs = 0, n;

	h_raw(h, "<section class=\"transport\" id=\"drift\">");
	box_head(h, "drift", "h3");
	h_raw(h, "Configuration drift</h3>");
	if (box_shut("drift")) {
		h_raw(h, "</section>");
		return;
	}
	if (strcmp(dr.sid, s->id) != 0 || (dr.o == NULL && dr.error[0] ==
	    '\0' && !dr.loading))
		drift_fetch(s);
	h_raw(h, "<p class=\"dim\">What the host has otherwise than its "
	    "running configuration (what rc(8) reads) says, by the standard "
	    "models: RFC 8342's intended against operational, each node with "
	    "where it came from.</p>");
	if (dr.error[0] != '\0') {
		h_raw(h, "<div class=\"notice bad\">");
		h_txt(h, dr.error);
		h_raw(h, "</div></section>");
		return;
	}
	if (dr.o == NULL) {
		h_raw(h, "<p class=\"dim\">Reading…</p></section>");
		return;
	}
	for (n = 0; (r = ucl_array_find_index(dr.o, n)) != NULL; n++) {
		if (jstr(r, "kind") != NULL && strcmp(jstr(r, "kind"),
		    "unapplied") == 0)
			unapplied++;
		else if (jstr(r, "kind") != NULL && strcmp(jstr(r, "kind"),
		    "differs") == 0)
			differs++;
		else if (jstr(r, "origin") != NULL && strcmp(jstr(r, "origin"),
		    "unknown") == 0)
			hand++;
		else
			learned++;
	}
	if (n == 0) {
		h_raw(h, "<p>None: the host is as running says.</p></section>");
		return;
	}
	h_fmt(h, "<p><b>%u</b> set by hand, <b>%u</b> learned or the "
	    "kernel's, <b>%u</b> configured but not in effect, <b>%u</b> "
	    "differing.</p><table class=\"net drift\">", hand, learned,
	    unapplied, differs);
	tbl_head(h, "drift", cols, 3, 0);
	h_raw(h, "<tbody>");
	rows = tbl_rows("drift", dr.o, cols, 3, app.filter);
	for (n = 0; (r = rows[n]) != NULL; n++) {
		h_raw(h, "<tr><td>");
		h_txt(h, kind_text(r));
		h_raw(h, "</td><td class=\"mono\">");
		h_txt(h, jstr(r, "path"));
		if (jget(r, "value") != NULL && (json = (char *)ucl_object_emit(
		    jget(r, "value"), UCL_EMIT_JSON_COMPACT)) != NULL) {
			h_raw(h, "<details class=\"wfmore\"><summary>value"
			    "</summary><pre class=\"mono\">");
			h_txt(h, json);
			h_raw(h, "</pre></details>");
			free(json);
		}
		h_raw(h, "</td><td>");
		h_txt(h, jstr(r, "origin") != NULL ? jstr(r, "origin") : "");
		h_raw(h, "</td></tr>");
	}
	free(rows);
	h_raw(h, "</tbody></table></section>");
}
