/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * A change of a host's configuration saved as the router advertisements
 * save it (ra.c), for the pages that change one: the edit sent to the
 * host's candidate (RFC 8527: a PUT, a PATCH, a YANG Patch, a DELETE),
 * then the candidate committed confirmed (RFC 6241 section 8.4) with a
 * token of the page's own, and confirmed at once; undone by the host at
 * the timeout if the confirm does not come.  A warning the host stops
 * at (its error-app-tag: rc-conf-files, rc-conf-conflict) is said with
 * a button that accepts it and commits again; a commit waiting can be
 * undone (cancel-commit), its seconds counted down.
 */

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "app.h"

/* What a RESTCONF error says, or the request's own failure. */
const char *
rc_why(const ucl_object_t *o, const char *err)
{
	const char	*m;

	if ((m = jstr(o, "ietf-restconf:errors.error.0.error-message")) !=
	    NULL)
		return (m);
	return (err != NULL ? err : "the console did not answer");
}

/* The host's rpc, an operation of ietf-netconf's. */
static void
rpc_url(char *buf, size_t len, const struct ycommit *yc, const char *rpc)
{

	snprintf(buf, len, "/restconf/data/arcana-fleet:fleet/host=%s/"
	    "ietf-netconf:%s", yc->sid, rpc);
}

static void
finish(struct ycommit *yc, int how)
{

	if (yc->done != NULL)
		yc->done(yc, how);
	render();
}

static void
cancel_cb(int status, const ucl_object_t *o, const char *err, void *arg)
{
	struct ycommit	*yc = arg;

	yc->busy = false;
	if (status == 204 || status == 200) {
		yc->token[0] = '\0';
		snprintf(yc->note, sizeof(yc->note), "%s", yc->undone != NULL ?
		    yc->undone : "Undone: as it was.");
		finish(yc, YC_UNDONE);
		return;
	}
	snprintf(yc->note, sizeof(yc->note), "Not undone: %s", rc_why(o,
	    err));
	render();
}

static void
confirm_cb(int status, const ucl_object_t *o, const char *err, void *arg)
{
	struct ycommit	*yc = arg;

	yc->busy = false;
	if (status == 204 || status == 200) {
		yc->token[0] = '\0';
		snprintf(yc->note, sizeof(yc->note), "%s", yc->saved != NULL ?
		    yc->saved : "Saved.");
		finish(yc, YC_SAVED);
		return;
	}
	snprintf(yc->note, sizeof(yc->note), "Not confirmed (%s): the host "
	    "undoes the change at the timeout.", rc_why(o, err));
	finish(yc, YC_REFUSED);
}

static void
commit_cb(int status, const ucl_object_t *o, const char *err, void *arg)
{
	struct ycommit	*yc = arg;
	char		 url[200], body[160];

	if (status != 204 && status != 200) {
		const char	*tag = jstr(o,
		    "ietf-restconf:errors.error.0.error-app-tag");

		yc->busy = false;
		yc->token[0] = '\0';
		/* A warning the host stops at: offered to be accepted, where
		 * its tag is a plain word (it goes into a query). */
		snprintf(yc->tag, sizeof(yc->tag), "%s", h_word(tag, ""));
		snprintf(yc->note, sizeof(yc->note), "Not committed: %s",
		    rc_why(o, err));
		finish(yc, YC_REFUSED);
		return;
	}
	snprintf(yc->note, sizeof(yc->note), "Committed; confirming.");
	rpc_url(url, sizeof(url), yc, "commit");
	snprintf(body, sizeof(body), "{\"ietf-netconf:input\":{\"persist-id\":"
	    "\"%s\"}}", yc->token);
	api("POST", url, body, confirm_cb, yc);
	render();
}

/* The candidate committed confirmed, with the warning accept accepted. */
static void
commit(struct ycommit *yc, const char *accept)
{
	uint8_t	r[16];
	char	url[300], body[200];

	if (getentropy(r, sizeof(r)) != 0) {
		yc->busy = false;
		snprintf(yc->note, sizeof(yc->note), "Not saved: no randomness "
		    "for the commit's token");
		finish(yc, YC_REFUSED);
		return;
	}
	for (size_t i = 0; i < sizeof(r); i++)
		snprintf(yc->token + 2 * i, sizeof(yc->token) - 2 * i, "%02x",
		    r[i]);
	yc->until = arc_now() + YC_TIMEOUT * 1000.0;
	rpc_url(url, sizeof(url), yc, "commit");
	if (h_word(accept, NULL) != NULL)
		snprintf(url + strlen(url), sizeof(url) - strlen(url),
		    "?arcana-accept=%s", accept);
	snprintf(body, sizeof(body), "{\"ietf-netconf:input\":{\"confirmed\":"
	    "[null],\"confirm-timeout\":%d,\"persist\":\"%s\"}}", YC_TIMEOUT,
	    yc->token);
	api("POST", url, body, commit_cb, yc);
}

static void
edit_cb(int status, const ucl_object_t *o, const char *err, void *arg)
{
	struct ycommit	*yc = arg;

	if (status != 204 && status != 200 && status != 201) {
		yc->busy = false;
		snprintf(yc->note, sizeof(yc->note), "Not saved: %s", rc_why(o,
		    err));
		finish(yc, YC_REFUSED);
		return;
	}
	commit(yc, NULL);
}

bool
ycommit_save(struct ycommit *yc, const char *sid, const char *method,
    const char *url, const char *body)
{

	if (yc->busy)
		return (false);
	snprintf(yc->sid, sizeof(yc->sid), "%s", sid);
	yc->busy = true;
	yc->note[0] = yc->tag[0] = '\0';
	api(method, url, body, edit_cb, yc);
	render();
	return (true);
}

void
ycommit_note(struct html *h, const struct ycommit *yc)
{

	if (yc->note[0] == '\0')
		return;
	h_raw(h, "<p class=\"note\">");
	h_txt(h, yc->note);
	if (yc->tag[0] != '\0' && !yc->busy) {
		h_fmt(h, " <button class=\"small\" data-act=\"%s-accept\">"
		    "Accept ", yc->act);
		h_txt(h, yc->tag);
		h_raw(h, " and commit again</button>");
	}
	if (yc->token[0] != '\0' && !yc->busy)
		h_fmt(h, " <button class=\"ghost small\" data-act=\""
		    "%s-cancel\">Undo now</button> <small class=\"dim\">"
		    "%d s left</small>", yc->act, (int)((yc->until -
		    arc_now()) / 1000));
	h_raw(h, "</p>");
}

bool
ycommit_action(struct ycommit *yc, const char *act)
{
	size_t	n = strlen(yc->act);
	char	url[200], body[160], tag[64];

	if (strncmp(act, yc->act, n) != 0 || act[n] != '-')
		return (false);
	act += n + 1;
	if (strcmp(act, "accept") == 0) {
		if (yc->tag[0] != '\0' && !yc->busy) {
			snprintf(tag, sizeof(tag), "%s", yc->tag);
			yc->busy = true;
			yc->tag[0] = '\0';
			commit(yc, tag);
		}
		return (true);
	}
	if (strcmp(act, "cancel") == 0) {
		if (yc->token[0] != '\0' && !yc->busy) {
			yc->busy = true;
			rpc_url(url, sizeof(url), yc, "cancel-commit");
			snprintf(body, sizeof(body), "{\"ietf-netconf:input\":{"
			    "\"persist-id\":\"%s\"}}", yc->token);
			api("POST", url, body, cancel_cb, yc);
		}
		return (true);
	}
	return (false);
}

void
ycommit_tick(struct ycommit *yc, double now)
{

	if (yc->token[0] == '\0' || now - yc->last < 1000)
		return;
	yc->last = now;
	if (now > yc->until + 2000) {
		yc->token[0] = '\0';
		yc->busy = false;
		snprintf(yc->note, sizeof(yc->note), "The host undid the change "
		    "that was not confirmed.");
		finish(yc, YC_UNDONE);
		return;
	}
	render();
}
