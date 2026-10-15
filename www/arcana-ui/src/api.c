/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Requests: every one gets an id and a callback; bridge.js answers with
 * arc_on_http() or arc_on_webauthn().
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <emscripten/emscripten.h>

#include "app.h"

#define	MAX_PENDING	256

struct inflight {
	int		 id;
	api_cb		*cb;
	/* A GET of a host's: kept for the tab it was made for (export.c). */
	char		 url[300];
	int		 node, tab;
	void		 (*wcb)(bool, const char *, void *);
	void		*arg;
};

static struct inflight	pend[MAX_PENDING];
static int		lastid;

static struct inflight *
slot(void)
{
	int	i;

	for (i = 0; i < MAX_PENDING; i++)
		if (pend[i].id == 0) {
			pend[i].id = ++lastid;
			return (&pend[i]);
		}
	return (NULL);
}

static struct inflight *
lookup(int id)
{
	int	i;

	for (i = 0; i < MAX_PENDING; i++)
		if (pend[i].id == id)
			return (&pend[i]);
	return (NULL);
}

/*
 * Send a request.  cb gets the HTTP status (0: no answer), the parsed
 * JSON reply and the error message, if any.
 */
int
api(const char *method, const char *url, const char *body, api_cb *cb,
    void *arg)
{
	struct inflight	*p;
	int		 id;

	/* Not sent is not "no answer": the console is not to blame. */
	if ((p = slot()) == NULL) {
		cb(429, NULL, "too many requests in flight here; try again",
		    arg);
		return (0);
	}
	p->cb = cb;
	p->arg = arg;
	id = p->id;
	p->url[0] = '\0';
	if (strcmp(method, "GET") == 0 && strlen(url) < sizeof(p->url)) {
		snprintf(p->url, sizeof(p->url), "%s", url);
		export_where(&p->node, &p->tab);
	}
	/*
	 * A task is made just before the request that does it: the first
	 * request after is its, said in its graph while it waits.
	 */
	if (app.nops > 0 && app.ops[0].await) {
		snprintf(app.ops[0].method, sizeof(app.ops[0].method), "%s",
		    method);
		snprintf(app.ops[0].url, sizeof(app.ops[0].url), "%s", url);
		app.ops[0].await = false;
	}
	arc_http(id, method, url, body);
	return (id);
}

EMSCRIPTEN_KEEPALIVE void
arc_on_http(int id, int status, char *text)
{
	struct inflight	 p, *pp;
	ucl_object_t	*o;
	const char	*err;
	char		 why[320];

	if ((pp = lookup(id)) == NULL) {
		free(text);
		return;
	}
	p = *pp;
	memset(pp, 0, sizeof(*pp));
	o = status != 0 ? json_parse(text) : NULL;
	if (status == 0)
		err = text;
	else if (status >= 400 && (err = jstr(o, "error.message")) == NULL)
		err = jstr(o, "error");
	else
		err = NULL;
	if (status >= 200 && status < 300 && o == NULL)
		err = "the console sent something that is not JSON";
	/* Every answer means the console is up; a 401 means log in. */
	if (status != 0)
		app.api = LINK_UP;
	if (status == 401 && app.screen == SCREEN_CONSOLE) {
		app.screen = SCREEN_LOGIN;
		snprintf(app.auth_error, sizeof(app.auth_error),
		    "Your session ended. Touch your key to continue.");
	}
	/*
	 * An error without a reason of ours did not come from the console's
	 * own handlers: a proxy in front of it, or Kore itself.  Say what
	 * came, so that it can be looked for.
	 */
	if (err == NULL && status >= 400) {
		snprintf(why, sizeof(why), "HTTP %d without a reason%s%.120s",
		    status, text != NULL && text[0] != '\0' && o == NULL ?
		    "; it said: " : " (not from the console's own code: a "
		    "proxy in front of it, or its server)", text != NULL &&
		    o == NULL ? text : "");
		err = why;
	}
	if (status == 200 && p.url[0] != '\0')
		export_note(p.url, p.node, p.tab, o);
	p.cb(status, o, err, p.arg);
	if (o != NULL)
		ucl_object_unref(o);
	free(text);
	render();
}

void
webauthn(bool create, const char *options, void (*cb)(bool, const char *,
    void *), void *arg)
{
	struct inflight	*p;

	if ((p = slot()) == NULL) {
		cb(false, "busy", arg);
		return;
	}
	p->wcb = cb;
	p->arg = arg;
	arc_webauthn(p->id, create ? 1 : 0, options);
}

EMSCRIPTEN_KEEPALIVE void
arc_on_webauthn(int id, int ok, char *result)
{
	struct inflight	 p, *pp;

	if ((pp = lookup(id)) == NULL) {
		free(result);
		return;
	}
	p = *pp;
	memset(pp, 0, sizeof(*pp));
	p.wcb(ok != 0, result, p.arg);
	free(result);
	render();
}
