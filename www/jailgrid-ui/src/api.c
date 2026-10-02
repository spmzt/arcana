/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Requests: every one gets an id and a callback; bridge.js answers with
 * jg_on_http() or jg_on_webauthn().
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <emscripten/emscripten.h>

#include "app.h"

#define	MAX_PENDING	64

struct inflight {
	int		 id;
	api_cb		*cb;
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
void
api(const char *method, const char *url, const char *body, api_cb *cb,
    void *arg)
{
	struct inflight	*p;

	if ((p = slot()) == NULL) {
		cb(0, NULL, "too many requests in flight", arg);
		return;
	}
	p->cb = cb;
	p->arg = arg;
	jg_http(p->id, method, url, body);
}

EMSCRIPTEN_KEEPALIVE void
jg_on_http(int id, int status, char *text)
{
	struct inflight	 p, *pp;
	ucl_object_t	*o;
	const char	*err;

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
	p.cb(status, o, err != NULL ? err : (status >= 400 ?
	    "request failed" : NULL), p.arg);
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
	jg_webauthn(p->id, create ? 1 : 0, options);
}

EMSCRIPTEN_KEEPALIVE void
jg_on_webauthn(int id, int ok, char *result)
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
