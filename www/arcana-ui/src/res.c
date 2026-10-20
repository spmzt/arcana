/*
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * A page's read of one host's resource: asked for, loading, there, or
 * failed with a reason; a reply not the latest asked for is dropped, a
 * failure is kept until Try again, and another host's read starts
 * afresh.  The pages that read one thing of a host (the system, the
 * network storage, Suricata's rules and sources) are this and what they
 * draw.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "app.h"

/* One request: whose, and which of its asks. */
struct res_ask {
	struct res	*r;
	unsigned	 gen;
};

static void
res_cb(int status, const ucl_object_t *o, const char *err, void *arg)
{
	struct res_ask	*a = arg;
	struct res	*r = a->r;
	unsigned	 gen = a->gen;

	free(a);
	if (gen != r->gen)
		return;
	r->loading = false;
	if (status != 200 || !jbool(o, "ok")) {
		snprintf(r->error, sizeof(r->error), "%s", jstr(o, "error") !=
		    NULL ? jstr(o, "error") : err != NULL ? err :
		    "the host did not answer");
		/* Nothing, kept: asked again by Try again, not every draw. */
		if (r->o == NULL)
			r->o = ucl_object_typed_new(UCL_OBJECT);
		render();
		return;
	}
	r->error[0] = '\0';
	if (r->o != NULL)
		ucl_object_unref(r->o);
	r->o = jget(o, "data") != NULL ? ucl_object_copy(jget(o, "data")) :
	    ucl_object_typed_new(UCL_OBJECT);
	render();
}

/* What was read, let go: the next draw asks again. */
void
res_drop(struct res *r)
{

	if (r->o != NULL)
		ucl_object_unref(r->o);
	r->o = NULL;
	r->error[0] = '\0';
}

/* Asked for, of a host, at a URL; another host's read is dropped first. */
void
res_load(struct res *r, const char *sid, const char *url)
{
	struct res_ask	*a;

	if (sid == NULL || sid[0] == '\0')
		return;
	if (strcmp(sid, r->sid) != 0) {
		snprintf(r->sid, sizeof(r->sid), "%s", sid);
		res_drop(r);
	}
	if ((a = calloc(1, sizeof(*a))) == NULL)
		abort();
	a->r = r;
	a->gen = ++r->gen;
	r->loading = true;
	api("GET", url, NULL, res_cb, a);
}

/*
 * The read, when it is this host's: true, its error (with a Try again
 * when retry names an action) drawn first when it failed.  Otherwise
 * asked for by load, a loader drawn, and false.
 */
bool
res_shown(struct html *h, struct res *r, const char *sid,
    void (*load)(const char *), const char *retry)
{

	if (r->o == NULL || strcmp(sid, r->sid) != 0) {
		if (!r->loading || strcmp(sid, r->sid) != 0)
			load(sid);
		h_raw(h, "<div class=\"loader\"></div>");
		return (false);
	}
	if (r->error[0] != '\0') {
		h_raw(h, "<div class=\"notice bad\">");
		h_txt(h, r->error);
		if (retry != NULL)
			h_fmt(h, " <button class=\"ghost small\" data-act=\"%s\">"
			    "Try again</button>", retry);
		h_raw(h, "</div>");
	}
	return (true);
}

/*
 * A job as the jobs API takes it: its kind, verb (or none), its words
 * as args, its text, and extra, more members as ",\"k\":v".  malloc(3)ed.
 */
char *
job_json(const char *kind, const char *verb, const char *const *words,
    size_t n, const char *text, const char *extra)
{
	struct html	b;
	char		*q;
	size_t		 i;

	memset(&b, 0, sizeof(b));
	h_fmt(&b, "{\"kind\":\"%s\"", kind);
	if (verb != NULL)
		h_fmt(&b, ",\"verb\":\"%s\"", verb);
	h_raw(&b, ",\"args\":[");
	for (i = 0; i < n; i++) {
		q = json_quote(words[i]);
		h_fmt(&b, "%s%s", i > 0 ? "," : "", q);
		free(q);
	}
	h_raw(&b, "]");
	if (text != NULL) {
		q = json_quote(text);
		h_fmt(&b, ",\"text\":%s", q);
		free(q);
	}
	if (extra != NULL)
		h_raw(&b, extra);
	h_raw(&b, "}");
	return (b.s);
}
