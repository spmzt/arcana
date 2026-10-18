/*-
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Labels on interfaces: the console's own tag on an interface of a host
 * ("uplink A", "the UCS to the IXP"), shown under its name in the
 * Interfaces table and changed there, in place; kept by the console
 * (GET /api/labels, PUT /api/labels/<server>/<interface>), not on the
 * host.
 */

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "app.h"

static struct {
	ucl_object_t	*all;		/* {"server/interface": "text"} */
	bool		 loading, loaded;
	char		 edit_sid[16];	/* the interface whose label is typed */
	char		 edit_if[16];
} lb;

static void
labels_cb(int status, const ucl_object_t *o, const char *err, void *arg)
{

	(void)err;
	(void)arg;
	lb.loading = false;
	if (status != 200)
		return;
	if (lb.all != NULL)
		ucl_object_unref(lb.all);
	lb.all = jget(o, "labels") != NULL ? ucl_object_copy(jget(o, "labels")) :
	    ucl_object_typed_new(UCL_OBJECT);
	lb.loaded = true;
	render();
}

/* Read once, and again after a change. */
void
labels_load(void)
{

	if (lb.loading)
		return;
	lb.loading = true;
	api("GET", "/api/labels", NULL, labels_cb, NULL);
}

/* The label of an interface of a server, or NULL. */
const char *
label_of(const char *sid, const char *ifname)
{
	const ucl_object_t	*v;
	char			 key[40];

	if (!lb.loaded && !lb.loading)
		labels_load();
	if (lb.all == NULL)
		return (NULL);
	snprintf(key, sizeof(key), "%s/%s", sid, ifname);
	v = ucl_object_lookup(lb.all, key);
	return (v != NULL && ucl_object_type(v) == UCL_STRING ?
	    ucl_object_tostring(v) : NULL);
}

/*
 * Under an interface's name: its label with a pencil, or the field to
 * type one when that is being done.
 */
void
label_cell(struct html *h, const char *sid, const char *ifname)
{
	const char	*l;

	l = label_of(sid, ifname);
	if (strcmp(lb.edit_sid, sid) == 0 && strcmp(lb.edit_if, ifname) == 0) {
		h_raw(h, "<form data-form=\"if-label\" class=\"if-label\"><input "
		    "name=\"label\" maxlength=\"64\" autofocus placeholder=\"a "
		    "label of the console's\" spellcheck=\"false\" autocomplete="
		    "\"off\"");
		h_attr(h, "value", l != NULL ? l : "");
		h_raw(h, "><button class=\"icon\" title=\"Keep\">&#10003;</button>"
		    "<button type=\"button\" class=\"icon\" data-act=\"if-label-"
		    "cancel\" title=\"Leave it\">×</button></form>");
		return;
	}
	h_raw(h, "<small class=\"label\">");
	if (l != NULL) {
		h_raw(h, "<span class=\"chip tag\">");
		h_txt(h, l);
		h_raw(h, "</span>");
	}
	h_raw(h, "<button class=\"icon\" data-act=\"if-label-edit\" title=\"");
	h_txt(h, l != NULL ? "Change the label" : "Label it: a tag of the "
	    "console's, whatever the interface's own description says");
	h_raw(h, "\"");
	h_attr(h, "data-arg", ifname);
	h_raw(h, ">&#9998;</button></small>");
}

static void
saved_cb(int status, const ucl_object_t *o, const char *err, void *arg)
{

	(void)arg;
	if (status != 200) {
		toast(true, "The label was not kept: %s", err != NULL ? err :
		    jstr(o, "error.message") != NULL ? jstr(o, "error.message") :
		    "no answer");
		return;
	}
	labels_cb(status, o, err, NULL);
}

bool
iflabel_form(const char *form, const ucl_object_t *f)
{
	char	url[96], *q, *body;

	if (strcmp(form, "if-label") != 0)
		return (false);
	if (lb.edit_sid[0] == '\0' || lb.edit_if[0] == '\0')
		return (true);
	snprintf(url, sizeof(url), "/api/labels/%s/%s", lb.edit_sid, lb.edit_if);
	q = json_quote(jstr(f, "label") != NULL ? jstr(f, "label") : "");
	if (asprintf(&body, "{\"label\":%s}", q) == -1)
		abort();
	free(q);
	api("PUT", url, body, saved_cb, NULL);
	free(body);
	lb.edit_sid[0] = lb.edit_if[0] = '\0';
	return (true);
}

bool
iflabel_action(const char *act, const char *arg)
{
	struct server	*s;

	if (strcmp(act, "if-label-edit") == 0) {
		if ((s = cur_server()) == NULL || arg == NULL)
			return (true);
		snprintf(lb.edit_sid, sizeof(lb.edit_sid), "%s", s->id);
		snprintf(lb.edit_if, sizeof(lb.edit_if), "%s", arg);
		return (true);
	}
	if (strcmp(act, "if-label-cancel") == 0) {
		lb.edit_sid[0] = lb.edit_if[0] = '\0';
		return (true);
	}
	return (false);
}
