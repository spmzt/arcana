/*-
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Settings, Cluster: the consoles that are one (web.conf's cluster
 * block), as the node the browser is on knows them: who leads, in which
 * term, how far each node holds the changes the leader made.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "app.h"

#define	CL_POLL_MS	2000

static struct {
	ucl_object_t	*o;
	bool		 loading;
	char		 error[300];
	double		 fetched;
} cl;

static const struct tcol ncols[] = {
	{ "Node", "name", false }, { "Origin", "origin", false },
	{ "Role", NULL, false }, { "Holds", "match", true },
};

static void
cl_cb(int status, const ucl_object_t *o, const char *err, void *arg)
{

	cl.loading = false;
	if (status != 200) {
		snprintf(cl.error, sizeof(cl.error), "%s", jstr(o,
		    "error.message") != NULL ? jstr(o, "error.message") : err !=
		    NULL ? err : "no answer");
		return;
	}
	cl.error[0] = '\0';
	if (cl.o != NULL)
		ucl_object_unref(cl.o);
	cl.o = ucl_object_ref((ucl_object_t *)(uintptr_t)o);
	cl.fetched = arc_now();
}

static void
cl_load(void)
{

	if (cl.loading || !app.online)
		return;
	cl.loading = true;
	api("GET", "/api/cluster", NULL, cl_cb, NULL);
}

/* Read again every CL_POLL_MS while it is shown: an election is seen. */
void
cluster_tick(double now)
{

	if (app.node != NODE_SETTINGS || app.settab != SET_CLUSTER ||
	    !app.visible)
		return;
	if (cl.o == NULL || now - cl.fetched > CL_POLL_MS)
		cl_load();
}

void
set_cluster(struct html *h)
{
	const ucl_object_t	**rows, *n;
	const char		 *self, *leader;
	int			  r;

	if (cl.o == NULL)
		cl_load();
	h_raw(h, "<p class=\"dim\">Consoles that are one, active on every "
	    "node: each serves its browsers from its own copy of the console's "
	    "documents, and a change made on any is every one's. The nodes "
	    "elect a leader (Raft, over cblink); it numbers each change and "
	    "makes it once a majority holds it. The workflow scheduler, the "
	    "SD-WAN manager and mail run on the leader alone. A node cut off "
	    "from the majority reads, and refuses changes.</p>");
	if (cl.error[0] != '\0') {
		h_raw(h, "<div class=\"notice bad\">");
		h_txt(h, cl.error);
		h_raw(h, "</div>");
	}
	if (cl.o == NULL) {
		h_raw(h, "<p class=\"dim\">Reading…</p>");
		return;
	}
	if (!jbool(cl.o, "on")) {
		h_raw(h, "<div class=\"empty\"><p>This console is not one of a "
		    "cluster.</p><p class=\"dim\">A <code>cluster</code> block in "
		    "web.conf makes it one: the nodes, each with its cblink "
		    "address and its web origin, and this one's name. See "
		    "arcana-console(8).</p></div>");
		return;
	}
	self = jstr(cl.o, "self");
	leader = jstr(cl.o, "leader");
	h_raw(h, "<p>This node, <b>");
	h_txt(h, self);
	h_raw(h, "</b>, is ");
	h_txt(h, jstr(cl.o, "role"));
	h_fmt(h, " in term %lld; ", (long long)jint(cl.o, "term", 0));
	if (leader != NULL && leader[0] != '\0') {
		h_raw(h, "the leader is <b>");
		h_txt(h, leader);
		h_raw(h, "</b>.");
	} else
		h_raw(h, "<span class=\"chip warn\">no leader</span>: no change "
		    "is made until a majority elects one.");
	h_fmt(h, " Changes committed: %lld, written here: %lld.</p>",
	    (long long)jint(cl.o, "commit", 0), (long long)jint(cl.o,
	    "applied", 0));
	h_raw(h, "<div class=\"toolbar\"><input class=\"filter\" id=\"filter\" "
	    "data-input=\"filter\" placeholder=\"Filter\" autocomplete=\"off\" "
	    "spellcheck=\"false\"");
	h_attr(h, "value", app.filter);
	h_raw(h, "></div><table class=\"net clnodes\">");
	tbl_head(h, "clnodes", ncols, 4, 0);
	h_raw(h, "<tbody>");
	rows = tbl_rows("clnodes", jget(cl.o, "nodes"), ncols, 4, app.filter);
	for (r = 0; (n = rows[r]) != NULL; r++) {
		h_raw(h, "<tr><td><b>");
		h_txt(h, jstr(n, "name"));
		h_raw(h, "</b>");
		if (self != NULL && strcmp(jstr(n, "name"), self) == 0)
			h_raw(h, " <small class=\"dim\">this one</small>");
		h_raw(h, "</td><td class=\"mono\">");
		if (jstr(n, "origin") != NULL && jstr(n, "origin")[0] != '\0') {
			h_raw(h, "<a");
			h_attr(h, "href", jstr(n, "origin"));
			h_raw(h, ">");
			h_txt(h, jstr(n, "origin"));
			h_raw(h, "</a>");
		}
		h_raw(h, "</td><td>");
		h_raw(h, leader != NULL && strcmp(jstr(n, "name"), leader) ==
		    0 ? "<span class=\"chip st-up\">leader</span>" : "follower");
		h_raw(h, "</td><td>");
		if (jget(n, "match") != NULL)
			h_fmt(h, "%lld", (long long)jint(n, "match", 0));
		else
			h_raw(h, "<span class=\"dim\">—</span>");
		h_raw(h, "</td></tr>");
	}
	free(rows);
	h_raw(h, "</tbody></table><p class=\"dim\">Holds: up to which change "
	    "the leader knows a node holds, as the leader sees it.</p>");
}
