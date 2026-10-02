/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * The workflow of one operation, drawn as a tree from left to right:
 * the API call, the session check, the cblink request, and under it
 * what jailgridd did.  The raw output of the programs it ran is one
 * click away, and only offered when there was a program.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "app.h"

#define	MAX_STEPS	300
#define	NODE_W		232
#define	NODE_H		60
#define	GAP_X		40
#define	GAP_Y		12
#define	PAD		12

struct layout {
	const ucl_object_t	*step[MAX_STEPS];
	int			 parent[MAX_STEPS];
	int			 depth[MAX_STEPS];
	int			 row[MAX_STEPS];
	int			 n;
	int			 rows;
	int			 cols;
};

static void	place(struct layout *, int, int);
static void	layout(struct layout *, const ucl_object_t *);
static bool	has_exec(const ucl_object_t *);
static void	step_details(struct html *, const ucl_object_t *);
static void	raw(struct html *, const struct op *);
static void	lines(struct html *, const char *, const char *, int);

/* Depth-first: a leaf takes the next row, a parent its first child's. */
static void
place(struct layout *l, int i, int depth)
{
	int	c, first;

	l->depth[i] = depth;
	if (depth + 1 > l->cols)
		l->cols = depth + 1;
	first = -1;
	for (c = 0; c < l->n; c++) {
		if (l->parent[c] != i || c == i)
			continue;
		place(l, c, depth + 1);
		if (first < 0)
			first = l->row[c];
	}
	l->row[i] = first >= 0 ? first : l->rows++;
}

static void
layout(struct layout *l, const ucl_object_t *trace)
{
	const ucl_object_t	*s;
	ucl_object_iter_t	 it;
	int			 i;

	memset(l, 0, sizeof(*l));
	it = NULL;
	while ((s = ucl_object_iterate(trace, &it, true)) != NULL &&
	    l->n < MAX_STEPS) {
		l->step[l->n] = s;
		l->parent[l->n] = (int)jint(s, "parent", -1);
		if (l->parent[l->n] >= l->n)
			l->parent[l->n] = -1;	/* only point backwards */
		l->n++;
	}
	for (i = 0; i < l->n; i++)
		if (l->parent[i] < 0)
			place(l, i, 0);
}

static bool
has_exec(const ucl_object_t *trace)
{
	const ucl_object_t	*s;
	ucl_object_iter_t	 it;

	it = NULL;
	while ((s = ucl_object_iterate(trace, &it, true)) != NULL)
		if (jstr(s, "kind") != NULL && strcmp(jstr(s, "kind"),
		    "exec") == 0)
			return (true);
	return (false);
}

/* Up to max lines of text, each escaped, in class cls. */
static void
lines(struct html *h, const char *text, const char *cls, int max)
{
	const char	*p, *e;
	char		 buf[1024];
	int		 n;

	if (text == NULL || *text == '\0')
		return;
	h_fmt(h, "<pre class=\"%s\">", cls);
	for (n = 0, p = text; *p != '\0' && (max < 0 || n < max); n++) {
		e = strchr(p, '\n');
		snprintf(buf, sizeof(buf), "%.*s", e != NULL ?
		    (int)(e - p) : (int)strlen(p), p);
		h_txt(h, buf);
		h_raw(h, "\n");
		if (e == NULL)
			break;
		p = e + 1;
	}
	if (max >= 0 && n == max && *p != '\0')
		h_raw(h, "<span class=\"dim\">…</span>");
	h_raw(h, "</pre>");
}

static void
step_details(struct html *h, const ucl_object_t *s)
{
	const ucl_object_t	*a;
	ucl_object_iter_t	 it;
	char			 dur[32];

	fmt_dur(dur, sizeof(dur), jint(s, "duration_us", 0));
	h_raw(h, "<div class=\"step-detail\"><dl class=\"kv\"><dt>kind</dt>"
	    "<dd>");
	h_txt(h, jstr(s, "kind"));
	h_raw(h, "</dd><dt>call</dt><dd class=\"mono\">");
	h_txt(h, jstr(s, "label"));
	h_raw(h, "</dd>");
	if (jstr(s, "detail") != NULL) {
		h_raw(h, "<dt>detail</dt><dd class=\"mono\">");
		h_txt(h, jstr(s, "detail"));
		h_raw(h, "</dd>");
	}
	h_raw(h, "<dt>status</dt><dd>");
	h_txt(h, jstr(s, "status"));
	h_raw(h, "</dd><dt>time</dt><dd>");
	h_txt(h, dur);
	h_raw(h, "</dd>");
	if ((a = jget(s, "argv")) != NULL) {
		h_raw(h, "<dt>argv</dt><dd class=\"mono\">");
		it = NULL;
		while ((s = ucl_object_iterate(a, &it, true)) != NULL) {
			h_raw(h, "<code>");
			h_txt(h, ucl_object_tostring(s));
			h_raw(h, "</code> ");
		}
		h_raw(h, "</dd>");
	}
	h_raw(h, "</dl></div>");
}

/* Every program the operation ran, as a terminal would show it. */
static void
raw(struct html *h, const struct op *o)
{
	const ucl_object_t	*s, *a;
	ucl_object_iter_t	 it, ait;
	char			 dur[32];

	h_raw(h, "<div class=\"raw\"><header><h2>Raw output</h2>"
	    "<span class=\"dim\">");
	if (o != NULL)
		h_txt(h, o->title);
	h_raw(h, "</span><button class=\"icon\" data-act=\"close\" "
	    "title=\"Close\">×</button></header><div class=\"terminal\">");
	it = NULL;
	while (o != NULL && (s = ucl_object_iterate(o->trace, &it,
	    true)) != NULL) {
		if (jstr(s, "kind") == NULL || strcmp(jstr(s, "kind"),
		    "exec") != 0)
			continue;
		h_raw(h, "<div class=\"cmd\"><span class=\"prompt\">#</span>");
		ait = NULL;
		while ((a = ucl_object_iterate(jget(s, "argv"), &ait,
		    true)) != NULL) {
			h_raw(h, " ");
			h_txt(h, ucl_object_tostring(a));
		}
		h_raw(h, "</div>");
		lines(h, jstr(s, "output"), "out", -1);
		lines(h, jstr(s, "error_output"), "out err", -1);
		fmt_dur(dur, sizeof(dur), jint(s, "duration_us", 0));
		h_fmt(h, "<div class=\"exit%s\">exit %lld · ",
		    jint(s, "exit", 0) != 0 ? " bad" : "",
		    (long long)jint(s, "exit", 0));
		h_txt(h, dur);
		h_raw(h, "</div>");
	}
	h_raw(h, "</div></div>");
}

/*
 * The trace pane for o; with o NULL, the raw output of app.raw_op for
 * the modal.
 */
void
view_trace(struct html *h, const struct op *o)
{
	struct layout		 l;
	const ucl_object_t	*s;
	const char		*kind, *st, *ps;
	char			 dur[32];
	int			 i, p, x, y, px, py, w, ht;

	if (o == NULL) {
		raw(h, op_find(app.raw_op));
		return;
	}
	h_fmt(h, "<div class=\"trace o-%s\"><header><i class=\"led\"></i>"
	    "<h3>", o->state == OP_RUNNING ? "running" : o->state == OP_OK ?
	    "ok" : "failed");
	h_txt(h, o->title);
	h_raw(h, "</h3><span class=\"dim\">");
	h_txt(h, o->server);
	h_raw(h, "</span>");
	if (o->state != OP_RUNNING) {
		fmt_dur(dur, sizeof(dur), (int64_t)((o->finished -
		    o->started) * 1000));
		h_raw(h, "<span class=\"dur\">");
		h_txt(h, dur);
		h_raw(h, "</span>");
	}
	if (o->trace != NULL && has_exec(o->trace))
		h_fmt(h, "<button class=\"ghost small\" data-act=\"raw\" "
		    "data-arg=\"%d\" title=\"A program ran: see exactly what "
		    "it printed\">&gt;_ Raw output</button>", o->id);
	h_raw(h, "</header>");
	if (o->error[0] != '\0') {
		h_raw(h, "<p class=\"err\">");
		h_txt(h, o->error);
		h_raw(h, "</p>");
	}

	if (o->trace == NULL) {
		h_raw(h, o->state == OP_RUNNING ? "<div class=\"graph "
		    "pending\"><div class=\"node k-api ghostnode\" "
		    "style=\"left:12px;top:12px\"><div class=\"nl\">"
		    "request</div></div><div class=\"node k-lib ghostnode\" "
		    "style=\"left:284px;top:12px\"><div class=\"nl\">"
		    "waiting for the host…</div></div></div>" :
		    "<p class=\"dim\">No trace: the request did not get an "
		    "answer.</p>");
		h_raw(h, "</div>");
		return;
	}

	layout(&l, o->trace);
	w = PAD * 2 + l.cols * (NODE_W + GAP_X) - GAP_X;
	ht = PAD * 2 + l.rows * (NODE_H + GAP_Y) - GAP_Y;
	h_fmt(h, "<div class=\"graph-scroll\"><div class=\"graph\" "
	    "style=\"width:%dpx;height:%dpx\">", w, ht);
	/* Edges first, under the nodes. */
	h_fmt(h, "<svg class=\"edges\" width=\"%d\" height=\"%d\" "
	    "aria-hidden=\"true\">", w, ht);
	for (i = 0; i < l.n; i++) {
		if ((p = l.parent[i]) < 0)
			continue;
		px = PAD + l.depth[p] * (NODE_W + GAP_X) + NODE_W;
		py = PAD + l.row[p] * (NODE_H + GAP_Y) + NODE_H / 2;
		x = PAD + l.depth[i] * (NODE_W + GAP_X);
		y = PAD + l.row[i] * (NODE_H + GAP_Y) + NODE_H / 2;
		st = h_word(jstr(l.step[i], "status"), "ok");
		h_fmt(h, "<path class=\"e-%s\" d=\"M%d %d C%d %d %d %d %d "
		    "%d\"/>", st, px, py, px + GAP_X / 2,
		    py, x - GAP_X / 2, y, x, y);
	}
	h_raw(h, "</svg>");
	for (i = 0; i < l.n; i++) {
		s = l.step[i];
		kind = h_word(jstr(s, "kind"), "lib");
		ps = h_word(jstr(s, "status"), "ok");
		x = PAD + l.depth[i] * (NODE_W + GAP_X);
		y = PAD + l.row[i] * (NODE_H + GAP_Y);
		fmt_dur(dur, sizeof(dur), jint(s, "duration_us", 0));
		h_fmt(h, "<div class=\"node k-%s st-%s%s\" style=\"left:%dpx;"
		    "top:%dpx\" data-act=\"step\" data-arg=\"%d\"", kind, ps,
		    i == app.trace_step ? " sel" : "", x, y, i);
		h_attr(h, "title", jstr(s, "label"));
		h_raw(h, "><div class=\"nh\"><span class=\"kind\">");
		h_txt(h, kind);
		h_raw(h, "</span><span class=\"dur\">");
		h_txt(h, dur);
		h_raw(h, "</span></div><div class=\"nl\">");
		h_txt(h, jstr(s, "label"));
		h_raw(h, "</div><div class=\"nd\">");
		h_txt(h, jstr(s, "detail"));
		h_raw(h, "</div></div>");
	}
	h_raw(h, "</div></div>");
	if (app.trace_step >= 0 && app.trace_step < l.n) {
		s = l.step[app.trace_step];
		step_details(h, s);
		if (jstr(s, "kind") != NULL && strcmp(jstr(s, "kind"),
		    "exec") == 0) {
			lines(h, jstr(s, "output"), "out preview", 12);
			lines(h, jstr(s, "error_output"), "out err preview",
			    12);
		}
	}
	if (o->diff != NULL) {
		h_raw(h, "<pre class=\"diff\">");
		h_txt(h, o->diff);
		h_raw(h, "</pre>");
	}
	h_raw(h, "</div>");
}
