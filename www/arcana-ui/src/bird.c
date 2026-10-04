/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * BIRD, in a host's network tab.  What birdc says is drawn: the router
 * in the middle and around it its BGP neighbours, its OSPF neighbours
 * and its RPKI caches, each a node to pick.  A neighbour picked opens
 * in a box, with what the daemon says of it and the part of the
 * configuration that makes it, to be changed there.
 *
 * The configuration is a text the host keeps; the page reads it whole,
 * finds its parts (protocols, filters, functions, definitions, tables),
 * and puts it back whole with one part changed.  The host has bird(8)
 * parse it first: what does not parse does not stay.  Filters and
 * functions are edited as they are written; a definition that is a set,
 * of communities, large communities or prefixes, as a list.
 */

#include <ctype.h>
#include <math.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "app.h"

#define	BLOCKS_MAX	512

/* A part of the configuration: where it is in the text, and what. */
struct block {
	size_t	start, end;
	char	kind[16];	/* protocol, template, filter, function, ... */
	char	type[16];	/* of a protocol: bgp, ospf, rpki, ... */
	char	name[64];
};

static struct {
	char		 sid[9];
	char		 path[256];	/* the file shown; "" the main one */
	char		*text;
	char		 sha[65];
	ucl_object_t	*files;
	bool		 loading;
	char		 error[300];
	struct block	 b[BLOCKS_MAX];
	int		 nb;
	/* What the open box edits. */
	int		 edit;		/* its block, or -1 for a new one */
	char		 proto[64];	/* the protocol the box is about */
	char		*draft;		/* what was typed, kept over a refusal */
	char		 newkind[16];	/* of a new part: filter, set, ... */
	bool		 saving;
} bd = { .edit = -1 };

/* The end of what starts at p and is not to be read: blanks, comments. */
static const char *
skip(const char *p)
{

	for (;;) {
		while (isspace((unsigned char)*p))
			p++;
		if (*p == '#') {
			p += strcspn(p, "\n");
		} else if (p[0] == '/' && p[1] == '*') {
			p = strstr(p + 2, "*/");
			if (p == NULL)
				return ("");
			p += 2;
		} else
			return (p);
	}
}

/* A word of the configuration at p, into buf; the place after it. */
static const char *
word(const char *p, char *buf, size_t len)
{
	size_t	n;

	p = skip(p);
	n = 0;
	while (*p != '\0' && (isalnum((unsigned char)*p) || *p == '_') &&
	    n + 1 < len)
		buf[n++] = *p++;
	buf[n] = '\0';
	return (p);
}

/*
 * The parts of the text: each from its first word to the ';' or the '}'
 * that ends it, outside any braces, brackets, strings and comments.
 */
static void
blocks(void)
{
	struct block	*b;
	const char	*t, *p, *q;
	char		 w2[64], w3[64];
	int		 depth;

	bd.nb = 0;
	if ((t = bd.text) == NULL)
		return;
	p = skip(t);
	while (*p != '\0' && bd.nb < BLOCKS_MAX) {
		b = &bd.b[bd.nb];
		memset(b, 0, sizeof(*b));
		b->start = (size_t)(p - t);
		depth = 0;
		for (q = p; *q != '\0'; q++) {
			if (*q == '#')
				q += strcspn(q, "\n") - 1;
			else if (q[0] == '/' && q[1] == '*') {
				q = strstr(q + 2, "*/");
				if (q == NULL) {
					q = p + strlen(p) - 1;
					break;
				}
				q++;
			} else if (*q == '"') {
				q++;
				q += strcspn(q, "\"\n");
				if (*q == '\0')
					q--;
			} else if (*q == '{' || *q == '[' || *q == '(')
				depth++;
			else if (*q == ']' || *q == ')')
				depth--;
			else if (*q == '}') {
				if (--depth <= 0) {
					/* "};" is one end, not two. */
					if (*skip(q + 1) == ';')
						q = skip(q + 1);
					break;
				}
			} else if (*q == ';' && depth <= 0)
				break;
		}
		if (*q != '\0')
			q++;
		b->end = (size_t)(q - t);
		q = word(p, b->kind, sizeof(b->kind));
		q = word(q, w2, sizeof(w2));
		(void)word(q, w3, sizeof(w3));
		if (strcmp(b->kind, "protocol") == 0 || strcmp(b->kind,
		    "template") == 0) {
			snprintf(b->type, sizeof(b->type), "%s", w2);
			if (strcmp(w3, "from") != 0)
				snprintf(b->name, sizeof(b->name), "%s", w3);
		} else if (strcmp(w3, "table") == 0 || strcmp(w2, "table") ==
		    0) {
			/* "roa4 table r4;", "ipv4 table t;" */
			snprintf(b->type, sizeof(b->type), "%s", b->kind);
			snprintf(b->name, sizeof(b->name), "%s", strcmp(w2,
			    "table") == 0 ? w3 : w2);
			snprintf(b->kind, sizeof(b->kind), "table");
		} else
			snprintf(b->name, sizeof(b->name), "%s", w2);
		bd.nb++;
		p = skip(t + b->end);
	}
}

static int
block_find(const char *kind, const char *name)
{
	int	i;

	for (i = 0; i < bd.nb; i++)
		if (strcmp(bd.b[i].kind, kind) == 0 && strcmp(bd.b[i].name,
		    name) == 0)
			return (i);
	return (-1);
}

/* The text of a part; free() it. */
static char *
block_text(int i)
{

	return (strndup(bd.text + bd.b[i].start, bd.b[i].end - bd.b[i].start));
}

/*
 * What a definition is, by what it is set to: a set of communities
 * (pairs), of large communities (triples), of something else in
 * brackets, or a value.
 */
static const char *
set_kind(int i)
{
	const char	*p, *e, *q;
	int		 commas, depth, pairs, triples, others;

	p = bd.text + bd.b[i].start;
	e = bd.text + bd.b[i].end;
	if ((p = memchr(p, '=', (size_t)(e - p))) == NULL)
		return ("value");
	p = skip(p + 1);
	if (*p != '[')
		return ("value");
	pairs = triples = others = 0;
	for (p++; p < e && *p != ']'; p++) {
		if (*p != '(') {
			if (!isspace((unsigned char)*p) && *p != ',')
				others++;
			continue;
		}
		commas = 0;
		depth = 1;
		for (q = p + 1; q < e && depth > 0; q++) {
			if (*q == '(')
				depth++;
			else if (*q == ')')
				depth--;
			else if (*q == ',' && depth == 1)
				commas++;
		}
		if (commas == 1)
			pairs++;
		else if (commas == 2)
			triples++;
		else
			others++;
		p = q - 1;
	}
	if (others == 0 && pairs > 0 && triples == 0)
		return ("communities");
	if (others == 0 && triples > 0 && pairs == 0)
		return ("large communities");
	return (pairs + triples + others == 0 ? "empty set" : "set");
}

/* The entries of a set, one a line, as the box shows them; free() it. */
static char *
set_lines(int i)
{
	struct html	 h;
	const char	*p, *e;
	int		 depth;
	bool		 any;

	memset(&h, 0, sizeof(h));
	p = bd.text + bd.b[i].start;
	e = bd.text + bd.b[i].end;
	if ((p = memchr(p, '[', (size_t)(e - p))) == NULL)
		return (strdup(""));
	depth = 0;
	any = false;
	for (p++; p < e && !(*p == ']' && depth == 0); p++) {
		if (*p == '(')
			depth++;
		else if (*p == ')')
			depth--;
		if (*p == ',' && depth == 0) {
			h_raw(&h, "\n");
			any = false;
			continue;
		}
		if (isspace((unsigned char)*p) && (!any || depth == 0))
			continue;
		h_fmt(&h, "%c", *p);
		any = true;
	}
	return (h.s != NULL ? h.s : strdup(""));
}

static void
conf_cb(int status, const ucl_object_t *o, const char *err, void *arg)
{
	bool	save;

	save = arg != NULL;
	bd.loading = false;
	bd.saving = false;
	if (status != 200 || !jbool(o, "ok")) {
		snprintf(save ? app.modal_error : bd.error, save ?
		    sizeof(app.modal_error) : sizeof(bd.error), "%s",
		    status == 200 && jstr(o, "error") != NULL ? jstr(o,
		    "error") : err != NULL ? err : "no answer");
		/* Refused: the text there is the one to start from again. */
		if (status == 200 && jstr(o, "sha256") != NULL && jstr(o,
		    "text") != NULL && !save) {
			free(bd.text);
			bd.text = strdup(jstr(o, "text"));
			snprintf(bd.sha, sizeof(bd.sha), "%s", jstr(o, "sha256"));
			blocks();
		}
		return;
	}
	bd.error[0] = '\0';
	if (jstr(o, "text") != NULL) {
		free(bd.text);
		bd.text = strdup(jstr(o, "text"));
		snprintf(bd.sha, sizeof(bd.sha), "%s", jstr(o, "sha256") !=
		    NULL ? jstr(o, "sha256") : "");
		blocks();
	}
	if (jget(o, "files") != NULL) {
		if (bd.files != NULL)
			ucl_object_unref(bd.files);
		bd.files = ucl_object_ref((ucl_object_t *)(uintptr_t)jget(o,
		    "files"));
	}
	if (save) {
		free(bd.draft);
		bd.draft = NULL;
		app.modal = MODAL_NONE;
		toast(false, "BIRD has its new configuration");
		if (cur_server() != NULL) {
			app.net.loading = false;
			refresh_network(cur_server(), false);
		}
	}
}

/* Read the configuration of the host shown, once for each host. */
static void
conf_load(struct server *s, bool again)
{
	char	url[400];

	if (bd.loading || (!again && strcmp(bd.sid, s->id) == 0 && (bd.text !=
	    NULL || bd.error[0] != '\0')))
		return;
	if (strcmp(bd.sid, s->id) != 0) {
		free(bd.text);
		bd.text = NULL;
		bd.nb = 0;
		bd.path[0] = '\0';
		bd.error[0] = '\0';
	}
	snprintf(bd.sid, sizeof(bd.sid), "%s", s->id);
	bd.loading = true;
	snprintf(url, sizeof(url), "/api/servers/%s/bird/config%s%s", s->id,
	    bd.path[0] != '\0' ? "?path=" : "", bd.path);
	api("GET", url, NULL, conf_cb, NULL);
}

/* Put text in the file's place; the box stays until the host took it. */
static void
conf_save(struct server *s, const char *text, bool check)
{
	char	url[96], *qt, *qp, *body;

	snprintf(url, sizeof(url), "/api/servers/%s/bird/config", s->id);
	qt = json_quote(text);
	qp = json_quote(bd.path);
	if (asprintf(&body, "{\"path\":%s,\"text\":%s,\"sha256\":\"%s\","
	    "\"check\":%s}", qp, qt, bd.sha, check ? "true" : "false") == -1)
		abort();
	free(qt);
	free(qp);
	bd.saving = true;
	app.modal_error[0] = '\0';
	api("POST", url, body, conf_cb, check ? NULL : &bd);
	free(body);
}

/* The whole text with part i replaced by with ("" takes it out). */
static char *
spliced(int i, const char *with)
{
	char	*out;
	size_t	 len, end;

	len = strlen(bd.text);
	if (i < 0) {
		if (asprintf(&out, "%s%s%s\n", bd.text, len > 0 &&
		    bd.text[len - 1] != '\n' ? "\n\n" : "\n", with) == -1)
			abort();
		return (out);
	}
	end = bd.b[i].end;
	/* A part taken out takes the line it ended with it. */
	if (with[0] == '\0')
		while (bd.text[end] == '\n' || bd.text[end] == ' ')
			end++;
	if (asprintf(&out, "%.*s%s%s", (int)bd.b[i].start, bd.text, with,
	    bd.text + end) == -1)
		abort();
	return (out);
}

static const ucl_object_t *
proto_find(const ucl_object_t *data, const char *name)
{
	const ucl_object_t	*o;
	ucl_object_iter_t	 it;

	it = NULL;
	while ((o = ucl_object_iterate(jget(data, "protocols"), &it, true)) !=
	    NULL)
		if (jstr(o, "name") != NULL && strcmp(jstr(o, "name"), name) ==
		    0)
			return (o);
	return (NULL);
}

static const char *
state_of(const ucl_object_t *o)
{
	const char	*st;

	st = jstr(o, "state") != NULL ? jstr(o, "state") : "";
	return (strcmp(st, "up") == 0 ? "up" : strcmp(st, "down") == 0 ?
	    "down" : "unknown");
}

/* The router in the middle, and what it speaks to around it. */
static void
graph(struct html *h, const ucl_object_t *data)
{
	const ucl_object_t	*o, *l;
	ucl_object_iter_t	 it;
	const char		*proto, *rid, *t;
	char			 sub[96];
	double			 a, x, y;
	int			 n, i, total;

	total = 0;
	it = NULL;
	while ((o = ucl_object_iterate(jget(data, "protocols"), &it, true)) !=
	    NULL) {
		proto = jstr(o, "proto") != NULL ? jstr(o, "proto") : "";
		if (strcmp(proto, "BGP") == 0 || strcmp(proto, "RPKI") == 0)
			total++;
	}
	total += (int)ucl_array_size(jget(data, "ospf"));
	if (total == 0)
		return;
	rid = "this router";
	it = NULL;
	while ((l = ucl_object_iterate(jget(data, "status"), &it, true)) !=
	    NULL)
		if ((t = ucl_object_tostring_forced(l)) != NULL && strncmp(t,
		    "Router ID is ", 13) == 0)
			rid = t + 13;
	h_raw(h, "<div class=\"map-wrap birdmap\"><svg class=\"topo big\" "
	    "viewBox=\"0 0 1000 440\">");
	/* The lines first, under the nodes. */
	for (i = 0; i < total && i < 48; i++) {
		a = -M_PI / 2 + 2 * M_PI * i / (total > 48 ? 48 : total);
		h_fmt(h, "<path class=\"spoke s%d\" d=\"M500 220 L%.1f %.1f\"/>",
		    i, 500 + 380 * cos(a), 220 + 165 * sin(a));
	}
	h_raw(h, "<g class=\"tnode up hub\" transform=\"translate(500,220)\">"
	    "<rect class=\"box\" x=\"-80\" y=\"-26\" width=\"160\" height=\"52\" "
	    "rx=\"10\"/><text class=\"name\" x=\"-68\" y=\"-3\">BIRD</text>"
	    "<text class=\"sub\" x=\"-68\" y=\"15\">");
	h_txt(h, rid);
	h_raw(h, "</text></g>");
	n = 0;
	it = NULL;
	while ((o = ucl_object_iterate(jget(data, "protocols"), &it, true)) !=
	    NULL && n < 48) {
		proto = jstr(o, "proto") != NULL ? jstr(o, "proto") : "";
		if (strcmp(proto, "BGP") != 0 && strcmp(proto, "RPKI") != 0)
			continue;
		a = -M_PI / 2 + 2 * M_PI * n / (total > 48 ? 48 : total);
		x = 500 + 380 * cos(a);
		y = 220 + 165 * sin(a);
		n++;
		h_fmt(h, "<g class=\"tnode %s peer %s\" transform=\"translate("
		    "%.1f,%.1f)\" data-act=\"bird-open\"", state_of(o),
		    proto[0] == 'B' ? "bgp" : "rpki", x, y);
		h_attr(h, "data-arg", jstr(o, "name"));
		h_raw(h, "><rect class=\"box\" x=\"-78\" y=\"-24\" width=\"156\" "
		    "height=\"48\" rx=\"10\"/><circle class=\"led\" cx=\"-64\" "
		    "cy=\"-8\" r=\"4\"/><text class=\"name\" x=\"-54\" y=\"-3\">");
		h_txt(h, jstr(o, "name"));
		h_raw(h, "</text><text class=\"sub\" x=\"-66\" y=\"14\">");
		if (proto[0] == 'B')
			snprintf(sub, sizeof(sub), "AS%s · %s", jstr(o,
			    "neighbor-as") != NULL ? jstr(o, "neighbor-as") :
			    "?", jstr(o, "neighbor") != NULL ? jstr(o,
			    "neighbor") : "?");
		else
			snprintf(sub, sizeof(sub), "RPKI · %s", jstr(o,
			    "cache") != NULL ? jstr(o, "cache") : "?");
		h_txt(h, sub);
		h_raw(h, "</text></g>");
	}
	it = NULL;
	while ((o = ucl_object_iterate(jget(data, "ospf"), &it, true)) !=
	    NULL && n < 48) {
		a = -M_PI / 2 + 2 * M_PI * n / (total > 48 ? 48 : total);
		x = 500 + 380 * cos(a);
		y = 220 + 165 * sin(a);
		n++;
		t = jstr(o, "state") != NULL ? jstr(o, "state") : "";
		h_fmt(h, "<g class=\"tnode %s peer ospf\" transform=\""
		    "translate(%.1f,%.1f)\" data-act=\"bird-open\"",
		    strncmp(t, "Full", 4) == 0 ? "up" : "unknown", x, y);
		h_attr(h, "data-arg", jstr(o, "proto"));
		h_raw(h, "><rect class=\"box\" x=\"-78\" y=\"-24\" width=\"156\" "
		    "height=\"48\" rx=\"10\"/><circle class=\"led\" cx=\"-64\" "
		    "cy=\"-8\" r=\"4\"/><text class=\"name\" x=\"-54\" y=\"-3\">");
		h_txt(h, jstr(o, "router-id"));
		h_raw(h, "</text><text class=\"sub\" x=\"-66\" y=\"14\">");
		snprintf(sub, sizeof(sub), "OSPF %s · %s", t, jstr(o,
		    "interface") != NULL ? jstr(o, "interface") : "");
		h_txt(h, sub);
		h_raw(h, "</text></g>");
	}
	h_raw(h, "</svg><ul class=\"map-legend\"><li class=\"bgp\">BGP</li>"
	    "<li class=\"ospf\">OSPF</li><li class=\"rpki\">RPKI</li></ul>"
	    "</div>");
}

/* A number of routes, short: 845233 as 845.2k. */
static void
count(char *buf, size_t len, int64_t n)
{

	if (n >= 1000000)
		snprintf(buf, len, "%.2fM", (double)n / 1e6);
	else if (n >= 10000)
		snprintf(buf, len, "%.1fk", (double)n / 1e3);
	else
		snprintf(buf, len, "%lld", (long long)n);
}

void
view_bird(struct html *h, struct server *s, const ucl_object_t *data)
{
	static const char *const verbs[] = { "restart", "reload" };
	const ucl_object_t	*o, *l, *c;
	ucl_object_iter_t	 it, cit;
	const char		*state, *kind;
	char			 in[24], out[24], *lines;
	size_t			 k;
	int64_t			 imp, exp;
	int			 i, n;

	conf_load(s, false);
	h_raw(h, "<section class=\"pane bird\"><h4><span>BIRD</span><span "
	    "class=\"pane-actions\"><button class=\"ghost small\" data-act=\""
	    "bird-file\" title=\"The configuration, whole\">Configuration"
	    "</button><button class=\"ghost small\" data-act=\"bird-verb\" "
	    "data-arg=\"configure\" data-value=\"\" title=\"Read its "
	    "configuration again\">Reconfigure</button></span></h4>"
	    "<p class=\"mono\">");
	it = NULL;
	while ((l = ucl_object_iterate(jget(data, "status"), &it, true)) !=
	    NULL) {
		h_txt(h, ucl_object_tostring_forced(l));
		h_raw(h, "<br>");
	}
	h_raw(h, "</p></section>");
	graph(h, data);

	h_raw(h, "<h4 class=\"family\">Protocols</h4><table class=\"net bird\">"
	    "<thead><tr><th>Protocol</th><th>Kind</th><th>Neighbour</th><th>"
	    "State</th><th>Since</th><th>Routes in / out</th><th>Info</th>"
	    "<th></th></tr></thead><tbody>");
	it = NULL;
	while ((o = ucl_object_iterate(jget(data, "protocols"), &it, true)) !=
	    NULL) {
		if (jstr(o, "name") == NULL || (app.filter[0] != '\0' &&
		    strstr(jstr(o, "name"), app.filter) == NULL && (jstr(o,
		    "proto") == NULL || strstr(jstr(o, "proto"), app.filter) ==
		    NULL) && (jstr(o, "neighbor") == NULL || strstr(jstr(o,
		    "neighbor"), app.filter) == NULL)))
			continue;
		state = jstr(o, "state") != NULL ? jstr(o, "state") : "";
		h_fmt(h, "<tr class=\"%s pick\" data-act=\"bird-open\"",
		    strcmp(state, "up") == 0 ? "up" : strcmp(state, "down") ==
		    0 ? "down" : "start");
		h_attr(h, "data-arg", jstr(o, "name"));
		h_raw(h, "><td><i class=\"led\"></i><b>");
		h_txt(h, jstr(o, "name"));
		h_raw(h, "</b>");
		if (jstr(o, "description") != NULL) {
			h_raw(h, "<small>");
			h_txt(h, jstr(o, "description"));
			h_raw(h, "</small>");
		}
		h_raw(h, "</td><td>");
		h_txt(h, jstr(o, "proto"));
		h_raw(h, "</td><td>");
		if (jstr(o, "neighbor") != NULL) {
			h_txt(h, jstr(o, "neighbor"));
			h_raw(h, "<small>AS");
			h_txt(h, jstr(o, "neighbor-as"));
			h_raw(h, "</small>");
		} else if (jstr(o, "cache") != NULL)
			h_txt(h, jstr(o, "cache"));
		h_raw(h, "</td><td>");
		h_txt(h, state);
		h_raw(h, "</td><td>");
		h_txt(h, jstr(o, "since"));
		h_raw(h, "</td><td>");
		imp = exp = 0;
		n = 0;
		cit = NULL;
		while ((c = ucl_object_iterate(jget(o, "channels"), &cit,
		    true)) != NULL) {
			imp += jint(c, "imported", 0);
			exp += jint(c, "exported", 0);
			n++;
		}
		if (n > 0) {
			count(in, sizeof(in), imp);
			count(out, sizeof(out), exp);
			h_txt(h, in);
			h_raw(h, " / ");
			h_txt(h, out);
		}
		h_raw(h, "</td><td>");
		h_txt(h, jstr(o, "info"));
		h_raw(h, "</td><td class=\"acts\">");
		for (k = 0; k < 2; k++) {
			h_fmt(h, "<button class=\"ghost small\" data-act=\""
			    "bird-verb\" data-arg=\"%s\"", verbs[k]);
			h_attr(h, "data-value", jstr(o, "name"));
			h_fmt(h, ">%s</button>", verbs[k]);
		}
		h_raw(h, "</td></tr>");
	}
	h_raw(h, "</tbody></table>");

	if (ucl_array_size(jget(data, "tables")) > 0) {
		h_raw(h, "<h4 class=\"family\">Tables</h4><div class=\"facts "
		    "tables\">");
		it = NULL;
		while ((o = ucl_object_iterate(jget(data, "tables"), &it,
		    true)) != NULL) {
			i = block_find("table", jstr(o, "name") != NULL ?
			    jstr(o, "name") : "");
			count(in, sizeof(in), jint(o, "routes", 0));
			h_raw(h, "<div><b>");
			h_txt(h, in);
			h_raw(h, "</b><span>");
			h_txt(h, jstr(o, "name"));
			if (i >= 0 && strncmp(bd.b[i].type, "roa", 3) == 0)
				h_raw(h, " · ROA");
			h_raw(h, "</span></div>");
		}
		h_raw(h, "</div>");
	}

	/* From here on: what the configuration is made of. */
	h_raw(h, "<h4 class=\"family\">Configuration");
	if (ucl_array_size(bd.files) > 1) {
		h_raw(h, " <select class=\"conf-file\" data-input=\""
		    "bird-path\">");
		it = NULL;
		n = 0;
		while ((l = ucl_object_iterate(bd.files, &it, true)) != NULL) {
			const char *f = ucl_object_tostring_forced(l);

			h_raw(h, "<option");
			h_attr(h, "value", n == 0 ? "" : f);
			if (strcmp(bd.path, n == 0 ? "" : f) == 0)
				h_raw(h, " selected");
			h_raw(h, ">");
			h_txt(h, f);
			h_raw(h, "</option>");
			n++;
		}
		h_raw(h, "</select>");
	}
	h_raw(h, "</h4>");
	if (bd.error[0] != '\0') {
		h_raw(h, "<div class=\"notice bad\">");
		h_txt(h, bd.error);
		h_raw(h, "</div>");
	}
	if (bd.text == NULL) {
		h_raw(h, bd.loading ? "<div class=\"empty small\"><div class=\""
		    "loader\"></div></div>" : "");
		return;
	}
	h_raw(h, "<div class=\"conf-grid\"><section class=\"pane\"><h4><span>"
	    "Filters and functions</span><span class=\"pane-actions\"><button "
	    "class=\"ghost small\" data-act=\"bird-new\" data-arg=\"filter\">"
	    "+ filter</button><button class=\"ghost small\" data-act=\""
	    "bird-new\" data-arg=\"function\">+ function</button></span></h4>"
	    "<p class=\"dim\">What BGP and OSPF take in and give out: named "
	    "in a protocol's <code>import</code> and <code>export</code>.</p>"
	    "<ul class=\"blocks\">");
	n = 0;
	for (i = 0; i < bd.nb; i++) {
		if (strcmp(bd.b[i].kind, "filter") != 0 && strcmp(bd.b[i].kind,
		    "function") != 0)
			continue;
		n++;
		h_fmt(h, "<li data-act=\"bird-edit\" data-arg=\"%d\"><b>", i);
		h_txt(h, bd.b[i].name);
		h_fmt(h, "</b><span class=\"dim\">%s</span></li>",
		    bd.b[i].kind);
	}
	if (n == 0)
		h_raw(h, "<li class=\"dim none\">None in this file.</li>");
	h_raw(h, "</ul></section><section class=\"pane\"><h4><span>"
	    "Communities and sets</span><span class=\"pane-actions\"><button "
	    "class=\"ghost small\" data-act=\"bird-new\" data-arg=\"set\">"
	    "+ communities</button><button class=\"ghost small\" data-act=\""
	    "bird-new\" data-arg=\"lset\">+ large</button></span></h4><p class="
	    "\"dim\">Named lists a filter tests against: <code>bgp_community "
	    "~ NAME</code>, <code>bgp_large_community ~ NAME</code>.</p>"
	    "<ul class=\"blocks\">");
	n = 0;
	for (i = 0; i < bd.nb; i++) {
		if (strcmp(bd.b[i].kind, "define") != 0)
			continue;
		kind = set_kind(i);
		n++;
		h_fmt(h, "<li data-act=\"bird-edit\" data-arg=\"%d\"><b>", i);
		h_txt(h, bd.b[i].name);
		h_fmt(h, "</b><span class=\"dim\">%s</span>", kind);
		if (strcmp(kind, "value") != 0) {
			lines = set_lines(i);
			h_raw(h, "<small class=\"mono\">");
			for (k = 0; lines[k] != '\0' && k < 120; k++)
				if (lines[k] == '\n')
					lines[k] = ' ';
			lines[k] = '\0';
			h_txt(h, lines);
			h_raw(h, "</small>");
			free(lines);
		}
		h_raw(h, "</li>");
	}
	if (n == 0)
		h_raw(h, "<li class=\"dim none\">None in this file.</li>");
	h_raw(h, "</ul></section><section class=\"pane\"><h4><span>RPKI</span>"
	    "<span class=\"pane-actions\"><button class=\"ghost small\" "
	    "data-act=\"bird-new\" data-arg=\"rpki\">+ cache</button></span>"
	    "</h4><p class=\"dim\">Route origins, from a validator's cache "
	    "into ROA tables that a filter checks with <code>roa_check</code>."
	    "</p><ul class=\"blocks\">");
	n = 0;
	it = NULL;
	while ((o = ucl_object_iterate(jget(data, "protocols"), &it, true)) !=
	    NULL) {
		if (jstr(o, "proto") == NULL || strcmp(jstr(o, "proto"),
		    "RPKI") != 0)
			continue;
		n++;
		h_fmt(h, "<li class=\"%s\" data-act=\"bird-open\"", state_of(o));
		h_attr(h, "data-arg", jstr(o, "name"));
		h_raw(h, "><b>");
		h_txt(h, jstr(o, "name"));
		h_raw(h, "</b><span class=\"dim\">");
		h_txt(h, jstr(o, "cache"));
		h_raw(h, " · ");
		h_txt(h, jstr(o, "rpki-status") != NULL ? jstr(o,
		    "rpki-status") : jstr(o, "info"));
		h_raw(h, "</span></li>");
	}
	for (i = 0; i < bd.nb; i++) {
		if (strcmp(bd.b[i].kind, "table") != 0 || strncmp(bd.b[i].type,
		    "roa", 3) != 0)
			continue;
		n++;
		h_fmt(h, "<li data-act=\"bird-edit\" data-arg=\"%d\"><b>", i);
		h_txt(h, bd.b[i].name);
		h_fmt(h, "</b><span class=\"dim\">%s table", bd.b[i].type);
		it = NULL;
		while ((o = ucl_object_iterate(jget(data, "tables"), &it,
		    true)) != NULL)
			if (jstr(o, "name") != NULL && strcmp(jstr(o, "name"),
			    bd.b[i].name) == 0) {
				count(in, sizeof(in), jint(o, "routes", 0));
				h_raw(h, " · ");
				h_txt(h, in);
				h_raw(h, " origins");
			}
		h_raw(h, "</span></li>");
	}
	if (n == 0)
		h_raw(h, "<li class=\"dim none\">No cache, no ROA table.</li>");
	h_raw(h, "</ul></section><section class=\"pane\"><h4><span>Protocols "
	    "and the rest</span><span class=\"pane-actions\"><button class=\""
	    "ghost small\" data-act=\"bird-new\" data-arg=\"bgp\">+ BGP "
	    "neighbour</button><button class=\"ghost small\" data-act=\""
	    "bird-new\" data-arg=\"ospf\">+ OSPF</button></span></h4><ul "
	    "class=\"blocks\">");
	for (i = 0; i < bd.nb; i++) {
		if (strcmp(bd.b[i].kind, "filter") == 0 || strcmp(bd.b[i].kind,
		    "function") == 0 || strcmp(bd.b[i].kind, "define") == 0 ||
		    (strcmp(bd.b[i].kind, "table") == 0 && strncmp(bd.b[i].type,
		    "roa", 3) == 0))
			continue;
		h_fmt(h, "<li data-act=\"bird-edit\" data-arg=\"%d\"><b>", i);
		h_txt(h, bd.b[i].name[0] != '\0' ? bd.b[i].name : bd.b[i].kind);
		h_raw(h, "</b><span class=\"dim\">");
		h_txt(h, bd.b[i].kind);
		if (bd.b[i].type[0] != '\0' && strcmp(bd.b[i].kind, "table") !=
		    0) {
			h_raw(h, " ");
			h_txt(h, bd.b[i].type);
		}
		h_raw(h, "</span></li>");
	}
	h_raw(h, "</ul></section></div>");
}

/* What a new part starts as, for the kind asked for. */
static const char *
skeleton(const char *kind)
{

	if (strcmp(kind, "filter") == 0)
		return ("filter NAME {\n\t# if bgp_community ~ CUSTOMERS then "
		    "accept;\n\t# if rpki_invalid() then reject;\n\taccept;\n}");
	if (strcmp(kind, "function") == 0)
		return ("function NAME() {\n\treturn true;\n}");
	if (strcmp(kind, "bgp") == 0)
		return ("protocol bgp NAME {\n\tdescription \"\";\n\tlocal as "
		    "65000;\n\tneighbor 192.0.2.1 as 65001;\n\tipv4 {\n\t\t"
		    "import filter NAME;\n\t\texport filter NAME;\n\t};\n\t"
		    "ipv6 {\n\t\timport none;\n\t\texport none;\n\t};\n}");
	if (strcmp(kind, "ospf") == 0)
		return ("protocol ospf v2 NAME {\n\tipv4 {\n\t\timport all;\n"
		    "\t\texport filter NAME;\n\t};\n\tarea 0 {\n\t\tinterface "
		    "\"em0\" {\n\t\t\tcost 10;\n\t\t};\n\t};\n}");
	return ("");
}

/* The boxes of BIRD; true when the one open is one of them. */
bool
bird_modal(struct html *h)
{
	const ucl_object_t	*o, *c, *l;
	ucl_object_iter_t	 it;
	const char		*kind;
	char			*text;
	int			 i;
	bool			 set;

	switch (app.modal) {
	case MODAL_BIRD_PROTO:
		o = strcmp(app.net.sid, bd.sid) == 0 ? proto_find(jget(
		    app.net.data, "data"), bd.proto) : NULL;
		i = block_find("protocol", bd.proto);
		h_raw(h, "<form data-form=\"bird-block\" class=\"wide\"><h2>");
		h_txt(h, bd.proto);
		if (o != NULL) {
			h_fmt(h, " <small class=\"state %s\">", state_of(o));
			h_txt(h, jstr(o, "proto"));
			h_raw(h, " · ");
			h_txt(h, jstr(o, "state"));
			if (jstr(o, "info") != NULL && jstr(o, "info")[0] !=
			    '\0') {
				h_raw(h, " · ");
				h_txt(h, jstr(o, "info"));
			}
			h_raw(h, "</small>");
		}
		h_raw(h, "</h2>");
		if (o != NULL) {
			static const struct {
				const char	*key, *title;
			} facts[] = {
				{ "description", "Description" },
				{ "neighbor", "Neighbour" },
				{ "neighbor-as", "Its AS" },
				{ "local-as", "Local AS" },
				{ "neighbor-id", "Its router ID" },
				{ "source", "Source address" },
				{ "bgp-state", "Session" },
				{ "hold", "Hold timer" },
				{ "last-error", "Last error" },
				{ "cache", "Cache server" },
				{ "rpki-status", "Status" },
				{ "serial", "Serial" },
				{ "since", "Since" },
			};
			size_t	k;

			h_raw(h, "<dl class=\"kv\">");
			for (k = 0; k < sizeof(facts) / sizeof(facts[0]); k++) {
				if (jstr(o, facts[k].key) == NULL)
					continue;
				h_fmt(h, "<dt>%s</dt><dd>", facts[k].title);
				h_txt(h, jstr(o, facts[k].key));
				h_raw(h, "</dd>");
			}
			h_raw(h, "</dl>");
			if (ucl_array_size(jget(o, "channels")) > 0) {
				h_raw(h, "<table class=\"net\"><thead><tr><th>"
				    "Channel</th><th>State</th><th>Table</th>"
				    "<th>Import filter</th><th>Export filter"
				    "</th><th>Routes</th></tr></thead><tbody>");
				it = NULL;
				while ((c = ucl_object_iterate(jget(o,
				    "channels"), &it, true)) != NULL) {
					h_raw(h, "<tr><td>");
					h_txt(h, jstr(c, "name"));
					h_raw(h, "</td><td>");
					h_txt(h, jstr(c, "state"));
					h_raw(h, "</td><td>");
					h_txt(h, jstr(c, "table"));
					h_raw(h, "</td><td>");
					h_txt(h, jstr(c, "input-filter"));
					h_raw(h, "</td><td>");
					h_txt(h, jstr(c, "output-filter"));
					h_raw(h, "</td><td>");
					h_txt(h, jstr(c, "routes"));
					h_raw(h, "</td></tr>");
				}
				h_raw(h, "</tbody></table>");
			}
			h_raw(h, "<div class=\"pane-actions\">");
			{
				static const char *const vs[] = { "restart",
				    "reload", "disable", "enable" };

				for (k = 0; k < 4; k++) {
					h_fmt(h, "<button type=\"button\" class="
					    "\"ghost small\" data-act=\""
					    "bird-verb\" data-arg=\"%s\"",
					    vs[k]);
					h_attr(h, "data-value", bd.proto);
					h_fmt(h, ">%s</button>", vs[k]);
				}
			}
			h_raw(h, "</div><details><summary>All that birdc says "
			    "of it</summary><pre>");
			it = NULL;
			while ((l = ucl_object_iterate(jget(o, "detail"), &it,
			    true)) != NULL) {
				h_txt(h, ucl_object_tostring_forced(l));
				h_raw(h, "\n");
			}
			h_raw(h, "</pre></details>");
		}
		if (i < 0) {
			h_raw(h, "<p class=\"dim\">Its configuration is not "
			    "in the file shown; pick the file it is in under "
			    "<b>Configuration</b>.</p>");
			return (true);
		}
		bd.edit = i;
		text = bd.draft != NULL ? strdup(bd.draft) : block_text(i);
		h_raw(h, "<label>Its configuration<textarea name=\"text\" "
		    "class=\"code\" spellcheck=\"false\" rows=\"14\">");
		h_txt(h, text);
		h_raw(h, "</textarea><small>Filters are named in <code>import"
		    "</code> and <code>export</code>; bird parses the whole "
		    "configuration before it is taken, and what it refuses "
		    "is not kept.</small></label>");
		free(text);
		return (true);
	case MODAL_BIRD_BLOCK:
		i = bd.edit;
		set = (i >= 0 && strcmp(bd.b[i].kind, "define") == 0 &&
		    strcmp(set_kind(i), "value") != 0) || strcmp(bd.newkind,
		    "set") == 0 || strcmp(bd.newkind, "lset") == 0;
		kind = i >= 0 ? bd.b[i].kind : bd.newkind;
		h_fmt(h, "<form data-form=\"%s\" class=\"wide\"><h2>", set ?
		    "bird-set" : "bird-block");
		if (i >= 0) {
			h_txt(h, bd.b[i].name[0] != '\0' ? bd.b[i].name :
			    bd.b[i].kind);
			h_raw(h, " <small>");
			h_txt(h, set ? set_kind(i) : kind);
			h_raw(h, "</small>");
		} else
			h_fmt(h, "New %s", strcmp(kind, "set") == 0 ?
			    "community set" : strcmp(kind, "lset") == 0 ?
			    "large community set" : strcmp(kind, "bgp") == 0 ?
			    "BGP neighbour" : strcmp(kind, "ospf") == 0 ?
			    "OSPF instance" : kind);
		h_raw(h, "</h2>");
		if (set) {
			text = bd.draft != NULL ? strdup(bd.draft) : i >= 0 ?
			    set_lines(i) : strdup("");
			h_raw(h, "<label>Name<input name=\"name\" spellcheck="
			    "\"false\" autocomplete=\"off\"");
			h_attr(h, "value", i >= 0 ? bd.b[i].name : "");
			h_fmt(h, "%s></label><label>Entries, one a line"
			    "<textarea name=\"text\" class=\"code\" "
			    "spellcheck=\"false\" rows=\"10\" placeholder=\"%s"
			    "\">", i >= 0 ? " readonly" : " autofocus",
			    strcmp(kind, "lset") == 0 || (i >= 0 && strcmp(
			    set_kind(i), "large communities") == 0) ?
			    "(65000, 1, 100)&#10;(65000, 2, *)" :
			    "(65000, 100)&#10;(65000, 200..299)");
			h_txt(h, text);
			h_raw(h, "</textarea><small>A community is <code>(AS, "
			    "value)</code>, a large one <code>(AS, a, b)"
			    "</code>; <code>*</code> stands for any, <code>"
			    "a..b</code> for a range.</small></label>");
			free(text);
		} else {
			text = bd.draft != NULL ? strdup(bd.draft) : i >= 0 ?
			    block_text(i) : strdup(skeleton(kind));
			h_raw(h, "<label>As bird reads it<textarea name=\""
			    "text\" class=\"code\" spellcheck=\"false\" rows="
			    "\"16\" autofocus>");
			h_txt(h, text);
			h_raw(h, "</textarea><small>The whole configuration is "
			    "parsed by bird before it is taken; what it "
			    "refuses is not kept.</small></label>");
			free(text);
		}
		return (true);
	case MODAL_BIRD_RPKI:
		h_raw(h, "<form data-form=\"bird-rpki\"><h2>An RPKI cache</h2>"
		    "<p>A validator (Routinator, rpki-client with an RTR "
		    "server, StayRTR…) that BIRD asks for route origins. They "
		    "go into ROA tables, and the function <code>rpki_invalid()"
		    "</code> is added for filters to use: <code>if "
		    "rpki_invalid() then reject;</code></p><div class=\"two\">"
		    "<label>Cache server<input name=\"host\" spellcheck=\""
		    "false\" autocomplete=\"off\" placeholder=\""
		    "rpki.example.net\" autofocus></label><label>Port<input "
		    "name=\"port\" inputmode=\"numeric\" value=\"3323\">"
		    "</label></div><div class=\"two\"><label>IPv4 ROA table"
		    "<input name=\"r4\" spellcheck=\"false\" value=\"r4\">"
		    "</label><label>IPv6 ROA table<input name=\"r6\" "
		    "spellcheck=\"false\" value=\"r6\"></label></div>");
		return (true);
	case MODAL_BIRD_FILE:
		text = bd.draft != NULL ? strdup(bd.draft) : strdup(bd.text !=
		    NULL ? bd.text : "");
		h_raw(h, "<form data-form=\"bird-file\" class=\"wide\"><h2>"
		    "BIRD's configuration <small>");
		h_txt(h, bd.path[0] != '\0' ? bd.path : "the main file");
		h_raw(h, "</small></h2><label>The whole file<textarea name=\""
		    "text\" class=\"code\" spellcheck=\"false\" rows=\"24\">");
		h_txt(h, text);
		h_raw(h, "</textarea><small>bird parses it before it is "
		    "taken; the file as it was is kept beside it, with "
		    "<code>.arcana-old</code> after its name.</small></label>");
		free(text);
		return (true);
	default:
		return (false);
	}
}

/* The buttons at the foot of a box of BIRD's. */
void
bird_modal_buttons(struct html *h)
{

	if ((app.modal == MODAL_BIRD_BLOCK || app.modal == MODAL_BIRD_PROTO) &&
	    bd.edit >= 0)
		h_raw(h, "<button type=\"button\" class=\"danger\" data-act=\""
		    "bird-delete\">Remove</button>");
	if (app.modal == MODAL_BIRD_PROTO && block_find("protocol",
	    bd.proto) < 0)
		return;
	h_fmt(h, "<button class=\"primary\"%s>%s</button>", bd.saving ?
	    " disabled" : "", bd.saving ? "Asking bird…" : app.modal ==
	    MODAL_BIRD_RPKI ? "Add" : "Save and reconfigure");
}

static bool
name_ok(const char *s)
{

	if (s == NULL || s[0] == '\0' || isdigit((unsigned char)s[0]) ||
	    strlen(s) > 60)
		return (false);
	for (; *s != '\0'; s++)
		if (!isalnum((unsigned char)*s) && *s != '_')
			return (false);
	return (true);
}

bool
bird_form(const char *form, const ucl_object_t *f)
{
	struct server	*s;
	struct html	 b;
	const char	*text, *name, *host, *port, *r4, *r6, *p, *nl;
	char		*all;
	bool		 first;

	if (strncmp(form, "bird-", 5) != 0)
		return (false);
	if ((s = cur_server()) == NULL || bd.text == NULL || bd.saving)
		return (true);
	text = jstr(f, "text") != NULL ? jstr(f, "text") : "";
	free(bd.draft);
	bd.draft = strdup(text);
	if (strcmp(form, "bird-file") == 0) {
		conf_save(s, text, false);
		return (true);
	}
	if (strcmp(form, "bird-block") == 0) {
		if (text[strspn(text, " \t\r\n")] == '\0') {
			snprintf(app.modal_error, sizeof(app.modal_error),
			    "Nothing to save: Remove takes it out");
			return (true);
		}
		all = spliced(bd.edit, text);
		conf_save(s, all, false);
		free(all);
		return (true);
	}
	if (strcmp(form, "bird-set") == 0) {
		name = jstr(f, "name");
		if (!name_ok(name)) {
			snprintf(app.modal_error, sizeof(app.modal_error),
			    "A name is letters, digits and _, as CUSTOMERS");
			return (true);
		}
		if (bd.edit < 0 && block_find("define", name) >= 0) {
			snprintf(app.modal_error, sizeof(app.modal_error),
			    "%s is defined already", name);
			return (true);
		}
		/* One entry a line becomes one set, a few to a line. */
		memset(&b, 0, sizeof(b));
		h_fmt(&b, "define %s = [", name);
		first = true;
		for (p = text; *p != '\0'; p = *nl != '\0' ? nl + 1 : nl) {
			nl = p + strcspn(p, "\n");
			while (p < nl && isspace((unsigned char)*p))
				p++;
			if (p == nl)
				continue;
			h_fmt(&b, "%s\n\t%.*s", first ? "" : ",", (int)(nl - p -
			    (nl > p && nl[-1] == '\r' ? 1 : 0)), p);
			first = false;
		}
		h_raw(&b, first ? " ];" : "\n];");
		all = spliced(bd.edit, b.s);
		free(b.s);
		conf_save(s, all, false);
		free(all);
		return (true);
	}
	if (strcmp(form, "bird-rpki") == 0) {
		host = jstr(f, "host") != NULL ? jstr(f, "host") : "";
		port = jstr(f, "port") != NULL ? jstr(f, "port") : "";
		r4 = jstr(f, "r4");
		r6 = jstr(f, "r6");
		if (host[0] == '\0' || host[strspn(host, "abcdefghijklmnopqrstu"
		    "vwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.:-")] != '\0' ||
		    port[0] == '\0' || port[strspn(port, "0123456789")] !=
		    '\0' || !name_ok(r4) || !name_ok(r6)) {
			snprintf(app.modal_error, sizeof(app.modal_error),
			    "A cache is a name or an address and a port; a "
			    "table's name is letters, digits and _");
			return (true);
		}
		memset(&b, 0, sizeof(b));
		if (block_find("table", r4) < 0)
			h_fmt(&b, "roa4 table %s;\n", r4);
		if (block_find("table", r6) < 0)
			h_fmt(&b, "roa6 table %s;\n", r6);
		for (first = true, port = jstr(f, "port"); first; first = false) {
			int n = 1;
			char pn[32];

			do
				snprintf(pn, sizeof(pn), "rpki%d", n++);
			while (block_find("protocol", pn) >= 0);
			h_fmt(&b, "\nprotocol rpki %s {\n\troa4 { table %s; };\n"
			    "\troa6 { table %s; };\n\tremote \"%s\" port %s;\n"
			    "\tretry keep 90;\n\trefresh keep 900;\n\texpire "
			    "keep 172800;\n}\n", pn, r4, r6, host, port);
		}
		if (block_find("function", "rpki_invalid") < 0)
			h_fmt(&b, "\nfunction rpki_invalid() {\n\treturn "
			    "(net.type = NET_IP4 && roa_check(%s, net, "
			    "bgp_path.last) = ROA_INVALID) ||\n\t    (net.type "
			    "= NET_IP6 && roa_check(%s, net, bgp_path.last) = "
			    "ROA_INVALID);\n}", r4, r6);
		all = spliced(-1, b.s);
		free(b.s);
		conf_save(s, all, false);
		free(all);
	}
	return (true);
}

bool
bird_action(const char *act, const char *arg, const char *value)
{
	struct server	*s;
	char		*all, body[300];
	int		 i;

	if (strcmp(act, "input:bird-path") != 0 && (strncmp(act, "bird-", 5) !=
	    0 || strcmp(act, "bird-verb") == 0) && strcmp(act,
	    "do-bird-delete") != 0)
		return (false);
	if ((s = cur_server()) == NULL)
		return (true);
	free(bd.draft);
	bd.draft = NULL;
	app.modal_error[0] = '\0';
	if (strcmp(act, "input:bird-path") == 0) {
		snprintf(bd.path, sizeof(bd.path), "%s", value);
		conf_load(s, true);
	} else if (strcmp(act, "bird-open") == 0) {
		snprintf(bd.proto, sizeof(bd.proto), "%s", arg);
		bd.edit = block_find("protocol", arg);
		app.modal = MODAL_BIRD_PROTO;
	} else if (strcmp(act, "bird-edit") == 0) {
		i = atoi(arg);
		if (i < 0 || i >= bd.nb)
			return (true);
		bd.edit = i;
		bd.newkind[0] = '\0';
		if (strcmp(bd.b[i].kind, "protocol") == 0 && bd.b[i].name[0] !=
		    '\0') {
			snprintf(bd.proto, sizeof(bd.proto), "%s", bd.b[i].name);
			app.modal = MODAL_BIRD_PROTO;
		} else
			app.modal = MODAL_BIRD_BLOCK;
	} else if (strcmp(act, "bird-new") == 0) {
		bd.edit = -1;
		snprintf(bd.newkind, sizeof(bd.newkind), "%s", arg);
		app.modal = strcmp(arg, "rpki") == 0 ? MODAL_BIRD_RPKI :
		    MODAL_BIRD_BLOCK;
	} else if (strcmp(act, "bird-file") == 0) {
		if (bd.text != NULL)
			app.modal = MODAL_BIRD_FILE;
	} else if (strcmp(act, "bird-delete") == 0) {
		if (bd.edit < 0 || bd.edit >= bd.nb)
			return (true);
		snprintf(body, sizeof(body), "%s %s is taken out of BIRD's "
		    "configuration on %s, and BIRD reads it again. A filter "
		    "or a set something else still names makes bird refuse, "
		    "and then nothing changes.", bd.b[bd.edit].kind,
		    bd.b[bd.edit].name, s->name);
		confirm("Remove it", body, "Remove", true, "",
		    "do-bird-delete", "", "");
	} else if (strcmp(act, "do-bird-delete") == 0) {
		if (bd.edit < 0 || bd.edit >= bd.nb || bd.text == NULL)
			return (true);
		all = spliced(bd.edit, "");
		app.modal = MODAL_BIRD_BLOCK;
		bd.draft = block_text(bd.edit);
		conf_save(s, all, false);
		free(all);
	}
	return (true);
}
