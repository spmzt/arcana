/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * What a tab shows, exported: every read of a host the page makes, by
 * GET or on the console's socket, is kept with the tab it was made for
 * (the last answer of each), and Export saves the open tab's as one
 * document, in JSON or in YAML:
 *
 *	{"arcana": "tab", "host": "web1", "tab": "services",
 *	 "taken": "2026-10-14T23:00:00Z",
 *	 "reads": {"services": {...}, "services/sshd": {...}}}
 *
 * Each read is its answer's data, without the trace of how it was
 * read.  The same two formats are offered wherever the panel saves a
 * document, and what it takes in may be either (data_parse()).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "app.h"

#define	KEPT_MAX	96

struct kept {
	char		 sid[9];
	char		 path[300];	/* after /api/servers/<sid>/ */
	int		 node, tab;
	char		 jail[256];	/* the drawer's, or "" */
	double		 t;
	ucl_object_t	*o;
};

static struct kept	kept[KEPT_MAX];

/* Where a request is made: the page's place then. */
void
export_where(int *node, int *tab)
{

	*node = (int)app.node;
	*tab = (int)app.tab;
}

/* A read's answer, kept for its tab: url is the GET it was. */
void
export_note(const char *url, int node, int tab, const ucl_object_t *o)
{
	const char	*p, *sl;
	struct kept	*k, *old;
	size_t		 n;
	int		 i;

	if (o == NULL || strncmp(url, "/api/servers/", 13) != 0)
		return;
	p = url + 13;
	if ((sl = strchr(p, '/')) == NULL || (n = (size_t)(sl - p)) >= 9)
		return;
	k = old = NULL;
	for (i = 0; i < KEPT_MAX; i++) {
		if (kept[i].o != NULL && strncmp(kept[i].sid, p, n) == 0 &&
		    kept[i].sid[n] == '\0' && strcmp(kept[i].path, sl + 1) ==
		    0 && kept[i].node == node && kept[i].tab == tab) {
			k = &kept[i];
			break;
		}
		if (kept[i].o == NULL && k == NULL)
			k = &kept[i];
		if (old == NULL || kept[i].t < old->t)
			old = &kept[i];
	}
	if (k == NULL)
		k = old;
	if (k->o != NULL)
		ucl_object_unref(k->o);
	memset(k, 0, sizeof(*k));
	memcpy(k->sid, p, n);
	snprintf(k->path, sizeof(k->path), "%s", sl + 1);
	k->node = node;
	k->tab = tab;
	snprintf(k->jail, sizeof(k->jail), "%s", app.jail);
	k->t = arc_now();
	/*
	 * The data, not how it was read: the reply's trace, the server it
	 * came from and when (the document says), its ok, and its error
	 * when there is none.
	 */
	k->o = ucl_object_copy(jget(o, "data") != NULL ? jget(o, "data") : o);
	if (ucl_object_type(k->o) == UCL_OBJECT) {
		(void)ucl_object_delete_key(k->o, "trace");
		(void)ucl_object_delete_key(k->o, "server");
		(void)ucl_object_delete_key(k->o, "fetched_at");
		(void)ucl_object_delete_key(k->o, "ok");
		if (ucl_object_type(ucl_object_lookup(k->o, "error")) ==
		    UCL_NULL)
			(void)ucl_object_delete_key(k->o, "error");
	}
}

/* o as text: pretty JSON, or YAML; free() it. */
char *
data_emit(const ucl_object_t *o, bool yaml)
{

	return (yaml ? yaml_emit(o) : (char *)ucl_object_emit(o,
	    UCL_EMIT_JSON));
}

/*
 * What one gives the page as a document: JSON, or YAML when it is not
 * JSON.  NULL with why in err.
 */
ucl_object_t *
data_parse(const char *text, char *err, size_t errlen)
{
	struct ucl_parser	*p;
	ucl_object_t		*o;
	const char		*s;

	err[0] = '\0';
	for (s = text; *s == ' ' || *s == '\t' || *s == '\n' || *s == '\r';
	    s++)
		;
	if (*s == '{' || *s == '[') {
		p = ucl_parser_new(UCL_PARSER_NO_IMPLICIT_ARRAYS);
		if (ucl_parser_add_string(p, text, 0) && (o =
		    ucl_parser_get_object(p)) != NULL) {
			ucl_parser_free(p);
			return (o);
		}
		snprintf(err, errlen, "JSON: %s", ucl_parser_get_error(p) !=
		    NULL ? ucl_parser_get_error(p) : "not read");
		ucl_parser_free(p);
		/* Flow-style YAML begins so too; else JSON's words. */
		{
			char	yerr[8];

			return (yaml_parse(text, yerr, sizeof(yerr)));
		}
	}
	return (yaml_parse(text, err, errlen));
}

/* A document saved: name's base, then .json or .yaml. */
void
export_save(const char *base, const ucl_object_t *o, bool yaml)
{
	char	 name[256], *text;

	snprintf(name, sizeof(name), "%s.%s", base, yaml ? "yaml" : "json");
	text = data_emit(o, yaml);
	arc_save_text(name, yaml ? "application/yaml" : "application/json",
	    text != NULL ? text : "{}");
	free(text);
}

/* A file name's part: letters, digits, - . _ only. */
static void
fname(char *dst, size_t len, const char *s)
{
	size_t	i;

	snprintf(dst, len, "%s", s);
	for (i = 0; dst[i] != '\0'; i++)
		if (!((dst[i] >= 'a' && dst[i] <= 'z') || (dst[i] >= 'A' &&
		    dst[i] <= 'Z') || (dst[i] >= '0' && dst[i] <= '9') ||
		    strchr("-._", dst[i]) != NULL))
			dst[i] = '-';
}

/* Now, as yang:date-and-time and as a file name's part. */
static void
stamp(char *iso, size_t ilen, char *file, size_t flen)
{
	struct tm	tm;
	time_t		t = (time_t)(arc_now() / 1000);

	gmtime_r(&t, &tm);
	strftime(iso, ilen, "%Y-%m-%dT%H:%M:%SZ", &tm);
	strftime(file, flen, "%Y%m%d-%H%M", &tm);
}

/* How many reads the open tab has to export. */
int
export_count(void)
{
	struct server	*s = cur_server();
	int		 i, n = 0;

	for (i = 0; s != NULL && i < KEPT_MAX; i++)
		if (kept[i].o != NULL && strcmp(kept[i].sid, s->id) == 0 &&
		    kept[i].node == (int)app.node && kept[i].tab ==
		    (int)app.tab && (app.node != NODE_JAIL || strcmp(
		    kept[i].jail, app.jail) == 0))
			n++;
	return (n);
}

/* The Export of a tab's bar: as JSON, as YAML. */
void
export_bar(struct html *h, const char *tab)
{

	h_raw(h, "<span class=\"tabexport\" title=\"What this tab shows, as "
	    "it was last read, saved as a file\">Export <button class=\""
	    "ghost small\" data-act=\"tab-export\" data-arg=\"json\"");
	h_attr(h, "data-value", tab);
	h_raw(h, ">JSON</button><button class=\"ghost small\" data-act=\""
	    "tab-export\" data-arg=\"yaml\"");
	h_attr(h, "data-value", tab);
	h_raw(h, ">YAML</button></span>");
}

bool
export_action(const char *act, const char *arg, const char *value)
{
	struct server	*s;
	ucl_object_t	*doc, *reads;
	char		 iso[32], when[32], base[400], hn[80], tn[64], jn[260];
	int		 i, newest;

	if (strcmp(act, "tab-export") != 0)
		return (false);
	if ((s = cur_server()) == NULL)
		return (true);
	stamp(iso, sizeof(iso), when, sizeof(when));
	doc = ucl_object_typed_new(UCL_OBJECT);
	ucl_object_insert_key(doc, ucl_object_fromstring("tab"), "arcana", 0,
	    true);
	ucl_object_insert_key(doc, ucl_object_fromstring(s->name), "host", 0,
	    true);
	if (app.node == NODE_JAIL)
		ucl_object_insert_key(doc, ucl_object_fromstring(app.jail),
		    "jail", 0, true);
	ucl_object_insert_key(doc, ucl_object_fromstring(value), "tab", 0,
	    true);
	ucl_object_insert_key(doc, ucl_object_fromstring(iso), "taken", 0,
	    true);
	reads = ucl_object_typed_new(UCL_OBJECT);
	/* Oldest first, each read once: its last answer. */
	for (;;) {
		newest = -1;
		for (i = 0; i < KEPT_MAX; i++)
			if (kept[i].o != NULL && strcmp(kept[i].sid, s->id) ==
			    0 && kept[i].node == (int)app.node && kept[i].tab ==
			    (int)app.tab && (app.node != NODE_JAIL || strcmp(
			    kept[i].jail, app.jail) == 0) &&
			    ucl_object_lookup(reads, kept[i].path) == NULL &&
			    (newest == -1 || kept[i].t < kept[newest].t))
				newest = i;
		if (newest == -1)
			break;
		ucl_object_insert_key(reads, ucl_object_ref(kept[newest].o),
		    kept[newest].path, 0, true);
	}
	ucl_object_insert_key(doc, reads, "reads", 0, false);
	fname(hn, sizeof(hn), s->name);
	fname(tn, sizeof(tn), value != NULL && value[0] != '\0' ? value :
	    "tab");
	fname(jn, sizeof(jn), app.jail);
	snprintf(base, sizeof(base), "%s-%s%s%s-%s", hn, app.node == NODE_JAIL
	    ? jn : "", app.node == NODE_JAIL ? "-" : "", tn, when);
	export_save(base, doc, strcmp(arg, "yaml") == 0);
	ucl_object_unref(doc);
	return (true);
}
