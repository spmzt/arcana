/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Workflows: chains of steps the console keeps and runs on several
 * hosts (workflows.c of the console).  The section lists them and their
 * last runs; one is made or changed in an editor whose forms come from
 * jobs.json, what share/arcana/jobs.yaml says each kind of job needs
 * and uses; a run is drawn as its chain, a row for each host, each step
 * coloured by how it went, and a step picked shows its trace.  What
 * waits in the queue can be kept as a workflow.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "app.h"

#define	WF_EDIT_STEPS	64	/* as the console takes them */

#define	nitems(x)	(sizeof(x) / sizeof((x)[0]))

#define	WF_EVERY_MS	2000	/* runs read again while one runs */

enum { WM_LIST, WM_EDIT, WM_RUN };

static struct {
	int		 mode;
	ucl_object_t	*list;		/* /api/workflows */
	ucl_object_t	*runs;		/* /api/runs */
	ucl_object_t	*run;		/* /api/runs/<n>, the one shown */
	ucl_object_t	*jobs;		/* /jobs.json */
	ucl_object_t	*draft;		/* the one being made or changed */
	char		 run_id[16];
	char		 pick[32];	/* "host:step" whose trace is shown */
	char		 run_wf[16];	/* the one asked to run */
	char		 error[300];
	char		 load_error[300];	/* the lists could not be read */
	double		 at;
	bool		 loading;
	/* The runs in the activity bar: each a task until it ends. */
	struct {
		long long	run;
		int		op;
	}		 watched[16];
	int		 nwatched;
	double		 watched_at;
} wf;

static void	runs_watch(void);

static void	wf_load(void);

/* ---- Reading -------------------------------------------------------- */

static void
list_cb(int status, const ucl_object_t *o, const char *err, void *arg)
{
	ucl_object_t	**slot = arg;

	wf.loading = false;
	if (status != 200) {
		/* Said, not a loader for ever. */
		snprintf(wf.load_error, sizeof(wf.load_error), "%s: %s",
		    slot == &wf.jobs ? "jobs.json" : slot == &wf.runs ?
		    "the runs" : slot == &wf.run ? "the run" : "the workflows",
		    jstr(o, "error.message") != NULL ? jstr(o,
		    "error.message") : err != NULL ? err : "no answer");
		return;
	}
	wf.load_error[0] = '\0';
	if (*slot != NULL)
		ucl_object_unref(*slot);
	*slot = ucl_object_ref((ucl_object_t *)(uintptr_t)o);
	if (slot == &wf.runs)
		runs_watch();
}

/* The name of a workflow by its id, as the lists have it. */
static const char *
wf_name(const char *id)
{
	const ucl_object_t	*w;
	ucl_object_iter_t	 it;

	it = NULL;
	while (id != NULL && (w = ucl_object_iterate(jget(wf.list,
	    "workflows"), &it, true)) != NULL)
		if (jstr(w, "id") != NULL && strcmp(jstr(w, "id"), id) == 0)
			return (jstr(w, "name"));
	return (id != NULL ? id : "workflow");
}

/*
 * Each run in the activity bar: one running becomes a task there, and
 * ends as the run does, whether it was begun here, by the clock or by
 * an event.
 */
static void
runs_watch(void)
{
	const ucl_object_t	*r;
	ucl_object_iter_t	 it;
	struct op		*o;
	long long		 id;
	int			 i, k;
	bool			 running;
	char			 title[160];

	it = NULL;
	while ((r = ucl_object_iterate(jget(wf.runs, "runs"), &it, true)) !=
	    NULL) {
		id = jint(r, "id", 0);
		running = jstr(r, "state") != NULL && strcmp(jstr(r, "state"),
		    "running") == 0;
		for (i = 0; i < wf.nwatched; i++)
			if (wf.watched[i].run == id)
				break;
		if (i == wf.nwatched) {
			if (!running || wf.nwatched == 16)
				continue;
			snprintf(title, sizeof(title), "workflow %s", wf_name(
			    jstr(r, "workflow")));
			o = op_begin(title, "console");
			wf.watched[i].run = id;
			wf.watched[i].op = o->id;
			wf.nwatched++;
			continue;
		}
		if (running)
			continue;
		o = op_find(wf.watched[i].op);
		if (o != NULL) {
			const ucl_object_t	*h, *s;
			ucl_object_iter_t	 hit, sit;
			const char		*why;

			/* Why it failed: the first step that did. */
			why = NULL;
			hit = NULL;
			while (why == NULL && (h = ucl_object_iterate(jget(r,
			    "hosts"), &hit, true)) != NULL) {
				sit = NULL;
				while ((s = ucl_object_iterate(jget(h, "steps"),
				    &sit, true)) != NULL)
					if (jstr(s, "state") != NULL && strcmp(
					    jstr(s, "state"), "failed") == 0) {
						why = jstr(s, "detail");
						break;
					}
			}
			op_end(o, strcmp(jstr(r, "state"), "done") == 0, why !=
			    NULL ? why : strcmp(jstr(r, "state"), "done") != 0 ?
			    jstr(r, "state") : NULL);
		}
		for (k = i; k + 1 < wf.nwatched; k++)
			wf.watched[k] = wf.watched[k + 1];
		wf.nwatched--;
	}
}

static void
wf_load(void)
{

	wf.at = arc_now();
	api("GET", "/api/workflows", NULL, list_cb, &wf.list);
	api("GET", "/api/runs", NULL, list_cb, &wf.runs);
	if (wf.jobs == NULL)
		api("GET", "/jobs.json", NULL, list_cb, &wf.jobs);
	if (wf.mode == WM_RUN && wf.run_id[0] != '\0') {
		char	url[64];

		snprintf(url, sizeof(url), "/api/runs/%s", wf.run_id);
		api("GET", url, NULL, list_cb, &wf.run);
	}
}

void
workflows_open(void)
{

	app.node = NODE_WORKFLOWS;
	app.jail[0] = '\0';
	app.rail_open = false;
	wf_load();
}

static bool
any_running(void)
{
	const ucl_object_t	*o;
	ucl_object_iter_t	 it;

	it = NULL;
	while ((o = ucl_object_iterate(jget(wf.runs, "runs"), &it, true)) !=
	    NULL)
		if (jstr(o, "state") != NULL && strcmp(jstr(o, "state"),
		    "running") == 0)
			return (true);
	return (false);
}

void
workflows_tick(double now)
{

	/* The runs in the activity bar are followed from any page. */
	if (wf.nwatched > 0 && app.online && now - wf.watched_at >
	    WF_EVERY_MS) {
		wf.watched_at = now;
		api("GET", "/api/runs", NULL, list_cb, &wf.runs);
	}
	if (app.node != NODE_WORKFLOWS || !app.visible || wf.mode == WM_EDIT)
		return;
	if (now - wf.at > (any_running() ? WF_EVERY_MS : 15000))
		wf_load();
}

/* ---- The draft: a path set ----------------------------------------- */

/* The object at path, made when it is not there; NULL when it cannot. */
static ucl_object_t *
walk(ucl_object_t *o, const char *path, bool make, char *leaf, size_t len)
{
	char		 buf[256], *p, *tok, *next, *end;
	ucl_object_t	*c;
	long		 i;

	snprintf(buf, sizeof(buf), "%s", path);
	p = buf;
	tok = strsep(&p, ".");
	while (p != NULL && o != NULL) {
		next = strsep(&p, ".");
		i = strtol(tok, &end, 10);
		if (*end == '\0' && ucl_object_type(o) == UCL_ARRAY)
			c = (ucl_object_t *)(uintptr_t)ucl_array_find_index(o,
			    (unsigned int)i);
		else {
			c = (ucl_object_t *)(uintptr_t)ucl_object_lookup(o, tok);
			if (c == NULL && make) {
				c = ucl_object_typed_new(UCL_OBJECT);
				ucl_object_insert_key(o, c, tok, 0, true);
			}
		}
		o = c;
		tok = next;
	}
	snprintf(leaf, len, "%s", tok != NULL ? tok : "");
	return (o);
}

/* A value set at path, or taken away when v is NULL. */
static void
set_path(const char *path, ucl_object_t *v)
{
	ucl_object_t	*o;
	char		 leaf[64], *end;
	long		 i;

	if (wf.draft == NULL || (o = walk(wf.draft, path, true, leaf,
	    sizeof(leaf))) == NULL) {
		if (v != NULL)
			ucl_object_unref(v);
		return;
	}
	i = strtol(leaf, &end, 10);
	if (*end == '\0' && ucl_object_type(o) == UCL_ARRAY) {
		if (v != NULL && ucl_array_replace_index(o, v, (unsigned int)
		    i) != NULL)
			return;
		if (v != NULL)
			ucl_object_unref(v);
		return;
	}
	(void)ucl_object_delete_key(o, leaf);
	if (v != NULL)
		ucl_object_insert_key(o, v, leaf, 0, true);
}

static ucl_object_t *
arr_at(const char *path)
{
	char		 leaf[64];
	ucl_object_t	*o;

	if (wf.draft == NULL || (o = walk(wf.draft, path, true, leaf,
	    sizeof(leaf))) == NULL)
		return (NULL);
	if (ucl_object_lookup(o, leaf) == NULL)
		ucl_object_insert_key(o, ucl_object_typed_new(UCL_ARRAY), leaf,
		    0, true);
	return ((ucl_object_t *)(uintptr_t)ucl_object_lookup(o, leaf));
}

/* "type:path" and what was typed, into the draft. */
static void
draft_input(const char *arg, const char *value)
{
	ucl_object_t	*v, *a;
	const char	*path, *p, *e;
	char		 word[512], *eq;
	size_t		 n;

	if ((path = strchr(arg, ':')) == NULL)
		return;
	path++;
	v = NULL;
	if (strncmp(arg, "text:", 5) == 0)
		v = value[0] != '\0' ? ucl_object_fromstring(value) : NULL;
	else if (strncmp(arg, "num:", 4) == 0)
		v = value[0] != '\0' ? ucl_object_fromint(strtoll(value, NULL,
		    10)) : NULL;
	else if (strncmp(arg, "bool:", 5) == 0)
		v = strcmp(value, "true") == 0 ? ucl_object_frombool(true) :
		    NULL;
	else if (strncmp(arg, "list:", 5) == 0) {
		/* Words with spaces or commas between them. */
		a = ucl_object_typed_new(UCL_ARRAY);
		for (p = value; *p != '\0'; p = e) {
			p += strspn(p, " ,\t\n");
			e = p + strcspn(p, " ,\t\n");
			n = (size_t)(e - p);
			if (n > 0 && n < sizeof(word)) {
				memcpy(word, p, n);
				word[n] = '\0';
				ucl_array_append(a, ucl_object_fromstring(word));
			}
		}
		v = a;
	} else if (strncmp(arg, "map:", 4) == 0) {
		/* "key=value", a line each. */
		a = ucl_object_typed_new(UCL_OBJECT);
		for (p = value; *p != '\0'; p = e) {
			p += strspn(p, " \t\n");
			e = p + strcspn(p, "\n");
			n = (size_t)(e - p);
			if (n == 0 || n >= sizeof(word))
				continue;
			memcpy(word, p, n);
			word[n] = '\0';
			if ((eq = strchr(word, '=')) == NULL || eq == word)
				continue;
			*eq++ = '\0';
			ucl_object_insert_key(a, ucl_object_fromstring(eq), word,
			    0, true);
		}
		v = a;
	} else
		return;
	set_path(path, v);
}

/* ---- What jobs.json says -------------------------------------------- */

static const ucl_object_t *
kind_of(const char *kind)
{
	const ucl_object_t	*k;
	ucl_object_iter_t	 it;

	it = NULL;
	while (kind != NULL && (k = ucl_object_iterate(jget(wf.jobs, "kinds"),
	    &it, true)) != NULL)
		if (jstr(k, "kind") != NULL && strcmp(jstr(k, "kind"), kind) ==
		    0)
			return (k);
	return (NULL);
}

static const ucl_object_t *
field_of(const char *name)
{
	const ucl_object_t	*f;
	ucl_object_iter_t	 it;

	it = NULL;
	while ((f = ucl_object_iterate(jget(wf.jobs, "fields"), &it, true)) !=
	    NULL)
		if (jstr(f, "field") != NULL && strcmp(jstr(f, "field"),
		    name) == 0)
			return (f);
	return (NULL);
}

static const char *
server_name(const char *sid)
{
	int	k;

	for (k = 0; sid != NULL && k < app.nservers; k++)
		if (strcmp(app.servers[k].id, sid) == 0)
			return (app.servers[k].name);
	return (sid != NULL ? sid : "?");
}

/* ---- The list ------------------------------------------------------- */

static void
triggers(struct html *h, const ucl_object_t *w)
{
	const ucl_object_t	*on;
	ucl_object_iter_t	 it;
	bool			 any;

	any = false;
	h_raw(h, "<span class=\"dim\">");
	if (jint(w, "every", 0) > 0) {
		h_fmt(h, "every %llds", (long long)jint(w, "every", 0));
		any = true;
	}
	it = NULL;
	while ((on = ucl_object_iterate(jget(w, "on"), &it, true)) != NULL) {
		h_raw(h, any ? ", on " : "on ");
		h_txt(h, jstr(on, "event"));
		any = true;
	}
	if (!any)
		h_raw(h, "by hand");
	h_raw(h, "</span>");
}

/* Arcana's own steps, as the console runs them (workflows.c). */
static const struct {
	const char	*what, *title, *hint;
} arcana_steps[] = {
	{ "check", "is its repository newer",
	    "Asks the step's host for the commit at the head of the "
	    "repository the console builds from (agent_source), beside the "
	    "ones the agents and the console were last updated to: its "
	    "answer has <code>new_agents</code>, <code>new_console</code> "
	    "and <code>new</code> (either), true when the head is newer, for "
	    "the steps after to be run only then." },
	{ "build", "build the agent",
	    "Has the step's host build arcana-agent from the repository; "
	    "the console keeps it, to send to the hosts." },
	{ "agents", "update every host's agent",
	    "Sends the agent the console keeps to every host it has, each "
	    "restarted with it, one after the other." },
	{ "console", "update the console",
	    "Builds all of Arcana on the host the console runs on (a server "
	    "added by its local socket) and installs it; the console "
	    "restarts once the step has ended, so it is the last." },
};

/*
 * Workflows made already: a draft each, to be looked over, given its
 * hosts and saved.  ${LOCAL} is the host the console runs on, or the
 * one picked.
 */
static const struct {
	const char	*name, *title, *json;
} templates[] = {
	{ "arcana-update", "Arcana kept up to date from its repository",
	    "{\"name\": \"Arcana from its repository\", \"every\": 3600, "
	    "\"hosts\": [\"${LOCAL}\"], \"steps\": ["
	    "{\"id\": \"check\", \"name\": \"Is there a newer commit\", "
	    "\"arcana\": \"check\"}, "
	    "{\"id\": \"build\", \"name\": \"Build the agent\", "
	    "\"arcana\": \"build\", \"when\": {\"step\": \"check\", "
	    "\"path\": \"new\", \"op\": \"eq\", \"value\": \"true\"}}, "
	    "{\"id\": \"agents\", \"name\": \"Every host's agent\", "
	    "\"arcana\": \"agents\", \"when\": {\"step\": \"check\", "
	    "\"path\": \"new_agents\", \"op\": \"eq\", \"value\": \"true\"}}, "
	    "{\"id\": \"console\", \"name\": \"The console itself\", "
	    "\"arcana\": \"console\", \"when\": {\"step\": \"check\", "
	    "\"path\": \"new_console\", \"op\": \"eq\", \"value\": "
	    "\"true\"}}]}" },
	{ "jail-restart", "A jail started again when it stops",
	    "{\"name\": \"Jails kept running\", \"hosts\": [\"${LOCAL}\"], "
	    "\"on\": [{\"event\": \"jail-state\", \"match\": {\"state\": "
	    "\"stopped\"}}], \"steps\": [{\"id\": \"start\", \"name\": "
	    "\"Start it\", \"job\": {\"kind\": \"jail-action\", \"jail\": "
	    "\"${event.jail}\", \"action\": \"start\"}}]}" },
	{ "pkg-weekly", "Packages upgraded every week",
	    "{\"name\": \"Weekly upgrade\", \"every\": 604800, \"hosts\": "
	    "[\"${LOCAL}\"], \"steps\": [{\"id\": \"upgrade\", \"name\": "
	    "\"Upgrade the host's packages\", \"job\": {\"kind\": "
	    "\"pkg-upgrade\"}}]}" },
	{ "plugin-install", "A plugin's package installed",
	    "{\"name\": \"Plugin installed\", \"hosts\": [\"${LOCAL}\"], "
	    "\"params\": [{\"name\": \"package\", \"default\": \"bird3\"}], "
	    "\"steps\": [{\"id\": \"install\", \"name\": \"Install the "
	    "plugin's package (bird3, wireguard-tools, strongswan, squid)\", "
	    "\"job\": {\"kind\": \"pkg-install\", \"packages\": "
	    "[\"${param.package}\"]}}]}" },
	{ "service-back", "A service restarted when its host answers again",
	    "{\"name\": \"Service back with its host\", \"hosts\": "
	    "[\"${LOCAL}\"], \"params\": [{\"name\": \"service\", "
	    "\"default\": \"nginx\"}], \"on\": [{\"event\": \"host-up\"}], "
	    "\"steps\": [{\"id\": \"restart\", \"name\": \"Restart it\", "
	    "\"job\": {\"kind\": \"service-action\", \"service\": "
	    "\"${param.service}\", \"action\": \"restart\"}}]}" },
};

/* The host a template names as ${LOCAL}: where the console runs. */
static const char *
local_host(void)
{
	struct server	*s;
	int		 i;

	for (i = 0; i < app.nservers; i++)
		if (strncmp(app.servers[i].uri, "unix:", 5) == 0)
			return (app.servers[i].id);
	return ((s = cur_server()) != NULL ? s->id : "");
}

static bool
draft_template(const char *name)
{
	struct ucl_parser	*p;
	ucl_object_t		*o;
	const char		*at;
	char			*json;
	size_t			 i;

	for (i = 0; i < nitems(templates); i++)
		if (strcmp(templates[i].name, name) == 0)
			break;
	if (i == nitems(templates))
		return (false);
	/* ${LOCAL}, once, as the host's id. */
	at = strstr(templates[i].json, "${LOCAL}");
	if (asprintf(&json, "%.*s%s%s", (int)(at - templates[i].json),
	    templates[i].json, local_host(), at + 8) == -1)
		return (false);
	p = ucl_parser_new(UCL_PARSER_NO_IMPLICIT_ARRAYS);
	o = ucl_parser_add_string(p, json, 0) ? ucl_parser_get_object(p) :
	    NULL;
	ucl_parser_free(p);
	free(json);
	if (o == NULL)
		return (false);
	if (ucl_object_lookup(o, "params") == NULL)
		ucl_object_insert_key(o, ucl_object_typed_new(UCL_ARRAY),
		    "params", 0, true);
	if (ucl_object_lookup(o, "on") == NULL)
		ucl_object_insert_key(o, ucl_object_typed_new(UCL_ARRAY), "on",
		    0, true);
	if (wf.draft != NULL)
		ucl_object_unref(wf.draft);
	wf.draft = o;
	return (true);
}

static void
view_list(struct html *h)
{
	const ucl_object_t	*w, *r, *x, *hh;
	ucl_object_iter_t	 it, hit, xit;
	char			 age[32];
	int			 n;

	h_raw(h, "<div class=\"toolbar\"><h3>Workflows</h3><button class=\""
	    "small\" data-act=\"wf-new\">+ workflow</button><select class=\""
	    "wf-template\" data-input=\"wf-template\" title=\"A workflow "
	    "made already, to be looked over and saved\"><option value=\"\">"
	    "From a template…</option>");
	for (n = 0; n < (int)nitems(templates); n++) {
		h_raw(h, "<option");
		h_attr(h, "value", templates[n].name);
		h_raw(h, ">");
		h_txt(h, templates[n].title);
		h_raw(h, "</option>");
	}
	h_raw(h, "</select>");
	if (app.nbatch > 0)
		h_fmt(h, "<button class=\"ghost small\" data-act=\"queue-to-wf\" "
		    "title=\"What waits in the queue, kept as a workflow\">The "
		    "queue, %d, as one</button>", app.nbatch);
	h_raw(h, "<span class=\"age\">steps the console runs on several "
	    "hosts at once: by hand, at an interval, or on an event</span>"
	    "</div>");
	n = 0;
	h_raw(h, "<ul class=\"wflist\">");
	it = NULL;
	while ((w = ucl_object_iterate(jget(wf.list, "workflows"), &it,
	    true)) != NULL) {
		n++;
		h_raw(h, "<li><div class=\"wfhead\"><b>");
		h_txt(h, jstr(w, "name"));
		h_fmt(h, "</b><span class=\"dim\">%d steps · ", (int)
		    ucl_array_size(jget(w, "steps")));
		hit = NULL;
		while ((hh = ucl_object_iterate(jget(w, "hosts"), &hit, true)) !=
		    NULL) {
			h_txt(h, server_name(ucl_object_tostring_forced(hh)));
			h_raw(h, " ");
		}
		h_raw(h, "</span>");
		triggers(h, w);
		if (jbool(w, "destructive"))
			h_raw(h, "<span class=\"chip warn\">destroys, by "
			    "itself</span>");
		h_raw(h, "</div><div class=\"acts\"><button class=\"small\" "
		    "data-act=\"wf-run\"");
		h_attr(h, "data-arg", jstr(w, "id"));
		h_raw(h, ">Run</button><button class=\"ghost small\" data-act=\""
		    "wf-edit\"");
		h_attr(h, "data-arg", jstr(w, "id"));
		h_raw(h, ">Edit</button><button class=\"icon\" data-act=\""
		    "wf-del\" title=\"Delete it\"");
		h_attr(h, "data-arg", jstr(w, "id"));
		h_raw(h, ">×</button></div></li>");
	}
	if (n == 0)
		h_raw(h, "<li class=\"dim\">No workflow yet: <b>+ workflow</b> "
		    "makes one, and what waits in the queue can be kept as "
		    "one.</li>");
	h_raw(h, "</ul><h4 class=\"family\">Runs</h4><ul class=\"wfruns\">");
	n = 0;
	it = NULL;
	/* The newest first. */
	{
		const ucl_object_t	*v[64];
		int			 k, nv;

		nv = 0;
		while ((r = ucl_object_iterate(jget(wf.runs, "runs"), &it,
		    true)) != NULL && nv < 64)
			v[nv++] = r;
		for (k = nv - 1; k >= 0; k--) {
			r = v[k];
			n++;
			h_fmt(h, "<li class=\"pick %s\" data-act=\"wf-run-open\"",
			    jstr(r, "state") != NULL ? jstr(r, "state") : "");
			h_attr(h, "data-arg", jstr(r, "id"));
			h_raw(h, "><i class=\"led\"></i><b>");
			h_txt(h, jstr(r, "name"));
			h_raw(h, "</b><span class=\"dim\">");
			h_txt(h, jstr(r, "trigger"));
			fmt_age(age, sizeof(age), (double)jint(r, "started", 0) *
			    1000);
			h_raw(h, " · ");
			h_txt(h, age);
			h_raw(h, "</span><span class=\"hosts\">");
			xit = NULL;
			while ((x = ucl_object_iterate(jget(r, "hosts"), &xit,
			    true)) != NULL) {
				h_fmt(h, "<span class=\"chip %s\">",
				    jstr(x, "state") != NULL ? jstr(x, "state") :
				    "");
				h_txt(h, jstr(x, "name"));
				h_raw(h, "</span>");
			}
			h_raw(h, "</span><span class=\"state\">");
			h_txt(h, jstr(r, "state"));
			h_raw(h, "</span></li>");
		}
	}
	if (n == 0)
		h_raw(h, "<li class=\"dim\">No run yet.</li>");
	h_raw(h, "</ul>");
}

/* ---- A run, drawn ---------------------------------------------------- */

static const ucl_object_t *
wf_by_id(const char *id)
{
	const ucl_object_t	*w;
	ucl_object_iter_t	 it;

	it = NULL;
	while (id != NULL && (w = ucl_object_iterate(jget(wf.list,
	    "workflows"), &it, true)) != NULL)
		if (jstr(w, "id") != NULL && strcmp(jstr(w, "id"), id) == 0)
			return (w);
	return (NULL);
}

static void
view_run(struct html *h)
{
	const ucl_object_t	*r, *w, *x, *s, *def, *tr, *t;
	ucl_object_iter_t	 it, sit, tit;
	char			 key[32];
	int			 hi, si;

	r = wf.run;
	h_raw(h, "<div class=\"toolbar\"><button class=\"ghost small\" "
	    "data-act=\"wf-back\">‹ Workflows</button><h3>");
	h_txt(h, jstr(r, "name") != NULL ? jstr(r, "name") : "Run");
	h_raw(h, "</h3>");
	if (jstr(r, "state") != NULL && strcmp(jstr(r, "state"), "running") ==
	    0) {
		h_raw(h, "<button class=\"ghost small\" data-act=\"wf-run-stop\"");
		h_attr(h, "data-arg", jstr(r, "id"));
		h_raw(h, ">Stop</button>");
	}
	h_raw(h, "<span class=\"age\">");
	h_txt(h, jstr(r, "trigger"));
	h_raw(h, " · ");
	h_txt(h, jstr(r, "state"));
	h_raw(h, "</span></div>");
	if (r == NULL) {
		h_raw(h, "<div class=\"loader\"></div>");
		return;
	}
	w = wf_by_id(jstr(r, "workflow"));
	/*
	 * A row for each host: its steps in order, as they went, on a grid
	 * whose columns are the steps and the arrows between them.  Where
	 * a failure goes on at a later step, an arrow is drawn under the
	 * row from the one to the other, in a lane of its own, bright when
	 * the run took it.
	 */
	h_raw(h, "<div class=\"wfgraph\">");
	it = NULL;
	hi = 0;
	while ((x = ucl_object_iterate(jget(r, "hosts"), &it, true)) != NULL) {
		int	n, lane, to;

		n = (int)ucl_array_size(jget(x, "steps"));
		h_fmt(h, "<div class=\"wfrow %s\" style=\"grid-template-"
		    "columns:auto repeat(%d,auto)\"><span class=\"wfhost\">",
		    jstr(x, "state") != NULL ? jstr(x, "state") : "",
		    n > 0 ? 2 * n - 1 : 1);
		h_txt(h, jstr(x, "name"));
		h_raw(h, "</span>");
		sit = NULL;
		si = 0;
		while ((s = ucl_object_iterate(jget(x, "steps"), &sit, true)) !=
		    NULL) {
			def = w != NULL ? ucl_array_find_index(jget(w, "steps"),
			    (unsigned int)si) : NULL;
			snprintf(key, sizeof(key), "%d:%d", hi, si);
			if (si > 0)
				h_fmt(h, "<span class=\"wfarrow\" style=\""
				    "grid-row:1;grid-column:%d\">→</span>",
				    1 + 2 * si);
			h_fmt(h, "<button class=\"wfstep %s%s\" style=\""
			    "grid-row:1;grid-column:%d\" data-act=\""
			    "wf-step-pick\" data-arg=\"%s\"", jstr(s, "state") !=
			    NULL ? jstr(s, "state") : "", strcmp(wf.pick, key) ==
			    0 ? " on" : "", 2 + 2 * si, key);
			h_attr(h, "title", jstr(s, "error") != NULL ? jstr(s,
			    "error") : jstr(s, "title"));
			h_raw(h, "><b>");
			h_txt(h, def != NULL && jstr(def, "name") != NULL ?
			    jstr(def, "name") : jstr(s, "id"));
			h_raw(h, "</b><small>");
			h_txt(h, jstr(s, "state"));
			h_raw(h, "</small>");
			if (def != NULL && jstr(def, "on_fail") != NULL &&
			    strcmp(jstr(def, "on_fail"), "continue") == 0)
				h_raw(h, "<small class=\"jump\">on a failure "
				    "on</small>");
			h_raw(h, "</button>");
			si++;
		}
		/* The jumps: each from its step to the one it names. */
		lane = 0;
		for (si = 0; w != NULL && si < n; si++) {
			const ucl_object_t	*st, *from;
			const char		*of;

			def = ucl_array_find_index(jget(w, "steps"),
			    (unsigned int)si);
			of = jstr(def, "on_fail");
			if (of == NULL || strcmp(of, "stop") == 0 || strcmp(of,
			    "continue") == 0)
				continue;
			for (to = si + 1; to < n; to++)
				if (jstr(ucl_array_find_index(jget(w, "steps"),
				    (unsigned int)to), "id") != NULL && strcmp(
				    jstr(ucl_array_find_index(jget(w, "steps"),
				    (unsigned int)to), "id"), of) == 0)
					break;
			if (to == n)
				continue;
			from = ucl_array_find_index(jget(x, "steps"),
			    (unsigned int)si);
			st = ucl_array_find_index(jget(x, "steps"),
			    (unsigned int)to);
			h_fmt(h, "<span class=\"wfjump%s\" style=\"grid-row:%d;"
			    "grid-column:%d / %d\" title=\"On a failure of ",
			    jstr(from, "state") != NULL && strcmp(jstr(from,
			    "state"), "failed") == 0 && jstr(st, "state") !=
			    NULL && (strcmp(jstr(st, "state"), "done") == 0 ||
			    strcmp(jstr(st, "state"), "failed") == 0 ||
			    strcmp(jstr(st, "state"), "running") == 0) ?
			    " taken" : "", 2 + lane, 2 + 2 * si, 3 + 2 * to);
			h_txt(h, jstr(def, "name") != NULL ? jstr(def, "name") :
			    jstr(def, "id"));
			h_raw(h, ", the run goes on at ");
			h_txt(h, of);
			h_raw(h, "\"><small>on a failure</small></span>");
			lane++;
		}
		h_raw(h, "</div>");
		hi++;
	}
	h_raw(h, "</div>");
	/* The step picked: what it did, and what it said. */
	if (wf.pick[0] == '\0' || sscanf(wf.pick, "%d:%d", &hi, &si) != 2)
		return;
	s = jget(ucl_array_find_index(jget(r, "hosts"), (unsigned int)hi),
	    "steps");
	s = s != NULL ? ucl_array_find_index(s, (unsigned int)si) : NULL;
	if (s == NULL)
		return;
	h_raw(h, "<section class=\"pane wftrace\"><h4><span>");
	h_txt(h, jstr(s, "title") != NULL ? jstr(s, "title") : jstr(s, "id"));
	h_raw(h, "</span></h4>");
	if (jstr(s, "error") != NULL) {
		h_raw(h, "<p class=\"notice bad\">");
		h_txt(h, jstr(s, "error"));
		h_raw(h, "</p>");
	}
	tr = jget(s, "trace.job.trace") != NULL ? jget(s, "trace.job.trace") :
	    jget(s, "trace.trace");
	h_raw(h, "<ol class=\"wftsteps\">");
	tit = NULL;
	while ((t = ucl_object_iterate(tr, &tit, true)) != NULL) {
		h_fmt(h, "<li class=\"%s\"><b>", jstr(t, "status") != NULL ?
		    jstr(t, "status") : "");
		h_txt(h, jstr(t, "label"));
		h_raw(h, "</b> ");
		h_txt(h, jstr(t, "detail"));
		h_raw(h, "</li>");
	}
	h_raw(h, "</ol></section>");
}

/* ---- The editor ----------------------------------------------------- */

static void
input(struct html *h, const char *type, const char *path, const char *value,
    const char *ph)
{

	h_raw(h, "<input data-input=\"wf\" spellcheck=\"false\" "
	    "autocomplete=\"off\"");
	{
		char	arg[300];

		snprintf(arg, sizeof(arg), "%s:%s", type, path);
		h_attr(h, "data-arg", arg);
	}
	if (value != NULL)
		h_attr(h, "value", value);
	if (ph != NULL)
		h_attr(h, "placeholder", ph);
	h_raw(h, ">");
}

/* A field of a job, as jobs.json has its type and its values. */
static void
job_field(struct html *h, const ucl_object_t *kind, const char *field,
    const char *path, const ucl_object_t *job, bool need)
{
	const ucl_object_t	*f, *vals, *v, *cur;
	ucl_object_iter_t	 it;
	const char		*type;
	char			 p[256], buf[1024];
	size_t			 n;

	f = field_of(field);
	type = f != NULL && jstr(f, "type") != NULL ? jstr(f, "type") : "text";
	snprintf(p, sizeof(p), "%s.%s", path, field);
	cur = jget(job, field);
	h_raw(h, "<label>");
	h_txt(h, f != NULL ? jstr(f, "label") : field);
	if (need)
		h_raw(h, " <em>needed</em>");
	vals = jget(jget(kind, "values"), field);
	if (vals != NULL) {
		h_raw(h, "<select data-input=\"wf\"");
		snprintf(buf, sizeof(buf), "text:%s", p);
		h_attr(h, "data-arg", buf);
		h_raw(h, "><option value=\"\">—</option>");
		it = NULL;
		while ((v = ucl_object_iterate(vals, &it, true)) != NULL) {
			h_raw(h, "<option");
			h_attr(h, "value", ucl_object_tostring_forced(v));
			if (cur != NULL && strcmp(ucl_object_tostring_forced(cur),
			    ucl_object_tostring_forced(v)) == 0)
				h_raw(h, " selected");
			h_raw(h, ">");
			h_txt(h, ucl_object_tostring_forced(v));
			h_raw(h, "</option>");
		}
		h_raw(h, "</select></label>");
		return;
	}
	if (strcmp(type, "bool") == 0) {
		h_raw(h, "<input type=\"checkbox\" data-input=\"wf\"");
		snprintf(buf, sizeof(buf), "bool:%s", p);
		h_attr(h, "data-arg", buf);
		h_raw(h, cur != NULL && ucl_object_toboolean(cur) ? " checked>" :
		    ">");
		h_raw(h, "</label>");
		return;
	}
	if (strcmp(type, "list") == 0 || strcmp(type, "map") == 0) {
		buf[0] = '\0';
		n = 0;
		it = NULL;
		while ((v = ucl_object_iterate(cur, &it, true)) != NULL &&
		    n < sizeof(buf) - 2) {
			if (type[0] == 'm')
				n += (size_t)snprintf(buf + n, sizeof(buf) - n,
				    "%s%s=%s", n > 0 ? "\n" : "", ucl_object_key(v),
				    ucl_object_tostring_forced(v));
			else
				n += (size_t)snprintf(buf + n, sizeof(buf) - n,
				    "%s%s", n > 0 ? " " : "",
				    ucl_object_tostring_forced(v));
			if (n >= sizeof(buf))
				n = sizeof(buf) - 1;
		}
		if (type[0] == 'm') {
			char	arg[300];

			h_raw(h, "<textarea data-input=\"wf\" rows=\"3\" "
			    "spellcheck=\"false\" placeholder=\"key=value, a "
			    "line each\"");
			snprintf(arg, sizeof(arg), "map:%s", p);
			h_attr(h, "data-arg", arg);
			h_raw(h, ">");
			h_txt(h, buf);
			h_raw(h, "</textarea></label>");
			return;
		}
		input(h, "list", p, buf, "with spaces between them");
		h_raw(h, "</label>");
		return;
	}
	input(h, strcmp(type, "number") == 0 ? "num" : "text", p, cur != NULL ?
	    ucl_object_tostring_forced(cur) : NULL, "a value, or ${param.x}, "
	    "${host.name}, ${step.id.path}");
	h_raw(h, "</label>");
}

/* The words of a list, "a b c", each a field of the job. */
static void
job_fields(struct html *h, const ucl_object_t *kind, const char *list_key,
    const char *path, const ucl_object_t *job, bool need)
{
	const ucl_object_t	*v;
	ucl_object_iter_t	 it;

	it = NULL;
	while ((v = ucl_object_iterate(jget(kind, list_key), &it, true)) !=
	    NULL)
		job_field(h, kind, ucl_object_tostring_forced(v), path, job,
		    need);
}

static const char *const reads[] = { "hello", "jails", "services", "stats",
    "events", "history", "packages" };
static const char *const ops[] = { "eq", "ne", "contains", "gt", "lt",
    "exists", "missing" };

static void
view_step(struct html *h, const ucl_object_t *st, int i, int n)
{
	const ucl_object_t	*job, *kind, *k, *when, *o;
	ucl_object_iter_t	 it;
	char			 path[64], buf[300];
	const char		*of;
	size_t			 r;
	int			 j;

	job = jget(st, "job");
	/* Dragged by its number to another place among the steps. */
	h_fmt(h, "<li class=\"wfedstep\" data-reorder=\"wf-step\" data-arg="
	    "\"%d\"><div class=\"wfedhead\"><span class=\"num grip\" "
	    "draggable=\"true\" title=\"Drag it to another place among the "
	    "steps\">%d</span>", i, i + 1);
	snprintf(path, sizeof(path), "steps.%d.id", i);
	input(h, "text", path, jstr(st, "id"), "its id");
	snprintf(path, sizeof(path), "steps.%d.name", i);
	input(h, "text", path, jstr(st, "name"), "what it is");
	h_fmt(h, "<select data-arg=\"%d\" data-input=\"wf-type\">", i);
	h_fmt(h, "<option value=\"job\"%s>a job</option>", job != NULL ?
	    " selected" : "");
	for (r = 0; r < nitems(reads); r++)
		h_fmt(h, "<option value=\"read:%s\"%s>a read of %s</option>",
		    reads[r], jstr(st, "read") != NULL && strcmp(jstr(st,
		    "read"), reads[r]) == 0 ? " selected" : "", reads[r]);
	for (r = 0; r < nitems(arcana_steps); r++)
		h_fmt(h, "<option value=\"arcana:%s\"%s>Arcana: %s</option>",
		    arcana_steps[r].what, jstr(st, "arcana") != NULL &&
		    strcmp(jstr(st, "arcana"), arcana_steps[r].what) == 0 ?
		    " selected" : "", arcana_steps[r].title);
	h_fmt(h, "</select><span class=\"acts\"><button class=\"icon\" "
	    "data-act=\"wf-step-up\" data-arg=\"%d\" title=\"Earlier\"%s>↑"
	    "</button><button class=\"icon\" data-act=\"wf-step-del\" "
	    "data-arg=\"%d\" title=\"Take it away\">×</button></span></div>",
	    i, i == 0 ? " disabled" : "", i);
	for (r = 0; jstr(st, "arcana") != NULL && r < nitems(arcana_steps);
	    r++)
		if (strcmp(jstr(st, "arcana"), arcana_steps[r].what) == 0) {
			h_raw(h, "<p class=\"dim wfhint\">");
			h_raw(h, arcana_steps[r].hint);
			h_raw(h, "</p>");
		}
	if (job != NULL) {
		h_fmt(h, "<label>Kind<select data-input=\"wf-kind\" data-arg="
		    "\"%d\"><option value=\"\">—</option>", i);
		it = NULL;
		while ((k = ucl_object_iterate(jget(wf.jobs, "kinds"), &it,
		    true)) != NULL) {
			h_raw(h, "<option");
			h_attr(h, "value", jstr(k, "kind"));
			if (jstr(job, "kind") != NULL && strcmp(jstr(job, "kind"),
			    jstr(k, "kind")) == 0)
				h_raw(h, " selected");
			h_raw(h, ">");
			h_txt(h, jstr(k, "kind"));
			h_raw(h, " · ");
			h_txt(h, jstr(k, "title"));
			h_raw(h, "</option>");
		}
		h_raw(h, "</select></label>");
		if ((kind = kind_of(jstr(job, "kind"))) != NULL) {
			snprintf(path, sizeof(path), "steps.%d.job", i);
			h_raw(h, "<div class=\"wffields\">");
			job_fields(h, kind, "needs", path, job, true);
			job_fields(h, kind, "uses", path, job, false);
			h_raw(h, "</div>");
			if (jstr(kind, "destroys") != NULL && jstr(kind,
			    "destroys")[0] != '\0')
				h_raw(h, "<p class=\"dim\">A job of this kind can "
				    "destroy: a workflow that runs by itself "
				    "says so.</p>");
		}
	}
	/* Its condition, if it has one. */
	when = jget(st, "when");
	h_fmt(h, "<label class=\"toggle\"><input type=\"checkbox\" "
	    "data-act=\"wf-when\" data-arg=\"%d\"%s><span>Only when…</span>"
	    "</label>", i, when != NULL ? " checked" : "");
	if (when != NULL) {
		h_fmt(h, "<div class=\"wfwhen\"><select data-input=\"wf-when-of\" "
		    "data-arg=\"%d\">", i);
		for (r = 0; r < nitems(reads); r++)
			h_fmt(h, "<option value=\"read:%s\"%s>a read of %s, "
			    "then</option>", reads[r], jstr(when, "read") !=
			    NULL && strcmp(jstr(when, "read"), reads[r]) == 0 ?
			    " selected" : "", reads[r]);
		for (j = 0; j < i; j++) {
			o = ucl_array_find_index(jget(wf.draft, "steps"),
			    (unsigned int)j);
			snprintf(buf, sizeof(buf), "step:%s", jstr(o, "id") !=
			    NULL ? jstr(o, "id") : "");
			h_raw(h, "<option");
			h_attr(h, "value", buf);
			if (jstr(when, "step") != NULL && jstr(o, "id") != NULL &&
			    strcmp(jstr(when, "step"), jstr(o, "id")) == 0)
				h_raw(h, " selected");
			h_raw(h, ">what ");
			h_txt(h, jstr(o, "id"));
			h_raw(h, " answered</option>");
		}
		h_raw(h, "</select>");
		snprintf(path, sizeof(path), "steps.%d.when.path", i);
		input(h, "text", path, jstr(when, "path"),
		    "where: jails[name=web].state");
		h_fmt(h, "<select data-input=\"wf\" data-arg=\"text:steps.%d."
		    "when.op\">", i);
		for (r = 0; r < nitems(ops); r++)
			h_fmt(h, "<option%s>%s</option>", jstr(when, "op") !=
			    NULL && strcmp(jstr(when, "op"), ops[r]) == 0 ?
			    " selected" : "", ops[r]);
		h_raw(h, "</select>");
		snprintf(path, sizeof(path), "steps.%d.when.value", i);
		input(h, "text", path, jstr(when, "value"), "what");
		h_raw(h, "</div>");
	}
	/* What follows a failure. */
	of = jstr(st, "on_fail") != NULL ? jstr(st, "on_fail") : "stop";
	h_fmt(h, "<label>When it fails<select data-input=\"wf\" data-arg=\""
	    "text:steps.%d.on_fail\"><option value=\"stop\"%s>the host's run "
	    "stops</option><option value=\"continue\"%s>the run goes on"
	    "</option>", i, strcmp(of, "stop") == 0 ? " selected" : "",
	    strcmp(of, "continue") == 0 ? " selected" : "");
	for (j = i + 1; j < n; j++) {
		o = ucl_array_find_index(jget(wf.draft, "steps"), (unsigned int)
		    j);
		h_raw(h, "<option");
		h_attr(h, "value", jstr(o, "id"));
		if (jstr(o, "id") != NULL && strcmp(of, jstr(o, "id")) == 0)
			h_raw(h, " selected");
		h_raw(h, ">on at ");
		h_txt(h, jstr(o, "id"));
		h_raw(h, "</option>");
	}
	h_raw(h, "</select></label></li>");
}

static void
view_edit(struct html *h)
{
	const ucl_object_t	*d, *st, *p, *on, *hh;
	ucl_object_iter_t	 it, hit;
	char			 path[64], buf[512];
	int			 i, n, k;
	bool			 mine;

	d = wf.draft;
	h_raw(h, "<div class=\"toolbar\"><button class=\"ghost small\" "
	    "data-act=\"wf-back\">‹ Workflows</button><h3>");
	h_raw(h, jstr(d, "id") != NULL ? "Change the workflow" : "A workflow");
	h_raw(h, "</h3><button class=\"small\" data-act=\"wf-save\">Save"
	    "</button></div>");
	if (wf.error[0] != '\0') {
		h_raw(h, "<div class=\"notice bad\">");
		h_txt(h, wf.error);
		h_raw(h, "</div>");
	}
	h_raw(h, "<div class=\"wfedit\"><label>Name");
	input(h, "text", "name", jstr(d, "name"), "restart a service");
	h_raw(h, "</label><fieldset class=\"wfhosts\"><legend>Hosts it runs on"
	    "</legend>");
	for (k = 0; k < app.nservers; k++) {
		mine = false;
		hit = NULL;
		while ((hh = ucl_object_iterate(jget(d, "hosts"), &hit, true)) !=
		    NULL)
			mine = mine || strcmp(ucl_object_tostring_forced(hh),
			    app.servers[k].id) == 0;
		h_raw(h, "<label class=\"toggle\"><input type=\"checkbox\" "
		    "data-act=\"wf-host\"");
		h_attr(h, "data-arg", app.servers[k].id);
		h_raw(h, mine ? " checked><span>" : "><span>");
		h_txt(h, app.servers[k].name);
		h_raw(h, "</span></label>");
	}
	h_raw(h, "</fieldset><fieldset><legend>Parameters, asked for when it "
	    "runs</legend><ul class=\"wfparams\">");
	i = 0;
	it = NULL;
	while ((p = ucl_object_iterate(jget(d, "params"), &it, true)) != NULL) {
		h_raw(h, "<li>");
		snprintf(path, sizeof(path), "params.%d.name", i);
		input(h, "text", path, jstr(p, "name"), "name");
		snprintf(path, sizeof(path), "params.%d.default", i);
		input(h, "text", path, jstr(p, "default"), "its default");
		h_fmt(h, "<button class=\"icon\" data-act=\"wf-param-del\" "
		    "data-arg=\"%d\">×</button></li>", i++);
	}
	h_raw(h, "</ul><button class=\"ghost small\" data-act=\"wf-param-add\">"
	    "+ parameter</button></fieldset>");
	h_raw(h, "<h4 class=\"family\">Steps</h4><ol class=\"wfsteps\">");
	n = (int)ucl_array_size(jget(d, "steps"));
	i = 0;
	it = NULL;
	while ((st = ucl_object_iterate(jget(d, "steps"), &it, true)) != NULL)
		view_step(h, st, i++, n);
	h_raw(h, "</ol><button class=\"ghost small\" data-act=\"wf-step-add\">"
	    "+ step</button>");
	/* By itself. */
	h_raw(h, "<fieldset><legend>By itself</legend><label>Every, seconds");
	snprintf(buf, sizeof(buf), "%lld", (long long)jint(d, "every", 0));
	input(h, "num", "every", jint(d, "every", 0) > 0 ? buf : NULL,
	    "0: not at an interval; 60 at least");
	h_raw(h, "</label><ul class=\"wfon\">");
	i = 0;
	it = NULL;
	while ((on = ucl_object_iterate(jget(d, "on"), &it, true)) != NULL) {
		const ucl_object_t	*m;
		ucl_object_iter_t	 mit;
		size_t			 len;

		h_raw(h, "<li>On");
		snprintf(path, sizeof(path), "on.%d.event", i);
		input(h, "text", path, jstr(on, "event"), "host-down, host-up, "
		    "jail-state, threshold, kmsg…");
		buf[0] = '\0';
		len = 0;
		mit = NULL;
		while ((m = ucl_object_iterate(jget(on, "match"), &mit, true)) !=
		    NULL && len < sizeof(buf) - 2) {
			len += (size_t)snprintf(buf + len, sizeof(buf) - len,
			    "%s%s=%s", len > 0 ? "\n" : "", ucl_object_key(m),
			    ucl_object_tostring_forced(m));
			if (len >= sizeof(buf))
				len = sizeof(buf) - 1;
		}
		h_fmt(h, "<textarea data-input=\"wf\" data-arg=\"map:on.%d.match\" "
		    "rows=\"2\" spellcheck=\"false\" placeholder=\"what it must "
		    "match: what=mem\">", i);
		h_txt(h, buf);
		h_fmt(h, "</textarea><button class=\"icon\" data-act=\""
		    "wf-on-del\" data-arg=\"%d\">×</button></li>", i++);
	}
	h_raw(h, "</ul><button class=\"ghost small\" data-act=\"wf-on-add\">+ "
	    "event</button><label class=\"toggle\"><input type=\"checkbox\" "
	    "data-input=\"wf\" data-arg=\"bool:destructive\"");
	h_raw(h, jbool(d, "destructive") ? " checked" : "");
	h_raw(h, "><span>It may destroy, by itself <em>a step that destroys "
	    "runs at an interval or on an event only so</em></span></label>"
	    "</fieldset></div>");
}

void
view_workflows(struct html *h)
{

	h_raw(h, "<section class=\"workflows\">");
	if (wf.load_error[0] != '\0' && (wf.jobs == NULL || wf.list == NULL)) {
		h_raw(h, "<div class=\"notice bad\">The workflows could not be "
		    "read: ");
		h_txt(h, wf.load_error);
		h_raw(h, "</div><button class=\"small\" data-act=\"wf-reload\">"
		    "Try again</button>");
	} else if (wf.jobs == NULL || wf.list == NULL)
		h_raw(h, "<div class=\"loader\"></div>");
	else if (wf.mode == WM_EDIT && wf.draft != NULL)
		view_edit(h);
	else if (wf.mode == WM_RUN)
		view_run(h);
	else
		view_list(h);
	h_raw(h, "</section>");
}

/* ---- What is done ---------------------------------------------------- */

static void
saved_cb(int status, const ucl_object_t *o, const char *err, void *arg)
{

	(void)arg;
	if (status != 200) {
		snprintf(wf.error, sizeof(wf.error), "%s", jstr(o,
		    "error.message") != NULL ? jstr(o, "error.message") : err !=
		    NULL ? err : "no answer");
		return;
	}
	wf.error[0] = '\0';
	wf.mode = WM_LIST;
	if (wf.draft != NULL)
		ucl_object_unref(wf.draft);
	wf.draft = NULL;
	toast(false, "Workflow kept");
	wf_load();
}

static void
started_cb(int status, const ucl_object_t *o, const char *err, void *arg)
{

	(void)arg;
	if (status != 200) {
		toast(true, "Not run: %s", jstr(o, "error.message") != NULL ?
		    jstr(o, "error.message") : err != NULL ? err : "no answer");
		return;
	}
	snprintf(wf.run_id, sizeof(wf.run_id), "%lld", (long long)jint(o,
	    "run", 0));
	wf.watched_at = 0;	/* into the activity bar at once */
	wf.mode = WM_RUN;
	wf.pick[0] = '\0';
	if (wf.run != NULL)
		ucl_object_unref(wf.run);
	wf.run = NULL;
	wf_load();
}

static void
done_cb(int status, const ucl_object_t *o, const char *err, void *arg)
{

	(void)arg;
	if (status != 200)
		toast(true, "%s", jstr(o, "error.message") != NULL ? jstr(o,
		    "error.message") : err != NULL ? err : "no answer");
	wf_load();
}

static void
run_now(const char *id, const ucl_object_t *f)
{
	const ucl_object_t	*w, *p, *v;
	ucl_object_iter_t	 it;
	ucl_object_t		*body, *params, *hosts;
	unsigned char		*json;
	char			 url[64], key[64];
	int			 k;

	w = wf_by_id(id);
	body = ucl_object_typed_new(UCL_OBJECT);
	params = ucl_object_typed_new(UCL_OBJECT);
	it = NULL;
	while ((p = ucl_object_iterate(jget(w, "params"), &it, true)) != NULL) {
		snprintf(key, sizeof(key), "p_%s", jstr(p, "name"));
		if ((v = jget(f, key)) != NULL)
			ucl_object_insert_key(params, ucl_object_fromstring(
			    ucl_object_tostring_forced(v)), jstr(p, "name"), 0,
			    true);
	}
	ucl_object_insert_key(body, params, "params", 0, false);
	hosts = ucl_object_typed_new(UCL_ARRAY);
	for (k = 0; f != NULL && k < app.nservers; k++) {
		snprintf(key, sizeof(key), "h_%s", app.servers[k].id);
		if (jbool(f, key))
			ucl_array_append(hosts, ucl_object_fromstring(
			    app.servers[k].id));
	}
	ucl_object_insert_key(body, hosts, "hosts", 0, false);
	json = ucl_object_emit(body, UCL_EMIT_JSON_COMPACT);
	ucl_object_unref(body);
	snprintf(url, sizeof(url), "/api/workflows/%s/run", id);
	api("POST", url, (char *)json, started_cb, NULL);
	free(json);
}

bool
workflows_modal(struct html *h)
{
	const ucl_object_t	*w, *p, *hh;
	ucl_object_iter_t	 it, hit;
	char			 name[64];
	int			 k;
	bool			 mine;

	if (app.modal != MODAL_WF_RUN || (w = wf_by_id(wf.run_wf)) == NULL)
		return (false);
	h_raw(h, "<form data-form=\"wf-run\"><h2>Run ");
	h_txt(h, jstr(w, "name"));
	h_raw(h, "</h2>");
	it = NULL;
	while ((p = ucl_object_iterate(jget(w, "params"), &it, true)) != NULL) {
		h_raw(h, "<label>");
		h_txt(h, jstr(p, "name"));
		snprintf(name, sizeof(name), "p_%s", jstr(p, "name"));
		h_raw(h, "<input spellcheck=\"false\" autocomplete=\"off\"");
		h_attr(h, "name", name);
		h_attr(h, "value", jstr(p, "default"));
		h_raw(h, "></label>");
	}
	h_raw(h, "<fieldset><legend>On</legend>");
	for (k = 0; k < app.nservers; k++) {
		mine = false;
		hit = NULL;
		while ((hh = ucl_object_iterate(jget(w, "hosts"), &hit, true)) !=
		    NULL)
			mine = mine || strcmp(ucl_object_tostring_forced(hh),
			    app.servers[k].id) == 0;
		snprintf(name, sizeof(name), "h_%s", app.servers[k].id);
		h_raw(h, "<label class=\"toggle\"><input type=\"checkbox\"");
		h_attr(h, "name", name);
		h_raw(h, mine ? " checked><span>" : "><span>");
		h_txt(h, app.servers[k].name);
		h_raw(h, "</span></label>");
	}
	h_raw(h, "</fieldset>");
	return (true);
}

bool
workflows_form(const char *form, const ucl_object_t *f)
{

	if (strcmp(form, "wf-run") != 0)
		return (false);
	run_now(wf.run_wf, f);
	app.modal = MODAL_NONE;
	return (true);
}

/* A new step's id: the first letter no step has. */
static void
new_step_id(char *buf, size_t len)
{
	const ucl_object_t	*s;
	ucl_object_iter_t	 it;
	int			 c;
	bool			 used;

	for (c = 0; c < 26 * 10; c++) {
		snprintf(buf, len, c < 26 ? "%c" : "%c%d", 'a' + c % 26, c / 26);
		used = false;
		it = NULL;
		while ((s = ucl_object_iterate(jget(wf.draft, "steps"), &it,
		    true)) != NULL)
			used = used || (jstr(s, "id") != NULL && strcmp(jstr(s,
			    "id"), buf) == 0);
		if (!used)
			return;
	}
}

static void
draft_new(void)
{
	ucl_object_t	*st, *job;
	struct server	*s;

	if (wf.draft != NULL)
		ucl_object_unref(wf.draft);
	wf.draft = ucl_object_typed_new(UCL_OBJECT);
	ucl_object_insert_key(wf.draft, ucl_object_typed_new(UCL_ARRAY),
	    "hosts", 0, true);
	if ((s = cur_server()) != NULL)
		ucl_array_append((ucl_object_t *)(uintptr_t)ucl_object_lookup(
		    wf.draft, "hosts"), ucl_object_fromstring(s->id));
	ucl_object_insert_key(wf.draft, ucl_object_typed_new(UCL_ARRAY),
	    "params", 0, true);
	ucl_object_insert_key(wf.draft, ucl_object_typed_new(UCL_ARRAY),
	    "steps", 0, true);
	ucl_object_insert_key(wf.draft, ucl_object_typed_new(UCL_ARRAY), "on",
	    0, true);
	st = ucl_object_typed_new(UCL_OBJECT);
	ucl_object_insert_key(st, ucl_object_fromstring("a"), "id", 0, true);
	job = ucl_object_typed_new(UCL_OBJECT);
	ucl_object_insert_key(job, ucl_object_fromstring("service-action"),
	    "kind", 0, true);
	ucl_object_insert_key(st, job, "job", 0, true);
	ucl_array_append((ucl_object_t *)(uintptr_t)ucl_object_lookup(wf.draft,
	    "steps"), st);
}

/* What waits in the queue, kept as a workflow's steps. */
static void
draft_from_queue(void)
{
	ucl_object_t	*steps, *hosts, *st, *job;
	char		 id[8];
	int		 i, k;
	bool		 seen;

	draft_new();
	steps = arr_at("steps");
	while (ucl_array_size(steps) > 0)
		ucl_object_unref(ucl_array_pop_last(steps));
	hosts = arr_at("hosts");
	while (ucl_array_size(hosts) > 0)
		ucl_object_unref(ucl_array_pop_last(hosts));
	for (i = 0; i < app.nbatch; i++) {
		if ((job = json_parse(app.batch[i].json)) == NULL)
			continue;
		st = ucl_object_typed_new(UCL_OBJECT);
		snprintf(id, sizeof(id), "s%d", i + 1);
		ucl_object_insert_key(st, ucl_object_fromstring(id), "id", 0,
		    true);
		ucl_object_insert_key(st, ucl_object_fromstring(
		    app.batch[i].title), "name", 0, true);
		ucl_object_insert_key(st, job, "job", 0, true);
		ucl_array_append(steps, st);
		seen = false;
		for (k = 0; k < i; k++)
			seen = seen || strcmp(app.batch[k].sid,
			    app.batch[i].sid) == 0;
		if (!seen)
			ucl_array_append(hosts, ucl_object_fromstring(
			    app.batch[i].sid));
	}
	ucl_object_insert_key(wf.draft, ucl_object_fromstring("From the queue"),
	    "name", 0, true);
}

/* The draft's step at from taken out and put back at to. */
static void
step_move(int from, int to)
{
	ucl_object_t	*a, *o, *rest[WF_EDIT_STEPS];
	int		 n, nr;

	a = arr_at("steps");
	n = (int)ucl_array_size(a);
	if (from < 0 || from >= n || to < 0 || to >= n || to == from ||
	    n > WF_EDIT_STEPS)
		return;
	o = ucl_array_delete(a, (ucl_object_t *)(uintptr_t)
	    ucl_array_find_index(a, (unsigned int)from));
	if (o == NULL)
		return;
	nr = 0;
	while ((int)ucl_array_size(a) > to)
		rest[nr++] = ucl_array_pop_last(a);
	ucl_array_append(a, o);
	while (nr > 0)
		ucl_array_append(a, rest[--nr]);
}

bool
workflows_action(const char *act, const char *arg, const char *value)
{
	ucl_object_t		*a, *o, *st;
	const ucl_object_t	*w;
	unsigned char		*json;
	char			 url[80], id[16], buf[64];
	int			 i, k;

	if (strcmp(act, "select-workflows") == 0) {
		workflows_open();
		return (true);
	}
	if (strncmp(act, "wf-", 3) != 0 && strncmp(act, "input:wf", 8) != 0 &&
	    strncmp(act, "do-wf-", 6) != 0 && strcmp(act, "queue-to-wf") != 0)
		return (false);
	i = atoi(arg);
	if (strcmp(act, "input:wf") == 0)
		draft_input(arg, value);
	else if (strcmp(act, "input:wf-kind") == 0) {
		/* Another kind: what the job was goes. */
		snprintf(buf, sizeof(buf), "steps.%d.job", i);
		o = ucl_object_typed_new(UCL_OBJECT);
		if (value[0] != '\0')
			ucl_object_insert_key(o, ucl_object_fromstring(value),
			    "kind", 0, true);
		set_path(buf, o);
	} else if (strcmp(act, "input:wf-type") == 0) {
		snprintf(buf, sizeof(buf), "steps.%d", i);
		if ((st = walk(wf.draft, buf, false, url, sizeof(url))) !=
		    NULL && (st = (ucl_object_t *)(uintptr_t)
		    ucl_array_find_index(st, (unsigned int)i)) != NULL) {
			(void)ucl_object_delete_key(st, "job");
			(void)ucl_object_delete_key(st, "read");
			(void)ucl_object_delete_key(st, "arcana");
			if (strncmp(value, "read:", 5) == 0)
				ucl_object_insert_key(st, ucl_object_fromstring(
				    value + 5), "read", 0, true);
			else if (strncmp(value, "arcana:", 7) == 0)
				ucl_object_insert_key(st, ucl_object_fromstring(
				    value + 7), "arcana", 0, true);
			else
				ucl_object_insert_key(st, ucl_object_typed_new(
				    UCL_OBJECT), "job", 0, true);
		}
	} else if (strcmp(act, "input:wf-when-of") == 0) {
		snprintf(buf, sizeof(buf), "steps.%d.when.read", i);
		set_path(buf, strncmp(value, "read:", 5) == 0 ?
		    ucl_object_fromstring(value + 5) : NULL);
		snprintf(buf, sizeof(buf), "steps.%d.when.step", i);
		set_path(buf, strncmp(value, "step:", 5) == 0 ?
		    ucl_object_fromstring(value + 5) : NULL);
	} else if (strcmp(act, "wf-when") == 0) {
		snprintf(buf, sizeof(buf), "steps.%d.when", i);
		st = (ucl_object_t *)(uintptr_t)ucl_array_find_index(jget(
		    wf.draft, "steps"), (unsigned int)i);
		if (st != NULL && ucl_object_lookup(st, "when") != NULL)
			set_path(buf, NULL);
		else if (st != NULL) {
			o = ucl_object_typed_new(UCL_OBJECT);
			ucl_object_insert_key(o, ucl_object_fromstring("hello"),
			    "read", 0, true);
			ucl_object_insert_key(o, ucl_object_fromstring("exists"),
			    "op", 0, true);
			set_path(buf, o);
		}
	} else if (strcmp(act, "wf-new") == 0) {
		draft_new();
		wf.error[0] = '\0';
		wf.mode = WM_EDIT;
	} else if (strcmp(act, "input:wf-template") == 0) {
		if (draft_template(value)) {
			wf.error[0] = '\0';
			wf.mode = WM_EDIT;
		}
	} else if (strcmp(act, "queue-to-wf") == 0) {
		if (app.node != NODE_WORKFLOWS)
			workflows_open();
		draft_from_queue();
		wf.error[0] = '\0';
		wf.mode = WM_EDIT;
	} else if (strcmp(act, "wf-edit") == 0) {
		if ((w = wf_by_id(arg)) == NULL)
			return (true);
		if (wf.draft != NULL)
			ucl_object_unref(wf.draft);
		wf.draft = ucl_object_copy(w);
		wf.error[0] = '\0';
		wf.mode = WM_EDIT;
	} else if (strcmp(act, "wf-reload") == 0) {
		wf.load_error[0] = '\0';
		wf_load();
	} else if (strcmp(act, "wf-back") == 0) {
		wf.mode = WM_LIST;
		wf_load();
	} else if (strcmp(act, "wf-save") == 0) {
		json = ucl_object_emit(wf.draft, UCL_EMIT_JSON_COMPACT);
		api("POST", "/api/workflows", (char *)json, saved_cb, NULL);
		free(json);
	} else if (strcmp(act, "wf-del") == 0) {
		w = wf_by_id(arg);
		confirm("Delete the workflow", "It no longer runs, by itself or "
		    "by hand; its runs are listed still.", "Delete", true, "",
		    "do-wf-del", arg, "");
		(void)w;
	} else if (strcmp(act, "do-wf-del") == 0) {
		snprintf(url, sizeof(url), "/api/workflows/%.8s", arg);
		api("DELETE", url, NULL, done_cb, NULL);
	} else if (strcmp(act, "wf-run") == 0) {
		snprintf(wf.run_wf, sizeof(wf.run_wf), "%.8s", arg);
		if ((w = wf_by_id(arg)) == NULL)
			return (true);
		app.modal = MODAL_WF_RUN;
		app.modal_error[0] = '\0';
	} else if (strcmp(act, "wf-run-open") == 0) {
		snprintf(wf.run_id, sizeof(wf.run_id), "%.15s", arg);
		wf.mode = WM_RUN;
		wf.pick[0] = '\0';
		if (wf.run != NULL)
			ucl_object_unref(wf.run);
		wf.run = NULL;
		wf_load();
	} else if (strcmp(act, "wf-run-stop") == 0) {
		snprintf(url, sizeof(url), "/api/runs/%.15s", arg);
		api("DELETE", url, NULL, done_cb, NULL);
	} else if (strcmp(act, "wf-step-pick") == 0) {
		snprintf(wf.pick, sizeof(wf.pick), "%s", strcmp(wf.pick, arg) ==
		    0 ? "" : arg);
	} else if (strcmp(act, "wf-host") == 0) {
		a = arr_at("hosts");
		for (k = 0; k < (int)ucl_array_size(a); k++)
			if (strcmp(ucl_object_tostring_forced(
			    ucl_array_find_index(a, (unsigned int)k)), arg) == 0)
				break;
		if (k < (int)ucl_array_size(a))
			ucl_object_unref(ucl_array_delete(a,
			    (ucl_object_t *)(uintptr_t)ucl_array_find_index(a,
			    (unsigned int)k)));
		else
			ucl_array_append(a, ucl_object_fromstring(arg));
	} else if (strcmp(act, "wf-param-add") == 0) {
		o = ucl_object_typed_new(UCL_OBJECT);
		ucl_object_insert_key(o, ucl_object_fromstring(""), "name", 0,
		    true);
		ucl_array_append(arr_at("params"), o);
	} else if (strcmp(act, "wf-param-del") == 0 || strcmp(act,
	    "wf-step-del") == 0 || strcmp(act, "wf-on-del") == 0) {
		a = arr_at(act[3] == 'p' ? "params" : act[3] == 's' ? "steps" :
		    "on");
		if ((o = (ucl_object_t *)(uintptr_t)ucl_array_find_index(a,
		    (unsigned int)i)) != NULL)
			ucl_object_unref(ucl_array_delete(a, o));
	} else if (strcmp(act, "wf-step-add") == 0) {
		st = ucl_object_typed_new(UCL_OBJECT);
		new_step_id(id, sizeof(id));
		ucl_object_insert_key(st, ucl_object_fromstring(id), "id", 0,
		    true);
		ucl_object_insert_key(st, ucl_object_typed_new(UCL_OBJECT),
		    "job", 0, true);
		ucl_array_append(arr_at("steps"), st);
	} else if (strcmp(act, "wf-step-up") == 0 && i > 0) {
		step_move(i, i - 1);
	} else if (strcmp(act, "wf-step-drop") == 0) {
		/* Dropped before or after another: "3:before". */
		k = atoi(value);
		if (strstr(value, ":after") != NULL)
			k++;
		step_move(i, k > i ? k - 1 : k);
	} else if (strcmp(act, "wf-on-add") == 0) {
		o = ucl_object_typed_new(UCL_OBJECT);
		ucl_object_insert_key(o, ucl_object_fromstring("host-down"),
		    "event", 0, true);
		ucl_array_append(arr_at("on"), o);
	}
	return (true);
}
