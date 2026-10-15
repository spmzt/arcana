/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Reads over the console's socket: what a GET would read, done by the
 * console as {"what": "read"} (stream.c), so that each step of the
 * host's trace reaches the page while the host takes it.  The task of
 * the read draws its steps as they come, a program's box the moment it
 * runs, and says it is live, not pending; the answer goes to the same
 * callback a GET's would.  Without the socket, or when it fails, the
 * read is a GET after all.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "app.h"

#define	LIVE_MAX	16
#define	LIVE_ID0	1000000		/* above the other streams' ids */

struct liveread {
	int	 id;		/* the socket's request, 0: a free slot */
	int	 op;		/* its task, 0: none */
	api_cb	*cb;
	void	*arg;
	char	 url[400];	/* the GET it would be */
	char	 fn[48];	/* its operation's call, as the trace says it */
	int	 node, tab;	/* where the page was: its tab's (export.c) */
};

static struct liveread	live[LIVE_MAX];
static int		live_next = LIVE_ID0;

static struct liveread *
live_find(int id)
{
	int	i;

	for (i = 0; i < LIVE_MAX; i++)
		if (live[i].id != 0 && live[i].id == id)
			return (&live[i]);
	return (NULL);
}

/* The read as a GET after all: the socket is not there, or failed. */
static void
live_fallback(struct liveread *l)
{
	struct liveread	 c = *l;
	struct op	*op;
	int		 req;

	memset(l, 0, sizeof(*l));
	if ((op = c.op != 0 ? op_find(c.op) : NULL) != NULL) {
		op->live = false;
		op->await = true;
	}
	req = api("GET", c.url, NULL, c.cb, c.arg);
	if (op != NULL)
		op->req = req;
}

/*
 * Read url's answer with the console's socket: read is what it reads
 * of server sid, the path after /api/servers/<sid>/ with its query
 * ("services", "net/routes?fib=1"); opid, when not 0, is its task.
 */
void
live_read(const char *sid, const char *read, const char *url, int opid,
    api_cb *cb, void *arg)
{
	struct liveread	*l;
	struct op	*op;
	char		 msg[640], *q;
	int		 i;

	op = opid != 0 ? op_find(opid) : NULL;
	for (i = 0, l = NULL; i < LIVE_MAX && l == NULL; i++)
		if (live[i].id == 0)
			l = &live[i];
	if (l == NULL || !app.online) {
		/* Too many at once here: as before. */
		i = api("GET", url, NULL, cb, arg);
		if (op != NULL)
			op->req = i;
		return;
	}
	l->id = live_next++;
	l->op = opid;
	l->cb = cb;
	l->arg = arg;
	snprintf(l->url, sizeof(l->url), "%s", url);
	export_where(&l->node, &l->tab);
	/* The console's call, by which the schema panel finds it. */
	{
		const char	*p;
		size_t		 n;

		n = strcspn(read, "/?");
		p = strncmp(read, "jails", n) == 0 && n == 5 ? "list" :
		    strncmp(read, "net", n) == 0 && n == 3 ? "network" : read;
		snprintf(l->fn, sizeof(l->fn), "libcblink arc_%.*s()",
		    (int)(p == read ? n : strlen(p)), p);
	}
	if (op != NULL) {
		op->live = true;
		op->await = false;
		/* What it reads, as its schema is found by. */
		snprintf(op->method, sizeof(op->method), "GET");
		snprintf(op->url, sizeof(op->url), "%s", url);
		snprintf(op->stage, sizeof(op->stage), "asked the host");
	}
	q = json_quote(read);
	snprintf(msg, sizeof(msg), "{\"id\":%d,\"server\":\"%s\",\"what\":"
	    "\"read\",\"read\":%s}", l->id, sid, q);
	free(q);
	arc_stream_send(msg);
}

/*
 * Task opid's read, no longer waited for: the console is told to stop
 * it, and its callback is told it was given up, as a GET's would be.
 */
void
live_cancel(int opid)
{
	struct liveread	 c;
	char		 msg[64];

	for (int i = 0; i < LIVE_MAX; i++) {
		if (live[i].id == 0 || live[i].op != opid)
			continue;
		c = live[i];
		memset(&live[i], 0, sizeof(live[i]));
		snprintf(msg, sizeof(msg), "{\"id\":%d,\"stop\":true}", c.id);
		arc_stream_send(msg);
		c.cb(0, NULL, "cancelled", c.arg);
		return;
	}
}

/* A task's state as the list and the graph say it: live, not pending. */
const char *
op_class(const struct op *o)
{

	return (o->state == OP_RUNNING ? (o->live ? "live" : "running") :
	    o->state == OP_OK ? "ok" : "failed");
}

/* The console's own three steps above the host's, until the answer. */
static ucl_object_t *
own_step(int id, int parent, const char *kind, const char *label)
{
	ucl_object_t	*o;

	o = ucl_object_typed_new(UCL_OBJECT);
	ucl_object_insert_key(o, ucl_object_fromint(id), "id", 0, true);
	ucl_object_insert_key(o, ucl_object_fromint(parent), "parent", 0,
	    true);
	ucl_object_insert_key(o, ucl_object_fromstring(kind), "kind", 0,
	    true);
	ucl_object_insert_key(o, ucl_object_fromstring(label), "label", 0,
	    true);
	ucl_object_insert_key(o, ucl_object_fromstring("incomplete"),
	    "status", 0, true);
	return (o);
}

/* A step the host told: put in its task's trace, or its place taken. */
static void
live_step(struct op *op, const char *fn, const ucl_object_t *step)
{
	const ucl_object_t	*e;
	ucl_object_iter_t	 it;
	ucl_object_t		*copy;
	int64_t			 id;
	unsigned int		 i;

	if (op == NULL || (id = jint(step, "id", -1)) < 0)
		return;
	if (op->trace == NULL) {
		op->trace = ucl_object_typed_new(UCL_ARRAY);
		ucl_array_append(op->trace, own_step(0, -1, "api",
		    "over the console's socket, live"));
		ucl_array_append(op->trace, own_step(1, 0, "auth",
		    "session check"));
		ucl_array_append(op->trace, own_step(2, 0, "lib", fn));
	}
	copy = ucl_object_copy(step);
	it = NULL;
	i = 0;
	while ((e = ucl_object_iterate(op->trace, &it, true)) != NULL) {
		if (jint(e, "id", -2) == id) {
			ucl_object_unref(ucl_array_replace_index(op->trace,
			    copy, i));
			copy = NULL;
			break;
		}
		i++;
	}
	if (copy != NULL)
		ucl_array_append(op->trace, copy);
	/* Where it is: the step that runs now. */
	if (jstr(step, "label") != NULL)
		snprintf(op->stage, sizeof(op->stage), "%s", jstr(step,
		    "label"));
}

/*
 * The open host's events, followed while its page is shown, each a sign
 * that something its tabs show changed (agent's gula/hostwatch.c and
 * the kernel's netlink(4) events): the tab that shows it is read again,
 * by itself and with no task, a moment later, so that a burst of them
 * is one read; a tab not shown is read when it is shown.  Some tabs
 * that nothing tells of are read again now and then while shown.
 */
#define	HF_ID0		3000000
#define	HF_RETRY	30000	/* ms before the events are tried again */
#define	HF_SOON		1200	/* ms an event's read waits for others */
#define	HF_GAP		3000	/* ms between two reads of one tab, at least */

enum ltab { LT_JAILS, LT_SERVICES, LT_NETWORK, LT_PROCS, LT_STORAGE,
    LT_SYSCTL, LT_KERNEL, LT_SSH, LT_CERTS, LT_N };

static const struct {
	enum tab	 tab;
	double		 every;	/* ms: read this often while shown, 0 never */
} ltabs[LT_N] = {
	[LT_JAILS] = { TAB_JAILS, 0 },		/* main.c's tick: 10 s */
	[LT_SERVICES] = { TAB_SERVICES, 60000 },
	[LT_NETWORK] = { TAB_NETWORK, 0 },
	[LT_PROCS] = { TAB_PROCESSES, 0 },	/* procs.c's: 3 s */
	[LT_STORAGE] = { TAB_STORAGE, 60000 },
	[LT_SYSCTL] = { TAB_SYSCTL, 0 },
	[LT_KERNEL] = { TAB_KERNEL, 60000 },
	[LT_SSH] = { TAB_SSH, 60000 },
	[LT_CERTS] = { TAB_CERTS, 120000 },
};

static struct {
	int		 id;
	bool		 on;
	char		 sid[9];
	double		 retry;
	double		 due[LT_N];	/* when an event asked, 0 not */
	double		 read[LT_N];	/* when it was read last, by us or
					 * by the tab being opened */
	enum tab	 shown;		/* the tab at the last tick */
	enum node	 node;
} hf = { .id = HF_ID0 };

static void
hf_stop(void)
{
	char	msg[64];

	if (hf.on) {
		snprintf(msg, sizeof(msg), "{\"id\":%d,\"stop\":true}", hf.id);
		arc_stream_send(msg);
	}
	hf.on = false;
}

static void
hf_start(const struct server *s)
{
	char	msg[128];

	hf_stop();
	if (strcmp(hf.sid, s->id) != 0)
		memset(hf.due, 0, sizeof(hf.due));
	hf.id++;
	hf.on = true;
	snprintf(hf.sid, sizeof(hf.sid), "%s", s->id);
	snprintf(msg, sizeof(msg), "{\"id\":%d,\"server\":\"%s\",\"what\":"
	    "\"events\"}", hf.id, s->id);
	arc_stream_send(msg);
}

static void
hf_due(enum ltab t)
{

	if (hf.due[t] == 0)
		hf.due[t] = arc_now();
}

/* An event of the host followed: which tabs it says changed. */
static void
hf_event(const ucl_object_t *e)
{
	const ucl_object_t	*d = jget(e, "data");
	const char		*kind = jstr(e, "kind"), *f, *jail;
	enum netkind		 nk = app.net.kind;

	if (kind == NULL)
		return;
	jail = jstr(e, "jail") != NULL ? jstr(e, "jail") : "";
	if (strcmp(kind, "jail-state") == 0)
		hf_due(LT_JAILS);
	else if (strcmp(kind, "procs") == 0) {
		hf_due(LT_PROCS);
		/* A daemon gone or come: a service's state. */
		hf_due(LT_SERVICES);
	} else if (strcmp(kind, "zfs") == 0 || strcmp(kind, "device") == 0) {
		hf_due(LT_STORAGE);
		/* Each kind of it, read again when shown. */
		if (cur_server() != NULL && strcmp(cur_server()->id, hf.sid) ==
		    0)
			storage_due(cur_server());
	}
	else if (strcmp(kind, "conf") == 0 && (f = jstr(d, "file")) != NULL) {
		f = strrchr(f, '/') != NULL ? strrchr(f, '/') + 1 : f;
		if (strncmp(f, "rc.conf", 7) == 0)
			hf_due(LT_SERVICES);
		else if (strcmp(f, "sysctl.conf") == 0)
			hf_due(LT_SYSCTL);
		else if (strcmp(f, "fstab") == 0)
			hf_due(LT_STORAGE);
		else if (strcmp(f, "jail.conf") == 0)
			hf_due(LT_JAILS);
		else if (strcmp(f, "loader.conf") == 0)
			hf_due(LT_KERNEL);
		else if (strcmp(f, "sshd_config") == 0)
			hf_due(LT_SSH);
	} else if (strcmp(jail, app.net_jail) != 0)
		;	/* another network than the one the tab shows */
	else if ((strncmp(kind, "link", 4) == 0 ||
	    strncmp(kind, "address-", 8) == 0) && (nk == NET_INTERFACES ||
	    nk == NET_BRIDGES || nk == NET_GENEVE || nk == NET_CARP ||
	    nk == NET_NETGRAPH || nk == NET_WIREGUARD))
		hf_due(LT_NETWORK);
	else if ((strncmp(kind, "route", 5) == 0) && (nk == NET_ROUTES ||
	    nk == NET_NEXTHOPS || nk == NET_NHGROUPS))
		hf_due(LT_NETWORK);
}

/* Is tab t of host s what the page shows? */
static bool
hf_shown(enum ltab t, const struct server *s)
{

	if (t == LT_JAILS)
		return ((app.node == NODE_HOST && (app.tab == TAB_JAILS ||
		    app.tab == TAB_SUMMARY)) || (app.node == NODE_JAIL &&
		    s != NULL));
	return (app.node == NODE_HOST && app.tab == ltabs[t].tab);
}

static void
hf_read(enum ltab t, struct server *s)
{

	switch (t) {
	case LT_JAILS:
		refresh_jails(s, false);
		break;
	case LT_SERVICES:
		refresh_services(s, false);
		break;
	case LT_NETWORK:
		/* Those read every two seconds anyway, and a stream's. */
		if (app.net.kind != NET_CONNECTIONS && app.net.kind !=
		    NET_SOCKETS && app.net.kind != NET_NEIGHBOURS &&
		    !app.net.loading)
			refresh_network(s, false);
		break;
	case LT_PROCS:
		procs_poke();
		break;
	case LT_STORAGE:
		storage_due(s);
		refresh_storage(s, false);
		break;
	case LT_SYSCTL:
		refresh_sysctl(s, true);
		break;
	case LT_KERNEL:
		refresh_kernel(s, true);
		break;
	case LT_SSH:
		refresh_ssh(s, true);
		break;
	case LT_CERTS:
		refresh_certs(s, true);
		break;
	case LT_N:
		break;
	}
}

/* Once a second, from main.c's tick, with app.quiet: no tasks. */
void
live_tick(double now)
{
	struct server	*s;
	bool		 want;

	s = cur_server();
	want = s != NULL && app.visible && (app.node == NODE_HOST ||
	    app.node == NODE_JAIL);
	if (hf.on && (!want || strcmp(hf.sid, s->id) != 0))
		hf_stop();
	if (want && !hf.on && now >= hf.retry)
		hf_start(s);
	if (!want)
		return;
	/* A tab just opened was read by opening it. */
	if (app.tab != hf.shown || app.node != hf.node)
		for (int t = 0; t < LT_N; t++)
			if (hf_shown((enum ltab)t, s) && hf.due[t] == 0)
				hf.read[t] = now;
	hf.shown = app.tab;
	hf.node = app.node;
	for (int t = 0; t < LT_N; t++) {
		if (!hf_shown((enum ltab)t, s))
			continue;
		/* Nothing tells of it: now and then. */
		if (hf.due[t] == 0 && ltabs[t].every > 0 && now - hf.read[t] >=
		    ltabs[t].every)
			hf.due[t] = now - HF_SOON;
		if (hf.due[t] == 0 || now - hf.due[t] < HF_SOON ||
		    now - hf.read[t] < HF_GAP)
			continue;
		hf.due[t] = 0;
		hf.read[t] = now;
		hf_read((enum ltab)t, s);
	}
}

/* What the socket says (arc_on_stream()): a read's step or answer. */
void
live_stream(const ucl_object_t *o)
{
	struct liveread	*l;
	struct op	*op;
	const char	*err;
	int		 i, status;

	if (jbool(o, "closed")) {
		hf.on = false;
		hf.retry = arc_now() + HF_RETRY;
	} else if (hf.on && jint(o, "id", -1) == hf.id) {
		if (jget(o, "event") != NULL)
			hf_event(jget(o, "event"));
		/* Some went past: whatever is shown is read again. */
		if (jbool(o, "lost"))
			for (int t = 0; t < LT_N; t++)
				hf_due((enum ltab)t);
		if (jstr(o, "error") != NULL) {
			hf.on = false;
			hf.retry = arc_now() + HF_RETRY;
		}
		return;
	}
	if (jbool(o, "closed")) {
		/* Lost: what was asked on it is asked again with GET. */
		for (i = 0; i < LIVE_MAX; i++)
			if (live[i].id != 0)
				live_fallback(&live[i]);
		return;
	}
	if ((l = live_find((int)jint(o, "id", -1))) == NULL)
		return;
	op = l->op != 0 ? op_find(l->op) : NULL;
	if (jget(o, "step") != NULL) {
		live_step(op, l->fn, jget(o, "step"));
		return;
	}
	if (jget(o, "reply") == NULL) {
		/* Refused, or the host did not answer: GET says why. */
		live_fallback(l);
		return;
	}
	status = (int)jint(o, "status", 0);
	err = NULL;
	if (status >= 400 && (err = jstr(jget(o, "reply"),
	    "error.message")) == NULL)
		err = jstr(jget(o, "reply"), "error");
	if (op != NULL)
		op->live = false;
	{
		struct liveread	c = *l;

		memset(l, 0, sizeof(*l));
		if (status == 200)
			export_note(c.url, c.node, c.tab, jget(o, "reply"));
		c.cb(status, jget(o, "reply"), err, c.arg);
	}
}

/*
 * What a tab says of what it shows, in its tally: how old it is, and
 * that it is being read again or that the last read failed, beside it:
 * what is shown stays until a new read replaces it.
 */
void
fresh(struct html *h, double fetched, bool loading, const char *error)
{
	char	age[32];
	bool	bad = error != NULL && error[0] != '\0';

	h_raw(h, "<span class=\"tally fresh");
	if (loading)
		h_raw(h, " reading");
	if (bad)
		h_raw(h, " is-stale");
	h_raw(h, "\"");
	if (bad)
		h_attr(h, "title", error);
	h_raw(h, ">");
	if (fetched > 0) {
		fmt_age(age, sizeof(age), fetched);
		h_txt(h, age);
	}
	if (loading)
		h_raw(h, fetched > 0 ? " · reading" : "reading");
	else if (bad)
		h_raw(h, fetched > 0 ? " · not read again" : "not read");
	h_raw(h, "</span>");
}
