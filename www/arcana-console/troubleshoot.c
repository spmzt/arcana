/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * The troubleshooter: a packet from one address to another followed
 * across the hosts the console has, and what stops it on the way.
 *
 *	POST /api/troubleshoot/path {"src", "dst", "proto", "port",
 *	    "places": [{"server", "jail"}]}
 *
 * Each place (a host, or a vnet jail of one; every host when none are
 * named) is asked what it would do with the packet (path-check, the
 * agent's: nothing is sent).  Where the packet comes in is the place
 * whose address the source is, or that is on the source's network;
 * from there each place's send route names its next hop, and the place
 * that has that address is asked next, the packet coming in on the
 * interface that has it, until the destination is reached, the next
 * hop is no place of the console's, or something stops it.  The reply
 * is followed the same way from the destination back, as a reply: a
 * place it passes that the request did not has no state of it, which a
 * stateful firewall drops.  Request and reply by other places is said
 * as the asymmetry it is.
 *
 * The answer: "hops" and "return", each place in turn with its ingress,
 * egress, next hop and its own check; "end" and "return_end", how each
 * way ended; "findings", worst first, each with its place.
 */

#include <sys/param.h>

#include <arpa/inet.h>

#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "console.h"

#define	TS_PLACES	64
#define	TS_HOPS		16
#define	TS_WAIT_S	20	/* the survey waits no longer for a place */

struct place {
	char		 sid[9];
	char		 name[128];
	char		 uri[256];
	char		 peer[256];
	char		 jail[64];
	ucl_object_t	*survey;	/* path-check, no interface given */
	char		 error[256];
};

struct tsh {
	struct kore_task task;
	char		 src[64], dst[64], proto[8];
	uint32_t	 port;
	struct place	 p[TS_PLACES];
	int		 n;
	char		*json;
};

static void
put(ucl_object_t *o, const char *k, ucl_object_t *v)
{

	ucl_object_insert_key(o, v, k, 0, true);
}

static void
put_s(ucl_object_t *o, const char *k, const char *v)
{

	if (v != NULL)
		put(o, k, ucl_object_fromstring(v));
}

static const char *
str(const ucl_object_t *o, const char *path)
{
	const ucl_object_t	*v = ucl_object_lookup_path(o, path);

	return (v != NULL && ucl_object_type(v) == UCL_STRING ?
	    ucl_object_tostring(v) : NULL);
}

static bool
flag(const ucl_object_t *o, const char *path)
{

	return (ucl_object_toboolean(ucl_object_lookup_path(o, path)));
}

static const char *
place_name(const struct place *p)
{
	static _Thread_local char	buf[256];

	if (p->jail[0] == '\0')
		return (p->name);
	snprintf(buf, sizeof(buf), "%s, jail %s", p->name, p->jail);
	return (buf);
}

/* A place's answer, as JSON: its data, or NULL with why in the place. */
static ucl_object_t *
answer(struct place *p, char *json)
{
	struct ucl_parser	*ps;
	ucl_object_t		*o, *d;

	o = NULL;
	if (json != NULL) {
		ps = ucl_parser_new(UCL_PARSER_NO_IMPLICIT_ARRAYS);
		if (ucl_parser_add_string(ps, json, 0))
			o = ucl_parser_get_object(ps);
		ucl_parser_free(ps);
		free(json);
	}
	if (o == NULL || (d = (ucl_object_t *)(uintptr_t)ucl_object_lookup(o,
	    "data")) == NULL) {
		snprintf(p->error, sizeof(p->error), "%s", o != NULL &&
		    str(o, "error") != NULL ? str(o, "error") : o != NULL &&
		    str(o, "error.message") != NULL ? str(o, "error.message") :
		    "it did not answer");
		if (o != NULL)
			ucl_object_unref(o);
		return (NULL);
	}
	d = ucl_object_ref(d);
	ucl_object_unref(o);
	return (d);
}

/* A place's check: its data, or NULL with why in the place. */
static ucl_object_t *
check(struct place *p, const struct tsh *t, const char *src,
    const char *dst, const char *iface, bool reply)
{
	int	status;

	return (answer(p, hosts_path_check(p->uri, p->peer[0] != '\0' ?
	    p->peer : NULL, p->name, p->jail[0] != '\0' ? p->jail : NULL,
	    src, dst, t->proto[0] != '\0' ? t->proto : NULL, t->port, iface,
	    reply, &status)));
}

/*
 * The survey: every place asked at once, each in a thread of its own,
 * and none waited for longer than TS_WAIT_S: a host whose agent takes
 * the connection and never answers holds up only itself.  A thread
 * still asking when the wait ends is left to end by itself; what it
 * holds is its own, and the last of it and the survey frees the round.
 */
struct round {
	pthread_mutex_t	 m;
	pthread_cond_t	 c;
	int		 refs;		/* the survey's, and each thread's */
	int		 pending;
};

struct ask {
	struct round	*r;
	struct place	 p;		/* a copy: the thread's own */
	char		 src[64], dst[64], proto[8];
	uint32_t	 port;
	char		*json;
	bool		 done, abandoned;
};

static void
round_drop(struct round *r)
{
	bool	last;

	pthread_mutex_lock(&r->m);
	last = --r->refs == 0;
	pthread_mutex_unlock(&r->m);
	if (last) {
		pthread_mutex_destroy(&r->m);
		pthread_cond_destroy(&r->c);
		free(r);
	}
}

static void *
ask_run(void *arg)
{
	struct ask	*a = arg;
	struct round	*r = a->r;
	char		*json;
	int		 status;
	bool		 abandoned;

	json = hosts_path_check(a->p.uri, a->p.peer[0] != '\0' ? a->p.peer :
	    NULL, a->p.name, a->p.jail[0] != '\0' ? a->p.jail : NULL, a->src,
	    a->dst, a->proto[0] != '\0' ? a->proto : NULL, a->port, NULL,
	    false, &status);
	pthread_mutex_lock(&r->m);
	abandoned = a->abandoned;
	a->json = json;
	a->done = true;
	r->pending--;
	pthread_cond_signal(&r->c);
	pthread_mutex_unlock(&r->m);
	if (abandoned) {
		free(json);
		free(a);
	}
	round_drop(r);
	return (NULL);
}

static void
survey(struct tsh *t)
{
	struct round	*r;
	struct ask	*a[TS_PLACES];
	struct timespec	 until;
	pthread_t	 th;
	int		 i;

	if ((r = calloc(1, sizeof(*r))) == NULL)
		abort();
	pthread_mutex_init(&r->m, NULL);
	pthread_cond_init(&r->c, NULL);
	r->refs = 1;
	for (i = 0; i < t->n; i++) {
		if ((a[i] = calloc(1, sizeof(*a[i]))) == NULL)
			abort();
		a[i]->r = r;
		a[i]->p = t->p[i];
		snprintf(a[i]->src, sizeof(a[i]->src), "%s", t->src);
		snprintf(a[i]->dst, sizeof(a[i]->dst), "%s", t->dst);
		snprintf(a[i]->proto, sizeof(a[i]->proto), "%s", t->proto);
		a[i]->port = t->port;
		pthread_mutex_lock(&r->m);
		r->refs++;
		r->pending++;
		pthread_mutex_unlock(&r->m);
		if (pthread_create(&th, NULL, ask_run, a[i]) != 0) {
			/* No thread: asked here, in turn. */
			pthread_mutex_lock(&r->m);
			r->refs--;
			r->pending--;
			pthread_mutex_unlock(&r->m);
			t->p[i].survey = check(&t->p[i], t, t->src, t->dst,
			    NULL, false);
			free(a[i]);
			a[i] = NULL;
			continue;
		}
		pthread_detach(th);
	}
	clock_gettime(CLOCK_REALTIME, &until);
	until.tv_sec += TS_WAIT_S;
	pthread_mutex_lock(&r->m);
	while (r->pending > 0 && pthread_cond_timedwait(&r->c, &r->m,
	    &until) != ETIMEDOUT)
		;
	for (i = 0; i < t->n; i++) {
		if (a[i] == NULL)
			continue;
		if (a[i]->done) {
			t->p[i].survey = answer(&t->p[i], a[i]->json);
			free(a[i]);
		} else {
			a[i]->abandoned = true;
			snprintf(t->p[i].error, sizeof(t->p[0].error), "no "
			    "answer in %d seconds", TS_WAIT_S);
			t->p[i].survey = NULL;
		}
	}
	pthread_mutex_unlock(&r->m);
	round_drop(r);
}

/* The place that has address a, and the interface it is on. */
static int
owner(const struct tsh *t, const char *a, const char **ifn)
{
	const ucl_object_t	*e;
	ucl_object_iter_t	 it;
	int			 i;

	for (i = 0; i < t->n; i++) {
		it = NULL;
		while ((e = ucl_object_iterate(ucl_object_lookup(t->p[i].survey,
		    "addresses"), &it, true)) != NULL)
			if (str(e, "address") != NULL && strcmp(str(e,
			    "address"), a) == 0) {
				*ifn = str(e, "interface");
				return (i);
			}
	}
	return (-1);
}

static void
finding(ucl_object_t *arr, const char *sev, const struct place *p,
    const char *fmt, ...) __printflike(4, 5);

static void
finding(ucl_object_t *arr, const char *sev, const struct place *p,
    const char *fmt, ...)
{
	ucl_object_t	*o;
	va_list		 ap;
	char		*s;

	va_start(ap, fmt);
	if (vasprintf(&s, fmt, ap) == -1)
		s = NULL;
	va_end(ap);
	if (s == NULL)
		return;
	o = ucl_object_typed_new(UCL_OBJECT);
	put_s(o, "severity", sev);
	/* The place by name, and by what names it to the page. */
	if (p != NULL) {
		put_s(o, "place", place_name(p));
		put_s(o, "server", p->sid);
		if (p->jail[0] != '\0')
			put_s(o, "jail", p->jail);
	}
	put_s(o, "what", s);
	free(s);
	ucl_array_append(arr, o);
}

/*
 * One way followed: from `from` to `to`, a reply or not.  The places
 * passed in order into hops; how it ended into *endp; what each place
 * found into findings.  inpath: the places of the request, whose state
 * lets a reply through.
 */
static void
follow(struct tsh *t, const char *from, const char *to, bool reply,
    const bool *inpath, bool *passed, ucl_object_t *hops,
    ucl_object_t **endp, ucl_object_t *findings)
{
	ucl_object_t		*hop, *c, *end;
	const ucl_object_t	*f;
	ucl_object_iter_t	 it;
	const char		*ifn, *gw, *nh, *sev, *what;
	char			 key[2][300];
	int			 i, k;
	bool			 blocked;

	end = ucl_object_typed_new(UCL_OBJECT);
	*endp = end;
	ifn = NULL;
	/* Where it comes in: the place it is made on, else the one on its
	 * network. */
	for (i = 0; i < t->n && !flag(t->p[i].survey, "src.local"); i++)
		;
	if (reply)
		for (i = 0; i < t->n && !flag(t->p[i].survey, "dst.local"); i++)
			;
	if (i == t->n) {
		for (i = 0; i < t->n; i++)
			if ((ifn = str(t->p[i].survey, reply ? "dst.connected" :
			    "src.connected")) != NULL)
				break;
	}
	if (i == t->n) {
		put_s(end, "how", "unknown");
		put_s(end, "what", reply ? "No place of the console's has the "
		    "destination, nor a network it is on: where its reply "
		    "begins is not known" : "No place of the console's has the "
		    "source, nor a network it is on: where the packet comes in "
		    "is not known. Name the places to look at, or check that "
		    "the source is right");
		return;
	}
	for (k = 0; k < TS_HOPS; k++) {
		/* A place and the interface it comes in on, seen before: a
		 * loop. */
		snprintf(key[0], sizeof(key[0]), "%d/%s", i, ifn != NULL ? ifn :
		    "");
		for (it = NULL, f = NULL; (f = ucl_object_iterate(hops, &it,
		    true)) != NULL; )
			if (strcmp(str(f, "key") != NULL ? str(f, "key") : "",
			    key[0]) == 0)
				break;
		if (f != NULL) {
			put_s(end, "how", "loop");
			put_s(end, "what", "It comes back to a place it passed: "
			    "the routes go round");
			finding(findings, "bad", &t->p[i], "A routing "
			    "loop: the %s comes back here on %s", reply ? "reply" :
			    "packet", ifn != NULL ? ifn : "the same interface");
			return;
		}
		/* The reply from the destination back: as a reply where
		 * no state of the request's can be. */
		c = reply ? check(&t->p[i], t, to, from, ifn, !inpath[i]) :
		    check(&t->p[i], t, from, to, ifn, false);
		hop = ucl_object_typed_new(UCL_OBJECT);
		put_s(hop, "key", key[0]);
		put_s(hop, "server", t->p[i].sid);
		put_s(hop, "place", place_name(&t->p[i]));
		if (t->p[i].jail[0] != '\0')
			put_s(hop, "jail", t->p[i].jail);
		put_s(hop, "ingress", ifn);
		passed[i] = true;
		if (c == NULL) {
			put_s(hop, "error", t->p[i].error);
			ucl_array_append(hops, hop);
			put_s(end, "how", "unknown");
			put_s(end, "what", "A place on the way did not answer");
			finding(findings, "warn", &t->p[i], "It did "
			    "not answer: %s", t->p[i].error);
			return;
		}
		put_s(hop, "egress", str(c, "route.interface"));
		put(hop, "check", c);
		ucl_array_append(hops, hop);
		/* Its findings, the place's name with them.  A reply passing
		 * a place the request passed is let in by the request's
		 * state there, which its own check (as a reply, no state)
		 * cannot know: those of the firewall are the request's. */
		blocked = false;
		it = NULL;
		while ((f = ucl_object_iterate(ucl_object_lookup(c,
		    "findings"), &it, true)) != NULL) {
			sev = str(f, "severity");
			what = str(f, "what");
			if (sev == NULL || what == NULL || strcmp(sev, "ok") == 0)
				continue;
			if (reply && inpath[i] && strstr(what, "firewall") != NULL)
				continue;
			/* Of the reply, its own reply is the request: said
			 * by the request's way already. */
			if (reply && (strstr(what, "the reply") != NULL ||
			    strstr(what, "a reply") != NULL || strstr(what,
			    "Asymmetric") != NULL))
				continue;
			finding(findings, sev, &t->p[i], "%s%s",
			    reply ? "The reply: " : "", what);
			if (strcmp(sev, "bad") == 0)
				blocked = true;
		}
		if (blocked) {
			put_s(end, "how", "blocked");
			put_s(end, "place", place_name(&t->p[i]));
			put_s(end, "what", reply ? "The reply is stopped here" :
			    "It is stopped here");
			return;
		}
		if (flag(c, "dst.local")) {
			put_s(end, "how", "delivered");
			put_s(end, "place", place_name(&t->p[i]));
			put_s(end, "what", reply ? "The reply reaches the source" :
			    "It reaches the destination");
			return;
		}
		gw = str(c, "route.gateway");
		nh = gw != NULL && strncmp(gw, "link#", 5) != 0 ? gw : (reply ?
		    from : to);
		if (gw != NULL && strncmp(gw, "link#", 5) == 0)
			nh = reply ? from : to;
		/* The firewall's fwd: where it really goes. */
		if (str(c, "firewall.out.fwd") != NULL && strcmp(str(c,
		    "firewall.out.fwd"), "tablearg") != 0)
			nh = str(c, "firewall.out.fwd");
		else if (str(c, "firewall.in.fwd") != NULL && strcmp(str(c,
		    "firewall.in.fwd"), "tablearg") != 0)
			nh = str(c, "firewall.in.fwd");
		put_s(hop, "next_hop", nh);
		k = owner(t, nh, &ifn);
		if (k < 0) {
			put_s(end, "how", strcmp(nh, reply ? from : to) == 0 ?
			    "delivered" : "leaves");
			put_s(end, "place", place_name(&t->p[i]));
			if (strcmp(nh, reply ? from : to) == 0)
				put_s(end, "what", reply ? "Sent onto the "
				    "source's own network: the reply is there" :
				    "Sent onto the destination's own network: "
				    "it is there, if the destination answers");
			else {
				snprintf(key[1], sizeof(key[1]), "It leaves the "
				    "console's places by %s, to %s: what is "
				    "beyond is not seen from here",
				    str(c, "route.interface") != NULL ? str(c,
				    "route.interface") : "?", nh);
				put_s(end, "what", key[1]);
			}
			return;
		}
		i = k;
	}
	put_s(end, "how", "loop");
	put_s(end, "what", "More than 16 places: the routes go round");
}

static int
ts_run(struct kore_task *task)
{
	struct tsh		*t = (struct tsh *)task;
	ucl_object_t		*top, *hops, *back, *end, *bend, *findings;
	ucl_object_t		*places, *o, *sorted;
	const ucl_object_t	*h, *f;
	ucl_object_iter_t	 it;
	bool			 inpath[TS_PLACES], passed[TS_PLACES], none[TS_PLACES];
	char			 fwd[1024], ret[1024];
	int			 i, sev;

	top = ucl_object_typed_new(UCL_OBJECT);
	put_s(top, "src", t->src);
	put_s(top, "dst", t->dst);
	put_s(top, "proto", t->proto[0] != '\0' ? t->proto : "ip");
	if (t->port != 0)
		put(top, "port", ucl_object_fromint(t->port));
	findings = ucl_object_typed_new(UCL_ARRAY);
	places = ucl_object_typed_new(UCL_ARRAY);
	/* Every place asked once: where the ends are. */
	survey(t);
	for (i = 0; i < t->n; i++) {
		o = ucl_object_typed_new(UCL_OBJECT);
		put_s(o, "server", t->p[i].sid);
		put_s(o, "place", place_name(&t->p[i]));
		if (t->p[i].survey == NULL) {
			put_s(o, "error", t->p[i].error);
			finding(findings, "info", &t->p[i], "Not "
			    "asked: %s", t->p[i].error);
			t->p[i].survey = ucl_object_typed_new(UCL_OBJECT);
		}
		ucl_array_append(places, o);
	}
	put(top, "places", places);
	memset(inpath, 0, sizeof(inpath));
	memset(passed, 0, sizeof(passed));
	memset(none, 0, sizeof(none));
	hops = ucl_object_typed_new(UCL_ARRAY);
	follow(t, t->src, t->dst, false, none, inpath, hops, &end, findings);
	put(top, "hops", hops);
	put(top, "end", end);
	/* The reply, when the request got there. */
	if (str(end, "how") != NULL && (strcmp(str(end, "how"), "delivered") ==
	    0 || strcmp(str(end, "how"), "leaves") == 0)) {
		back = ucl_object_typed_new(UCL_ARRAY);
		follow(t, t->src, t->dst, true, inpath, passed, back, &bend,
		    findings);
		put(top, "return", back);
		put(top, "return_end", bend);
		/* Request and reply by other places: asymmetric. */
		fwd[0] = ret[0] = '\0';
		it = NULL;
		while ((h = ucl_object_iterate(hops, &it, true)) != NULL) {
			if (fwd[0] != '\0')
				strlcat(fwd, " → ", sizeof(fwd));
			strlcat(fwd, str(h, "place"), sizeof(fwd));
		}
		for (i = (int)ucl_array_size(back) - 1; i >= 0; i--) {
			h = ucl_array_find_index(back, (unsigned)i);
			if (ret[0] != '\0')
				strlcat(ret, " → ", sizeof(ret));
			strlcat(ret, str(h, "place"), sizeof(ret));
		}
		if (strcmp(fwd, ret) != 0 && ret[0] != '\0') {
			char	how[2200];

			snprintf(how, sizeof(how), "Asymmetric across the "
			    "places: the request goes %s, the reply comes back "
			    "%s (read from the source's side). A place on only "
			    "one of the ways holds no state of the other's: a "
			    "stateful firewall or uRPF there drops it", fwd,
			    ret);
			finding(findings, "warn", NULL, "%s", how);
		}
		/* A state the reply never comes by: said only of a reply
		 * whose way is known. */
		for (i = 0; i < t->n && ucl_array_size(back) > 0; i++)
			if (inpath[i] && !passed[i])
				finding(findings, "info", &t->p[i],
				    "The request passes here, the reply does "
				    "not: a state made here is never used");
	}
	/* Worst first: bad, warn, info. */
	sorted = ucl_object_typed_new(UCL_ARRAY);
	for (sev = 0; sev < 3; sev++) {
		it = NULL;
		while ((f = ucl_object_iterate(findings, &it, true)) != NULL)
			if (str(f, "severity") != NULL && strcmp(str(f,
			    "severity"), (const char *[]){ "bad", "warn",
			    "info" }[sev]) == 0)
				ucl_array_append(sorted, ucl_object_ref(
				    (ucl_object_t *)(uintptr_t)f));
	}
	ucl_object_unref(findings);
	if (ucl_array_size(sorted) == 0)
		finding(sorted, "ok", NULL, "Nothing found on the way that stops "
		    "it, nor its reply");
	put(top, "findings", sorted);
	put(top, "ok", ucl_object_frombool(true));
	t->json = (char *)ucl_object_emit(top, UCL_EMIT_JSON_COMPACT);
	ucl_object_unref(top);
	for (i = 0; i < t->n; i++)
		if (t->p[i].survey != NULL)
			ucl_object_unref(t->p[i].survey);
	return (KORE_RESULT_OK);
}

static bool
address_ok(const char *s)
{
	unsigned char	buf[16];

	return (s != NULL && (inet_pton(AF_INET, s, buf) == 1 ||
	    inet_pton(AF_INET6, s, buf) == 1));
}

int
api_troubleshoot_path(struct http_request *req)
{
	const struct server	*s;
	const ucl_object_t	*e;
	ucl_object_iter_t	 it;
	ucl_object_t		*body;
	struct tsh		*t;
	const char		*proto, *sid;
	int			 i;

	if (req->hdlr_extra != NULL) {
		t = req->hdlr_extra;
		if (kore_task_state(&t->task) != KORE_TASK_STATE_FINISHED) {
			http_request_sleep(req);
			return (KORE_RESULT_RETRY);
		}
		http_response_header(req, "content-type",
		    "application/json; charset=utf-8");
		http_response_header(req, "cache-control", "no-store");
		if (t->json != NULL)
			http_response(req, 200, t->json, strlen(t->json));
		else
			http_response(req, 500, NULL, 0);
		return (KORE_RESULT_OK);
	}
	/* It changes nothing: who may read may ask. */
	if (!guard(req, false))
		return (KORE_RESULT_OK);
	if ((body = read_json(req)) == NULL)
		return (reply_error(req, 400, "invalid", "a JSON object: src, "
		    "dst, proto, port, places"));
	proto = ucl_str(body, "proto");
	if (!address_ok(ucl_str(body, "src")) || !address_ok(ucl_str(body,
	    "dst")) || (strchr(ucl_str(body, "src"), ':') != NULL) !=
	    (strchr(ucl_str(body, "dst"), ':') != NULL)) {
		ucl_object_unref(body);
		return (reply_error(req, 400, "invalid", "src and dst are "
		    "addresses, both IPv4 or both IPv6"));
	}
	if (proto != NULL && proto[0] != '\0' && strcmp(proto, "tcp") != 0 &&
	    strcmp(proto, "udp") != 0 && strcmp(proto, "icmp") != 0 &&
	    strcmp(proto, "ip") != 0) {
		ucl_object_unref(body);
		return (reply_error(req, 400, "invalid", "proto is tcp, udp, "
		    "icmp or ip"));
	}
	t = kore_calloc(1, sizeof(*t));
	snprintf(t->src, sizeof(t->src), "%s", ucl_str(body, "src"));
	snprintf(t->dst, sizeof(t->dst), "%s", ucl_str(body, "dst"));
	snprintf(t->proto, sizeof(t->proto), "%s", proto != NULL ? proto : "");
	t->port = (uint32_t)ucl_object_toint(ucl_object_lookup(body, "port"));
	if (ucl_object_lookup(body, "places") != NULL) {
		it = NULL;
		while ((e = ucl_object_iterate(ucl_object_lookup(body,
		    "places"), &it, true)) != NULL && t->n < TS_PLACES) {
			if ((sid = ucl_str(e, "server")) == NULL ||
			    (s = server_find(sid)) == NULL)
				continue;
			snprintf(t->p[t->n].jail, sizeof(t->p[0].jail), "%s",
			    ucl_str(e, "jail") != NULL ? ucl_str(e, "jail") :
			    "");
			snprintf(t->p[t->n].sid, sizeof(t->p[0].sid), "%s",
			    s->id);
			snprintf(t->p[t->n].name, sizeof(t->p[0].name), "%s",
			    s->name);
			snprintf(t->p[t->n].uri, sizeof(t->p[0].uri), "%s",
			    s->uri);
			snprintf(t->p[t->n].peer, sizeof(t->p[0].peer), "%s",
			    s->peer_name != NULL ? s->peer_name : "");
			t->n++;
		}
	} else
		for (i = 0; (s = server_at(i)) != NULL && t->n < TS_PLACES;
		    i++) {
			snprintf(t->p[t->n].sid, sizeof(t->p[0].sid), "%s",
			    s->id);
			snprintf(t->p[t->n].name, sizeof(t->p[0].name), "%s",
			    s->name);
			snprintf(t->p[t->n].uri, sizeof(t->p[0].uri), "%s",
			    s->uri);
			snprintf(t->p[t->n].peer, sizeof(t->p[0].peer), "%s",
			    s->peer_name != NULL ? s->peer_name : "");
			t->n++;
		}
	ucl_object_unref(body);
	if (t->n == 0) {
		kore_free(t);
		return (reply_error(req, 400, "invalid", "no place to ask: the "
		    "console has no such host"));
	}
	req->hdlr_extra = t;
	kore_task_create(&t->task, ts_run);
	kore_task_bind_request(&t->task, req);
	kore_task_run(&t->task);
	return (KORE_RESULT_RETRY);
}

/* on_free: what the task made goes with the request. */
void
api_troubleshoot_free(struct http_request *req)
{
	struct tsh	*t = req->hdlr_extra;

	if (t == NULL)
		return;
	kore_task_destroy(&t->task);
	free(t->json);
	kore_free(t);
	req->hdlr_extra = NULL;
}
