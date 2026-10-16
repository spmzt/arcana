/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Luxuria: the host's BIRD, and each vnet jail's, watched for what goes
 * wrong with its sessions, as faults (Mplify 119 Table 4, and ours):
 *
 * - bgp-neighbor, a BGP session turned on but not established: Major
 *   once it was established, Minor while it never was;
 * - ospf-neighbor, an OSPF neighbour that was Full (or 2-Way, as two
 *   routers neither of which is the designated one stay) and is no
 *   more, or is gone from the list: Major;
 * - bfd, a BFD session that was up and is down: Major;
 * - bird-instance, a BIRD that answered and answers no more: Critical.
 *
 * Each is cleared when it is well again.  Faults are events too, and so
 * reach the console's mail, its workflows' triggers and its faults.
 * What is read is what do_bird() reads for the console's tables; it is
 * read every --bird-watch seconds, 15 unless said, never with 0.
 */

#include <sys/param.h>

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include <ucl.h>

#include "agent.h"

#define	SEEN_MAX	1024

enum { K_BIRD, K_BGP, K_OSPF, K_BFD };

/* What was seen of a session: well once, and in the last round. */
static struct seen {
	char	place[64];		/* the jail, "" the host */
	int	kind;
	char	key[200];		/* the fault's object */
	bool	up;
	bool	here;
} *seen;
static int	nseen;

static struct seen *
seen_find(const char *place, int kind, const char *key)
{
	int	i;

	for (i = 0; i < nseen; i++)
		if (seen[i].kind == kind && strcmp(seen[i].key, key) == 0 &&
		    strcmp(seen[i].place, place) == 0)
			return (&seen[i]);
	if (nseen == SEEN_MAX)
		return (NULL);
	snprintf(seen[nseen].place, sizeof(seen[0].place), "%s", place);
	seen[nseen].kind = kind;
	snprintf(seen[nseen].key, sizeof(seen[0].key), "%s", key);
	seen[nseen].up = seen[nseen].here = false;
	return (&seen[nseen++]);
}

static const char *
str(const ucl_object_t *o, const char *key)
{
	const ucl_object_t	*v;

	if ((v = ucl_object_lookup(o, key)) == NULL)
		return ("");
	return (ucl_object_tostring_forced(v));
}

/* The object a fault is of: the protocol, the jail's before it. */
static void
object(char *buf, size_t len, const char *place, const char *a,
    const char *b)
{

	snprintf(buf, len, "%s%s%s%s%s", place, place[0] != '\0' ? "/" : "",
	    a, b != NULL ? "/" : "", b != NULL ? b : "");
}

static void
bgp(const char *place, const ucl_object_t *o)
{
	struct seen	*s;
	const char	*name, *st, *why;
	char		 obj[200];

	name = str(o, "name");
	object(obj, sizeof(obj), place, name, NULL);
	if ((s = seen_find(place, K_BGP, obj)) == NULL)
		return;
	st = str(o, "state");
	/* Up, or turned off by hand: no fault of the session's. */
	if (strcmp(st, "up") == 0 || strcmp(st, "down") == 0) {
		if (strcmp(st, "up") == 0)
			s->up = true;
		fault_clear("bgp-neighbor", obj, "BGP %s%s%s is %s", name,
		    place[0] != '\0' ? " in " : "", place, strcmp(st, "up") ==
		    0 ? "established" : "turned off");
		return;
	}
	why = str(o, "last-error")[0] != '\0' ? str(o, "last-error") :
	    str(o, "info");
	fault_set("bgp-neighbor", s->up ? "Major" : "Minor", obj, "bird",
	    "BGP %s%s%s to %s is %s%s%s%s", name, place[0] != '\0' ? " in " :
	    "", place, str(o, "neighbor"), str(o, "bgp-state")[0] != '\0' ?
	    str(o, "bgp-state") : st, s->up ? "" : ", never established",
	    why[0] != '\0' ? ": " : "", why);
}

static void
ospf(const char *place, const ucl_object_t *o)
{
	struct seen	*s;
	const char	*st;
	char		 obj[200], who[140];

	snprintf(who, sizeof(who), "%s@%s", str(o, "router-id"), str(o,
	    "interface"));
	object(obj, sizeof(obj), place, str(o, "proto"), who);
	if ((s = seen_find(place, K_OSPF, obj)) == NULL)
		return;
	s->here = true;
	st = str(o, "state");
	if (strncmp(st, "Full", 4) == 0 || strncmp(st, "2-Way", 5) == 0) {
		s->up = true;
		fault_clear("ospf-neighbor", obj, "OSPF neighbour %s on %s is %s",
		    str(o, "router-id"), str(o, "interface"), st);
	} else if (s->up)
		fault_set("ospf-neighbor", "Major", obj, "bird", "OSPF "
		    "neighbour %s on %s%s%s is %s", str(o, "router-id"), str(o,
		    "interface"), place[0] != '\0' ? " in " : "", place, st);
}

static void
bfd(const char *place, const ucl_object_t *o)
{
	struct seen	*s;
	const char	*st;
	char		 obj[200], who[140];

	snprintf(who, sizeof(who), "%s@%s", str(o, "address"), str(o,
	    "interface"));
	object(obj, sizeof(obj), place, str(o, "proto"), who);
	if ((s = seen_find(place, K_BFD, obj)) == NULL)
		return;
	s->here = true;
	st = str(o, "state");
	if (strcmp(st, "Up") == 0) {
		s->up = true;
		fault_clear("bfd", obj, "BFD to %s on %s is up", str(o,
		    "address"), str(o, "interface"));
	} else if (s->up && strcmp(st, "Init") != 0)
		fault_set("bfd", "Major", obj, "bird", "BFD to %s on %s%s%s is %s",
		    str(o, "address"), str(o, "interface"), place[0] != '\0' ?
		    " in " : "", place, st);
}

/* One BIRD, the host's ("") or a jail's: read, and what it says judged. */
static void
place_watch(struct work *w, const char *place)
{
	struct arc_network_rsp	 rsp;
	struct ucl_parser	*p;
	const ucl_object_t	*top, *o;
	ucl_object_iter_t	 it;
	struct seen		*s;
	int			 i;

	memset(&rsp, 0, sizeof(rsp));
	if ((s = seen_find(place, K_BIRD, "bird")) == NULL)
		return;
	if (do_bird(w, &rsp) != 0 || !rsp.ok || rsp.json == NULL) {
		if (s->up)
			fault_set("bird-instance", "Critical", place[0] != '\0' ?
			    place : "bird", "bird", "BIRD%s%s does not answer%s%s",
			    place[0] != '\0' ? " in " : "", place, rsp.error !=
			    NULL ? ": " : "", rsp.error != NULL ? rsp.error : "");
		return;
	}
	if (s->up)
		fault_clear("bird-instance", place[0] != '\0' ? place : "bird",
		    "BIRD%s%s answers again", place[0] != '\0' ? " in " : "",
		    place);
	s->up = true;
	p = ucl_parser_new(UCL_PARSER_NO_TIME);
	if (!ucl_parser_add_string(p, rsp.json, 0) || (top =
	    ucl_parser_get_object(p)) == NULL) {
		ucl_parser_free(p);
		return;
	}
	/* Who is listed this round, to find who went. */
	for (i = 0; i < nseen; i++)
		if (strcmp(seen[i].place, place) == 0)
			seen[i].here = false;
	it = NULL;
	while ((o = ucl_object_iterate(ucl_object_lookup(top, "protocols"),
	    &it, true)) != NULL)
		if (strcmp(str(o, "proto"), "BGP") == 0)
			bgp(place, o);
	it = NULL;
	while ((o = ucl_object_iterate(ucl_object_lookup(top, "ospf"), &it,
	    true)) != NULL)
		ospf(place, o);
	it = NULL;
	while ((o = ucl_object_iterate(ucl_object_lookup(top, "bfd"), &it,
	    true)) != NULL)
		bfd(place, o);
	ucl_object_unref((ucl_object_t *)(uintptr_t)top);
	ucl_parser_free(p);
	/* An OSPF neighbour that was well and is listed no more is gone;
	 * a BFD session too, with the protocol that asked for it. */
	for (i = 0; i < nseen; i++)
		if (strcmp(seen[i].place, place) == 0 && !seen[i].here &&
		    seen[i].up && (seen[i].kind == K_OSPF || seen[i].kind ==
		    K_BFD))
			fault_set(seen[i].kind == K_BFD ? "bfd" : "ospf-neighbor",
			    "Major", seen[i].key, "bird", "%s %s is gone from "
			    "BIRD's list", seen[i].kind == K_BFD ? "BFD session" :
			    "OSPF neighbour", seen[i].key);
}

static void *
watch(void *arg __unused)
{
	struct work	 w;
	struct jinfo	*list;
	const char	*e, *const *pl;
	size_t		 n, i, np, k;

	for (;;) {
		sleep((unsigned int)opts.bird_watch_s);
		work_init(&w);
		plugins_there(&w, 0, NULL, &pl, &np);
		for (k = 0; k < np; k++)
			if (strcmp(pl[k], "bird") == 0)
				break;
		if (k < np)
			place_watch(&w, "");
		list = NULL;
		n = 0;
		if (jails_running(&w, &list, &n, &e) == 0)
			for (i = 0; i < n; i++) {
				if (!list[i].vnet || list[i].dying)
					continue;
				plugins_there(&w, list[i].jid, list[i].path, &pl,
				    &np);
				for (k = 0; k < np; k++)
					if (strcmp(pl[k], "bird") == 0)
						break;
				if (k == np || scope_enter(&w, list[i].name,
				    &e) != 0)
					continue;
				place_watch(&w, list[i].name);
				(void)scope_enter(&w, NULL, &e);
			}
		work_free(&w);
	}
	return (NULL);
}

void
bird_watch_start(void)
{
	pthread_t	tid;
	int		error;

	if (opts.bird_watch_s <= 0)
		return;
	if ((seen = calloc(SEEN_MAX, sizeof(*seen))) == NULL)
		return;
	if ((error = pthread_create(&tid, NULL, watch, NULL)) != 0) {
		logmsg(LOG_WARNING, "BIRD is not watched: pthread_create: %s",
		    strerror(error));
		return;
	}
	(void)pthread_detach(tid);
}
