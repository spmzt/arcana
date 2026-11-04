/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * An SD-WAN edge's steering pinned by the console (PLAN-SDN-YANG
 * 3.5.1): arcana-steer's pins as running has them, one of an edge's
 * put in place or taken away, written to the candidate and committed
 * confirmed, the commit confirmed at once.  The agent refuses a pin
 * that is not of the edge's steering.
 */

#include <sys/param.h>

#include <ctype.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <cblink.h>
#include <cbl_schema.h>
#include <ucl.h>

#include "ymodel.h"
#include "yqueue.h"
#include "ysdwan.h"
#include "ytrans.h"

static const char *
str(const ucl_object_t *o, const char *key)
{
	const ucl_object_t	*v;

	v = ucl_object_lookup(o, key);
	return (v != NULL && ucl_object_type(v) == UCL_STRING ?
	    ucl_object_tostring(v) : NULL);
}

static ucl_object_t *
parse(const char *json)
{
	struct ucl_parser	*p;
	ucl_object_t		*o;

	p = ucl_parser_new(UCL_PARSER_NO_IMPLICIT_ARRAYS |
	    UCL_PARSER_DISABLE_MACRO | UCL_PARSER_NO_TIME);
	o = ucl_parser_add_string(p, json, 0) ? ucl_parser_get_object(p) :
	    NULL;
	ucl_parser_free(p);
	return (o);
}

/* A jail's name as the agent takes one: letters, digits and _ . -. */
static bool
jail_ok(const char *s)
{

	if (s[0] == '\0' || s[0] == '.' || s[0] == '-' || strstr(s, "..") !=
	    NULL || strlen(s) > 63)
		return (false);
	for (; *s != '\0'; s++)
		if (!isalnum((unsigned char)*s) && strchr("_.-", *s) == NULL)
			return (false);
	return (true);
}

/* An edge's pins of s's (jail NULL: the host's), and where they go. */
static void
pins_at(struct arcana_steer_steering *s, const char *jail, size_t **npp,
    const struct arcana_steer_pin ***vpp)
{
	*npp = NULL;
	*vpp = NULL;
	if (jail == NULL) {
		*npp = &s->pin.n;
		*vpp = &s->pin.v;
		return;
	}
	for (size_t i = 0; i < s->jail.n; i++)
		if (strcmp(s->jail.v[i].name, jail) == 0) {
			struct arcana_steer_steering_jail *j = (void *)(uintptr_t)
			    &s->jail.v[i];

			*npp = &j->pin.n;
			*vpp = &j->pin.v;
			return;
		}
}

int
ysdwan_pin(cbl_conn *conn, const char *json, char *err, size_t errlen,
    char *tag, size_t taglen)
{
	struct arcana_steer_steering_jail	*jv;
	struct arcana_steer_steering		 s;
	struct arcana_steer_pin			*pv;
	const struct arcana_steer_pin		**vp;
	const struct cbl_ynode			*n;
	struct arcana_steer			 d;
	ucl_object_t				*in;
	const char				*jail, *table, *prefix, *cand;
	cbl_yarena				*a;
	size_t					*np, k, m;
	char					 tok[33];
	int					 error;

	err[0] = tag[0] = '\0';
	if ((n = yq_top("arcana-steer", "steering")) == NULL) {
		snprintf(err, errlen, "arcana-steer is not in the tables");
		return (ENOENT);
	}
	if ((in = parse(json)) == NULL || (table = str(in, "table")) == NULL ||
	    (prefix = str(in, "prefix")) == NULL) {
		if (in != NULL)
			ucl_object_unref(in);
		snprintf(err, errlen, "a pin is a table, a prefix and a "
		    "candidate (none: the pin cleared), of an edge (jail)");
		return (EINVAL);
	}
	jail = str(in, "jail") != NULL && str(in, "jail")[0] != '\0' ?
	    str(in, "jail") : NULL;
	cand = str(in, "candidate");
	if (jail != NULL && !jail_ok(jail)) {
		ucl_object_unref(in);
		snprintf(err, errlen, "invalid jail name");
		return (EINVAL);
	}
	if ((a = cbl_yarena_new()) == NULL) {
		ucl_object_unref(in);
		return (ENOMEM);
	}
	/* Running's pins, that edge's with this one in place of its own. */
	memset(&d, 0, sizeof(d));
	if ((error = yq_get(conn, n, CBL_YDS_RUNNING, &d, a, err, errlen)) !=
	    0)
		goto out;
	memset(&s, 0, sizeof(s));
	if (d.steering != NULL) {
		s.pin = d.steering->pin;
		s.jail = d.steering->jail;
	}
	if (jail != NULL) {
		pins_at(&s, jail, &np, &vp);
		if (np == NULL) {
			if ((jv = cbl_yarena_alloc(a, (s.jail.n + 1) *
			    sizeof(*jv))) == NULL) {
				error = ENOMEM;
				goto out;
			}
			if (s.jail.n > 0)
				memcpy(jv, s.jail.v, s.jail.n * sizeof(*jv));
			memset(&jv[s.jail.n], 0, sizeof(*jv));
			jv[s.jail.n].name = jail;
			s.jail.v = jv;
			s.jail.n++;
		}
	}
	pins_at(&s, jail, &np, &vp);
	if ((pv = cbl_yarena_alloc(a, (*np + 1) * sizeof(*pv))) == NULL) {
		error = ENOMEM;
		goto out;
	}
	for (k = m = 0; k < *np; k++)
		if (strcmp((*vp)[k].table, table) != 0 || strcmp((*vp)[k].prefix,
		    prefix) != 0)
			pv[m++] = (*vp)[k];
	if (cand != NULL && cand[0] != '\0') {
		pv[m].table = table;
		pv[m].prefix = prefix;
		pv[m].candidate = cand;
		m++;
	}
	*np = m;
	*vp = pv;
	/* A jail's edge without pins: its entry gone. */
	if (jail != NULL && m == 0) {
		if ((jv = cbl_yarena_alloc(a, (s.jail.n + 1) * sizeof(*jv))) ==
		    NULL) {
			error = ENOMEM;
			goto out;
		}
		for (k = m = 0; k < s.jail.n; k++)
			if (strcmp(s.jail.v[k].name, jail) != 0)
				jv[m++] = s.jail.v[k];
		s.jail.v = jv;
		s.jail.n = m;
	}
	d.steering = &s;
	error = ytrans_commit(conn, n, &d, NULL, 0, 0, tok, sizeof(tok), err,
	    errlen, tag, taglen);
out:
	cbl_yarena_free(a);
	ucl_object_unref(in);
	return (error);
}
