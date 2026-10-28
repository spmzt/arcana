/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * A host's configuration drift: what it has otherwise than its running
 * configuration says (RFC 8342 section 5.3: intended against
 * operational).  Running and the operational datastore are read whole,
 * the state taken out of the latter, and the edit that would make the
 * one the other (cbl_dtree_diff()) is the drift: a node running has
 * that is not in effect, one that differs, and one the host has that
 * running does not, said with its origin (with-origin, section 5.3.4):
 * set by hand since (unknown), learned (DHCP, SLAAC, a neighbour), or
 * the kernel's (system).
 */

#include <sys/param.h>

#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <cblink.h>
#include <cbl_data.h>
#include <cbl_schema.h>
#include <ucl.h>

#include "console.h"
#include "ymodel.h"
#include "ytrans.h"

/* The state taken out of n and below: what running never has. */
static void
prune_state(cbl_dnode *n)
{
	cbl_dnode	*c, *next;

	for (c = cbl_dnode_first(n); c != NULL; c = next) {
		next = cbl_dnode_next(c);
		if ((cbl_dnode_schema(c)->flags & CBL_YNF_CONFIG) == 0)
			(void)cbl_dnode_remove(c);
		else
			prune_state(c);
	}
}

/* The node of tree t that c (of another tree of the schema) is. */
static const cbl_dnode *
same(const cbl_dtree *t, const cbl_dnode *c)
{
	const struct cbl_ynode	*sn = cbl_dnode_schema(c);
	const cbl_dnode		*p, *pr, *k;
	const void		*keys[16];

	p = cbl_dnode_parent(c);
	pr = p == NULL || cbl_dnode_schema(p) == NULL ? cbl_dtree_root(t) :
	    same(t, p);
	if (pr == NULL)
		return (NULL);
	switch (sn->kind) {
	case CBL_YN_LIST:
		if (sn->nkeys == 0 || sn->nkeys > nitems(keys))
			return (NULL);
		for (uint16_t i = 0; i < sn->nkeys; i++) {
			if ((k = cbl_dnode_child(c, sn->child[sn->keys[i]])) ==
			    NULL)
				return (NULL);
			keys[i] = cbl_dnode_value(k);
		}
		return (cbl_dnode_entry(pr, sn, keys));
	case CBL_YN_LEAFLIST:
		return (cbl_dnode_llentry(pr, sn, cbl_dnode_value(c)));
	default:
		return (cbl_dnode_child(pr, sn));
	}
}

/* n's origin: its annotation, or the nearest above it; "" none. */
static const char *
origin_of(const cbl_dnode *n)
{
	static const struct cbl_yannot	*an;
	const void			*v;

	if (an == NULL) {
		for (uint32_t i = 0; an == NULL && i < ymodel_schema.nmod; i++)
			if (strcmp(ymodel_schema.mod[i]->name, "ietf-origin") ==
			    0)
				an = cbl_ymodule_annot(ymodel_schema.mod[i],
				    "origin");
		if (an == NULL)
			return ("");
	}
	for (; n != NULL && cbl_dnode_schema(n) != NULL; n = cbl_dnode_parent(n))
		if ((v = cbl_dnode_meta(n, an)) != NULL) {
			const struct cbl_yident *id = cbl_yschema_ident(
			    &ymodel_schema, *(const uint64_t *)v);

			return (id != NULL ? id->name : "");
		}
	return ("");
}

/* The node of t that c is, as RFC 7951's JSON with the nodes above it;
 * NULL where t has it not. */
static ucl_object_t *
value_of(const cbl_dtree *t, const cbl_dnode *c)
{
	struct cbl_ybuf		 b = { NULL, 0, 0 };
	struct ucl_parser	*p;
	const cbl_dnode		*n;
	cbl_dtree		*sel;
	ucl_object_t		*o = NULL;
	char			*json;

	if ((n = same(t, c)) == NULL ||
	    (sel = cbl_dtree_select(t, &n, 1)) == NULL)
		return (NULL);
	if (cbl_dtree_json(sel, &b) == 0 && (json = strndup((const char *)
	    b.p, b.len)) != NULL) {
		p = ucl_parser_new(UCL_PARSER_NO_IMPLICIT_ARRAYS |
		    UCL_PARSER_DISABLE_MACRO | UCL_PARSER_NO_TIME);
		if (ucl_parser_add_string(p, json, 0))
			o = ucl_parser_get_object(p);
		ucl_parser_free(p);
		free(json);
	}
	cbl_ybuf_free(&b);
	cbl_dtree_free(sel);
	return (o);
}

static ucl_object_t *
row(const char *kind, const cbl_dnode *c, const char *origin,
    ucl_object_t *value, ucl_object_t *was)
{
	struct cbl_ybuf	 b = { NULL, 0, 0 };
	ucl_object_t	*r;

	r = ucl_object_typed_new(UCL_OBJECT);
	ucl_object_insert_key(r, ucl_object_fromstring(kind), "kind", 0, false);
	if (cbl_dnode_apipath(c, &b) == 0)
		ucl_object_insert_key(r, ucl_object_fromstring_common(
		    (const char *)b.p, b.len, UCL_STRING_RAW), "path", 0, false);
	cbl_ybuf_free(&b);
	if (origin != NULL && origin[0] != '\0')
		ucl_object_insert_key(r, ucl_object_fromstring(origin),
		    "origin", 0, false);
	if (value != NULL)
		ucl_object_insert_key(r, value, "value", 0, false);
	if (was != NULL)
		ucl_object_insert_key(r, was, "was", 0, false);
	return (r);
}

/*
 * The rows of diff d below n: what the edit from the operational
 * configuration (op) to running (run) creates is running's and not in
 * effect; what it merges differs; what it removes the host has beyond
 * running, with its origin.
 */
static void
rows(ucl_object_t *arr, const cbl_dnode *n, const cbl_dtree *op,
    const cbl_dtree *run, int depth)
{
	const cbl_dnode	*c, *o;

	if (depth > 64)
		return;
	for (c = cbl_dnode_first(n); c != NULL; c = cbl_dnode_next(c)) {
		switch (cbl_dnode_op(c)) {
		case CBL_DOP_CREATE:
			ucl_array_append(arr, row("unapplied", c, NULL,
			    value_of(run, c), NULL));
			break;
		case CBL_DOP_MERGE:
		case CBL_DOP_REPLACE:
			o = same(op, c);
			ucl_array_append(arr, row("differs", c, origin_of(o),
			    value_of(run, c), value_of(op, c)));
			break;
		case CBL_DOP_REMOVE:
		case CBL_DOP_DELETE:
			o = same(op, c);
			ucl_array_append(arr, row("extra", c, origin_of(o),
			    value_of(op, c), NULL));
			break;
		default:
			rows(arr, c, op, run, depth + 1);
		}
	}
}

int
drift_read(cbl_conn *conn, ucl_object_t **out, char *err, size_t errlen)
{
	const struct cbl_ynode	*tops[64];
	cbl_dtree		*op = NULL, *run = NULL, *d;
	uint64_t		 errsid;
	size_t			 ntop = 0;
	int			 error;

	*out = NULL;
	/* The top-level nodes that are configuration: what running has. */
	for (uint32_t i = 0; i < ymodel_schema.nmod; i++)
		for (uint32_t k = 0; k < ymodel_schema.mod[i]->ntop; k++) {
			const struct cbl_ynode *t = ymodel_schema.mod[i]->top[k];

			if ((t->kind == CBL_YN_CONTAINER || t->kind ==
			    CBL_YN_LIST) && (t->flags & CBL_YNF_CONFIG) != 0 &&
			    ntop < nitems(tops))
				tops[ntop++] = t;
		}
	if ((error = ytrans_get_tree_origin(conn, tops, ntop,
	    CBL_YDS_OPERATIONAL, true, &op, err, errlen, &errsid)) != 0 ||
	    (error = ytrans_get_tree_origin(conn, tops, ntop, CBL_YDS_RUNNING,
	    false, &run, err, errlen, &errsid)) != 0) {
		cbl_dtree_free(op);
		return (error);
	}
	prune_state(cbl_dtree_root(op));
	if ((d = cbl_dtree_diff(op, run)) == NULL) {
		error = errno != 0 ? errno : ENOMEM;
		snprintf(err, errlen, "%s", strerror(error));
		cbl_dtree_free(op);
		cbl_dtree_free(run);
		return (error);
	}
	*out = ucl_object_typed_new(UCL_ARRAY);
	rows(*out, cbl_dtree_root(d), op, run, 0);
	cbl_dtree_free(d);
	cbl_dtree_free(op);
	cbl_dtree_free(run);
	return (0);
}
