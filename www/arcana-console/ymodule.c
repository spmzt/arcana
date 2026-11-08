/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * A module described for forms (PLAN-SDN-YANG 4.8.3): what the page,
 * and the Arcana app, draw a module's configuration from, so that a new
 * module needs no page or app of its own.
 *
 *	GET /yang/<module>@<revision>.json
 *
 * The module as a host's YANG library names it; the console's schema
 * tables of that module and revision (cblink-gen's, what RESTCONF checks
 * a change by), with what they leave out from ydesc.c (ydescgen at the
 * build: descriptions, the order the module writes its nodes in, the
 * typedefs' names).  A revision the console has not is 404: the host's
 * agent is newer or older than the console.  The document:
 *
 *	{ "name", "revision", "namespace", "prefix", "description",
 *	  "nodes": [ node... ],			its tops and rpcs
 *	  "augments": [ { "target": path, "nodes": [ node... ] }... ] }
 *
 *	node: "name", "module", "kind" (container, list, leaf, leaf-list,
 *	anydata, anyxml, rpc, action, input, choice, case), "path" (the
 *	schema-node path, as RFC 9595's .sid files name it; a choice's and
 *	a case's that of its data node with "/(name)"), "config",
 *	"mandatory", "presence", "keys", "min-elements", "max-elements",
 *	"ordered-by", "default", "units", "status", "description",
 *	"typedef", "type", "children" (keys first, then as the module
 *	writes them; a choice's "cases", each a case with "children").
 *	An action's output and the notifications are left out.
 *
 *	type: "base" (RFC 7950's built-in; a leafref its target's), and as
 *	it has them "range", "length" ([[min, max]...], as strings),
 *	"pattern" ([{"pattern", "ere", "invert", "error-message"}]),
 *	"fraction-digits", "enum" ([{"name", "value", "description"}]),
 *	"bits" ([{"name", "position"}]), "identities" (those an
 *	identityref takes, "module:name" with "description"), "leafref"
 *	({"path", "target", "require-instance"}), "members" (a union's).
 *
 * Read by any user signed in, or a token that reads: the modules are
 * no secret.  Made once for each module, the console's while it runs;
 * its entity-tag the console's version, so a browser asks again with
 * If-None-Match and gets 304.
 */

#include <sys/param.h>

#include <inttypes.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <cblink.h>
#include <cbl_schema.h>
#include <ucl.h>

#include "console.h"
#include "restconf.h"
#include "ydesc.h"
#include "ymodel.h"
#include "ysid.h"

#define	YM_PREFIX	"/yang/"
#define	YM_PATH		512

static pthread_mutex_t	 ym_lock = PTHREAD_MUTEX_INITIALIZER;
static char		*ym_json[256];		/* by module, made once */

static const struct ydesc *
desc_of(const char *key)
{
	size_t	lo = 0, hi = nydesc, mid;
	int	c;

	while (lo < hi) {
		mid = lo + (hi - lo) / 2;
		if ((c = strcmp(key, ydesc[mid].key)) == 0)
			return (&ydesc[mid]);
		if (c < 0)
			hi = mid;
		else
			lo = mid + 1;
	}
	return (NULL);
}

static void
put_str(ucl_object_t *o, const char *key, const char *v)
{

	if (v != NULL)
		ucl_object_insert_key(o, ucl_object_fromstring(v), key, 0,
		    true);
}

static void
put_bool(ucl_object_t *o, const char *key)
{

	ucl_object_insert_key(o, ucl_object_frombool(true), key, 0, true);
}

static void
put_desc(ucl_object_t *o, const char *key)
{
	const struct ydesc	*d;

	if ((d = desc_of(key)) != NULL && d->dsc != NULL)
		put_str(o, "description", d->dsc);
}

static const char *
base_name(int kind)
{
	static const char *const names[] = {
		[CBL_YT_BINARY] = "binary", [CBL_YT_BITS] = "bits",
		[CBL_YT_BOOLEAN] = "boolean", [CBL_YT_DECIMAL64] = "decimal64",
		[CBL_YT_EMPTY] = "empty", [CBL_YT_ENUMERATION] = "enumeration",
		[CBL_YT_IDENTITYREF] = "identityref",
		[CBL_YT_INSTANCEID] = "instance-identifier",
		[CBL_YT_INT8] = "int8", [CBL_YT_INT16] = "int16",
		[CBL_YT_INT32] = "int32", [CBL_YT_INT64] = "int64",
		[CBL_YT_STRING] = "string", [CBL_YT_UINT8] = "uint8",
		[CBL_YT_UINT16] = "uint16", [CBL_YT_UINT32] = "uint32",
		[CBL_YT_UINT64] = "uint64", [CBL_YT_UNION] = "union",
	};

	if (kind <= 0 || (size_t)kind >= nitems(names) || names[kind] == NULL)
		return ("string");
	return (names[kind]);
}

static bool
is_signed(int kind)
{

	return (kind == CBL_YT_INT8 || kind == CBL_YT_INT16 || kind ==
	    CBL_YT_INT32 || kind == CBL_YT_INT64 || kind == CBL_YT_DECIMAL64);
}

/* A bound as text: a decimal64's scaled by its fraction digits. */
static ucl_object_t *
bound(const struct cbl_ytype *t, int64_t i, uint64_t u, bool sig)
{
	char		 buf[48];
	uint64_t	 a, p = 1;

	if (!sig) {
		snprintf(buf, sizeof(buf), "%" PRIu64, u);
		return (ucl_object_fromstring(buf));
	}
	if (t->kind != CBL_YT_DECIMAL64 || t->fdigits == 0) {
		snprintf(buf, sizeof(buf), "%" PRId64, i);
		return (ucl_object_fromstring(buf));
	}
	for (int k = 0; k < t->fdigits; k++)
		p *= 10;
	a = i < 0 ? (uint64_t)0 - (uint64_t)i : (uint64_t)i;
	snprintf(buf, sizeof(buf), "%s%" PRIu64 ".%0*" PRIu64, i < 0 ? "-" :
	    "", a / p, (int)t->fdigits, a % p);
	return (ucl_object_fromstring(buf));
}

static ucl_object_t *
restrict_of(const struct cbl_ytype *t, const struct cbl_yrestrict *r,
    bool sig)
{
	ucl_object_t	*arr, *pair;

	arr = ucl_object_typed_new(UCL_ARRAY);
	for (uint16_t i = 0; i < r->n; i++) {
		pair = ucl_object_typed_new(UCL_ARRAY);
		ucl_array_append(pair, bound(t, r->v[i].min.i, r->v[i].min.u,
		    sig));
		ucl_array_append(pair, bound(t, r->v[i].max.i, r->v[i].max.u,
		    sig));
		ucl_array_append(arr, pair);
	}
	return (arr);
}

/* The identities a value of t may name: derived from each of its bases,
 * the bases themselves not. */
static ucl_object_t *
identities(const struct cbl_ytype *t)
{
	const struct cbl_yident	*b, *x;
	ucl_object_t		*arr, *o;
	char			 name[192];

	arr = ucl_object_typed_new(UCL_ARRAY);
	if (t->nbases == 0 ||
	    (b = cbl_yschema_ident(&ymodel_schema, t->bases[0])) == NULL)
		return (arr);
	for (uint32_t i = 0; i < b->nderived; i++) {
		bool	all = true;

		for (uint16_t k = 1; k < t->nbases && all; k++)
			all = cbl_yderived_from(&ymodel_schema, b->derived[i],
			    t->bases[k], false);
		if (!all || (x = cbl_yschema_ident(&ymodel_schema,
		    b->derived[i])) == NULL || x->module == NULL ||
		    (x->flags & CBL_YNF_OBSOLETE) != 0)
			continue;
		snprintf(name, sizeof(name), "%s:%s", x->module->name,
		    x->name);
		o = ucl_object_typed_new(UCL_OBJECT);
		put_str(o, "name", name);
		put_desc(o, name);
		if ((x->flags & CBL_YNF_DEPRECATED) != 0)
			put_str(o, "status", "deprecated");
		ucl_array_append(arr, o);
	}
	return (arr);
}

static ucl_object_t *
type_of(const struct cbl_ytype *t, const struct cbl_ynode *n,
    const char *path)
{
	ucl_object_t	*o, *arr, *e;
	char		 key[YM_PATH + 80], tgt[YM_PATH];
	bool		 sig = is_signed(t->kind);

	o = ucl_object_typed_new(UCL_OBJECT);
	put_str(o, "base", base_name(t->kind));
	if (t->kind == CBL_YT_DECIMAL64)
		ucl_object_insert_key(o, ucl_object_fromint(t->fdigits),
		    "fraction-digits", 0, false);
	if (t->range.n > 0)
		ucl_object_insert_key(o, restrict_of(t, &t->range, sig),
		    "range", 0, false);
	if (t->length.n > 0)
		ucl_object_insert_key(o, restrict_of(t, &t->length, false),
		    "length", 0, false);
	if (t->npatterns > 0) {
		arr = ucl_object_typed_new(UCL_ARRAY);
		for (uint16_t i = 0; i < t->npatterns; i++) {
			e = ucl_object_typed_new(UCL_OBJECT);
			put_str(e, "pattern", t->patterns[i].xsd);
			put_str(e, "ere", t->patterns[i].ere);
			if (t->patterns[i].invert)
				put_bool(e, "invert");
			put_str(e, "error-message", t->patterns[i].emsg);
			ucl_array_append(arr, e);
		}
		ucl_object_insert_key(o, arr, "pattern", 0, false);
	}
	if (t->kind == CBL_YT_ENUMERATION || t->kind == CBL_YT_BITS) {
		arr = ucl_object_typed_new(UCL_ARRAY);
		for (uint32_t i = 0; i < t->nitems; i++) {
			e = ucl_object_typed_new(UCL_OBJECT);
			put_str(e, "name", t->items[i].name);
			ucl_object_insert_key(e, ucl_object_fromint(
			    t->items[i].value), t->kind == CBL_YT_BITS ?
			    "position" : "value", 0, false);
			if (path != NULL) {
				snprintf(key, sizeof(key), "%s=%s", path,
				    t->items[i].name);
				put_desc(e, key);
			}
			ucl_array_append(arr, e);
		}
		ucl_object_insert_key(o, arr, t->kind == CBL_YT_BITS ? "bits" :
		    "enum", 0, false);
	}
	if (t->kind == CBL_YT_IDENTITYREF)
		ucl_object_insert_key(o, identities(t), "identities", 0, false);
	if ((t->flags & CBL_YTF_LEAFREF) != 0) {
		e = ucl_object_typed_new(UCL_OBJECT);
		if (t->path >= 0 && (uint32_t)t->path < ymodel_schema.nxpath)
			put_str(e, "path", ymodel_schema.xpath[t->path]);
		if (n != NULL && n->lref != NULL &&
		    ysids_node_path(n->lref, tgt, sizeof(tgt)))
			put_str(e, "target", tgt);
		ucl_object_insert_key(e, ucl_object_frombool((t->flags &
		    CBL_YTF_REQUIRE) != 0), "require-instance", 0, false);
		ucl_object_insert_key(o, e, "leafref", 0, false);
	}
	if (t->kind == CBL_YT_UNION) {
		arr = ucl_object_typed_new(UCL_ARRAY);
		for (uint16_t i = 0; i < t->nmembers; i++)
			ucl_array_append(arr, type_of(t->members[i], NULL,
			    NULL));
		ucl_object_insert_key(o, arr, "members", 0, false);
	}
	return (o);
}

static const char *
kind_name(int kind)
{

	switch (kind) {
	case CBL_YN_CONTAINER:
		return ("container");
	case CBL_YN_LEAF:
		return ("leaf");
	case CBL_YN_LEAFLIST:
		return ("leaf-list");
	case CBL_YN_LIST:
		return ("list");
	case CBL_YN_ANYDATA:
		return ("anydata");
	case CBL_YN_ANYXML:
		return ("anyxml");
	case CBL_YN_RPC:
		return ("rpc");
	case CBL_YN_ACTION:
		return ("action");
	case CBL_YN_INPUT:
		return ("input");
	default:
		return (NULL);
	}
}

static bool
shown(const struct cbl_ynode *n)
{

	return (kind_name(n->kind) != NULL &&
	    (n->flags & CBL_YNF_OBSOLETE) == 0);
}

static ucl_object_t	*node_of(const struct cbl_ynode *);

/* A node's place: keys first, then the module's order, then by SID
 * (a module ydescgen has no order of). */
struct place {
	const struct cbl_ynode	*n;
	uint32_t		 key;		/* 1 + its index among keys */
	uint32_t		 order;
};

static int
by_place(const void *a, const void *b)
{
	const struct place *x = a, *y = b;

	if ((x->key != 0) != (y->key != 0))
		return (x->key != 0 ? -1 : 1);
	if (x->key != y->key)
		return (x->key < y->key ? -1 : 1);
	if ((x->order != 0) != (y->order != 0))
		return (x->order != 0 ? -1 : 1);
	if (x->order != y->order)
		return (x->order < y->order ? -1 : 1);
	return (x->n->sid < y->n->sid ? -1 : x->n->sid > y->n->sid);
}

/* The choices met below one data node, and their cases' arrays. */
struct chgrp {
	const struct cbl_ychoice *ch;
	ucl_object_t		 *cases;	/* the choice's "cases" */
};

static ucl_object_t *
case_children(struct chgrp *g, size_t *ng, size_t maxg, ucl_object_t *top,
    const char *base, const struct cbl_ychoice *ch, uint16_t ccase)
{
	ucl_object_t	*o, *c, *into;
	char		 key[YM_PATH + 160];
	size_t		 i;

	for (i = 0; i < *ng; i++)
		if (g[i].ch == ch)
			break;
	if (i == *ng) {
		if (*ng == maxg)
			return (NULL);
		into = ch->parent == NULL ? top : case_children(g, ng, maxg,
		    top, base, ch->parent, ch->parent_case);
		if (into == NULL)
			return (NULL);
		o = ucl_object_typed_new(UCL_OBJECT);
		put_str(o, "name", ch->name);
		put_str(o, "kind", "choice");
		snprintf(key, sizeof(key), "%s/(%s)", base, ch->name);
		put_str(o, "path", key);
		if (ch->mandatory)
			put_bool(o, "mandatory");
		if (ch->dflt >= 0 && (uint16_t)ch->dflt < ch->ncases)
			put_str(o, "default", ch->cases[ch->dflt].name);
		put_desc(o, key);
		g[i].ch = ch;
		g[i].cases = ucl_object_typed_new(UCL_ARRAY);
		for (uint16_t k = 0; k < ch->ncases; k++) {
			c = ucl_object_typed_new(UCL_OBJECT);
			put_str(c, "name", ch->cases[k].name);
			put_str(c, "kind", "case");
			snprintf(key, sizeof(key), "%s/(%s)/(%s)", base,
			    ch->name, ch->cases[k].name);
			put_str(c, "path", key);
			put_desc(c, key);
			ucl_object_insert_key(c, ucl_object_typed_new(
			    UCL_ARRAY), "children", 0, false);
			ucl_array_append(g[i].cases, c);
		}
		ucl_object_insert_key(o, g[i].cases, "cases", 0, false);
		ucl_array_append(into, o);
		(*ng)++;
	}
	if ((c = (ucl_object_t *)(uintptr_t)ucl_array_find_index(g[i].cases,
	    ccase)) == NULL)
		return (NULL);
	return ((ucl_object_t *)(uintptr_t)ucl_object_lookup(c, "children"));
}

/* The children of p (the module's tops when p is NULL and m is given),
 * keys first, then in order, each in its choice's case. */
static ucl_object_t *
children_of(const struct cbl_ynode *p, const struct cbl_ymodule *m)
{
	const struct cbl_ynode	*const *v = p != NULL ? p->child : m->top;
	uint32_t		 nv = p != NULL ? p->nchild : m->ntop;
	struct place		*pl;
	struct chgrp		 g[32];
	size_t			 npl = 0, ng = 0;
	ucl_object_t		*arr, *into;
	char			 base[YM_PATH], path[YM_PATH];
	const struct ydesc	*d;

	base[0] = '\0';
	if (p != NULL && !ysids_node_path(p, base, sizeof(base)))
		base[0] = '\0';
	pl = xcalloc(nv + 1, sizeof(*pl));
	for (uint32_t i = 0; i < nv; i++) {
		if (!shown(v[i]))
			continue;
		pl[npl].n = v[i];
		if (p != NULL && p->kind == CBL_YN_LIST)
			for (uint16_t k = 0; k < p->nkeys; k++)
				if (p->child[p->keys[k]] == v[i])
					pl[npl].key = k + 1u;
		if (ysids_node_path(v[i], path, sizeof(path)) &&
		    (d = desc_of(path)) != NULL)
			pl[npl].order = d->order;
		npl++;
	}
	qsort(pl, npl, sizeof(*pl), by_place);
	arr = ucl_object_typed_new(UCL_ARRAY);
	for (size_t i = 0; i < npl; i++) {
		into = pl[i].n->choice == NULL ? arr : case_children(g, &ng,
		    nitems(g), arr, base, pl[i].n->choice, pl[i].n->ccase);
		ucl_array_append(into != NULL ? into : arr, node_of(pl[i].n));
	}
	free(pl);
	return (arr);
}

static ucl_object_t *
node_of(const struct cbl_ynode *n)
{
	const struct ydesc	*d = NULL;
	ucl_object_t		*o, *arr;
	char			 path[YM_PATH];
	bool			 op = false;

	for (const struct cbl_ynode *a = n; a != NULL; a = a->parent)
		if (a->kind == CBL_YN_RPC || a->kind == CBL_YN_ACTION)
			op = true;
	o = ucl_object_typed_new(UCL_OBJECT);
	put_str(o, "name", n->name);
	put_str(o, "module", n->module->name);
	put_str(o, "kind", kind_name(n->kind));
	if (ysids_node_path(n, path, sizeof(path))) {
		put_str(o, "path", path);
		d = desc_of(path);
	} else
		path[0] = '\0';
	if (!op && n->kind != CBL_YN_RPC && n->kind != CBL_YN_ACTION)
		ucl_object_insert_key(o, ucl_object_frombool((n->flags &
		    CBL_YNF_CONFIG) != 0), "config", 0, false);
	if ((n->flags & CBL_YNF_MANDATORY) != 0)
		put_bool(o, "mandatory");
	if ((n->flags & CBL_YNF_PRESENCE) != 0)
		put_bool(o, "presence");
	if ((n->flags & CBL_YNF_DEPRECATED) != 0)
		put_str(o, "status", "deprecated");
	if (n->kind == CBL_YN_LIST && n->nkeys > 0) {
		arr = ucl_object_typed_new(UCL_ARRAY);
		for (uint16_t k = 0; k < n->nkeys; k++)
			ucl_array_append(arr, ucl_object_fromstring(
			    n->child[n->keys[k]]->name));
		ucl_object_insert_key(o, arr, "keys", 0, false);
	}
	if (n->kind == CBL_YN_LIST || n->kind == CBL_YN_LEAFLIST) {
		if (n->min > 0)
			ucl_object_insert_key(o, ucl_object_fromint(n->min),
			    "min-elements", 0, false);
		if (n->max > 0)
			ucl_object_insert_key(o, ucl_object_fromint(n->max),
			    "max-elements", 0, false);
		if ((n->flags & CBL_YNF_USERORDER) != 0)
			put_str(o, "ordered-by", "user");
	}
	if (n->ndflt > 0) {
		if (n->kind == CBL_YN_LEAFLIST) {
			arr = ucl_object_typed_new(UCL_ARRAY);
			for (uint16_t k = 0; k < n->ndflt; k++)
				ucl_array_append(arr, ucl_object_fromstring(
				    n->dflt[k]));
			ucl_object_insert_key(o, arr, "default", 0, false);
		} else
			put_str(o, "default", n->dflt[0]);
	}
	put_str(o, "units", n->units);
	if (d != NULL) {
		put_str(o, "description", d->dsc);
		put_str(o, "typedef", d->tname);
	}
	if (n->type != NULL)
		ucl_object_insert_key(o, type_of(n->type, n, path[0] != '\0' ?
		    path : NULL), "type", 0, false);
	if ((n->kind == CBL_YN_CONTAINER || n->kind == CBL_YN_LIST ||
	    n->kind == CBL_YN_RPC || n->kind == CBL_YN_ACTION || n->kind ==
	    CBL_YN_INPUT) && (n->flags & CBL_YNF_MOUNT) == 0)
		ucl_object_insert_key(o, children_of(n, NULL), "children", 0,
		    false);
	return (o);
}

/* What m puts below other modules' nodes, by the node it augments. */
static ucl_object_t *
augments_of(const struct cbl_ymodule *m)
{
	ucl_object_t		*arr, *e, *nodes;
	char			 path[YM_PATH], prev[YM_PATH];
	const struct cbl_ynode	*n;

	arr = ucl_object_typed_new(UCL_ARRAY);
	prev[0] = '\0';
	nodes = NULL;
	for (uint32_t i = 0; i < ymodel_schema.nnode; i++) {
		n = ymodel_schema.node[i];
		if (n->module != m || n->parent == NULL ||
		    n->parent->module == m || !shown(n) ||
		    n->kind == CBL_YN_INPUT ||
		    !ysids_node_path(n->parent, path, sizeof(path)))
			continue;
		if (nodes == NULL || strcmp(path, prev) != 0) {
			e = ucl_object_typed_new(UCL_OBJECT);
			put_str(e, "target", path);
			nodes = ucl_object_typed_new(UCL_ARRAY);
			ucl_object_insert_key(e, nodes, "nodes", 0, false);
			ucl_array_append(arr, e);
			snprintf(prev, sizeof(prev), "%s", path);
		}
		ucl_array_append(nodes, node_of(n));
	}
	return (arr);
}

static char *
module_json(const struct cbl_ymodule *m)
{
	ucl_object_t		*o, *nodes;
	char			*json;

	o = ucl_object_typed_new(UCL_OBJECT);
	put_str(o, "name", m->name);
	put_str(o, "revision", m->revision);
	put_str(o, "namespace", m->ns);
	put_str(o, "prefix", m->prefix);
	put_desc(o, m->name);
	/* Its data and rpcs; its notifications and structures not. */
	nodes = children_of(NULL, m);
	ucl_object_insert_key(o, nodes, "nodes", 0, false);
	ucl_object_insert_key(o, augments_of(m), "augments", 0, false);
	json = (char *)ucl_object_emit(o, UCL_EMIT_JSON_COMPACT);
	ucl_object_unref(o);
	return (json);
}

/* The module's description, made the first time it is asked for. */
const char *
ymodule_json(const char *name, const char *revision)
{
	const struct cbl_ymodule	*m = NULL;
	uint32_t			 i;
	const char			*json;

	for (i = 0; i < ymodel_schema.nmod && i < nitems(ym_json); i++)
		if (strcmp(ymodel_schema.mod[i]->name, name) == 0) {
			m = ymodel_schema.mod[i];
			break;
		}
	if (m == NULL || strcmp(m->revision != NULL ? m->revision : "",
	    revision) != 0)
		return (NULL);
	pthread_mutex_lock(&ym_lock);
	if (ym_json[i] == NULL)
		ym_json[i] = module_json(m);
	json = ym_json[i];
	pthread_mutex_unlock(&ym_lock);
	return (json);
}

/* GET /yang/<module>@<revision>.json */
int
api_yang_module(struct http_request *req)
{
	char		 name[80], rev[16], etag[64], why[200];
	const char	*p, *at, *dot, *json, *inm;
	size_t		 n;

	if (!guard(req, false))
		return (WEB_OK);
	p = req->path + sizeof(YM_PREFIX) - 1;
	if ((at = strchr(p, '@')) == NULL || (dot = strstr(at, ".json")) ==
	    NULL || dot[5] != '\0' || (n = (size_t)(at - p)) == 0 ||
	    n >= sizeof(name) || (size_t)(dot - at - 1) >= sizeof(rev))
		return (restconf_error(req, 400, "not /yang/<module>@"
		    "<revision>.json"));
	memcpy(name, p, n);
	name[n] = '\0';
	memcpy(rev, at + 1, (size_t)(dot - at - 1));
	rev[dot - at - 1] = '\0';
	if ((json = ymodule_json(name, rev)) == NULL) {
		const char *have = NULL;

		for (uint32_t i = 0; i < ymodel_schema.nmod; i++)
			if (strcmp(ymodel_schema.mod[i]->name, name) == 0)
				have = ymodel_schema.mod[i]->revision;
		if (have != NULL)
			snprintf(why, sizeof(why), "the console has %s@%s, "
			    "not of revision %s: the host's agent and the "
			    "console are not of the same release", name, have,
			    rev);
		else
			snprintf(why, sizeof(why), "the console has no module "
			    "%s", name);
		return (restconf_error(req, 404, why));
	}
	snprintf(etag, sizeof(etag), "\"%s-%s\"", rev, ARCW_VERSION);
	http_response_header(req, "etag", etag);
	http_response_header(req, "cache-control", "private, no-cache");
	if (http_request_header(req, "if-none-match", &inm) &&
	    strcmp(inm, etag) == 0) {
		http_response(req, 304, NULL, 0);
		return (WEB_OK);
	}
	http_response_header(req, "content-type", "application/json");
	http_response_header(req, "x-content-type-options", "nosniff");
	http_response(req, 200, json, strlen(json));
	return (WEB_OK);
}
