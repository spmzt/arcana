/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * RFC 7951's JSON into YANG data (PLAN-SDN-YANG 4.2.1): a top-level
 * node's value, as RESTCONF's PUT carries it or the pages send it, made
 * into the tree cblink encodes as YANG-CBOR (cbl_data.h), by the
 * schema.  A member's name is the node's, its module's before it where
 * the module changes (RFC 7951 section 4); each leaf's value is read as
 * its type reads text (cbl_yvalue_parse()): a number, a 64-bit integer
 * or a decimal64 as a string, true or false, [null] for empty, base64
 * for binary, bits by their names, an identity as module:name, a union
 * by the member that reads it.  Anydata and anyxml are not taken.
 */

#include <sys/param.h>

#include <errno.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <cblink.h>
#include <cbl_schema.h>
#include <cbl_data.h>
#include <ucl.h>

#include "ymodel.h"
#include "yjsonin.h"

#define	DEPTH_MAX	64

static int
fail(char *why, size_t len, const char *fmt, ...)
{
	va_list	ap;

	va_start(ap, fmt);
	(void)vsnprintf(why, len, fmt, ap);
	va_end(ap);
	return (EINVAL);
}

/* The child of n a member's name says: "name", or "module:name". */
static const struct cbl_ynode *
child_named(const struct cbl_ynode *n, const char *key)
{
	const char	*colon, *name;
	size_t		 mlen;

	colon = strchr(key, ':');
	name = colon != NULL ? colon + 1 : key;
	mlen = colon != NULL ? (size_t)(colon - key) : 0;
	/* A mount point's (RFC 8528): the schema's top-level nodes,
	 * named with their modules. */
	if ((n->flags & CBL_YNF_MOUNT) != 0 && colon != NULL) {
		const struct cbl_yschema *sc = n->module->schema;

		for (uint32_t j = 0; j < sc->nmod; j++) {
			const struct cbl_ymodule *m = sc->mod[j];

			if (strlen(m->name) != mlen || strncmp(m->name, key,
			    mlen) != 0)
				continue;
			for (uint32_t k = 0; k < m->ntop; k++)
				if (strcmp(m->top[k]->name, name) == 0 &&
				    m->top[k]->off != CBL_YOFF_NONE)
					return (m->top[k]);
		}
		return (NULL);
	}
	for (uint32_t i = 0; i < n->nchild; i++) {
		const struct cbl_ynode *c = n->child[i];

		if (strcmp(c->name, name) != 0)
			continue;
		if (colon != NULL && (strlen(c->module->name) != mlen ||
		    strncmp(c->module->name, key, mlen) != 0))
			continue;
		/* Unqualified: of the parent's module (section 4). */
		if (colon == NULL && c->module != n->module)
			continue;
		return (c);
	}
	return (NULL);
}

/* A scalar's value of leaf (or leaf-list) sn, read as its type, in a. */
static int
value_of(const struct cbl_ynode *sn, const ucl_object_t *v, cbl_yarena *a,
    void **out, char *why, size_t len)
{
	char	 num[64];
	const char *s;
	void	*p;

	switch (ucl_object_type(v)) {
	case UCL_STRING:
		s = ucl_object_tostring(v);
		break;
	case UCL_INT:
		(void)snprintf(num, sizeof(num), "%" PRId64,
		    (int64_t)ucl_object_toint(v));
		s = num;
		break;
	case UCL_FLOAT:
		(void)snprintf(num, sizeof(num), "%.*f",
		    sn->type->fdigits > 0 ? sn->type->fdigits : 6,
		    ucl_object_todouble(v));
		s = num;
		break;
	case UCL_BOOLEAN:
		s = ucl_object_toboolean(v) ? "true" : "false";
		break;
	case UCL_NULL:
		s = "";
		break;
	case UCL_ARRAY:
		/* empty: [null], there: its member is a bool. */
		if (ucl_array_size(v) == 1 && ucl_object_type(ucl_array_find_index(
		    v, 0)) == UCL_NULL && sn->type->kind == CBL_YT_EMPTY) {
			if ((p = cbl_yarena_alloc(a, sizeof(bool))) == NULL)
				return (ENOMEM);
			*(bool *)p = true;
			*out = p;
			return (0);
		}
		return (fail(why, len, "%s: not a value", sn->name));
	default:
		return (fail(why, len, "%s: not a value", sn->name));
	}
	return (yjson_text(sn, s, a, out, why, len));
}

int
yjson_text(const struct cbl_ynode *sn, const char *s, cbl_yarena *a,
    void **out, char *why, size_t len)
{
	char	*text;
	void	*p;

	if ((text = cbl_yarena_alloc(a, strlen(s) + 1)) == NULL ||
	    (p = cbl_yarena_alloc(a, sn->type->csize > 0 ? sn->type->csize :
	    1)) == NULL)
		return (ENOMEM);
	memcpy(text, s, strlen(s) + 1);
	if (cbl_yvalue_parse(sn, sn->type, text, p, a) != 0)
		return (fail(why, len, "%s: '%s' is not a value of it", sn->name,
		    s));
	*out = p;
	return (0);
}

static int	members(cbl_dnode *, const struct cbl_ynode *,
		    const ucl_object_t *, cbl_yarena *, int, char *, size_t);

/* Node sn's value v under parent; *out, if given, the node made, a
 * list's or a leaf-list's last entry. */
static int
node(cbl_dnode *parent, const struct cbl_ynode *sn, const ucl_object_t *v,
    cbl_yarena *a, int depth, char *why, size_t len, cbl_dnode **out)
{
	const ucl_object_t	*e, *k;
	ucl_object_iter_t	 it;
	const void		**keys;
	cbl_dnode		*made;
	void			*val;
	int			 error;

	if (depth > DEPTH_MAX)
		return (fail(why, len, "%s: nested too deep", sn->name));
	switch (sn->kind) {
	case CBL_YN_CONTAINER:
		if (ucl_object_type(v) != UCL_OBJECT)
			return (fail(why, len, "%s: not an object", sn->name));
		if ((error = cbl_dnode_add(parent, sn, NULL, &made)) != 0)
			return (fail(why, len, "%s: %s", sn->name,
			    strerror(error)));
		if (out != NULL)
			*out = made;
		return (members(made, sn, v, a, depth, why, len));
	case CBL_YN_LEAF:
		if ((error = value_of(sn, v, a, &val, why, len)) != 0)
			return (error);
		if ((error = cbl_dnode_add(parent, sn, val, out)) != 0)
			return (fail(why, len, "%s: %s", sn->name,
			    strerror(error)));
		return (0);
	case CBL_YN_LEAFLIST:
		if (ucl_object_type(v) != UCL_ARRAY)
			return (fail(why, len, "%s: not an array", sn->name));
		it = NULL;
		while ((e = ucl_object_iterate(v, &it, true)) != NULL) {
			if ((error = value_of(sn, e, a, &val, why, len)) != 0)
				return (error);
			if ((error = cbl_dnode_add(parent, sn, val, out)) != 0)
				return (fail(why, len, "%s: %s", sn->name,
				    strerror(error)));
		}
		return (0);
	case CBL_YN_LIST:
		if (ucl_object_type(v) != UCL_ARRAY)
			return (fail(why, len, "%s: not an array", sn->name));
		if ((keys = cbl_yarena_alloc(a, (sn->nkeys + 1) *
		    sizeof(*keys))) == NULL)
			return (ENOMEM);
		it = NULL;
		while ((e = ucl_object_iterate(v, &it, true)) != NULL) {
			if (ucl_object_type(e) != UCL_OBJECT)
				return (fail(why, len, "%s: an entry not an "
				    "object", sn->name));
			for (uint16_t i = 0; i < sn->nkeys; i++) {
				const struct cbl_ynode *kn =
				    sn->child[sn->keys[i]];

				if ((k = ucl_object_lookup(e, kn->name)) ==
				    NULL)
					return (fail(why, len, "%s: an entry "
					    "without its key %s", sn->name,
					    kn->name));
				if ((error = value_of(kn, k, a, &val, why,
				    len)) != 0)
					return (error);
				keys[i] = val;
			}
			if ((error = cbl_dnode_add_entry(parent, sn, keys,
			    &made)) != 0)
				return (fail(why, len, "%s: %s", sn->name,
				    error == EEXIST ? "an entry twice" :
				    strerror(error)));
			if (out != NULL)
				*out = made;
			if ((error = members(made, sn, e, a, depth, why,
			    len)) != 0)
				return (error);
		}
		return (0);
	default:
		return (fail(why, len, "%s: not taken from JSON", sn->name));
	}
}

/* The members of object v, children of made (sn's): a list's keys are
 * its entry's already. */
static int
members(cbl_dnode *made, const struct cbl_ynode *sn, const ucl_object_t *v,
    cbl_yarena *a, int depth, char *why, size_t len)
{
	const struct cbl_ynode	*c;
	const ucl_object_t	*m;
	ucl_object_iter_t	 it;
	int			 error;

	it = NULL;
	while ((m = ucl_object_iterate(v, &it, true)) != NULL) {
		/* ENOENT: a member that is no node, apart from a bad value. */
		if ((c = child_named(sn, ucl_object_key(m))) == NULL) {
			(void)fail(why, len, "%s: no member %s", sn->name,
			    ucl_object_key(m));
			return (ENOENT);
		}
		if (sn->kind == CBL_YN_LIST &&
		    (c->flags & CBL_YNF_KEY) != 0)
			continue;
		if ((error = node(made, c, m, a, depth + 1, why, len,
		    NULL)) != 0)
			return (error);
	}
	return (0);
}

int
yjson_member(cbl_dtree *t, const struct cbl_ynode *n, const ucl_object_t *v,
    cbl_yarena *a, char *why, size_t len)
{

	if (why != NULL && len > 0)
		why[0] = '\0';
	return (node(cbl_dtree_root(t), n, v, a, 0, why, len, NULL));
}

int
yjson_node(cbl_dnode *parent, const struct cbl_ynode *n,
    const ucl_object_t *v, cbl_yarena *a, cbl_dnode **made, char *why,
    size_t len)
{

	if (why != NULL && len > 0)
		why[0] = '\0';
	*made = NULL;
	return (node(parent, n, v, a, 0, why, len, made));
}

/* len bytes of p after what *b holds (*cap of it), malloc'd. */
static int
grow(uint8_t **b, size_t *len, size_t *cap, const void *p, size_t n)
{
	uint8_t	*nb;
	size_t	 nc;

	if (*len + n > *cap) {
		nc = MAX(*cap * 2, *len + n + 64);
		if ((nb = realloc(*b, nc)) == NULL)
			return (ENOMEM);
		*b = nb;
		*cap = nc;
	}
	memcpy(*b + *len, p, n);
	*len += n;
	return (0);
}

/*
 * The YANG-CBOR of top-level node n in tree t, as an EDIT sends it, in
 * *pp (malloc'd, *lenp bytes): a container's or leaf's value, a list's
 * entries in an array.  ENOENT: none there.
 */
int
yjson_top_cbor(const cbl_dtree *t, const struct cbl_ynode *n, uint8_t **pp,
    size_t *lenp)
{
	struct cbl_ybuf	 e = { NULL, 0, 0 };
	const cbl_dnode	*c;
	size_t		 count = 0, len = 0, cap = 0;
	uint8_t		 head[9], *b = NULL;
	int		 error = 0;

	*pp = NULL;
	*lenp = 0;
	for (c = cbl_dnode_first(cbl_dtree_root(t)); c != NULL;
	    c = cbl_dnode_next(c))
		if (cbl_dnode_schema(c) == n)
			count++;
	if (count == 0)
		return (ENOENT);
	/* A list's, an array of them: its head, major type 4. */
	if (n->kind == CBL_YN_LIST || n->kind == CBL_YN_LEAFLIST) {
		if (count < 24) {
			head[0] = (uint8_t)(0x80 | count);
			error = grow(&b, &len, &cap, head, 1);
		} else {
			head[0] = 0x9b;
			for (int i = 0; i < 8; i++)
				head[1 + i] = (uint8_t)((uint64_t)count >>
				    (56 - 8 * i));
			error = grow(&b, &len, &cap, head, 9);
		}
	}
	for (c = cbl_dnode_first(cbl_dtree_root(t)); error == 0 && c != NULL;
	    c = cbl_dnode_next(c)) {
		if (cbl_dnode_schema(c) != n)
			continue;
		if ((error = cbl_dnode_encode(c, &e)) == 0)
			error = grow(&b, &len, &cap, e.p, e.len);
		cbl_ybuf_free(&e);
		memset(&e, 0, sizeof(e));
	}
	if (error != 0) {
		free(b);
		return (error);
	}
	*pp = b;
	*lenp = len;
	return (0);
}

int
yjson_edit(cbl_conn *conn, const struct cbl_ynode *n, const ucl_object_t *v,
    enum cbl_yds_name ds, const char *const *accept, size_t naccept,
    char *err, size_t errlen, uint64_t *errsid, char *tag, size_t taglen)
{
	cbl_dtree	*t;
	cbl_yarena	*a;
	int		 error;

	err[0] = '\0';
	*errsid = 0;
	if (tag != NULL && taglen > 0)
		tag[0] = '\0';
	if ((a = cbl_yarena_new()) == NULL ||
	    (t = cbl_dtree_new(&ymodel_schema)) == NULL) {
		cbl_yarena_free(a);
		return (ENOMEM);
	}
	if (v == NULL || (error = yjson_member(t, n, v, a, err, errlen)) == 0)
		error = yjson_edit_tree(conn, t, &n, 1, ds, accept, naccept, err,
		    errlen, errsid, tag, taglen);
	cbl_dtree_free(t);
	cbl_yarena_free(a);
	return (error);
}

int
yjson_edit_tree(cbl_conn *conn, const cbl_dtree *t,
    const struct cbl_ynode *const *tops, size_t ntop, enum cbl_yds_name ds,
    const char *const *accept, size_t naccept, char *err, size_t errlen,
    uint64_t *errsid, char *tag, size_t taglen)
{
	cbl_msg		*m = NULL, *rep = NULL;
	uint8_t		*p;
	size_t		 len;
	int		 error;

	err[0] = '\0';
	*errsid = 0;
	if (tag != NULL && taglen > 0)
		tag[0] = '\0';
	if ((error = cbl_msg_new(cbl_conn_ctx(conn), CBL_YANG_FAMILY,
	    CBL_YCMD_EDIT, 0, &m)) != 0)
		return (error);
	if ((error = cbl_msg_set_datastore(m, ds)) == 0 && naccept > 0)
		error = cbl_msg_set_accept(m, accept, naccept);
	/* Each node whole, as the tree has it; one it has none of null,
	 * deleted. */
	for (size_t i = 0; error == 0 && i < ntop; i++) {
		p = NULL;
		if ((error = yjson_top_cbor(t, tops[i], &p, &len)) == ENOENT)
			error = cbl_msg_put_ynull(m, tops[i]->sid);
		else if (error == 0)
			error = cbl_msg_put_sid_raw(m, tops[i]->sid, p, len);
		free(p);
	}
	if (error != 0) {
		cbl_msg_free(m);
		return (error);
	}
	if ((error = cbl_request(conn, m, &rep, -1)) != 0) {
		snprintf(err, errlen, "%s", rep != NULL &&
		    cbl_msg_err_str(rep) != NULL ? cbl_msg_err_str(rep) :
		    strerror(error));
		if (rep != NULL) {
			*errsid = cbl_msg_err_sid(rep);
			if (tag != NULL && cbl_msg_err_apptag(rep) != NULL)
				snprintf(tag, taglen, "%s",
				    cbl_msg_err_apptag(rep));
		}
	}
	cbl_msg_free(rep);
	return (error);
}
