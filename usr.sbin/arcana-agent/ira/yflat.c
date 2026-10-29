/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * A read's JSON and its module's struct, either way, by the schema
 * tables (PLAN-SDN-YANG 3.8): for the modules made of the operations
 * of arcana.yaml whose JSON was flat enough to name the nodes by its
 * keys.  The agent reads a do_*() function's JSON into an action's
 * output; the console and arcanactl write it back for the pages.
 *
 * names says what is not the plain rule, each a word, a node's name
 * and then:
 *	=key		the JSON's key is key
 *	{}		a list is an object keyed by its entries' key, each
 *			value its entry's one other node, or its others
 *	[a,b,c]		a list is an array of arrays, each its entry's
 *			nodes a, b and c in that order
 *	#		a string leaf is written as a number when it is one
 *	^		a container's nodes are its parent's keys: there when
 *			any of them is
 *	?		a list or leaf-list is left out when it is empty
 * as "node{}=key" or "node[a,b]=key".  A node's keys are written in the
 * order the module declares the nodes, its struct's.
 */

#include <sys/param.h>

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <cblink.h>
#include <cbl_schema.h>
#include <ucl.h>

#include "yflat.h"

#define	AT(p, off)	((char *)(p) + (off))
#define	CAT(p, off)	((const char *)(p) + (off))

struct yarr {
	size_t		 n;
	const void	*v;
};

/* What names says of a node. */
struct rule {
	char		 key[128];
	bool		 map;
	bool		 num;
	bool		 inl;
	bool		 opt;
	const char	*tuple;		/* "a,b,c]" */
};

static void
rule_of(const struct cbl_ynode *n, const char *const *names, struct rule *r)
{
	const char	*w, *eq;
	size_t		 nl;

	memset(r, 0, sizeof(*r));
	nl = strlen(n->name);
	(void)snprintf(r->key, sizeof(r->key), "%s", n->name);
	for (char *p = r->key; *p != '\0'; p++)
		if (*p == '-')
			*p = '_';
	for (size_t i = 0; names != NULL && names[i] != NULL; i++) {
		w = names[i];
		if (strncmp(w, n->name, nl) != 0 || (w[nl] != '\0' &&
		    strchr("={[#^?", w[nl]) == NULL))
			continue;
		for (w += nl; *w != '\0' && *w != '='; ) {
			if (strncmp(w, "{}", 2) == 0) {
				r->map = n->kind == CBL_YN_LIST;
				w += 2;
			} else if (*w == '[' && n->kind == CBL_YN_LIST) {
				r->tuple = w + 1;
				w = strchr(w, ']') != NULL ? strchr(w, ']') + 1 :
				    "";
			} else {
				r->num = r->num || *w == '#';
				r->inl = r->inl || (*w == '^' && n->kind ==
				    CBL_YN_CONTAINER);
				r->opt = r->opt || *w == '?';
				w++;
			}
		}
		if ((eq = strchr(w, '=')) != NULL)
			(void)snprintf(r->key, sizeof(r->key), "%s", eq + 1);
	}
}

/* The child of entry list n that a tuple's i'th place is; NULL: none. */
static const struct cbl_ynode *
tuple_child(const struct cbl_ynode *n, const char *tuple, size_t i)
{
	const char	*w;
	size_t		 len;

	w = tuple;
	while (i-- > 0 && (w = strpbrk(w, ",]")) != NULL && *w == ',')
		w++;
	if (w == NULL || *w == ']')
		return (NULL);
	len = strcspn(w, ",]");
	for (uint32_t k = 0; k < n->nchild; k++)
		if (strlen(n->child[k]->name) == len && strncmp(n->child[k]->name,
		    w, len) == 0)
			return (n->child[k]);
	return (NULL);
}

static size_t
tuple_len(const char *tuple)
{
	size_t	n = 1;

	for (; *tuple != '\0' && *tuple != ']'; tuple++)
		if (*tuple == ',')
			n++;
	return (n);
}

/* 10 to the power of n, for a decimal64's fraction digits. */
static double
scale(uint8_t n)
{
	double	d = 1;

	while (n-- > 0)
		d *= 10;
	return (d);
}

static bool
is_datetime(const struct cbl_ytype *t)
{
	const char	*x;

	/* yang:date-and-time, by its pattern: a date, T and a time. */
	if (t->kind != CBL_YT_STRING || t->npatterns == 0 ||
	    (x = t->patterns[0].xsd) == NULL)
		return (false);
	return ((strncmp(x, "[0-9]{4}-", 9) == 0 || strncmp(x, "\\d{4}-",
	    7) == 0) && (strstr(x, ")T(") != NULL || strstr(x, "}T\\d") !=
	    NULL));
}

static bool
is_signed(uint8_t kind)
{

	return (kind == CBL_YT_INT8 || kind == CBL_YT_INT16 ||
	    kind == CBL_YT_INT32 || kind == CBL_YT_INT64 ||
	    kind == CBL_YT_DECIMAL64 || kind == CBL_YT_ENUMERATION);
}

static void
int_put(void *p, uint32_t size, int64_t v)
{
	int8_t	i8;
	int16_t	i16;
	int32_t	i32;

	switch (size) {
	case 1:
		i8 = (int8_t)v;
		memcpy(p, &i8, 1);
		break;
	case 2:
		i16 = (int16_t)v;
		memcpy(p, &i16, 2);
		break;
	case 4:
		i32 = (int32_t)v;
		memcpy(p, &i32, 4);
		break;
	default:
		memcpy(p, &v, 8);
		break;
	}
}

static int64_t
int_get(const void *p, uint32_t size, bool sgn)
{
	int8_t		i8;
	int16_t		i16;
	int32_t		i32;
	int64_t		i64;

	switch (size) {
	case 1:
		memcpy(&i8, p, 1);
		return (sgn ? i8 : (uint8_t)i8);
	case 2:
		memcpy(&i16, p, 2);
		return (sgn ? i16 : (uint16_t)i16);
	case 4:
		memcpy(&i32, p, 4);
		return (sgn ? i32 : (uint32_t)i32);
	default:
		memcpy(&i64, p, 8);
		return (i64);
	}
}

static const char *
adup(cbl_yarena *a, const char *s)
{
	char	*d;

	if (s == NULL || (d = cbl_yarena_alloc(a, strlen(s) + 1)) == NULL)
		return (NULL);
	memcpy(d, s, strlen(s) + 1);
	return (d);
}

/* One value of type t from v into dst; false: none to put. */
static bool
value_in(const struct cbl_ytype *t, const ucl_object_t *v, void *dst,
    cbl_yarena *a)
{
	const char	*s;
	char		 buf[32];
	struct tm	 tm;
	time_t		 tt;
	int64_t		 n;
	double		 d;

	switch (t->kind) {
	case CBL_YT_STRING:
		if (ucl_object_type(v) == UCL_NULL || ucl_object_type(v) ==
		    UCL_OBJECT || ucl_object_type(v) == UCL_ARRAY)
			return (false);
		if (is_datetime(t) && (ucl_object_type(v) == UCL_INT ||
		    ucl_object_type(v) == UCL_FLOAT)) {
			tt = (time_t)ucl_object_toint(v);
			if (gmtime_r(&tt, &tm) == NULL || strftime(buf,
			    sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", &tm) == 0)
				return (false);
			s = buf;
		} else
			s = ucl_object_tostring_forced(v);
		if ((s = adup(a, s)) == NULL)
			return (false);
		memcpy(dst, &s, sizeof(s));
		return (true);
	case CBL_YT_BOOLEAN:
		if (ucl_object_type(v) != UCL_BOOLEAN)
			return (false);
		*(bool *)dst = ucl_object_toboolean(v);
		return (true);
	case CBL_YT_ENUMERATION:
		if ((s = ucl_object_tostring(v)) == NULL)
			return (false);
		for (uint32_t i = 0; i < t->nitems; i++)
			if (strcmp(t->items[i].name, s) == 0) {
				int_put(dst, t->csize, t->items[i].value);
				return (true);
			}
		return (false);
	case CBL_YT_DECIMAL64:
		if (!ucl_object_todouble_safe(v, &d))
			return (false);
		d *= scale(t->fdigits);
		int_put(dst, 8, (int64_t)(d < 0 ? d - 0.5 : d + 0.5));
		return (true);
	case CBL_YT_INT8:
	case CBL_YT_INT16:
	case CBL_YT_INT32:
	case CBL_YT_INT64:
	case CBL_YT_UINT8:
	case CBL_YT_UINT16:
	case CBL_YT_UINT32:
	case CBL_YT_UINT64:
		if (ucl_object_type(v) == UCL_INT || ucl_object_type(v) ==
		    UCL_FLOAT)
			n = ucl_object_toint(v);
		else if (ucl_object_type(v) == UCL_STRING &&
		    (s = ucl_object_tostring(v)) != NULL && *s != '\0' &&
		    strspn(s, "-0123456789") == strlen(s))
			n = strtoll(s, NULL, 10);
		else
			return (false);
		int_put(dst, t->csize, n);
		return (true);
	default:
		return (false);
	}
}

static ucl_object_t *
value_out(const struct cbl_ytype *t, const void *src, bool num)
{
	const char	*s;
	struct tm	 tm;
	int64_t		 n;

	switch (t->kind) {
	case CBL_YT_STRING:
		memcpy(&s, src, sizeof(s));
		if (s == NULL)
			return (NULL);
		if (is_datetime(t)) {
			memset(&tm, 0, sizeof(tm));
			if (strptime(s, "%Y-%m-%dT%H:%M:%S", &tm) != NULL)
				return (ucl_object_fromint((int64_t)timegm(&tm)));
		}
		if (num && *s != '\0' && strspn(s + (*s == '-'),
		    "0123456789") == strlen(s + (*s == '-')) && s[*s == '-'] !=
		    '\0')
			return (ucl_object_fromint(strtoll(s, NULL, 10)));
		return (ucl_object_fromstring(s));
	case CBL_YT_BOOLEAN:
		return (ucl_object_frombool(*(const bool *)src));
	case CBL_YT_ENUMERATION:
		n = int_get(src, t->csize, true);
		for (uint32_t i = 0; i < t->nitems; i++)
			if (t->items[i].value == n)
				return (ucl_object_fromstring(t->items[i].name));
		return (NULL);
	case CBL_YT_DECIMAL64:
		return (ucl_object_fromdouble((double)int_get(src, 8, true) /
		    scale(t->fdigits)));
	case CBL_YT_INT8:
	case CBL_YT_INT16:
	case CBL_YT_INT32:
	case CBL_YT_INT64:
	case CBL_YT_UINT8:
	case CBL_YT_UINT16:
	case CBL_YT_UINT32:
	case CBL_YT_UINT64:
		return (ucl_object_fromint(int_get(src, t->csize,
		    is_signed(t->kind))));
	default:
		return (NULL);
	}
}

/* The children of n that are data, as a struct has them. */
static bool
is_data(const struct cbl_ynode *c)
{

	return ((c->kind == CBL_YN_LEAF || c->kind == CBL_YN_LEAFLIST ||
	    c->kind == CBL_YN_CONTAINER || c->kind == CBL_YN_LIST) &&
	    c->off != CBL_YOFF_NONE);
}

/* An entry's one data node other than its key; NULL: none or more. */
static const struct cbl_ynode *
other_of(const struct cbl_ynode *n, const struct cbl_ynode *key)
{
	const struct cbl_ynode	*other;
	size_t			 nother;

	other = NULL;
	nother = 0;
	for (uint32_t i = 0; i < n->nchild; i++)
		if (is_data(n->child[i]) && n->child[i] != key) {
			other = n->child[i];
			nother++;
		}
	return (nother == 1 ? other : NULL);
}

static int	node_in(const struct cbl_ynode *, const ucl_object_t *, void *,
		    cbl_yarena *, const char *const *);

/* Whether o has a key of any of n's nodes, an inline one's too. */
static bool
any_key(const struct cbl_ynode *n, const ucl_object_t *o,
    const char *const *names)
{
	const struct cbl_ynode	*c;
	struct rule		 r;

	for (uint32_t i = 0; i < n->nchild; i++) {
		c = n->child[i];
		if (!is_data(c))
			continue;
		rule_of(c, names, &r);
		if (r.inl ? any_key(c, o, names) : ucl_object_lookup(o, r.key) !=
		    NULL)
			return (true);
	}
	return (false);
}
static int	children_in(const struct cbl_ynode *, const ucl_object_t *,
		    void *, cbl_yarena *, const char *const *);

/* A map's entry: key k, the value v its one other node, or its others. */
static int
entry_in(const struct cbl_ynode *n, const char *k, const ucl_object_t *v,
    void *e, cbl_yarena *a, const char *const *names)
{
	const struct cbl_ynode	*key, *other;
	ucl_object_t		*ko;
	int			 error;

	if (n->nkeys < 1)
		return (EINVAL);
	key = n->child[n->keys[0]];
	ko = ucl_object_fromstring(k);
	error = node_in(key, ko, e, a, names);
	ucl_object_unref(ko);
	if (error != 0)
		return (error);
	if ((other = other_of(n, key)) != NULL)
		return (node_in(other, v, e, a, names));
	return (children_in(n, v, e, a, names));
}

/* A tuple's entry: its places, the nodes the rule names. */
static int
tuple_in(const struct cbl_ynode *n, const char *tuple, const ucl_object_t *v,
    void *e, cbl_yarena *a, const char *const *names)
{
	const struct cbl_ynode	*c;
	const ucl_object_t	*x;
	ucl_object_iter_t	 it;
	size_t			 i;
	int			 error;

	it = NULL;
	for (i = 0; (x = ucl_object_iterate(v, &it, true)) != NULL; i++)
		if ((c = tuple_child(n, tuple, i)) != NULL && (error =
		    node_in(c, x, e, a, names)) != 0)
			return (error);
	return (0);
}

/* Node n, JSON value v, into its member of p. */
static int
node_in(const struct cbl_ynode *n, const ucl_object_t *v, void *p,
    cbl_yarena *a, const char *const *names)
{
	const ucl_object_t	*e;
	ucl_object_iter_t	 it;
	struct yarr		*arr;
	struct rule		 r;
	char			*vals;
	void			*sub;
	size_t			 cnt, k;
	int			 error;

	rule_of(n, names, &r);
	switch (n->kind) {
	case CBL_YN_LEAF:
		if (value_in(n->type, v, AT(p, n->off), a) &&
		    n->hoff != CBL_YOFF_NONE)
			*(bool *)AT(p, n->hoff) = true;
		return (0);
	case CBL_YN_LEAFLIST:
		if (ucl_object_type(v) != UCL_ARRAY)
			return (0);
		cnt = ucl_array_size(v);
		if ((vals = cbl_yarena_alloc(a, (cnt + 1) *
		    n->type->csize)) == NULL)
			return (ENOMEM);
		k = 0;
		it = NULL;
		while ((e = ucl_object_iterate(v, &it, true)) != NULL)
			if (value_in(n->type, e, vals + k * n->type->csize, a))
				k++;
		arr = (struct yarr *)(void *)AT(p, n->off);
		arr->n = k;
		arr->v = vals;
		return (0);
	case CBL_YN_CONTAINER:
		if (ucl_object_type(v) != UCL_OBJECT)
			return (0);
		if ((sub = cbl_yarena_alloc(a, n->size)) == NULL)
			return (ENOMEM);
		memset(sub, 0, n->size);
		if ((error = children_in(n, v, sub, a, names)) != 0)
			return (error);
		memcpy(AT(p, n->off), &sub, sizeof(sub));
		return (0);
	case CBL_YN_LIST:
		if (ucl_object_type(v) != (r.map ? UCL_OBJECT : UCL_ARRAY))
			return (0);
		cnt = 0;
		it = NULL;
		while (ucl_object_iterate(v, &it, true) != NULL)
			cnt++;
		if ((vals = cbl_yarena_alloc(a, (cnt + 1) * n->size)) == NULL)
			return (ENOMEM);
		memset(vals, 0, (cnt + 1) * n->size);
		k = 0;
		it = NULL;
		while (k < cnt && (e = ucl_object_iterate(v, &it, true)) !=
		    NULL) {
			if (r.map) {
				if (ucl_object_key(e) == NULL)
					continue;
				error = entry_in(n, ucl_object_key(e), e,
				    vals + k * n->size, a, names);
			} else if (r.tuple != NULL) {
				if (ucl_object_type(e) != UCL_ARRAY)
					continue;
				error = tuple_in(n, r.tuple, e, vals + k *
				    n->size, a, names);
			} else if (ucl_object_type(e) != UCL_OBJECT)
				continue;
			else
				error = children_in(n, e, vals + k * n->size, a,
				    names);
			if (error != 0)
				return (error);
			k++;
		}
		arr = (struct yarr *)(void *)AT(p, n->off);
		arr->n = k;
		arr->v = vals;
		return (0);
	default:
		return (0);
	}
}

static int
children_in(const struct cbl_ynode *n, const ucl_object_t *o, void *p,
    cbl_yarena *a, const char *const *names)
{
	const struct cbl_ynode	*c;
	const ucl_object_t	*v;
	struct rule		 r;
	int			 error;

	if (ucl_object_type(o) != UCL_OBJECT)
		return (0);
	for (uint32_t i = 0; i < n->nchild; i++) {
		c = n->child[i];
		if (!is_data(c))
			continue;
		rule_of(c, names, &r);
		if (r.inl) {
			if (!any_key(c, o, names))
				continue;
			v = o;
		} else if ((v = ucl_object_lookup(o, r.key)) == NULL)
			continue;
		if ((error = node_in(c, v, p, a, names)) != 0)
			return (error);
	}
	return (0);
}

int
yflat_in(const struct cbl_ynode *n, const ucl_object_t *o, void *p,
    cbl_yarena *a, const char *const *names)
{

	memset(p, 0, n->size);
	return (children_in(n, o, p, a, names));
}

static ucl_object_t	*node_out(const struct cbl_ynode *, const void *,
			    const char *const *);
static ucl_object_t	*children_out(const struct cbl_ynode *, const void *,
			    const char *const *, const struct cbl_ynode *);

/* A map's entry's value: its one other node's, or the others. */
static ucl_object_t *
entry_out(const struct cbl_ynode *n, const void *e, const char *const *names)
{
	const struct cbl_ynode	*key, *other;

	key = n->child[n->keys[0]];
	if ((other = other_of(n, key)) != NULL)
		return (node_out(other, e, names));
	return (children_out(n, e, names, key));
}

static ucl_object_t *
tuple_out(const struct cbl_ynode *n, const char *tuple, const void *e,
    const char *const *names)
{
	const struct cbl_ynode	*c;
	ucl_object_t		*o, *v;
	size_t			 len;

	o = ucl_object_typed_new(UCL_ARRAY);
	len = tuple_len(tuple);
	for (size_t i = 0; i < len; i++) {
		if ((c = tuple_child(n, tuple, i)) == NULL || (v = node_out(c,
		    e, names)) == NULL)
			v = ucl_object_typed_new(UCL_NULL);
		ucl_array_append(o, v);
	}
	return (o);
}

static ucl_object_t *
node_out(const struct cbl_ynode *n, const void *p, const char *const *names)
{
	const struct yarr	*arr;
	const void		*sub;
	const char		*k;
	ucl_object_t		*o, *v;
	struct rule		 r;

	rule_of(n, names, &r);
	switch (n->kind) {
	case CBL_YN_LEAF:
		if (n->hoff != CBL_YOFF_NONE && !*(const bool *)CAT(p,
		    n->hoff))
			return (NULL);
		return (value_out(n->type, CAT(p, n->off), r.num));
	case CBL_YN_LEAFLIST:
		arr = (const struct yarr *)(const void *)CAT(p, n->off);
		o = ucl_object_typed_new(UCL_ARRAY);
		for (size_t i = 0; i < arr->n; i++)
			if ((v = value_out(n->type, (const char *)arr->v + i *
			    n->type->csize, r.num)) != NULL)
				ucl_array_append(o, v);
		return (o);
	case CBL_YN_CONTAINER:
		memcpy(&sub, CAT(p, n->off), sizeof(sub));
		return (sub != NULL ? children_out(n, sub, names, NULL) : NULL);
	case CBL_YN_LIST:
		arr = (const struct yarr *)(const void *)CAT(p, n->off);
		o = ucl_object_typed_new(r.map ? UCL_OBJECT : UCL_ARRAY);
		for (size_t i = 0; i < arr->n; i++) {
			sub = (const char *)arr->v + i * n->size;
			if (r.tuple != NULL) {
				ucl_array_append(o, tuple_out(n, r.tuple, sub,
				    names));
				continue;
			}
			if (!r.map) {
				ucl_array_append(o, children_out(n, sub, names,
				    NULL));
				continue;
			}
			memcpy(&k, CAT(sub, n->child[n->keys[0]]->off),
			    sizeof(k));
			if (k != NULL && (v = entry_out(n, sub, names)) !=
			    NULL)
				ucl_object_insert_key(o, v, k, 0, true);
		}
		return (o);
	default:
		return (NULL);
	}
}

/* An array or an object with nothing in it. */
static bool
is_empty(const ucl_object_t *x)
{
	ucl_object_iter_t	it = NULL;

	if (ucl_object_type(x) == UCL_ARRAY)
		return (ucl_array_size(x) == 0);
	return (ucl_object_type(x) == UCL_OBJECT &&
	    ucl_object_iterate(x, &it, true) == NULL);
}

/* n's children that are data, in the order its struct has them. */
static size_t
in_order(const struct cbl_ynode *n, const struct cbl_ynode **v, size_t room)
{
	const struct cbl_ynode	*t;
	size_t			 k = 0;

	for (uint32_t i = 0; i < n->nchild && k < room; i++)
		if (is_data(n->child[i]))
			v[k++] = n->child[i];
	for (size_t i = 1; i < k; i++)
		for (size_t j = i; j > 0 && v[j - 1]->off > v[j]->off; j--) {
			t = v[j];
			v[j] = v[j - 1];
			v[j - 1] = t;
		}
	return (k);
}

static void
members_out(ucl_object_t *o, const struct cbl_ynode *n, const void *p,
    const char *const *names, const struct cbl_ynode *skip)
{
	const struct cbl_ynode	*c, *v[256];
	const void		*sub;
	ucl_object_t		*x;
	struct rule		 r;
	size_t			 k;

	k = in_order(n, v, nitems(v));
	for (size_t i = 0; i < k; i++) {
		c = v[i];
		if (c == skip)
			continue;
		rule_of(c, names, &r);
		if (r.inl) {
			memcpy(&sub, CAT(p, c->off), sizeof(sub));
			if (sub != NULL)
				members_out(o, c, sub, names, NULL);
			continue;
		}
		if ((x = node_out(c, p, names)) == NULL)
			continue;
		if (r.opt && is_empty(x)) {
			ucl_object_unref(x);
			continue;
		}
		ucl_object_insert_key(o, x, r.key, 0, true);
	}
}

static ucl_object_t *
children_out(const struct cbl_ynode *n, const void *p,
    const char *const *names, const struct cbl_ynode *skip)
{
	ucl_object_t	*o;

	o = ucl_object_typed_new(UCL_OBJECT);
	members_out(o, n, p, names, skip);
	return (o);
}

ucl_object_t *
yflat_out(const struct cbl_ynode *n, const void *p, const char *const *names)
{

	return (children_out(n, p, names, NULL));
}

const struct cbl_ynode *
yflat_find(const struct cbl_yschema *s, const char *mod, const char *path)
{
	const struct cbl_ymodule	*m;
	const struct cbl_ynode		*n, *next, *c;
	const char			*w;
	size_t				 len;

	n = NULL;
	len = strcspn(path, "/");
	for (uint32_t i = 0; i < s->nmod && n == NULL; i++) {
		m = s->mod[i];
		if (strcmp(m->name, mod) != 0)
			continue;
		for (uint32_t k = 0; k < m->ntop; k++)
			if (strlen(m->top[k]->name) == len &&
			    strncmp(m->top[k]->name, path, len) == 0)
				n = m->top[k];
	}
	for (w = path + len; n != NULL && *w == '/'; w += len) {
		w++;
		len = strcspn(w, "/");
		next = NULL;
		for (uint32_t i = 0; i < n->nchild && next == NULL; i++) {
			c = n->child[i];
			if ((strlen(c->name) == len && strncmp(c->name, w,
			    len) == 0) || (len == 5 && strncmp(w, "input",
			    5) == 0 && c->kind == CBL_YN_INPUT) || (len == 6 &&
			    strncmp(w, "output", 6) == 0 && c->kind ==
			    CBL_YN_OUTPUT))
				next = c;
		}
		n = next;
	}
	return (n);
}
