/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * The page's reader of YANG-CBOR (RFC 9254), as the console passes a
 * host's through for application/yang-data+cbor (PLAN-SDN-YANG 4.1.10):
 * its keys SIDs, named by the host's .sid files (RFC 9595's JSON, each
 * {"ietf-sid-file:sid-file": ...}), made the shape of RFC 7951's JSON.
 * A member is "module:name" at the top, across modules and below a
 * mount point (an absolute SID, tag 47), else "name".  A value is what
 * CBOR's own kind says, the types being the schema's: an integer a
 * number (past 2^53, a string), a text string a string, a byte string
 * base64, true and false, null [null]; tag 4's decimal a string, tag
 * 43's bits and 44's enum their names, tag 45's identity its
 * "module:name", tag 46's instance-identifier its node's path; tag
 * 109's annotations RFC 7952's "@" members.  An enumeration sent as its
 * value stays a number: the page knows its names from the schema.
 *
 * Built natively too, for the console's test of the pass-through.
 */

#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <ucl.h>

#define	DEPTH_MAX	64

struct sitem {
	uint64_t	 sid;
	const char	*id;
	const char	*module;	/* the file's */
	const char	*name;		/* the last name */
	char		 nmod[96];	/* its module */
	int		 ns;		/* 1 identity, 3 data, 4 annotation */
};

struct rd {
	const uint8_t	*p;
	const uint8_t	*end;
	struct sitem	*v;
	size_t		 n;
	char		*why;
	size_t		 whylen;
};

ucl_object_t	*ycbor_json(const void *, size_t, const ucl_object_t *,
		    char *, size_t);

static int
by_sid(const void *a, const void *b)
{
	const struct sitem *x = a, *y = b;

	return (x->sid < y->sid ? -1 : x->sid > y->sid);
}

static const struct sitem *
item(const struct rd *r, uint64_t sid)
{
	struct sitem	key;

	key.sid = sid;
	return (bsearch(&key, r->v, r->n, sizeof(*r->v), by_sid));
}

static bool
bad(struct rd *r, const char *what)
{

	if (r->why != NULL && r->whylen > 0)
		snprintf(r->why, r->whylen, "%s", what);
	return (false);
}

/* An item's head: its major type and argument. */
static bool
head(struct rd *r, int *major, uint64_t *arg)
{
	unsigned	ai;
	size_t		k;

	if (r->p >= r->end)
		return (bad(r, "the CBOR ends early"));
	*major = r->p[0] >> 5;
	ai = r->p[0] & 0x1f;
	r->p++;
	if (ai < 24) {
		*arg = ai;
		return (true);
	}
	if (ai > 27)
		return (bad(r, "an indefinite length"));
	k = (size_t)1 << (ai - 24);
	if ((size_t)(r->end - r->p) < k)
		return (bad(r, "the CBOR ends early"));
	for (*arg = 0; k > 0; k--)
		*arg = *arg << 8 | *r->p++;
	return (true);
}

static bool
peek(struct rd *r, int *major, uint64_t *arg)
{
	const uint8_t	*p = r->p;
	bool		 ok = head(r, major, arg);

	r->p = p;
	return (ok);
}

static char *
b64(const uint8_t *p, size_t len)
{
	static const char t[] =
	    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
	char		*s, *o;
	uint32_t	 v;

	if ((s = o = malloc(len / 3 * 4 + 5)) == NULL)
		return (NULL);
	for (size_t i = 0; i < len; i += 3) {
		v = (uint32_t)p[i] << 16 | (i + 1 < len ? (uint32_t)p[i + 1] <<
		    8 : 0) | (i + 2 < len ? p[i + 2] : 0);
		*o++ = t[v >> 18 & 63];
		*o++ = t[v >> 12 & 63];
		*o++ = i + 1 < len ? t[v >> 6 & 63] : '=';
		*o++ = i + 2 < len ? t[v & 63] : '=';
	}
	*o = '\0';
	return (s);
}

static ucl_object_t	*object(struct rd *, const struct sitem *, int);

/* A scalar's value, as its CBOR kind says. */
static ucl_object_t *
scalar(struct rd *r, int depth)
{
	const struct sitem	*it;
	ucl_object_t		*o;
	uint64_t		 arg, e, m;
	int			 major, mm;
	char			 buf[48], *s;

	if (!head(r, &major, &arg))
		return (NULL);
	switch (major) {
	case 0:
		if (arg > (UINT64_C(1) << 53)) {
			snprintf(buf, sizeof(buf), "%" PRIu64, arg);
			return (ucl_object_fromstring(buf));
		}
		return (ucl_object_fromint((int64_t)arg));
	case 1:
		if (arg >= (UINT64_C(1) << 53)) {
			snprintf(buf, sizeof(buf), "-%" PRIu64, arg + 1);
			return (ucl_object_fromstring(buf));
		}
		return (ucl_object_fromint(-1 - (int64_t)arg));
	case 2:
	case 3:
		if (arg > (uint64_t)(r->end - r->p))
			return (bad(r, "the CBOR ends early"), NULL);
		if (major == 3)
			o = ucl_object_fromlstring((const char *)r->p,
			    (size_t)arg);
		else {
			s = b64(r->p, (size_t)arg);
			o = ucl_object_fromstring(s != NULL ? s : "");
			free(s);
		}
		r->p += arg;
		return (o);
	case 6:
		switch (arg) {
		case 4:
			if (!head(r, &major, &arg) || major != 4 || arg != 2 ||
			    !head(r, &major, &e) || major != 1 || e > 17 ||
			    !head(r, &mm, &m) || mm > 1)
				return (bad(r, "a decimal not [exp, mantissa]"),
				    NULL);
			{
				char d[32];
				int n, fd = (int)e + 1, k = 0;

				n = snprintf(d, sizeof(d), "%0*" PRIu64, fd + 1,
				    mm == 1 ? m + 1 : m);
				if (mm == 1)
					buf[k++] = '-';
				for (int i = 0; i < n; i++) {
					if (i == n - fd)
						buf[k++] = '.';
					buf[k++] = d[i];
				}
				buf[k] = '\0';
			}
			return (ucl_object_fromstring(buf));
		case 43:
		case 44:
			return (scalar(r, depth + 1));
		case 45:
			if (!head(r, &major, &arg) || major != 0)
				return (bad(r, "an identity not a SID"), NULL);
			if ((it = item(r, arg)) == NULL || it->ns != 1)
				return (bad(r, "an identity's SID in no file"),
				    NULL);
			{
				char t[256];

				snprintf(t, sizeof(t), "%s:%s", it->module,
				    it->name);
				return (ucl_object_fromstring(t));
			}
		case 46:
			/* The node's path; a list's keys are the schema's. */
			if (!peek(r, &major, &arg))
				return (NULL);
			if (major == 4) {
				(void)head(r, &major, &arg);
				if (arg == 0 || !head(r, &major, &e) ||
				    major != 0)
					return (bad(r,
					    "an instance-identifier"), NULL);
				for (uint64_t i = 1; i < arg; i++)
					if ((o = scalar(r, depth + 1)) == NULL)
						return (NULL);
					else
						ucl_object_unref(o);
			} else if (!head(r, &major, &e) || major != 0)
				return (bad(r, "an instance-identifier"), NULL);
			if ((it = item(r, e)) == NULL || it->ns != 3)
				return (bad(r, "an instance-identifier's "
				    "SID in no file"), NULL);
			return (ucl_object_fromstring(it->id));
		default:
			return (bad(r, "a tag not of YANG-CBOR"), NULL);
		}
	case 7:
		if (arg == 20 || arg == 21)
			return (ucl_object_frombool(arg == 21));
		if (arg == 22) {
			o = ucl_object_typed_new(UCL_ARRAY);
			ucl_array_append(o, ucl_object_typed_new(UCL_NULL));
			return (o);
		}
		break;
	}
	return (bad(r, "a value of no YANG type"), NULL);
}

/* Tag 109's metadata, keys deltas from base: an object. */
static ucl_object_t *
meta(struct rd *r, uint64_t base, int depth)
{
	const struct sitem	*an;
	ucl_object_t		*o, *v;
	uint64_t		 n, d;
	int			 major;
	char			 key[160];

	if (!head(r, &major, &n) || major != 5)
		return (bad(r, "metadata not a map"), NULL);
	o = ucl_object_typed_new(UCL_OBJECT);
	for (uint64_t i = 0; i < n; i++) {
		if (!head(r, &major, &d) || major > 1 || (an = item(r, major ==
		    0 ? base + d : base - 1 - d)) == NULL || an->ns != 4 ||
		    (v = scalar(r, depth + 1)) == NULL) {
			ucl_object_unref(o);
			return (bad(r, "an annotation in no file"), NULL);
		}
		snprintf(key, sizeof(key), "%s:%s", an->module, an->name);
		ucl_object_insert_key(o, v, key, 0, true);
	}
	return (o);
}

/* Tag 109 at r: its metadata read, r then at the value. */
static bool
annotated(struct rd *r, uint64_t base, ucl_object_t **m, int depth)
{
	const uint8_t	*p = r->p;
	uint64_t	 arg;
	int		 major;

	*m = NULL;
	if (!head(r, &major, &arg) || major != 6 || arg != 109 ||
	    !head(r, &major, &arg) || major != 4 || arg != 2) {
		r->p = p;
		return (true);
	}
	return ((*m = meta(r, base, depth)) != NULL);
}

/* Node it's value at r, put in parent under its name (qualified unless
 * of pmod), its annotations as "@" or "@name". */
static bool
member(struct rd *r, ucl_object_t *parent, const struct sitem *it,
    const char *pmod, int depth)
{
	ucl_object_t	*v, *m, *metas = NULL, *e;
	uint64_t	 n, arg;
	int		 major;
	bool		 any = false;
	char		 key[200];

	if (pmod == NULL || strcmp(pmod, it->nmod) != 0)
		snprintf(key, sizeof(key), "%s:%s", it->nmod, it->name);
	else
		snprintf(key, sizeof(key), "%s", it->name);
	if (!annotated(r, it->sid, &m, depth) || !peek(r, &major, &arg))
		return (false);
	if (major == 5) {
		if ((v = object(r, it, depth + 1)) == NULL)
			return (false);
		if (m != NULL)
			ucl_object_insert_key(v, m, "@", 0, false);
	} else if (major == 4) {
		(void)head(r, &major, &n);
		v = ucl_object_typed_new(UCL_ARRAY);
		for (uint64_t i = 0; i < n; i++) {
			if (!annotated(r, it->sid, &m, depth) ||
			    !peek(r, &major, &arg))
				return (false);
			if (major == 5) {
				if ((e = object(r, it, depth + 1)) == NULL)
					return (false);
				if (m != NULL)
					ucl_object_insert_key(e, m, "@", 0,
					    false);
				ucl_array_append(v, e);
				continue;
			}
			if ((e = scalar(r, depth + 1)) == NULL)
				return (false);
			ucl_array_append(v, e);
			if (metas == NULL)
				metas = ucl_object_typed_new(UCL_ARRAY);
			ucl_array_append(metas, m != NULL ? m :
			    ucl_object_typed_new(UCL_NULL));
			any |= m != NULL;
		}
		if (any) {
			char at[204];

			snprintf(at, sizeof(at), "@%s", key);
			ucl_object_insert_key(parent, metas, at, 0, true);
		} else
			ucl_object_unref(metas);
	} else {
		if ((v = scalar(r, depth + 1)) == NULL)
			return (false);
		if (m != NULL) {
			char at[204];

			snprintf(at, sizeof(at), "@%s", key);
			ucl_object_insert_key(parent, m, at, 0, true);
		}
	}
	ucl_object_insert_key(parent, v, key, 0, true);
	return (true);
}

/* A map of it's children (it NULL: the top, keys absolute). */
static ucl_object_t *
object(struct rd *r, const struct sitem *it, int depth)
{
	const struct sitem	*c;
	ucl_object_t		*o;
	uint64_t		 n, d;
	int			 major;
	bool			 abs;

	if (depth > DEPTH_MAX || !head(r, &major, &n) || major != 5)
		return (bad(r, "not a map"), NULL);
	o = ucl_object_typed_new(UCL_OBJECT);
	for (uint64_t i = 0; i < n; i++) {
		abs = false;
		if (!head(r, &major, &d))
			goto fail;
		if (major == 6 && d == 47) {
			if (!head(r, &major, &d) || major != 0)
				goto fail;
			abs = true;
		} else if (major > 1)
			goto fail;
		if (it != NULL && !abs)
			d = major == 0 ? it->sid + d : it->sid - 1 - d;
		if ((c = item(r, d)) == NULL || c->ns != 3) {
			bad(r, "a SID in none of the host's files");
			goto fail;
		}
		if (!member(r, o, c, it == NULL || abs ? NULL : it->nmod,
		    depth))
			goto fail;
	}
	return (o);
fail:
	ucl_object_unref(o);
	return (NULL);
}

/* The items of one file. */
static bool
add_file(struct rd *r, const ucl_object_t *file)
{
	const ucl_object_t	*f, *items, *e;
	ucl_object_iter_t	 it = NULL;
	const char		*mod, *ns, *id, *sid, *last, *p, *colon;
	struct sitem		*v;

	if ((f = ucl_object_lookup(file, "ietf-sid-file:sid-file")) == NULL)
		f = file;
	if ((mod = ucl_object_tostring(ucl_object_lookup(f,
	    "module-name"))) == NULL)
		return (bad(r, "a .sid file without module-name"));
	items = ucl_object_lookup(f, "item");
	while ((e = ucl_object_iterate(items, &it, true)) != NULL) {
		ns = ucl_object_tostring(ucl_object_lookup(e, "namespace"));
		id = ucl_object_tostring(ucl_object_lookup(e, "identifier"));
		sid = ucl_object_tostring_forced(ucl_object_lookup(e, "sid"));
		if (ns == NULL || id == NULL || sid == NULL)
			continue;
		if ((v = realloc(r->v, (r->n + 1) * sizeof(*v))) == NULL)
			return (bad(r, "out of memory"));
		r->v = v;
		v = &r->v[r->n];
		memset(v, 0, sizeof(*v));
		v->sid = strtoull(sid, NULL, 10);
		v->id = id;
		v->module = mod;
		v->ns = strcmp(ns, "identity") == 0 ? 1 : strcmp(ns, "data") ==
		    0 ? 3 : strcmp(ns, "annotation") == 0 ? 4 : 0;
		v->name = id;
		snprintf(v->nmod, sizeof(v->nmod), "%s", mod);
		if (v->ns == 3) {
			/* The last name, and the module said last. */
			last = id;
			for (p = id; *p != '\0'; p++) {
				if (*p != '/')
					continue;
				last = p + 1;
				colon = strchr(last, ':');
				if (colon != NULL && (strchr(last, '/') ==
				    NULL || colon < strchr(last, '/')))
					snprintf(v->nmod, sizeof(v->nmod),
					    "%.*s", (int)(colon - last), last);
			}
			colon = strchr(last, ':');
			v->name = colon != NULL ? colon + 1 : last;
		}
		r->n++;
	}
	return (true);
}

ucl_object_t *
ycbor_json(const void *cbor, size_t len, const ucl_object_t *sidfiles,
    char *why, size_t whylen)
{
	struct rd		 r = { cbor, (const uint8_t *)cbor + len, NULL,
				    0, why, whylen };
	const ucl_object_t	*f;
	ucl_object_iter_t	 it = NULL;
	ucl_object_t		*o = NULL;

	if (ucl_object_type(sidfiles) == UCL_ARRAY) {
		while ((f = ucl_object_iterate(sidfiles, &it, true)) != NULL)
			if (!add_file(&r, f))
				goto done;
	} else if (!add_file(&r, sidfiles))
		goto done;
	qsort(r.v, r.n, sizeof(*r.v), by_sid);
	if ((o = object(&r, NULL, 0)) != NULL && r.p != r.end) {
		bad(&r, "bytes after the data");
		ucl_object_unref(o);
		o = NULL;
	}
done:
	free(r.v);
	return (o);
}
