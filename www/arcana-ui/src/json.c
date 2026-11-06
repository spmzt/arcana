/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * JSON with libucl, the same library the console and arcana-agent use,
 * compiled here from the base system's sources.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "app.h"

ucl_object_t *
json_parse(const char *s)
{
	struct ucl_parser	*p;
	ucl_object_t		*o;

	if (s == NULL || *s == '\0')
		return (NULL);
	p = ucl_parser_new(UCL_PARSER_NO_IMPLICIT_ARRAYS |
	    UCL_PARSER_DISABLE_MACRO | UCL_PARSER_NO_TIME);
	o = NULL;
	if (ucl_parser_add_string(p, s, 0))
		o = ucl_parser_get_object(p);
	ucl_parser_free(p);
	return (o);
}

/* "a.b.0.c" */
const ucl_object_t *
jget(const ucl_object_t *o, const char *path)
{

	if (o == NULL)
		return (NULL);
	return (ucl_object_lookup_path(o, path));
}

/* A string, or NULL for anything else (null included). */
const char *
jstr(const ucl_object_t *o, const char *path)
{
	const ucl_object_t	*v;

	if ((v = jget(o, path)) == NULL || ucl_object_type(v) != UCL_STRING)
		return (NULL);
	return (ucl_object_tostring(v));
}

int64_t
jint(const ucl_object_t *o, const char *path, int64_t def)
{
	const ucl_object_t	*v;
	const char		*s;
	char			*end;
	int64_t			 i;

	if ((v = jget(o, path)) == NULL)
		return (def);
	/* RFC 7951's 64-bit integers are strings. */
	if (ucl_object_type(v) == UCL_STRING) {
		s = ucl_object_tostring(v);
		i = strtoll(s, &end, 10);
		return (s[0] != '\0' && *end == '\0' ? i : def);
	}
	if (!ucl_object_toint_safe(v, &i))
		return (def);
	return (i);
}

double
jnum(const ucl_object_t *o, const char *path, double def)
{
	const ucl_object_t	*v;
	const char		*s;
	char			*end;
	double			 d;

	if ((v = jget(o, path)) == NULL)
		return (def);
	/* RFC 7951's 64-bit integers and decimal64 are strings. */
	if (ucl_object_type(v) == UCL_STRING) {
		s = ucl_object_tostring(v);
		d = strtod(s, &end);
		return (s[0] != '\0' && *end == '\0' ? d : def);
	}
	if (!ucl_object_todouble_safe(v, &d))
		return (def);
	return (d);
}

bool
jbool(const ucl_object_t *o, const char *path)
{
	const ucl_object_t	*v;

	return ((v = jget(o, path)) != NULL &&
	    ucl_object_type(v) == UCL_BOOLEAN && ucl_object_toboolean(v));
}

/*
 * A YANG node's members as a screen names them: map is pairs of a
 * path in o ("state.run-state") and the name it gets, NULL ended; the
 * members it does not name are left out.
 */
ucl_object_t *
jmap(const ucl_object_t *o, const char *const *map)
{
	const ucl_object_t	*v;
	ucl_object_t		*r;

	r = ucl_object_typed_new(UCL_OBJECT);
	for (; map[0] != NULL; map += 2)
		if ((v = jget(o, map[0])) != NULL)
			ucl_object_insert_key(r, ucl_object_copy(v), map[1], 0,
			    true);
	return (r);
}

/* The same of each entry of a list, as an array. */
ucl_object_t *
jmap_each(const ucl_object_t *list, const char *const *map)
{
	const ucl_object_t	*e;
	ucl_object_t		*r;
	ucl_object_iter_t	 it = NULL;

	r = ucl_object_typed_new(UCL_ARRAY);
	while ((e = ucl_object_iterate(list, &it, true)) != NULL)
		ucl_array_append(r, jmap(e, map));
	return (r);
}

/*
 * A read's YANG JSON with the names a screen reads it by: each member's
 * - as _, but where names (NULL ended) says otherwise of a node's name:
 *	node=key	its key is key
 *	node{k}		a list as an object keyed by its entries' k, each
 *			value its entry's one other node, or its others
 *	node[a,b]	a list as an array of arrays of a's and b's values
 *	node^		a container's members are its parent's
 *	node#		a string leaf a number where it is one
 *	node?		left out when empty (as RESTCONF leaves it out)
 * as "node{k}=key".
 */
static const char *
jflat_rule(const char *const *names, const char *node, char *key, size_t
    klen, char *list, size_t llen, char *how)
{
	const char	*r, *p;
	size_t		 n;

	*how = '\0';
	list[0] = '\0';
	snprintf(key, klen, "%s", node);
	for (p = key; (p = strchr(p, '-')) != NULL; p++)
		key[p - key] = '_';
	for (; names != NULL && *names != NULL; names++) {
		r = *names;
		n = strcspn(r, "{[^=#?");
		if (strlen(node) != n || strncmp(node, r, n) != 0)
			continue;
		r += n;
		/* ? says what RESTCONF does anyway: nothing to do. */
		if (*r == '?')
			r++;
		if (*r == '{' || *r == '[') {
			*how = *r;
			n = strcspn(r + 1, "}]");
			snprintf(list, llen, "%.*s", (int)n, r + 1);
			r += n + 2;
		}
		if (*r == '^' || *r == '#')
			*how = *r++;
		if (*r == '=')
			snprintf(key, klen, "%s", r + 1);
		return (*names);
	}
	return (NULL);
}

static ucl_object_t *jflat_v(const ucl_object_t *, const char *const *);

/* A number written as a string (RFC 7951's 64-bit and decimal64
 * leaves), as a number; NULL where it is none. */
ucl_object_t *
jnumber(const char *s)
{
	char	*end;
	double	 d;
	int64_t	 i;

	if (s == NULL || s[0] == '\0')
		return (NULL);
	i = strtoll(s, &end, 10);
	if (*end == '\0')
		return (ucl_object_fromint(i));
	d = strtod(s, &end);
	if (*end == '\0')
		return (ucl_object_fromdouble(d));
	return (NULL);
}

/* The members of o into r, flattened. */
static void
jflat_into(ucl_object_t *r, const ucl_object_t *o, const char *const *names)
{
	const ucl_object_t	*v, *e, *m;
	ucl_object_t		*x, *t;
	ucl_object_iter_t	 it = NULL, eit, mit;
	const char		*node, *c;
	char			 key[128], list[128], how, *w, *ws;
	size_t			 others;

	while ((v = ucl_object_iterate(o, &it, true)) != NULL) {
		node = ucl_object_key(v);
		if ((c = strchr(node, ':')) != NULL)
			node = c + 1;
		jflat_rule(names, node, key, sizeof(key), list, sizeof(list),
		    &how);
		if (how == '^' && ucl_object_type(v) == UCL_OBJECT) {
			jflat_into(r, v, names);
			continue;
		}
		if (how == '{') {
			x = ucl_object_typed_new(UCL_OBJECT);
			eit = NULL;
			while ((e = ucl_object_iterate(v, &eit, true)) != NULL) {
				if ((m = ucl_object_lookup(e, list)) == NULL)
					continue;
				t = ucl_object_typed_new(UCL_OBJECT);
				jflat_into(t, e, names);
				ucl_object_delete_key(t, list);
				others = t->len;
				mit = NULL;
				if (others == 1 && (m = ucl_object_iterate(t, &mit,
				    true)) != NULL) {
					ucl_object_insert_key(x, ucl_object_copy(m),
					    ucl_object_tostring_forced(ucl_object_lookup(
					    e, list)), 0, true);
					ucl_object_unref(t);
				} else
					ucl_object_insert_key(x, t,
					    ucl_object_tostring_forced(ucl_object_lookup(
					    e, list)), 0, true);
			}
		} else if (how == '[') {
			x = ucl_object_typed_new(UCL_ARRAY);
			eit = NULL;
			while ((e = ucl_object_iterate(v, &eit, true)) != NULL) {
				t = ucl_object_typed_new(UCL_ARRAY);
				if ((ws = strdup(list)) == NULL)
					abort();
				for (c = ws; (w = strsep(&ws, ",")) != NULL;)
					ucl_array_append(t, ucl_object_lookup(e,
					    w) != NULL ? ucl_object_copy(
					    ucl_object_lookup(e, w)) :
					    ucl_object_typed_new(UCL_NULL));
				free((void *)(uintptr_t)c);
				ucl_array_append(x, t);
			}
		} else if (how == '#' && ucl_object_type(v) == UCL_STRING &&
		    (x = jnumber(ucl_object_tostring(v))) != NULL)
			;
		else
			x = jflat_v(v, names);
		ucl_object_replace_key(r, x, key, 0, true);
	}
}

static ucl_object_t *
jflat_v(const ucl_object_t *v, const char *const *names)
{
	const ucl_object_t	*e;
	ucl_object_t		*x;
	ucl_object_iter_t	 it = NULL;

	if (ucl_object_type(v) == UCL_OBJECT) {
		x = ucl_object_typed_new(UCL_OBJECT);
		jflat_into(x, v, names);
		return (x);
	}
	if (ucl_object_type(v) != UCL_ARRAY)
		return (ucl_object_copy(v));
	x = ucl_object_typed_new(UCL_ARRAY);
	while ((e = ucl_object_iterate(v, &it, true)) != NULL)
		ucl_array_append(x, jflat_v(e, names));
	return (x);
}

ucl_object_t *
jflat(const ucl_object_t *o, const char *const *names)
{

	return (jflat_v(o, names));
}

/*
 * arcana-suricata's read-rules, read-sources and read-profiling outputs
 * as the pages have them: yflat's names, the counts numbers, each
 * profiling's rules (rule_perf.log's dump, Suricata's own JSON) parsed
 * with its time.
 */
ucl_object_t *
suricata_conv(const ucl_object_t *o)
{
	static const char *const names[] = { "page-rule=rules",
	    "group=groups", "class=classes", "source=sources",
	    "section=sections", "row=rows", NULL };
	static const char *const nums[] = { "size", "cnt", "min", "max",
	    "avg", "tot", "pct", "proto", NULL };
	static const char *const dirs[] = { "running", "replay" };
	const ucl_object_t	*r;
	ucl_object_t		*f, *out, *doc;

	f = jflat(o, names);
	out = net_plain(f, nums);
	ucl_object_unref(f);
	for (size_t i = 0; i < nitems(dirs); i++) {
		r = jget(jget(out, dirs[i]), "rules");
		if (r == NULL || (doc = json_parse(jstr(r, "document"))) ==
		    NULL)
			continue;
		if (jget(r, "at") != NULL)
			ucl_object_insert_key(doc, ucl_object_copy(jget(r, "at")),
			    "at", 0, false);
		ucl_object_replace_key((ucl_object_t *)(uintptr_t)jget(out,
		    dirs[i]), doc, "rules", 0, true);
	}
	return (out);
}

/* s as a JSON string literal, quotes included; free() it. */
char *
json_quote(const char *s)
{
	ucl_object_t	*o;
	char		*q;

	o = ucl_object_fromstring(s != NULL ? s : "");
	q = (char *)ucl_object_emit(o, UCL_EMIT_JSON_COMPACT);
	ucl_object_unref(o);
	return (q);
}

/*
 * The SHA-256 of text (FIPS 180-4) as 64 hex digits in hex: what the
 * host's kept files are told apart by, a change made from one refused
 * when the file is another by then.
 */
void
sha256_hex(const char *text, char hex[65])
{
	static const uint32_t	k[64] = {
	    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b,
	    0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01,
	    0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7,
	    0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
	    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152,
	    0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
	    0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
	    0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819,
	    0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08,
	    0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f,
	    0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
	    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2 };
	uint32_t	 h[8] = { 0x6a09e667, 0xbb67ae85, 0x3c6ef372,
	    0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19 };
	uint32_t	 w[64], a, b, c, d, e, f, g, hh, t1, t2;
	unsigned char	 blk[64];
	size_t		 len, i, off, n, j;
	uint64_t	 bits;

#define	ROR(x, r)	(((x) >> (r)) | ((x) << (32 - (r))))
	len = text != NULL ? strlen(text) : 0;
	bits = (uint64_t)len * 8;
	/* The text, a 1 bit, zeros, and its length: whole blocks. */
	n = (len + 9 + 63) / 64;
	for (i = 0; i < n; i++) {
		for (j = 0; j < 64; j++) {
			off = i * 64 + j;
			blk[j] = off < len ? (unsigned char)text[off] : off ==
			    len ? 0x80 : 0;
		}
		if (i == n - 1)
			for (j = 0; j < 8; j++)
				blk[56 + j] = (unsigned char)(bits >> (56 - 8 *
				    j));
		for (j = 0; j < 16; j++)
			w[j] = (uint32_t)blk[4 * j] << 24 | (uint32_t)blk[4 *
			    j + 1] << 16 | (uint32_t)blk[4 * j + 2] << 8 |
			    blk[4 * j + 3];
		for (j = 16; j < 64; j++)
			w[j] = (ROR(w[j - 2], 17) ^ ROR(w[j - 2], 19) ^
			    (w[j - 2] >> 10)) + w[j - 7] + (ROR(w[j - 15], 7) ^
			    ROR(w[j - 15], 18) ^ (w[j - 15] >> 3)) + w[j - 16];
		a = h[0];
		b = h[1];
		c = h[2];
		d = h[3];
		e = h[4];
		f = h[5];
		g = h[6];
		hh = h[7];
		for (j = 0; j < 64; j++) {
			t1 = hh + (ROR(e, 6) ^ ROR(e, 11) ^ ROR(e, 25)) +
			    ((e & f) ^ (~e & g)) + k[j] + w[j];
			t2 = (ROR(a, 2) ^ ROR(a, 13) ^ ROR(a, 22)) + ((a & b) ^
			    (a & c) ^ (b & c));
			hh = g;
			g = f;
			f = e;
			e = d + t1;
			d = c;
			c = b;
			b = a;
			a = t1 + t2;
		}
		h[0] += a;
		h[1] += b;
		h[2] += c;
		h[3] += d;
		h[4] += e;
		h[5] += f;
		h[6] += g;
		h[7] += hh;
	}
#undef	ROR
	for (i = 0; i < 8; i++)
		snprintf(hex + 8 * i, 65 - 8 * i, "%08x", h[i]);
}
