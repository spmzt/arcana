/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * RFC 7951's JSON and RFC 9254's YANG-CBOR, each into the other
 * (PLAN-SDN-YANG 4.2.1, 4.2.2), by a schema's SIDs as a peer numbers
 * them (ysid.c): a member's name is its item's, "module:name" at the
 * top, across modules and below a mount point, its key the delta from
 * its parent's SID (an absolute SID, tag 47, below a mount point); a
 * value is read and written as the console's tables type the node:
 *
 *	int8 to int32, uint8 to uint32	a number
 *	int64, uint64, decimal64	a string (decimal64: tag 4, [-fd, m])
 *	boolean, string			as they are
 *	empty				[null]; CBOR's null
 *	binary				base64; a byte string
 *	bits				the names set; a byte string by position
 *	enumeration			its name; its value
 *	identityref			"module:name"; its SID
 *	instance-identifier		"/m:a/b[k='v']/c"; SID or [SID, keys...]
 *	union				the first member it is a value of, by
 *					its JSON type then by which member's
 *					form the string has (RFC 7950 9.12),
 *					tagged 4, 43, 44, 45, 46 in YANG-CBOR
 *
 * A node the console's tables do not have (a newer peer's) is named by
 * the peer's file and its value taken as CBOR's or JSON's own kind says.
 * Annotations (RFC 7952), tag 109's [metadata, value], are written as
 * its section 5.2 has them: a container's or an entry's as its member
 * "@", a leaf's as its sibling "@name", a leaf-list's "@name", an array
 * of its entries' (null where one has none); read, they are passed over,
 * as the console sends none.  Anydata is written as an object of
 * qualified members; JSON's anydata and anyxml are not read.
 */

#include <sys/param.h>

#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <regex.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <cblink.h>
#include <cbl_schema.h>
#include <ucl.h>

#include "ysid.h"
#include "yxlate.h"

#define	DEPTH_MAX	64
#define	IID_MAX		512

/* What a conversion carries. */
struct xc {
	const struct ysids	*s;
	struct cbl_ybuf		*b;
	const char		*tag;		/* RFC 8040's error-tag */
	char			*why;
	size_t			 whylen;
	int			 depth;
};

static int
fail(struct xc *x, const char *tag, const char *fmt, ...)
{
	va_list	ap;

	x->tag = tag;
	if (x->why != NULL && x->whylen > 0) {
		va_start(ap, fmt);
		(void)vsnprintf(x->why, x->whylen, fmt, ap);
		va_end(ap);
	}
	return (EINVAL);
}

/*
 * CBOR, read.
 */

int
yxrd_peek(const struct yxrd *r, int *major, uint64_t *arg)
{
	struct yxrd	t = *r;

	return (yxrd_head(&t, major, arg));
}

int
yxrd_head(struct yxrd *r, int *major, uint64_t *arg)
{
	const uint8_t	*p = r->p;
	unsigned	 ai;
	size_t		 k;

	if (p == NULL || p >= r->end)
		return (EINVAL);
	*major = p[0] >> 5;
	ai = p[0] & 0x1f;
	p++;
	if (ai < 24)
		*arg = ai;
	else if (ai <= 27) {
		k = (size_t)1 << (ai - 24);
		if ((size_t)(r->end - p) < k)
			return (EINVAL);
		for (*arg = 0; k > 0; k--)
			*arg = *arg << 8 | *p++;
	} else
		return (EINVAL);	/* indefinite lengths: none */
	r->p = p;
	return (0);
}

int
yxrd_text(struct yxrd *r, const char **s, size_t *len)
{
	uint64_t	n;
	int		major;

	if (yxrd_head(r, &major, &n) != 0 || major != 3 ||
	    n > (uint64_t)(r->end - r->p))
		return (EINVAL);
	*s = (const char *)r->p;
	*len = (size_t)n;
	r->p += n;
	return (0);
}

static int
skip_depth(struct yxrd *r, int depth)
{
	uint64_t	n;
	int		major;

	if (depth > DEPTH_MAX || yxrd_head(r, &major, &n) != 0)
		return (EINVAL);
	switch (major) {
	case 2:
	case 3:
		if (n > (uint64_t)(r->end - r->p))
			return (EINVAL);
		r->p += n;
		return (0);
	case 4:
	case 5:
		if (n > (uint64_t)(r->end - r->p))
			return (EINVAL);
		for (uint64_t i = 0; i < (major == 5 ? 2 * n : n); i++)
			if (skip_depth(r, depth + 1) != 0)
				return (EINVAL);
		return (0);
	case 6:
		return (skip_depth(r, depth + 1));
	default:
		return (0);
	}
}

int
yxrd_skip(struct yxrd *r)
{

	return (skip_depth(r, 0));
}

/*
 * Output: bytes, JSON's strings, CBOR's heads.
 */

static int
put(struct cbl_ybuf *b, const void *p, size_t len)
{
	uint8_t	*n;
	size_t	 cap;

	if (b->len + len > b->cap) {
		cap = b->cap > 0 ? b->cap : 256;
		while (cap < b->len + len)
			cap *= 2;
		if ((n = realloc(b->p, cap)) == NULL)
			return (ENOMEM);
		b->p = n;
		b->cap = cap;
	}
	if (len > 0)
		memcpy(b->p + b->len, p, len);
	b->len += len;
	return (0);
}

static int
puts_(struct cbl_ybuf *b, const char *s)
{

	return (put(b, s, strlen(s)));
}

static int
putf(struct cbl_ybuf *b, const char *fmt, ...)
{
	va_list	ap;
	char	buf[64];
	int	n;

	va_start(ap, fmt);
	n = vsnprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);
	if (n < 0 || (size_t)n >= sizeof(buf))
		return (EINVAL);
	return (put(b, buf, (size_t)n));
}

/* A JSON string of len bytes of s, escaped (RFC 8259 section 7). */
static int
jstr(struct cbl_ybuf *b, const char *s, size_t len)
{
	char	esc[8];
	int	error;

	if ((error = puts_(b, "\"")) != 0)
		return (error);
	for (size_t i = 0; i < len; i++) {
		unsigned char c = (unsigned char)s[i];

		if (c == '"' || c == '\\') {
			esc[0] = '\\';
			esc[1] = (char)c;
			error = put(b, esc, 2);
		} else if (c < 0x20) {
			(void)snprintf(esc, sizeof(esc), "\\u%04x", c);
			error = puts_(b, esc);
		} else
			error = put(b, &s[i], 1);
		if (error != 0)
			return (error);
	}
	return (puts_(b, "\""));
}

int
yx_put_head(struct cbl_ybuf *b, int major, uint64_t arg)
{
	uint8_t	h[9];
	size_t	n;

	if (arg < 24) {
		h[0] = (uint8_t)(major << 5 | (int)arg);
		n = 1;
	} else if (arg <= UINT8_MAX) {
		h[0] = (uint8_t)(major << 5 | 24);
		n = 2;
	} else if (arg <= UINT16_MAX) {
		h[0] = (uint8_t)(major << 5 | 25);
		n = 3;
	} else if (arg <= UINT32_MAX) {
		h[0] = (uint8_t)(major << 5 | 26);
		n = 5;
	} else {
		h[0] = (uint8_t)(major << 5 | 27);
		n = 9;
	}
	for (size_t i = 1; i < n; i++)
		h[i] = (uint8_t)(arg >> (8 * (n - 1 - i)));
	return (put(b, h, n));
}

static int
put_int(struct cbl_ybuf *b, int64_t v)
{

	return (v >= 0 ? yx_put_head(b, 0, (uint64_t)v) :
	    yx_put_head(b, 1, (uint64_t)(-1 - v)));
}

static int
put_text(struct cbl_ybuf *b, const char *s, size_t len)
{
	int	error;

	if ((error = yx_put_head(b, 3, len)) != 0)
		return (error);
	return (put(b, s, len));
}

static const char b64[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static int
base64_put(struct cbl_ybuf *b, const uint8_t *p, size_t len)
{
	char		q[4];
	uint32_t	v;
	int		error;

	for (size_t i = 0; i < len; i += 3) {
		v = (uint32_t)p[i] << 16;
		if (i + 1 < len)
			v |= (uint32_t)p[i + 1] << 8;
		if (i + 2 < len)
			v |= p[i + 2];
		q[0] = b64[v >> 18 & 63];
		q[1] = b64[v >> 12 & 63];
		q[2] = i + 1 < len ? b64[v >> 6 & 63] : '=';
		q[3] = i + 2 < len ? b64[v & 63] : '=';
		if ((error = put(b, q, 4)) != 0)
			return (error);
	}
	return (0);
}

/* base64 text s into b's bytes; EINVAL: not base64. */
static int
base64_get(const char *s, struct cbl_ybuf *b)
{
	const char	*q;
	uint32_t	 acc = 0;
	int		 bits = 0, pad = 0, error;
	uint8_t		 c;

	for (; *s != '\0'; s++) {
		if (*s == '=') {
			pad++;
			continue;
		}
		if (pad > 0 || (q = strchr(b64, *s)) == NULL || *s == '\0')
			return (EINVAL);
		acc = acc << 6 | (uint32_t)(q - b64);
		if ((bits += 6) >= 8) {
			bits -= 8;
			c = (uint8_t)(acc >> bits);
			if ((error = put(b, &c, 1)) != 0)
				return (error);
		}
	}
	return (pad > 2 ? EINVAL : 0);
}

/*
 * Values as text: an integer, a decimal64, the names, a SID's identity,
 * an instance-identifier's path; what kind of JSON value it is.
 */
enum tkind { TK_NUM, TK_BOOL, TK_STR, TK_EMPTY };

static int	text_of(struct xc *, const struct cbl_ytype *, const char *,
		    struct yxrd *, struct cbl_ybuf *, enum tkind *);

static bool
is_int(int kind)
{

	return (kind >= CBL_YT_INT8 && kind <= CBL_YT_INT64) ||
	    (kind >= CBL_YT_UINT8 && kind <= CBL_YT_UINT64);
}

static bool
is_signed(int kind)
{

	return (kind >= CBL_YT_INT8 && kind <= CBL_YT_INT64);
}

/* Whether integer v (negative: neg) is in kind's range. */
static bool
int_fits(int kind, bool neg, uint64_t mag)
{
	static const struct {
		int		 kind;
		uint64_t	 pos;	/* the greatest */
		uint64_t	 neg;	/* the greatest magnitude below 0 */
	} r[] = {
		{ CBL_YT_INT8, INT8_MAX, 128 },
		{ CBL_YT_INT16, INT16_MAX, 32768 },
		{ CBL_YT_INT32, INT32_MAX, UINT64_C(2147483648) },
		{ CBL_YT_INT64, INT64_MAX, UINT64_C(9223372036854775808) },
		{ CBL_YT_UINT8, UINT8_MAX, 0 },
		{ CBL_YT_UINT16, UINT16_MAX, 0 },
		{ CBL_YT_UINT32, UINT32_MAX, 0 },
		{ CBL_YT_UINT64, UINT64_MAX, 0 },
	};

	for (size_t i = 0; i < nitems(r); i++)
		if (r[i].kind == kind)
			return (neg ? mag <= r[i].neg && mag > 0 :
			    mag <= r[i].pos);
	return (false);
}

/* A decimal: m with fd fraction digits. */
static int
dec_text(struct cbl_ybuf *t, bool neg, uint64_t mag, unsigned fd)
{
	char	 digits[32], out[48];
	size_t	 n, o = 0;

	n = (size_t)snprintf(digits, sizeof(digits), "%0*" PRIu64,
	    (int)fd + 1, mag);
	if (neg)
		out[o++] = '-';
	for (size_t i = 0; i < n; i++) {
		if (fd > 0 && i == n - fd)
			out[o++] = '.';
		out[o++] = digits[i];
	}
	/* The canonical form: no zeros at the end but one after the point
	 * (RFC 7950 9.3.2). */
	if (fd > 0)
		while (o > 2 && out[o - 1] == '0' && out[o - 2] != '.')
			o--;
	return (put(t, out, o));
}

/* An instance-identifier's YANG-CBOR at r as RFC 7951 section 6.11's
 * path. */
static int	iid_text(struct xc *, struct yxrd *, struct cbl_ybuf *);

/* The member a union's YANG-CBOR at r is a value of, NULL: none. */
static const struct cbl_ytype *
union_member(const struct cbl_ytype *t, const struct yxrd *r)
{
	struct yxrd	 q = *r;
	const struct cbl_ytype *m, *in;
	uint64_t	 arg, tag = 0;
	int		 major;
	const char	*s;
	size_t		 len;

	if (yxrd_head(&q, &major, &arg) != 0)
		return (NULL);
	if (major == 6) {
		tag = arg;
		if (yxrd_peek(&q, &major, &arg) != 0)
			return (NULL);
	}
	for (uint16_t i = 0; i < t->nmembers; i++) {
		m = t->members[i];
		if (m->kind == CBL_YT_UNION) {
			if ((in = union_member(m, r)) != NULL)
				return (in);
			continue;
		}
		if (tag != 0) {
			if ((tag == 4 && m->kind == CBL_YT_DECIMAL64) ||
			    (tag == 43 && m->kind == CBL_YT_BITS) ||
			    (tag == 45 && m->kind == CBL_YT_IDENTITYREF) ||
			    (tag == 46 && m->kind == CBL_YT_INSTANCEID))
				return (m);
			if (tag == 44 && m->kind == CBL_YT_ENUMERATION &&
			    yxrd_text(&(struct yxrd){ q.p, q.end }, &s, &len) ==
			    0)
				for (uint32_t k = 0; k < m->nitems; k++)
					if (strlen(m->items[k].name) == len &&
					    strncmp(m->items[k].name, s, len) ==
					    0)
						return (m);
			continue;
		}
		switch (major) {
		case 0:
		case 1:
			if (is_int(m->kind) && int_fits(m->kind, major == 1,
			    major == 1 ? arg + 1 : arg))
				return (m);
			break;
		case 2:
			if (m->kind == CBL_YT_BINARY || m->kind == CBL_YT_BITS)
				return (m);
			break;
		case 3:
			if (m->kind == CBL_YT_STRING)
				return (m);
			break;
		case 7:
			if ((arg == 20 || arg == 21) &&
			    m->kind == CBL_YT_BOOLEAN)
				return (m);
			if (arg == 22 && m->kind == CBL_YT_EMPTY)
				return (m);
			break;
		}
	}
	return (NULL);
}

/* What CBOR's own kind says, of a node the tables do not have. */
static int
loose_text(struct xc *x, const char *ctxmod, struct yxrd *r,
    struct cbl_ybuf *t, enum tkind *k)
{
	const struct ysid_item *it;
	const char	*s;
	uint64_t	 arg, e, m, cnt;
	size_t		 len;
	int		 major, mm;

	(void)ctxmod;
	if (yxrd_peek(r, &major, &arg) != 0)
		return (fail(x, "malformed-message", "not CBOR"));
	*k = TK_STR;
	switch (major) {
	case 0:
	case 1:
		(void)yxrd_head(r, &major, &arg);
		*k = TK_NUM;
		if (major == 1)
			return (arg == UINT64_MAX ? putf(t,
			    "-18446744073709551616") : putf(t, "-%" PRIu64,
			    arg + 1));
		return (putf(t, "%" PRIu64, arg));
	case 2:
		(void)yxrd_head(r, &major, &arg);
		if (arg > (uint64_t)(r->end - r->p))
			return (fail(x, "malformed-message", "not CBOR"));
		r->p += arg;
		return (base64_put(t, r->p - arg, (size_t)arg));
	case 3:
		if (yxrd_text(r, &s, &len) != 0)
			return (fail(x, "malformed-message", "not CBOR"));
		return (put(t, s, len));
	case 6:
		(void)yxrd_head(r, &major, &arg);
		switch (arg) {
		case 4:
			if (yxrd_head(r, &major, &cnt) != 0 || major != 4 ||
			    cnt != 2 || yxrd_head(r, &major, &e) != 0 ||
			    major != 1 || e > 18 ||
			    yxrd_head(r, &mm, &m) != 0 || mm > 1)
				return (fail(x, "malformed-message", "a "
				    "decimal64 not [exponent, mantissa]"));
			return (dec_text(t, mm == 1, mm == 1 ? m + 1 : m,
			    (unsigned)e + 1));
		case 43:
		case 44:
			if (yxrd_text(r, &s, &len) != 0)
				return (fail(x, "malformed-message", "not a "
				    "name"));
			return (put(t, s, len));
		case 45:
			if (yxrd_head(r, &major, &arg) != 0 || major != 0 ||
			    (it = ysids_sid(x->s, arg)) == NULL ||
			    it->ns != YSID_NS_IDENTITY)
				return (fail(x, "invalid-value", "identity SID "
				    "%" PRIu64 " is in none of the files",
				    arg));
			return (putf(t, "%s:", it->module) != 0 ? ENOMEM :
			    puts_(t, it->name));
		case 46:
			return (iid_text(x, r, t));
		default:
			return (fail(x, "malformed-message", "tag %" PRIu64,
			    arg));
		}
	case 7:
		(void)yxrd_head(r, &major, &arg);
		if (arg == 20 || arg == 21) {
			*k = TK_BOOL;
			return (puts_(t, arg == 21 ? "true" : "false"));
		}
		if (arg == 22) {
			*k = TK_EMPTY;
			return (0);
		}
		break;
	}
	return (fail(x, "malformed-message", "a value of no YANG type"));
}

static int
text_of(struct xc *x, const struct cbl_ytype *t, const char *ctxmod,
    struct yxrd *r, struct cbl_ybuf *out, enum tkind *k)
{
	const struct ysid_item *it;
	const char	*s;
	uint64_t	 arg, e, m, cnt, tag = 0;
	size_t		 len;
	int		 major, mm, error;
	bool		 first;

	if (t == NULL)
		return (loose_text(x, ctxmod, r, out, k));
	if (t->kind == CBL_YT_UNION) {
		const struct cbl_ytype *mt = union_member(t, r);

		if (mt == NULL)
			return (fail(x, "invalid-value", "a value of none of "
			    "the union's types"));
		return (text_of(x, mt, ctxmod, r, out, k));
	}
	if (yxrd_peek(r, &major, &arg) != 0)
		return (fail(x, "malformed-message", "not CBOR"));
	if (major == 6) {
		(void)yxrd_head(r, &major, &tag);
		if (yxrd_peek(r, &major, &arg) != 0)
			return (fail(x, "malformed-message", "not CBOR"));
	}
	*k = TK_STR;
	switch (t->kind) {
	case CBL_YT_INT8:
	case CBL_YT_INT16:
	case CBL_YT_INT32:
	case CBL_YT_UINT8:
	case CBL_YT_UINT16:
	case CBL_YT_UINT32:
		*k = TK_NUM;
		/* FALLTHROUGH */
	case CBL_YT_INT64:
	case CBL_YT_UINT64:
		if (major > 1 || (major == 1 && !is_signed(t->kind)))
			return (fail(x, "invalid-value", "not an integer"));
		(void)yxrd_head(r, &major, &arg);
		if (major == 1)
			return (arg == UINT64_MAX ? EINVAL : putf(out,
			    "-%" PRIu64, arg + 1));
		return (putf(out, "%" PRIu64, arg));
	case CBL_YT_DECIMAL64:
		if (tag != 4 || yxrd_head(r, &major, &cnt) != 0 ||
		    major != 4 || cnt != 2 || yxrd_head(r, &major, &e) != 0 ||
		    major != 1 || e > 18 || yxrd_head(r, &mm, &m) != 0 ||
		    mm > 1)
			return (fail(x, "invalid-value", "a decimal64 not "
			    "[exponent, mantissa]"));
		return (dec_text(out, mm == 1, mm == 1 ? m + 1 : m,
		    (unsigned)e + 1));
	case CBL_YT_BOOLEAN:
		if (major != 7 || (arg != 20 && arg != 21))
			return (fail(x, "invalid-value", "not a boolean"));
		(void)yxrd_head(r, &major, &arg);
		*k = TK_BOOL;
		return (puts_(out, arg == 21 ? "true" : "false"));
	case CBL_YT_EMPTY:
		if (major != 7 || arg != 22)
			return (fail(x, "invalid-value", "empty not null"));
		(void)yxrd_head(r, &major, &arg);
		*k = TK_EMPTY;
		return (0);
	case CBL_YT_STRING:
		if (yxrd_text(r, &s, &len) != 0)
			return (fail(x, "invalid-value", "not a string"));
		return (put(out, s, len));
	case CBL_YT_BINARY:
		if (major != 2)
			return (fail(x, "invalid-value", "not bytes"));
		(void)yxrd_head(r, &major, &arg);
		if (arg > (uint64_t)(r->end - r->p))
			return (fail(x, "malformed-message", "not CBOR"));
		r->p += arg;
		return (base64_put(out, r->p - arg, (size_t)arg));
	case CBL_YT_BITS:
		if (major == 3)
			goto name;
		if (major != 2)
			return (fail(x, "invalid-value", "bits not bytes"));
		(void)yxrd_head(r, &major, &arg);
		if (arg > (uint64_t)(r->end - r->p))
			return (fail(x, "malformed-message", "not CBOR"));
		first = true;
		for (uint64_t pos = 0; pos < arg * 8; pos++) {
			uint32_t i;

			if ((r->p[pos / 8] & (1u << (pos % 8))) == 0)
				continue;
			for (i = 0; i < t->nitems; i++)
				if (t->items[i].value == (int64_t)pos)
					break;
			if (i == t->nitems)
				return (fail(x, "invalid-value", "bit %" PRIu64
				    " is none of the type's", pos));
			if ((!first && (error = puts_(out, " ")) != 0) ||
			    (error = puts_(out, t->items[i].name)) != 0)
				return (error);
			first = false;
		}
		r->p += arg;
		return (0);
	case CBL_YT_ENUMERATION:
		if (major == 3)
			goto name;
		if (major > 1)
			return (fail(x, "invalid-value", "not an enum"));
		(void)yxrd_head(r, &major, &arg);
		for (uint32_t i = 0; i < t->nitems; i++)
			if (t->items[i].value == (major == 1 ? -1 -
			    (int64_t)arg : (int64_t)arg))
				return (puts_(out, t->items[i].name));
		return (fail(x, "invalid-value", "enum value %s%" PRIu64
		    " is none of the type's", major == 1 ? "-1-" : "", arg));
	case CBL_YT_IDENTITYREF:
		if (major == 3) {
			/* Its name, prefixed where another module's. */
			if (yxrd_text(r, &s, &len) != 0)
				return (EINVAL);
			if (memchr(s, ':', len) == NULL && ctxmod != NULL &&
			    (error = putf(out, "%s:", ctxmod)) != 0)
				return (error);
			return (put(out, s, len));
		}
		if (major != 0)
			return (fail(x, "invalid-value", "not an identity"));
		(void)yxrd_head(r, &major, &arg);
		if ((it = ysids_sid(x->s, arg)) == NULL ||
		    it->ns != YSID_NS_IDENTITY)
			return (fail(x, "invalid-value", "identity SID %" PRIu64
			    " is in none of the files", arg));
		if ((error = puts_(out, it->module)) != 0 ||
		    (error = puts_(out, ":")) != 0)
			return (error);
		return (puts_(out, it->name));
	case CBL_YT_INSTANCEID:
		return (iid_text(x, r, out));
	}
	return (fail(x, "invalid-value", "a type not known"));
name:
	if (yxrd_text(r, &s, &len) != 0)
		return (fail(x, "invalid-value", "not a name"));
	return (put(out, s, len));
}

/* A value as JSON: its text, quoted but where a number or a boolean. */
static int
json_value(struct xc *x, const struct cbl_ytype *t, const char *ctxmod,
    struct yxrd *r)
{
	struct cbl_ybuf	 tb = { NULL, 0, 0 };
	enum tkind	 k;
	int		 error;

	if ((error = text_of(x, t, ctxmod, r, &tb, &k)) == 0) {
		if (k == TK_EMPTY)
			error = puts_(x->b, "[null]");
		else if (k == TK_STR)
			error = jstr(x->b, tb.p != NULL ? (const char *)tb.p :
			    "", tb.len);
		else
			error = put(x->b, tb.p, tb.len);
	}
	cbl_ybuf_free(&tb);
	return (error);
}

/* The console's node of item it: a data node, or NULL. */
static const struct cbl_ynode *
node_of(const struct ysid_item *it)
{

	return (it != NULL && it->ns == YSID_NS_DATA ? it->what : NULL);
}

/* The item of a path's first plen bytes (one of the files'), NULL else. */
static const struct ysid_item *
prefix_item(const struct ysids *s, const char *path, size_t plen)
{
	char	buf[IID_MAX];

	if (plen >= sizeof(buf))
		return (NULL);
	memcpy(buf, path, plen);
	buf[plen] = '\0';
	return (ysids_data(s, buf));
}

static int
iid_text(struct xc *x, struct yxrd *r, struct cbl_ybuf *out)
{
	const struct ysid_item *it, *seg;
	const struct cbl_ynode *n;
	struct cbl_ybuf	 v = { NULL, 0, 0 };
	enum tkind	 k;
	const char	*p, *e;
	uint64_t	 arg, nv = 0, sid;
	int		 major, error = 0;
	char		 q;

	if (yxrd_head(r, &major, &arg) != 0)
		return (fail(x, "malformed-message", "not CBOR"));
	if (major == 4) {
		if (arg == 0 || yxrd_head(r, &major, &sid) != 0 || major != 0)
			return (fail(x, "invalid-value", "an "
			    "instance-identifier not [SID, keys...]"));
		nv = arg - 1;
	} else if (major == 0)
		sid = arg;
	else
		return (fail(x, "invalid-value", "not an instance-identifier"));
	if ((it = ysids_sid(x->s, sid)) == NULL || it->ns != YSID_NS_DATA)
		return (fail(x, "invalid-value", "instance-identifier SID %"
		    PRIu64 " is in none of the files", sid));
	/* Each segment of its path, with the keys of a list's. */
	for (p = it->id; error == 0 && *p == '/'; p = e) {
		e = strchrnul(p + 1, '/');
		if ((error = put(out, p, (size_t)(e - p))) != 0)
			break;
		seg = prefix_item(x->s, it->id, (size_t)(e - it->id));
		n = node_of(seg);
		if (n == NULL || nv == 0)
			continue;
		if (n->kind == CBL_YN_LIST) {
			for (uint16_t i = 0; error == 0 && i < n->nkeys &&
			    nv > 0; i++, nv--) {
				const struct cbl_ynode *kn =
				    n->child[n->keys[i]];

				v.len = 0;
				if ((error = text_of(x, kn->type,
				    kn->module->name, r, &v, &k)) != 0)
					break;
				q = v.len > 0 && memchr(v.p, '\'', v.len) !=
				    NULL ? '"' : '\'';
				if ((error = putf(out, "[%s=%c", kn->name,
				    q)) != 0 || (error = put(out, v.p,
				    v.len)) != 0)
					break;
				error = putf(out, "%c]", q);
			}
		} else if (n->kind == CBL_YN_LEAFLIST && *e == '\0') {
			v.len = 0;
			if ((error = text_of(x, n->type, n->module->name, r,
			    &v, &k)) != 0)
				break;
			nv--;
			q = v.len > 0 && memchr(v.p, '\'', v.len) != NULL ?
			    '"' : '\'';
			if ((error = putf(out, "[.=%c", q)) == 0 &&
			    (error = put(out, v.p, v.len)) == 0)
				error = putf(out, "%c]", q);
		}
	}
	cbl_ybuf_free(&v);
	if (error == 0 && nv != 0)
		return (fail(x, "invalid-value", "%s: keys the tables cannot "
		    "place", it->id));
	return (error);
}

/*
 * YANG-CBOR into JSON.
 */

static int	json_node(struct xc *, const struct ysid_item *, const char *,
		    struct yxrd *, bool *);

/* An annotation's map at r, its keys deltas from base: an object. */
static int
json_meta(struct xc *x, uint64_t base, struct yxrd *r)
{
	const struct ysid_item	*an;
	const struct cbl_yannot	*ca;
	uint64_t		 n, d;
	int			 major, error;

	if (yxrd_head(r, &major, &n) != 0 || major != 5)
		return (fail(x, "malformed-message", "metadata not a map"));
	if ((error = puts_(x->b, "{")) != 0)
		return (error);
	for (uint64_t i = 0; i < n; i++) {
		if (yxrd_head(r, &major, &d) != 0 || major > 1)
			return (fail(x, "malformed-message", "a metadata key"));
		d = major == 0 ? base + d : base - 1 - d;
		if ((an = ysids_sid(x->s, d)) == NULL ||
		    an->ns != YSID_NS_ANNOTATION)
			return (fail(x, "invalid-value", "annotation SID %"
			    PRIu64 " is in none of the files", d));
		ca = an->what;
		if ((i > 0 && (error = puts_(x->b, ",")) != 0) ||
		    (error = putf(x->b, "\"%s:", an->module)) != 0 ||
		    (error = puts_(x->b, an->name)) != 0 ||
		    (error = puts_(x->b, "\":")) != 0 ||
		    (error = json_value(x, ca != NULL ? ca->type : NULL,
		    an->module, r)) != 0)
			return (error);
	}
	return (puts_(x->b, "}"));
}

/* Tag 109 at r: true, r then at its metadata (*meta) and value. */
static bool
annotated(struct yxrd *r, struct yxrd *meta)
{
	struct yxrd	q = *r;
	uint64_t	arg;
	int		major;

	if (yxrd_head(&q, &major, &arg) != 0 || major != 6 || arg != 109 ||
	    yxrd_head(&q, &major, &arg) != 0 || major != 4 || arg != 2)
		return (false);
	*meta = q;
	if (yxrd_skip(&q) != 0)
		return (false);
	*r = q;
	return (true);
}

/* A map at r of children of it (keys deltas from base, or absolute,
 * tag 47), as an object, the metadata meta first. */
static int
json_object(struct xc *x, const struct ysid_item *it, uint64_t base,
    bool qualify, struct yxrd *r, struct yxrd *meta)
{
	const struct ysid_item	*c;
	uint64_t		 n, d;
	int			 major, error;
	bool			 first = true, abs;

	if (++x->depth > DEPTH_MAX)
		return (fail(x, "malformed-message", "nested too deep"));
	if (yxrd_head(r, &major, &n) != 0 || major != 5)
		return (fail(x, "invalid-value", "%s: not a map", it != NULL ?
		    it->id : "the data"));
	if ((error = puts_(x->b, "{")) != 0)
		return (error);
	if (meta != NULL) {
		if ((error = puts_(x->b, "\"@\":")) != 0 ||
		    (error = json_meta(x, base, meta)) != 0)
			return (error);
		first = false;
	}
	for (uint64_t i = 0; i < n; i++) {
		abs = false;
		if (yxrd_head(r, &major, &d) != 0)
			return (fail(x, "malformed-message", "a key"));
		if (major == 6 && d == 47) {
			if (yxrd_head(r, &major, &d) != 0 || major != 0)
				return (fail(x, "malformed-message", "a key"));
			abs = true;
		} else if (major > 1)
			return (fail(x, "malformed-message", "a key"));
		if (!abs)
			d = major == 0 ? base + d : base - 1 - d;
		if ((c = ysids_sid(x->s, d)) == NULL || c->ns != YSID_NS_DATA)
			return (fail(x, "unknown-element", "SID %" PRIu64
			    " is in none of the files", d));
		if ((error = json_node(x, c, qualify || abs || it == NULL ?
		    NULL : it->nmod, r, &first)) != 0)
			return (error);
	}
	x->depth--;
	return (puts_(x->b, "}"));
}

/* Node it's member at r: its name (qualified unless of pmod), value. */
static int
json_node(struct xc *x, const struct ysid_item *it, const char *pmod,
    struct yxrd *r, bool *first)
{
	const struct cbl_ynode	*n = node_of(it);
	struct yxrd		 meta, q;
	uint64_t		 cnt, arg;
	int			 kind, major, error;
	bool			 any, has;

	/* Its kind: the tables', else the CBOR's. */
	if (n != NULL)
		kind = n->kind;
	else {
		q = *r;
		(void)annotated(&q, &meta);
		if (yxrd_peek(&q, &major, &arg) != 0)
			return (fail(x, "malformed-message", "not CBOR"));
		kind = CBL_YN_LEAF;
		if (major == 5)
			kind = CBL_YN_CONTAINER;
		else if (major == 4) {
			(void)yxrd_head(&q, &major, &arg);
			kind = CBL_YN_LEAFLIST;
			(void)annotated(&q, &meta);
			if (arg > 0 && yxrd_peek(&q, &major, &arg) == 0 &&
			    major == 5)
				kind = CBL_YN_LIST;
		}
	}
	if ((!*first && (error = puts_(x->b, ",")) != 0) ||
	    (error = puts_(x->b, "\"")) != 0 ||
	    ((pmod == NULL || strcmp(pmod, it->nmod) != 0) &&
	    (error = putf(x->b, "%s:", it->nmod)) != 0) ||
	    (error = puts_(x->b, it->name)) != 0 ||
	    (error = puts_(x->b, "\":")) != 0)
		return (error);
	*first = false;
	switch (kind) {
	case CBL_YN_LIST:
		if (yxrd_head(r, &major, &cnt) != 0 || major != 4)
			return (fail(x, "invalid-value", "%s: not an array",
			    it->id));
		if ((error = puts_(x->b, "[")) != 0)
			return (error);
		for (uint64_t i = 0; i < cnt; i++) {
			has = annotated(r, &meta);
			if ((i > 0 && (error = puts_(x->b, ",")) != 0) ||
			    (error = json_object(x, it, it->sid, false, r,
			    has ? &meta : NULL)) != 0)
				return (error);
		}
		return (puts_(x->b, "]"));
	case CBL_YN_LEAFLIST:
		if (yxrd_head(r, &major, &cnt) != 0 || major != 4)
			return (fail(x, "invalid-value", "%s: not an array",
			    it->id));
		if ((error = puts_(x->b, "[")) != 0)
			return (error);
		any = false;
		q = *r;
		for (uint64_t i = 0; i < cnt; i++) {
			any |= annotated(r, &meta);
			if ((i > 0 && (error = puts_(x->b, ",")) != 0) ||
			    (error = json_value(x, n != NULL ? n->type : NULL,
			    it->nmod, r)) != 0)
				return (error);
		}
		if ((error = puts_(x->b, "]")) != 0 || !any)
			return (error);
		/* "@name": each entry's, null where it has none, read again
		 * from the first. */
		if ((error = puts_(x->b, ",\"@")) != 0 ||
		    (error = puts_(x->b, it->name)) != 0 ||
		    (error = puts_(x->b, "\":[")) != 0)
			return (error);
		for (uint64_t i = 0; i < cnt; i++) {
			has = annotated(&q, &meta);
			if ((i > 0 && (error = puts_(x->b, ",")) != 0) ||
			    (error = has ? json_meta(x, it->sid, &meta) :
			    puts_(x->b, "null")) != 0)
				return (error);
			if (yxrd_skip(&q) != 0)
				return (fail(x, "malformed-message",
				    "not CBOR"));
		}
		return (puts_(x->b, "]"));
	case CBL_YN_LEAF:
		has = annotated(r, &meta);
		if ((error = json_value(x, n != NULL ? n->type : NULL,
		    it->nmod, r)) != 0 || !has)
			return (error);
		if ((error = puts_(x->b, ",\"@")) != 0 ||
		    (error = puts_(x->b, it->name)) != 0 ||
		    (error = puts_(x->b, "\":")) != 0)
			return (error);
		return (json_meta(x, it->sid, &meta));
	case CBL_YN_ANYDATA:
	case CBL_YN_ANYXML:
		/* Its members anywhere in the schema, each qualified. */
		return (json_object(x, it, it->sid, true, r, NULL));
	default:
		has = annotated(r, &meta);
		/* A mount point's children: absolute SIDs, qualified; an
		 * input's or an output's, deltas from its action's. */
		return (json_object(x, it, it->io ? it->base : it->sid,
		    n != NULL && (n->flags & CBL_YNF_MOUNT) != 0, r,
		    has ? &meta : NULL));
	}
}

int
yx_json_member(const struct ysids *s, const struct ysid_item *it,
    const void *cbor, size_t len, bool *first, struct cbl_ybuf *b,
    char *why, size_t whylen)
{
	struct xc	 x = { s, b, NULL, why, whylen, 0 };
	struct yxrd	 r = { cbor, (const uint8_t *)cbor + len };
	int		 error;

	if ((error = json_node(&x, it, NULL, &r, first)) == 0 && r.p != r.end)
		error = fail(&x, "malformed-message", "%s: bytes after its "
		    "value", it->id);
	return (error);
}

int
yx_json(const struct ysids *s, const void *cbor, size_t len,
    struct cbl_ybuf *b, char *why, size_t whylen)
{
	struct xc	 x = { s, b, NULL, why, whylen, 0 };
	struct yxrd	 r = { cbor, (const uint8_t *)cbor + len };
	int		 error;

	if ((error = json_object(&x, NULL, 0, true, &r, NULL)) == 0 &&
	    r.p != r.end)
		error = fail(&x, "malformed-message", "bytes after the data");
	return (error);
}

/*
 * JSON into YANG-CBOR.
 */

/* Whether s is a value of string type t: its length, its patterns. */
static bool
string_ok(const struct cbl_ytype *t, const char *s)
{
	size_t	n = 0;
	regex_t	re;
	bool	ok;

	/* Its length in characters (RFC 7950 9.4.4). */
	for (const char *p = s; *p != '\0'; p++)
		n += ((unsigned char)*p & 0xc0) != 0x80;
	if (t->length.n > 0) {
		ok = false;
		for (uint16_t i = 0; i < t->length.n; i++)
			ok |= n >= t->length.v[i].min.u &&
			    n <= t->length.v[i].max.u;
		if (!ok)
			return (false);
	}
	for (uint16_t i = 0; i < t->npatterns; i++) {
		if (regcomp(&re, t->patterns[i].ere, REG_EXTENDED |
		    REG_NOSUB) != 0)
			return (false);
		ok = regexec(&re, s, 0, NULL, 0) == 0;
		regfree(&re);
		if (ok == t->patterns[i].invert)
			return (false);
	}
	return (true);
}

/* An integer's text: its sign and magnitude; false: not one. */
static bool
int_text(const char *s, bool *neg, uint64_t *mag)
{
	char	*end;

	*neg = *s == '-';
	if (*s == '-' || *s == '+')
		s++;
	if (*s < '0' || *s > '9')
		return (false);
	errno = 0;
	*mag = strtoull(s, &end, 10);
	return (errno == 0 && *end == '\0');
}

static int	enc_text(struct xc *, const struct cbl_ytype *, const char *,
		    const char *, bool);
static int	iid_cbor(struct xc *, const char *);

/* Bits' names into their bytes (no zero bytes at the end); EINVAL. */
static int
bits_bytes(const struct cbl_ytype *t, const char *s, uint8_t *out,
    size_t cap, size_t *len)
{
	size_t	w;
	uint32_t k;

	memset(out, 0, cap);
	*len = 0;
	while (*s != '\0') {
		s += strspn(s, " ");
		if ((w = strcspn(s, " ")) == 0)
			break;
		for (k = 0; k < t->nitems; k++)
			if (strlen(t->items[k].name) == w &&
			    strncmp(t->items[k].name, s, w) == 0)
				break;
		if (k == t->nitems || t->items[k].value < 0 ||
		    (size_t)t->items[k].value / 8 >= cap)
			return (EINVAL);
		out[t->items[k].value / 8] |=
		    (uint8_t)(1u << (t->items[k].value % 8));
		*len = MAX(*len, (size_t)t->items[k].value / 8 + 1);
		s += w;
	}
	while (*len > 0 && out[*len - 1] == 0)
		(*len)--;
	return (0);
}

/* A decimal's text with fd fraction digits: its mantissa. */
static bool
dec_mantissa(const char *s, unsigned fd, int64_t *m)
{
	uint64_t	v = 0;
	unsigned	frac = 0;
	bool		neg = false, point = false, digit = false;

	if (*s == '-' || *s == '+')
		neg = *s++ == '-';
	for (; *s != '\0'; s++) {
		if (*s == '.' && !point) {
			point = true;
			continue;
		}
		if (*s < '0' || *s > '9')
			return (false);
		if (point && ++frac > fd)
			return (false);
		if (v > (UINT64_C(1) << 63) / 10)
			return (false);
		v = v * 10 + (uint64_t)(*s - '0');
		digit = true;
	}
	for (; frac < fd; frac++) {
		if (v > (UINT64_C(1) << 63) / 10)
			return (false);
		v *= 10;
	}
	if (!digit || v > (neg ? UINT64_C(1) << 63 : (uint64_t)INT64_MAX))
		return (false);
	*m = neg ? (int64_t)(0 - v) : (int64_t)v;
	return (true);
}

/* Whether text s is a value of member t, as enc_text() would read it. */
static bool
text_is(struct xc *x, const struct cbl_ytype *t, const char *ctxmod,
    const char *s)
{
	struct xc	 y = *x;
	struct cbl_ybuf	 scratch = { NULL, 0, 0 };
	int		 error;

	y.b = &scratch;
	y.why = NULL;
	y.whylen = 0;
	error = enc_text(&y, t, ctxmod, s, true);
	cbl_ybuf_free(&scratch);
	return (error == 0);
}

/* Text s as a value of type t (in a union: tagged, RFC 9254 9.1). */
static int
enc_text(struct xc *x, const struct cbl_ytype *t, const char *ctxmod,
    const char *s, bool inunion)
{
	const struct ysid_item *id;
	struct cbl_ybuf	 by = { NULL, 0, 0 };
	uint8_t		 bits[64];
	uint64_t	 mag;
	int64_t		 m;
	size_t		 len, mlen;
	const char	*colon;
	char		 mod[128];
	int		 error;
	bool		 neg;

	switch (t->kind) {
	case CBL_YT_INT8:
	case CBL_YT_INT16:
	case CBL_YT_INT32:
	case CBL_YT_INT64:
	case CBL_YT_UINT8:
	case CBL_YT_UINT16:
	case CBL_YT_UINT32:
	case CBL_YT_UINT64:
		if (!int_text(s, &neg, &mag) || !int_fits(t->kind, neg, mag))
			return (fail(x, "invalid-value", "'%s' is not an "
			    "integer of its type", s));
		return (neg ? yx_put_head(x->b, 1, mag - 1) :
		    yx_put_head(x->b, 0, mag));
	case CBL_YT_DECIMAL64:
		if (!dec_mantissa(s, t->fdigits, &m))
			return (fail(x, "invalid-value", "'%s' is not a "
			    "decimal64 of %u fraction digits", s, t->fdigits));
		if ((error = yx_put_head(x->b, 6, 4)) != 0 ||
		    (error = yx_put_head(x->b, 4, 2)) != 0 ||
		    (error = put_int(x->b, -(int64_t)t->fdigits)) != 0)
			return (error);
		return (put_int(x->b, m));
	case CBL_YT_BOOLEAN:
		if (strcmp(s, "true") != 0 && strcmp(s, "false") != 0)
			return (fail(x, "invalid-value", "'%s' is not a "
			    "boolean", s));
		return (yx_put_head(x->b, 7, strcmp(s, "true") == 0 ? 21 : 20));
	case CBL_YT_EMPTY:
		return (fail(x, "invalid-value", "empty is [null]"));
	case CBL_YT_STRING:
		if (inunion && !string_ok(t, s))
			return (fail(x, "invalid-value", "'%s': not of its "
			    "pattern or length", s));
		return (put_text(x->b, s, strlen(s)));
	case CBL_YT_BINARY:
		if ((error = base64_get(s, &by)) != 0) {
			cbl_ybuf_free(&by);
			return (fail(x, "invalid-value", "not base64"));
		}
		if ((error = yx_put_head(x->b, 2, by.len)) == 0)
			error = put(x->b, by.p, by.len);
		cbl_ybuf_free(&by);
		return (error);
	case CBL_YT_BITS:
		if (bits_bytes(t, s, bits, sizeof(bits), &len) != 0)
			return (fail(x, "invalid-value", "'%s' are not bits of "
			    "its type", s));
		if (inunion) {
			if ((error = yx_put_head(x->b, 6, 43)) != 0)
				return (error);
			return (put_text(x->b, s, strlen(s)));
		}
		if ((error = yx_put_head(x->b, 2, len)) != 0)
			return (error);
		return (put(x->b, bits, len));
	case CBL_YT_ENUMERATION:
		for (uint32_t k = 0; k < t->nitems; k++) {
			if (strcmp(t->items[k].name, s) != 0)
				continue;
			if (!inunion)
				return (put_int(x->b, t->items[k].value));
			if ((error = yx_put_head(x->b, 6, 44)) != 0)
				return (error);
			return (put_text(x->b, s, strlen(s)));
		}
		return (fail(x, "invalid-value", "'%s' is none of its enums",
		    s));
	case CBL_YT_IDENTITYREF:
		/* "module:name"; a name alone, of the node's module. */
		if ((colon = strchr(s, ':')) != NULL) {
			mlen = (size_t)(colon - s);
			if (mlen >= sizeof(mod))
				return (fail(x, "invalid-value", "'%s'", s));
			memcpy(mod, s, mlen);
			mod[mlen] = '\0';
		} else
			(void)snprintf(mod, sizeof(mod), "%s", ctxmod != NULL ?
			    ctxmod : "");
		if ((id = ysids_named(x->s, YSID_NS_IDENTITY, mod, colon !=
		    NULL ? colon + 1 : s)) == NULL)
			return (fail(x, "invalid-value", "identity '%s' is in "
			    "none of the files", s));
		if (inunion && (error = yx_put_head(x->b, 6, 45)) != 0)
			return (error);
		return (yx_put_head(x->b, 0, id->sid));
	case CBL_YT_INSTANCEID:
		if (inunion && (error = yx_put_head(x->b, 6, 46)) != 0)
			return (error);
		return (iid_cbor(x, s));
	case CBL_YT_UNION:
		for (uint16_t i = 0; i < t->nmembers; i++)
			if (text_is(x, t->members[i], ctxmod, s))
				return (enc_text(x, t->members[i], ctxmod, s,
				    true));
		return (fail(x, "invalid-value", "'%s' is a value of none of "
		    "its types", s));
	}
	return (fail(x, "invalid-value", "a type not known"));
}

static int	enc_json(struct xc *, const struct cbl_ytype *, const char *,
		    const ucl_object_t *, bool);

/* Whether JSON value v is one of union t's. */
static bool
json_is(struct xc *x, const struct cbl_ytype *t, const char *ctxmod,
    const ucl_object_t *v)
{
	struct xc	 y = *x;
	struct cbl_ybuf	 scratch = { NULL, 0, 0 };
	int		 error;

	y.b = &scratch;
	y.why = NULL;
	y.whylen = 0;
	error = enc_json(&y, t, ctxmod, v, true);
	cbl_ybuf_free(&scratch);
	return (error == 0);
}

/*
 * A JSON value v of type t: RFC 7951's kinds by type, a union's member
 * the first whose kind the JSON's is and which reads it.
 */
static int
enc_json(struct xc *x, const struct cbl_ytype *t, const char *ctxmod,
    const ucl_object_t *v, bool inunion)
{
	char		 num[64];
	const char	*s;
	int		 type = ucl_object_type(v);

	/* [null]: empty. */
	if (type == UCL_ARRAY && ucl_array_size(v) == 1 &&
	    ucl_object_type(ucl_array_find_index(v, 0)) == UCL_NULL) {
		if (t == NULL || t->kind == CBL_YT_EMPTY)
			return (yx_put_head(x->b, 7, 22));
		if (t->kind == CBL_YT_UNION)
			for (uint16_t i = 0; i < t->nmembers; i++)
				if (t->members[i]->kind == CBL_YT_EMPTY)
					return (yx_put_head(x->b, 7, 22));
		return (fail(x, "invalid-value", "[null] is empty's alone"));
	}
	switch (type) {
	case UCL_INT:
		(void)snprintf(num, sizeof(num), "%" PRId64,
		    (int64_t)ucl_object_toint(v));
		s = num;
		break;
	case UCL_FLOAT:
		if (t == NULL || (t->kind != CBL_YT_DECIMAL64 &&
		    t->kind != CBL_YT_UNION))
			return (fail(x, "invalid-value", "a number with a "
			    "fraction, not of its type"));
		(void)snprintf(num, sizeof(num), "%.*f", t->kind ==
		    CBL_YT_DECIMAL64 ? t->fdigits : 6, ucl_object_todouble(v));
		s = num;
		break;
	case UCL_BOOLEAN:
		s = ucl_object_toboolean(v) ? "true" : "false";
		break;
	case UCL_STRING:
		s = ucl_object_tostring(v);
		break;
	default:
		return (fail(x, "invalid-value", "not a value"));
	}
	if (t == NULL) {
		/* A node the tables lack: as JSON's kind says. */
		if (type == UCL_INT)
			return (put_int(x->b, ucl_object_toint(v)));
		if (type == UCL_BOOLEAN)
			return (yx_put_head(x->b, 7, ucl_object_toboolean(v) ?
			    21 : 20));
		if (type == UCL_STRING)
			return (put_text(x->b, s, strlen(s)));
		return (fail(x, "invalid-value", "a value of no type known"));
	}
	if (t->kind == CBL_YT_UNION) {
		/* By its JSON kind first (RFC 7951 section 6.10). */
		for (uint16_t i = 0; i < t->nmembers; i++) {
			const struct cbl_ytype *m = t->members[i];
			int k = m->kind;
			bool kind_ok;

			if (k == CBL_YT_UNION)
				kind_ok = true;
			else if (type == UCL_INT)
				kind_ok = (is_int(k) && k != CBL_YT_INT64 &&
				    k != CBL_YT_UINT64) ||
				    k == CBL_YT_DECIMAL64;
			else if (type == UCL_FLOAT)
				kind_ok = k == CBL_YT_DECIMAL64;
			else if (type == UCL_BOOLEAN)
				kind_ok = k == CBL_YT_BOOLEAN;
			else
				kind_ok = k != CBL_YT_BOOLEAN &&
				    k != CBL_YT_EMPTY && (!is_int(k) ||
				    k == CBL_YT_INT64 || k == CBL_YT_UINT64);
			if (kind_ok && (k == CBL_YT_UNION ? json_is(x, m,
			    ctxmod, v) : text_is(x, m, ctxmod, s)))
				return (k == CBL_YT_UNION ? enc_json(x, m,
				    ctxmod, v, true) : enc_text(x, m, ctxmod, s,
				    true));
		}
		return (fail(x, "invalid-value", "'%s' is a value of none of "
		    "its types", s));
	}
	return (enc_text(x, t, ctxmod, s, inunion));
}

/* The child path of item it a member's name says: "name" of its module,
 * else "module:name". */
static const struct ysid_item *
child_item(const struct ysids *s, const struct ysid_item *it,
    const char *key, bool mount)
{
	char		 path[IID_MAX];
	const char	*colon = strchr(key, ':');
	int		 n;

	if (it == NULL || mount) {
		if (colon == NULL)
			return (NULL);
		n = snprintf(path, sizeof(path), "/%s", key);
	} else if (colon != NULL && strlen(it->nmod) == (size_t)(colon -
	    key) && strncmp(it->nmod, key, (size_t)(colon - key)) == 0)
		n = snprintf(path, sizeof(path), "%s/%s", it->id, colon + 1);
	else
		n = snprintf(path, sizeof(path), "%s/%s", it->id, key);
	if (n < 0 || (size_t)n >= sizeof(path))
		return (NULL);
	return (ysids_data(s, path));
}

static int	enc_node(struct xc *, const struct ysid_item *,
		    const ucl_object_t *);

/* Object v's members, children of it: a map. */
static int
enc_object(struct xc *x, const struct ysid_item *it, const ucl_object_t *v)
{
	const struct cbl_ynode	*n = node_of(it);
	const struct ysid_item	*c;
	const ucl_object_t	*m;
	ucl_object_iter_t	 iter = NULL;
	const char		*key, *colon;
	uint64_t		 cnt = 0;
	int			 error;
	bool			 mount = n != NULL && (n->flags &
				    CBL_YNF_MOUNT) != 0;

	if (++x->depth > DEPTH_MAX)
		return (fail(x, "malformed-message", "nested too deep"));
	if (ucl_object_type(v) != UCL_OBJECT)
		return (fail(x, "invalid-value", "%s: not an object",
		    it != NULL ? it->id : "the data"));
	while ((m = ucl_object_iterate(v, &iter, true)) != NULL)
		cnt += ucl_object_key(m)[0] != '@';
	if ((error = yx_put_head(x->b, 5, cnt)) != 0)
		return (error);
	iter = NULL;
	while ((m = ucl_object_iterate(v, &iter, true)) != NULL) {
		key = ucl_object_key(m);
		/* Annotations (RFC 7952): the console sends none. */
		if (key[0] == '@')
			continue;
		if ((c = child_item(x->s, it, key, mount)) == NULL) {
			colon = strchr(key, ':');
			if ((it == NULL || mount) && colon == NULL)
				return (fail(x, "malformed-message", "%s: a "
				    "top-level member without its module",
				    key));
			if (colon != NULL) {
				char mod[128];

				(void)snprintf(mod, sizeof(mod), "%.*s",
				    (int)(colon - key), key);
				if (ysids_named(x->s, YSID_NS_MODULE, mod,
				    mod) == NULL)
					return (fail(x, "unknown-namespace",
					    "%s: no module %s", key, mod));
			}
			return (fail(x, "unknown-element", "%s%s%s: no such "
			    "node", it != NULL ? it->id : "", it != NULL ? "/" :
			    "", key));
		}
		if (it == NULL)
			error = yx_put_head(x->b, 0, c->sid);
		else if (mount) {
			if ((error = yx_put_head(x->b, 6, 47)) == 0)
				error = yx_put_head(x->b, 0, c->sid);
		} else
			error = put_int(x->b, (int64_t)(c->sid - c->base));
		if (error != 0 || (error = enc_node(x, c, m)) != 0)
			return (error);
	}
	x->depth--;
	return (0);
}

/* Node it's value v. */
static int
enc_node(struct xc *x, const struct ysid_item *it, const ucl_object_t *v)
{
	const struct cbl_ynode	*n = node_of(it);
	const ucl_object_t	*e;
	ucl_object_iter_t	 iter = NULL;
	int			 kind, type = ucl_object_type(v), error;

	if (n != NULL)
		kind = n->kind;
	else if (type == UCL_OBJECT)
		kind = CBL_YN_CONTAINER;
	else if (type == UCL_ARRAY && !(ucl_array_size(v) == 1 &&
	    ucl_object_type(ucl_array_find_index(v, 0)) == UCL_NULL))
		kind = ucl_array_size(v) > 0 && ucl_object_type(
		    ucl_array_find_index(v, 0)) == UCL_OBJECT ? CBL_YN_LIST :
		    CBL_YN_LEAFLIST;
	else
		kind = CBL_YN_LEAF;
	switch (kind) {
	case CBL_YN_LIST:
	case CBL_YN_LEAFLIST:
		if (type != UCL_ARRAY)
			return (fail(x, "invalid-value", "%s: not an array",
			    it->id));
		if ((error = yx_put_head(x->b, 4, ucl_array_size(v))) != 0)
			return (error);
		while ((e = ucl_object_iterate(v, &iter, true)) != NULL) {
			error = kind == CBL_YN_LIST ? enc_object(x, it, e) :
			    enc_json(x, n != NULL ? n->type : NULL, it->nmod, e,
			    false);
			if (error != 0)
				return (error);
		}
		return (0);
	case CBL_YN_LEAF:
		return (enc_json(x, n != NULL ? n->type : NULL, it->nmod, v,
		    false));
	case CBL_YN_ANYDATA:
	case CBL_YN_ANYXML:
		return (fail(x, "operation-not-supported", "%s: anydata is "
		    "not taken from JSON", it->id));
	default:
		return (enc_object(x, it, v));
	}
}

/*
 * An instance-identifier's path (RFC 7951 section 6.11): each segment a
 * node, its module said where it changes, a list's with a predicate of
 * each key ([name='value'], any order), a leaf-list's with [.='value'].
 */
static int
iid_cbor(struct xc *x, const char *s)
{
	const struct ysid_item *it = NULL;
	const struct cbl_ynode *n;
	struct cbl_ybuf	 vals = { NULL, 0, 0 }, *keep;
	const char	*p = s, *e, *colon, *vstart, *kv[16], *kname[16];
	char		 path[IID_MAX], prev[128], seg[IID_MAX], *texts;
	size_t		 o = 0, nkv, nvals = 0, klen[16], sl;
	int		 error = 0;
	char		 q;

	prev[0] = '\0';
	if ((texts = strdup(s)) == NULL)
		return (ENOMEM);
	keep = x->b;
	x->b = &vals;
	while (error == 0 && *p == '/') {
		p++;
		e = p + strcspn(p, "/[");
		sl = (size_t)(e - p);
		if (sl == 0 || sl >= sizeof(seg)) {
			error = fail(x, "invalid-value", "'%s': a segment", s);
			break;
		}
		memcpy(seg, p, sl);
		seg[sl] = '\0';
		colon = strchr(seg, ':');
		if (colon == NULL && prev[0] == '\0') {
			error = fail(x, "invalid-value", "'%s': its first "
			    "segment without its module", s);
			break;
		}
		if (colon != NULL && (strlen(prev) != (size_t)(colon - seg) ||
		    strncmp(prev, seg, strlen(prev)) != 0)) {
			(void)snprintf(prev, sizeof(prev), "%.*s",
			    (int)(colon - seg), seg);
			o += (size_t)snprintf(path + o, sizeof(path) - o,
			    "/%s", seg);
		} else
			o += (size_t)snprintf(path + o, sizeof(path) - o,
			    "/%s", colon != NULL ? colon + 1 : seg);
		if (o >= sizeof(path) || (it = ysids_data(x->s, path)) ==
		    NULL) {
			error = fail(x, "invalid-value", "'%s': %s is in none "
			    "of the files", s, path);
			break;
		}
		/* Its predicates. */
		nkv = 0;
		p = e;
		while (*p == '[') {
			const char *eq = p + 1 + strcspn(p + 1, "=]");

			if (*eq != '=' || (eq[1] != '\'' && eq[1] != '"') ||
			    nkv == nitems(kv)) {
				error = fail(x, "invalid-value", "'%s': a "
				    "predicate", s);
				break;
			}
			q = eq[1];
			vstart = eq + 2;
			if ((e = strchr(vstart, q)) == NULL || e[1] != ']') {
				error = fail(x, "invalid-value", "'%s': a "
				    "predicate", s);
				break;
			}
			kname[nkv] = p + 1;
			klen[nkv] = (size_t)(eq - p - 1);
			/* The value, NUL-terminated in the copy. */
			kv[nkv] = texts + (vstart - s);
			texts[e - s] = '\0';
			nkv++;
			p = e + 2;
		}
		if (error != 0 || nkv == 0)
			continue;
		if ((n = node_of(it)) == NULL) {
			error = fail(x, "invalid-value", "'%s': %s's keys are "
			    "not known", s, path);
			break;
		}
		if (n->kind == CBL_YN_LEAFLIST && nkv == 1 && klen[0] == 1 &&
		    kname[0][0] == '.') {
			error = enc_text(x, n->type, n->module->name, kv[0],
			    false);
			nvals++;
			continue;
		}
		if (n->kind != CBL_YN_LIST || nkv != n->nkeys) {
			error = fail(x, "invalid-value", "'%s': %s's keys", s,
			    path);
			break;
		}
		for (uint16_t i = 0; error == 0 && i < n->nkeys; i++) {
			const struct cbl_ynode *kn = n->child[n->keys[i]];
			size_t j;

			for (j = 0; j < nkv; j++) {
				const char *kc = memchr(kname[j], ':',
				    klen[j]);
				const char *nm = kc != NULL ? kc + 1 : kname[j];
				size_t nl = klen[j] - (size_t)(nm - kname[j]);

				if (strlen(kn->name) == nl &&
				    strncmp(kn->name, nm, nl) == 0)
					break;
			}
			if (j == nkv) {
				error = fail(x, "invalid-value", "'%s': no "
				    "key %s", s, kn->name);
				break;
			}
			error = enc_text(x, kn->type, kn->module->name, kv[j],
			    false);
			nvals++;
		}
	}
	x->b = keep;
	if (error == 0 && (it == NULL || *p != '\0'))
		error = fail(x, "invalid-value", "'%s' is not an "
		    "instance-identifier", s);
	if (error == 0) {
		if (nvals == 0)
			error = yx_put_head(x->b, 0, it->sid);
		else if ((error = yx_put_head(x->b, 4, nvals + 1)) == 0 &&
		    (error = yx_put_head(x->b, 0, it->sid)) == 0)
			error = put(x->b, vals.p, vals.len);
	}
	cbl_ybuf_free(&vals);
	free(texts);
	return (error);
}

int
yx_cbor_member(const struct ysids *s, const struct ysid_item *it,
    const ucl_object_t *v, struct cbl_ybuf *b, const char **tag, char *why,
    size_t whylen)
{
	struct xc	x = { s, b, NULL, why, whylen, 0 };
	int		error;

	error = enc_node(&x, it, v);
	if (tag != NULL)
		*tag = x.tag != NULL ? x.tag : "invalid-value";
	return (error);
}

int
yx_iid(const struct ysids *s, const char *path, struct cbl_ybuf *b,
    char *why, size_t whylen)
{
	struct xc	x = { s, b, NULL, why, whylen, 0 };

	return (iid_cbor(&x, path));
}

int
yx_cbor(const struct ysids *s, const ucl_object_t *v, struct cbl_ybuf *b,
    const char **tag, char *why, size_t whylen)
{
	struct xc	x = { s, b, NULL, why, whylen, 0 };
	int		error;

	error = enc_object(&x, NULL, v);
	if (tag != NULL)
		*tag = x.tag != NULL ? x.tag : "invalid-value";
	return (error);
}

int
yx_cbor_text(const struct ysids *s, const char *json, struct cbl_ybuf *b,
    const char **tag, char *why, size_t whylen)
{
	struct ucl_parser	*p;
	ucl_object_t		*v = NULL;
	int			 error;

	p = ucl_parser_new(UCL_PARSER_NO_IMPLICIT_ARRAYS |
	    UCL_PARSER_DISABLE_MACRO | UCL_PARSER_NO_TIME);
	if (ucl_parser_add_string(p, json, 0))
		v = ucl_parser_get_object(p);
	ucl_parser_free(p);
	if (v == NULL) {
		if (tag != NULL)
			*tag = "malformed-message";
		(void)snprintf(why, whylen, "not JSON");
		return (EINVAL);
	}
	error = yx_cbor(s, v, b, tag, why, whylen);
	ucl_object_unref(v);
	return (error);
}
