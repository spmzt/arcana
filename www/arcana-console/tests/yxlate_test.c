/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * The console's translator between RFC 7951's JSON and YANG-CBOR
 * (yxlate.c, ysid.c; PLAN-SDN-YANG 4.2.1, 4.2.2) over the example
 * modules in yang/: RFC 7951's examples each way, checked against
 * cblink's own codec (what one writes the other reads, and its JSON is
 * the same); RFC 7952's annotations in the shape its section 5.2 has;
 * a peer that numbers the items otherwise, and one that has a node the
 * console's tables do not.
 */

#include <atf-c.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <cblink.h>
#include <cbl_schema.h>
#include <cbl_data.h>
#include <ucl.h>

#include "yxtest.h"
#include "ysid.h"
#include "yxlate.h"

static const char *const files[] = {
	"example-foomod@2026-11-05.sid",
	"example-barmod@2026-11-05.sid",
	"example-last-modified@2026-11-05.sid",
};

static ucl_object_t *
json(const char *s)
{
	struct ucl_parser	*p;
	ucl_object_t		*o;

	p = ucl_parser_new(UCL_PARSER_NO_IMPLICIT_ARRAYS);
	ATF_REQUIRE_MSG(ucl_parser_add_string(p, s, 0), "%s: %s", s,
	    ucl_parser_get_error(p));
	o = ucl_parser_get_object(p);
	ucl_parser_free(p);
	return (o);
}

static ucl_object_t *
json_file(const char *name)
{
	struct ucl_parser	*p;
	ucl_object_t		*o;
	char			 path[512];

	snprintf(path, sizeof(path), "%s/%s", YXDIR, name);
	p = ucl_parser_new(UCL_PARSER_NO_IMPLICIT_ARRAYS);
	ATF_REQUIRE_MSG(ucl_parser_add_file(p, path), "%s", path);
	o = ucl_parser_get_object(p);
	ucl_parser_free(p);
	return (o);
}

/* Each item's SID moved by shift; one more item, extra, if given. */
static void
renumber(ucl_object_t *file, uint64_t shift, const char *extra,
    uint64_t extra_sid)
{
	ucl_object_t		*f, *items, *e;
	ucl_object_iter_t	 it = NULL;
	char			 buf[32];

	f = (ucl_object_t *)(uintptr_t)ucl_object_lookup(file,
	    "ietf-sid-file:sid-file");
	items = (ucl_object_t *)(uintptr_t)ucl_object_lookup(f, "item");
	while ((e = (ucl_object_t *)(uintptr_t)ucl_object_iterate(items, &it,
	    true)) != NULL) {
		uint64_t sid = strtoull(ucl_object_tostring(ucl_object_lookup(e,
		    "sid")), NULL, 10) + shift;

		snprintf(buf, sizeof(buf), "%" PRIu64, sid);
		ucl_object_replace_key(e, ucl_object_fromstring(buf), "sid", 0,
		    false);
	}
	if (extra != NULL) {
		e = ucl_object_typed_new(UCL_OBJECT);
		ucl_object_insert_key(e, ucl_object_fromstring("data"),
		    "namespace", 0, false);
		ucl_object_insert_key(e, ucl_object_fromstring(extra),
		    "identifier", 0, false);
		snprintf(buf, sizeof(buf), "%" PRIu64, extra_sid);
		ucl_object_insert_key(e, ucl_object_fromstring(buf), "sid", 0,
		    false);
		ucl_array_append(items, e);
	}
}

/* The example modules' items, as the files have them (shift 0), or a
 * peer's numbering of them. */
static struct ysids *
view(uint64_t shift, const char *extra, uint64_t extra_sid)
{
	struct ysids	*s;
	ucl_object_t	*f;
	char		 why[256];

	ATF_REQUIRE((s = ysids_new(&yxtest_schema)) != NULL);
	for (size_t i = 0; i < sizeof(files) / sizeof(files[0]); i++) {
		f = json_file(files[i]);
		if (shift != 0 || (i == 0 && extra != NULL))
			renumber(f, shift, i == 0 ? extra : NULL, extra_sid);
		ATF_REQUIRE_MSG(ysids_file_json(s, f, why, sizeof(why)) == 0,
		    "%s", why);
		ucl_object_unref(f);
	}
	ATF_REQUIRE_MSG(ysids_done(s, why, sizeof(why)) == 0, "%s", why);
	return (s);
}

/* JSON text of what b holds. */
static char *
text(const struct cbl_ybuf *b)
{

	return (strndup(b->p != NULL ? (const char *)b->p : "", b->len));
}

/* doc into YANG-CBOR and back: the same; cblink reads the CBOR, and its
 * JSON of it is doc too, but where its JSON differs (CBL_JSON: an
 * instance-identifier's null) or its tables number otherwise. */
#define	CBL_ALL		0
#define	CBL_JSON	1
#define	NO_CBLINK	2

static void
both_ways(const struct ysids *s, const char *doc, int cbl)
{
	struct cbl_ybuf	 c = { NULL, 0, 0 }, j = { NULL, 0, 0 },
			 k = { NULL, 0, 0 };
	ucl_object_t	*want, *got;
	cbl_dtree	*t;
	const char	*tag = NULL;
	char		 why[256], *out;

	want = json(doc);
	ATF_REQUIRE_MSG(yx_cbor(s, want, &c, &tag, why, sizeof(why)) == 0,
	    "%s: %s %s", doc, tag, why);
	ATF_REQUIRE_MSG(yx_json(s, c.p, c.len, &j, why, sizeof(why)) == 0,
	    "%s: back: %s", doc, why);
	out = text(&j);
	got = json(out);
	ATF_CHECK_MSG(ucl_object_compare(want, got) == 0, "%s\n  came back "
	    "as %s", doc, out);
	ucl_object_unref(got);
	free(out);
	/* cblink's codec: it decodes what this wrote, strictly. */
	if (cbl == NO_CBLINK)
		goto done;
	ATF_REQUIRE((t = cbl_dtree_new(&yxtest_schema)) != NULL);
	ATF_CHECK_MSG(cbl_dtree_decode(t, c.p, c.len, CBL_YD_STRICT, why,
	    sizeof(why)) == 0, "%s: cblink: %s", doc, why);
	if (cbl == CBL_ALL) {
		ATF_REQUIRE(cbl_dtree_json(t, &k) == 0);
		out = text(&k);
		got = json(out);
		ATF_CHECK_MSG(ucl_object_compare(want, got) == 0, "%s\n  is "
		    "cblink's %s", doc, out);
		ucl_object_unref(got);
		free(out);
	}
	cbl_dtree_free(t);
done:
	ucl_object_unref(want);
	cbl_ybuf_free(&c);
	cbl_ybuf_free(&j);
	cbl_ybuf_free(&k);
}

/* doc refused with that error-tag. */
static void
refused(const struct ysids *s, const char *doc, const char *want)
{
	struct cbl_ybuf	 c = { NULL, 0, 0 };
	ucl_object_t	*v = json(doc);
	const char	*tag = NULL;
	char		 why[256];

	ATF_CHECK_MSG(yx_cbor(s, v, &c, &tag, why, sizeof(why)) != 0,
	    "%s: taken", doc);
	ATF_CHECK_MSG(tag != NULL && strcmp(tag, want) == 0, "%s: %s, not %s "
	    "(%s)", doc, tag != NULL ? tag : "none", want, why);
	ucl_object_unref(v);
	cbl_ybuf_free(&c);
}

ATF_TC_WITHOUT_HEAD(rfc7951);
ATF_TC_BODY(rfc7951, tc)
{
	struct ysids *s = view(0, NULL, 0);

	/* Section 4: a member's module said where it changes. */
	both_ways(s, "{\"example-foomod:top\":{\"foo\":54,"
	    "\"example-barmod:bar\":true}}", CBL_ALL);
	/* 5.3, 5.4: a leaf-list, a list. */
	both_ways(s, "{\"example-foomod:top\":{\"bars\":[true,false],"
	    "\"item\":[{\"name\":\"b\",\"count\":0,\"tag\":[\"x\",\"y\"]},"
	    "{\"name\":\"a\",\"count\":-123}]}}", CBL_ALL);
	/* 6.1: numbers, 64-bit ones and decimal64 strings. */
	both_ways(s, "{\"example-foomod:top\":{\"foo\":255,\"big\":"
	    "\"-9223372036854775808\",\"ubig\":\"18446744073709551615\","
	    "\"price\":\"-12.25\"}}", CBL_ALL);
	/* 6.2 to 6.9: a string, an enum, bits, binary, an identity of
	 * another module, empty. */
	both_ways(s, "{\"example-foomod:top\":"
	    "{\"text\":\"a \\\"b\\\"\\t\\u0001\","
	    "\"color\":\"green\",\"flags\":\"read execute\",\"blob\":\"AQID\","
	    "\"kind\":\"example-barmod:dog\",\"on\":[null]}}", CBL_ALL);
	/* 6.10: a union by its JSON kind, then by which member reads it. */
	both_ways(s, "{\"example-foomod:top\":{\"mixed\":-7}}", CBL_ALL);
	both_ways(s, "{\"example-foomod:top\":{\"mixed\":\"auto\"}}", CBL_ALL);
	both_ways(s, "{\"example-foomod:top\":{\"mixed\":\"abc\"}}", CBL_ALL);
	both_ways(s, "{\"example-foomod:top\":{\"mixed\":\"1234567890123\"}}",
	    CBL_ALL);
	both_ways(s, "{\"example-foomod:top\":{\"mixed\":"
	    "\"example-foomod:cat\"}}", CBL_ALL);
	/* 6.11: an instance-identifier, which cblink's JSON has as null. */
	both_ways(s, "{\"example-foomod:top\":{\"where\":"
	    "\"/example-foomod:top/item[name='a']/count\"}}", CBL_JSON);
	both_ways(s, "{\"example-foomod:top\":{\"where\":"
	    "\"/example-foomod:top/example-barmod:bar\"}}", CBL_JSON);
	both_ways(s, "{\"example-foomod:top\":{\"where\":"
	    "\"/example-foomod:top/item[name=\\\"it's\\\"]/tag[.='x']\"}}",
	    CBL_JSON);
	/* A decimal64's canonical form has no zeros at its end (RFC 7950
	 * 9.3.2), which cblink's JSON keeps. */
	both_ways(s, "{\"example-foomod:top\":{\"price\":\"0.5\"}}", CBL_JSON);

	/* What is not: the errors RFC 8040 section 7 names. */
	refused(s, "{\"example-foomod:top\":{\"nope\":1}}", "unknown-element");
	refused(s, "{\"example-nomod:top\":{}}", "unknown-namespace");
	refused(s, "{\"top\":{}}", "malformed-message");
	refused(s, "{\"example-foomod:top\":{\"foo\":256}}", "invalid-value");
	refused(s, "{\"example-foomod:top\":{\"color\":\"blue\"}}",
	    "invalid-value");
	refused(s, "{\"example-foomod:top\":{\"mixed\":\"A-1\"}}",
	    "invalid-value");
	refused(s, "{\"example-foomod:top\":{\"price\":\"1.234\"}}",
	    "invalid-value");
	refused(s, "{\"example-foomod:top\":{\"on\":true}}", "invalid-value");
	ysids_free(s);
}

static const struct cbl_ynode *
child(const struct cbl_ynode *n, const char *name)
{

	for (uint32_t i = 0; i < n->nchild; i++)
		if (strcmp(n->child[i]->name, name) == 0)
			return (n->child[i]);
	atf_tc_fail("no %s under %s", name, n->name);
	return (NULL);
}

/* RFC 7952 section 5.2: a container's, an entry's, a leaf's and a
 * leaf-list entry's annotations, as cblink writes them in YANG-CBOR. */
ATF_TC_WITHOUT_HEAD(rfc7952);
ATF_TC_BODY(rfc7952, tc)
{
	static const char lmt[] = "2015-09-16T10:27:35+02:00";
	struct ysids		*s = view(0, NULL, 0);
	const struct cbl_ymodule *fm = NULL, *lm = NULL;
	const struct cbl_ynode	*top, *n;
	const struct cbl_yannot	*an;
	struct cbl_ybuf		 c = { NULL, 0, 0 }, j = { NULL, 0, 0 },
				 k = { NULL, 0, 0 };
	cbl_dtree		*t;
	cbl_dnode		*dt, *x;
	ucl_object_t		*got, *want;
	const char		*lp = lmt, *key = "a";
	uint8_t			 u8 = 42;
	bool			 tru = true, fls = false;
	char			 why[256], *out;

	for (uint32_t i = 0; i < yxtest_schema.nmod; i++) {
		if (strcmp(yxtest_schema.mod[i]->name, "example-foomod") == 0)
			fm = yxtest_schema.mod[i];
		if (strcmp(yxtest_schema.mod[i]->name,
		    "example-last-modified") == 0)
			lm = yxtest_schema.mod[i];
	}
	ATF_REQUIRE(fm != NULL && lm != NULL);
	ATF_REQUIRE((an = cbl_ymodule_annot(lm, "last-modified")) != NULL);
	top = fm->top[0];
	ATF_REQUIRE((t = cbl_dtree_new(&yxtest_schema)) != NULL);
	ATF_REQUIRE(cbl_dnode_add(cbl_dtree_root(t), top, NULL, &dt) == 0);
	ATF_REQUIRE(cbl_dnode_meta_set(dt, an, &lp) == 0);
	ATF_REQUIRE(cbl_dnode_add(dt, child(top, "foo"), &u8, &x) == 0);
	ATF_REQUIRE(cbl_dnode_meta_set(x, an, &lp) == 0);
	n = child(top, "bars");
	ATF_REQUIRE(cbl_dnode_add(dt, n, &tru, NULL) == 0);
	ATF_REQUIRE(cbl_dnode_add(dt, n, &fls, &x) == 0);
	ATF_REQUIRE(cbl_dnode_meta_set(x, an, &lp) == 0);
	{
		const void *keys[] = { &key };

		ATF_REQUIRE(cbl_dnode_add_entry(dt, child(top, "item"), keys,
		    &x) == 0);
		ATF_REQUIRE(cbl_dnode_meta_set(x, an, &lp) == 0);
	}
	ATF_REQUIRE(cbl_dtree_encode(t, &c) == 0);
	ATF_REQUIRE_MSG(yx_json(s, c.p, c.len, &j, why, sizeof(why)) == 0,
	    "%s", why);
	out = text(&j);
	printf("%s\n", out);
	got = json(out);
	want = json("{\"example-foomod:top\":{"
	    "\"@\":{\"example-last-modified:last-modified\":"
	    "\"2015-09-16T10:27:35+02:00\"},"
	    "\"foo\":42,\"@foo\":{\"example-last-modified:last-modified\":"
	    "\"2015-09-16T10:27:35+02:00\"},"
	    "\"bars\":[true,false],\"@bars\":[null,"
	    "{\"example-last-modified:last-modified\":"
	    "\"2015-09-16T10:27:35+02:00\"}],"
	    "\"item\":[{\"@\":{\"example-last-modified:last-modified\":"
	    "\"2015-09-16T10:27:35+02:00\"},\"name\":\"a\"}]}}");
	ATF_CHECK_MSG(ucl_object_compare(want, got) == 0, "%s", out);
	ucl_object_unref(got);
	free(out);
	/* cblink's JSON of the tree: the same shape. */
	ATF_REQUIRE(cbl_dtree_json(t, &k) == 0);
	out = text(&k);
	got = json(out);
	ATF_CHECK_MSG(ucl_object_compare(want, got) == 0, "cblink's: %s", out);
	ucl_object_unref(got);
	free(out);
	ucl_object_unref(want);
	cbl_dtree_free(t);
	cbl_ybuf_free(&c);
	cbl_ybuf_free(&j);
	cbl_ybuf_free(&k);
	ysids_free(s);
}

/*
 * A peer that numbers every item 500 on, and has a node the console's
 * tables do not: its YANG-CBOR named and typed by its files, that node
 * as CBOR's kind says; the console's own numbering reads it as nothing.
 */
ATF_TC_WITHOUT_HEAD(peer_sids);
ATF_TC_BODY(peer_sids, tc)
{
	static const char doc[] = "{\"example-foomod:top\":{\"foo\":7,"
	    "\"kind\":\"example-foomod:cat\",\"where\":"
	    "\"/example-foomod:top/foo\"}}";
	struct ysids	*own = view(0, NULL, 0), *peer;
	const struct ysid_item *it;
	struct cbl_ybuf	 c = { NULL, 0, 0 }, j = { NULL, 0, 0 };
	ucl_object_t	*v, *got;
	const char	*tag;
	char		 why[256], *out;
	uint8_t		*p;

	peer = view(500, "/example-foomod:top/newer", 99599);
	ATF_REQUIRE((it = ysids_data(peer, "/example-foomod:top/foo")) !=
	    NULL);
	ATF_CHECK_EQ(99509, it->sid);
	ATF_CHECK(it->what != NULL && it->what == ysids_data(own,
	    "/example-foomod:top/foo")->what);
	ATF_REQUIRE((it = ysids_data(peer, "/example-foomod:top/newer")) !=
	    NULL);
	ATF_CHECK(it->what == NULL);
	ATF_CHECK_EQ(99503, it->base);
	both_ways(peer, doc, NO_CBLINK);
	v = json(doc);
	ATF_REQUIRE(yx_cbor(peer, v, &c, &tag, why, sizeof(why)) == 0);
	ucl_object_unref(v);
	/* Read by the console's own numbering: SIDs it does not have. */
	ATF_CHECK(yx_json(own, c.p, c.len, &j, why, sizeof(why)) != 0);
	cbl_ybuf_free(&j);
	cbl_ybuf_free(&c);
	memset(&j, 0, sizeof(j));
	/* The peer's {top: {newer(+96): 5, foo(+6): 7}}, by hand. */
	p = (uint8_t[]){ 0xa1, 0x1a, 0x00, 0x01, 0x84, 0xaf, 0xa2, 0x18, 0x60,
	    0x05, 0x06, 0x07 };
	ATF_REQUIRE_MSG(yx_json(peer, p, 12, &j, why, sizeof(why)) == 0, "%s",
	    why);
	out = text(&j);
	got = json(out);
	v = json("{\"example-foomod:top\":{\"newer\":5,\"foo\":7}}");
	ATF_CHECK_MSG(ucl_object_compare(v, got) == 0, "%s", out);
	ucl_object_unref(v);
	ucl_object_unref(got);
	free(out);
	cbl_ybuf_free(&j);
	ysids_free(own);
	ysids_free(peer);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, rfc7951);
	ATF_TP_ADD_TC(tp, rfc7952);
	ATF_TP_ADD_TC(tp, peer_sids);
	return (atf_no_error());
}
