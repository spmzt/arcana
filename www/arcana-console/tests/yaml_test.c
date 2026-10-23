/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * The panel's YAML (www/arcana-ui/src/yaml.c), built natively against
 * base's libucl and libyaml: what it writes reads back as the object it
 * was, and what one writes by hand is read as YAML 1.2's core schema
 * says, an alias refused.
 */

#include <atf-c.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <ucl.h>

char		*yaml_emit(const ucl_object_t *);
ucl_object_t	*yaml_parse(const char *, char *, size_t);

static ucl_object_t *
json(const char *s)
{
	struct ucl_parser	*p;
	ucl_object_t		*o;

	p = ucl_parser_new(UCL_PARSER_NO_IMPLICIT_ARRAYS);
	ATF_REQUIRE(ucl_parser_add_string(p, s, 0));
	o = ucl_parser_get_object(p);
	ucl_parser_free(p);
	return (o);
}

/* Written and read back: the same object. */
static void
round_trip(const ucl_object_t *o)
{
	ucl_object_t	*back;
	char		*y, err[200];

	y = yaml_emit(o);
	back = yaml_parse(y, err, sizeof(err));
	ATF_REQUIRE_MSG(back != NULL, "%s\n%s", err, y);
	ATF_CHECK_MSG(ucl_object_compare(o, back) == 0, "not the same:\n%s",
	    y);
	ucl_object_unref(back);
	free(y);
}

ATF_TC_WITHOUT_HEAD(round_trip);
ATF_TC_BODY(round_trip, tc)
{
	ucl_object_t	*o;
	char		*y;

	o = json("{\"name\":\"a: b\",\"n\":3,\"neg\":-7,\"f\":1.5,\"e\":2e-5,"
	    "\"t\":true,\"z\":null,\"empty\":\"\",\"yes\":\"yes\",\"no\":\"No\","
	    "\"num\":\"0123\",\"ver\":\"0.115.0\",\"ip\":\"192.0.2.1\",\"v6\":"
	    "\"2001:db8::1\",\"multi\":\"line1\\nline2\\n\",\"lead\":\"  sp\","
	    "\"nolf\":\"a\\nb\",\"lf2\":\"x\\n\\n\",\"arr\":[1,\"x\",{\"k\":\"v\","
	    "\"k2\":[1,2]},[],[[1,2],{\"a\":{}}]],\"o\":{},\"q\":\"he said "
	    "\\\"hi\\\" #c\",\"k-ey with space\":\"- dash\",\"hash\":\"a#b\","
	    "\"url\":\"https://x.y/z\",\"star\":\"*\",\"tilde\":\"~\",\"dot\":"
	    "\".5\",\"conf\":\"# comment\\nifconfig_em0=\\\"DHCP\\\"\\n\\n  "
	    "indented\\n\",\"utf\":\"caf\\u00e9\",\"id\":\"933e5390\"}");
	round_trip(o);
	/* Lines of text a literal block, the words that would be read as
	 * something else quoted, plain what may be. */
	y = yaml_emit(o);
	ATF_CHECK(strstr(y, "\nconf: |\n  # comment\n  ifconfig_em0=\"DHCP\"\n"
	    "\n    indented\n") != NULL);
	ATF_CHECK(strstr(y, "\n\"yes\": \"yes\"\n") != NULL);
	ATF_CHECK(strstr(y, "\nver: \"0.115.0\"\n") != NULL);
	ATF_CHECK(strstr(y, "\nurl: https://x.y/z\n") != NULL);
	ATF_CHECK(strstr(y, "\n  - k: v\n    k2:\n      - 1\n") != NULL);
	free(y);
	ucl_object_unref(o);
	/* The panel's own documents, as they are served. */
	{
		static const char *const files[] = { "openapi.json",
		    "schema.json", "yang.json" };
		char	path[1024], *buf;
		FILE	*fp;
		size_t	n;

		for (size_t i = 0; i < sizeof(files) / sizeof(files[0]); i++) {
			snprintf(path, sizeof(path), "%s/%s", DISTDIR,
			    files[i]);
			if ((fp = fopen(path, "r")) == NULL)
				continue;
			buf = malloc(8 << 20);
			n = fread(buf, 1, (8 << 20) - 1, fp);
			buf[n] = '\0';
			fclose(fp);
			o = json(buf);
			round_trip(o);
			ucl_object_unref(o);
			free(buf);
		}
	}
}

ATF_TC_WITHOUT_HEAD(by_hand);
ATF_TC_BODY(by_hand, tc)
{
	ucl_object_t	*o;
	char		 err[200], *j;

	o = yaml_parse("# a workflow by hand\nname: Restart\nhosts: "
	    "[933e5390, 12]\nparams:\n  - {name: service, default: nginx}\n"
	    "on:\n  - event: crash\n    match: {process: \"${param.p}\", jid: "
	    "\"0\"}\nx: 0x1F\ny: 1.5e3\nz: ~\nw: yes\nt: True\nq: 'it''s'\n",
	    err, sizeof(err));
	ATF_REQUIRE_MSG(o != NULL, "%s", err);
	j = (char *)ucl_object_emit(o, UCL_EMIT_JSON_COMPACT);
	/* A host's id that looks like a too big float stays a word; yes
	 * is YAML 1.1's boolean only, a string here. */
	ATF_CHECK_STREQ_MSG("{\"name\":\"Restart\",\"hosts\":[\"933e5390\",12],"
	    "\"params\":[{\"name\":\"service\",\"default\":\"nginx\"}],\"on\":"
	    "[{\"event\":\"crash\",\"match\":{\"process\":\"${param.p}\","
	    "\"jid\":\"0\"}}],\"x\":31,\"y\":1500.0,\"z\":null,\"w\":\"yes\","
	    "\"t\":true,\"q\":\"it's\"}", j, "%s", j);
	free(j);
	ucl_object_unref(o);
	/* An alias is refused: a few lines could stand for a great many. */
	ATF_CHECK(yaml_parse("a: &x [1, 2]\nb: *x\n", err, sizeof(err)) ==
	    NULL);
	ATF_CHECK(strstr(err, "alias") != NULL);
	ATF_CHECK(yaml_parse("a: [1, 2\n", err, sizeof(err)) == NULL);
	ATF_CHECK(strstr(err, "line 2") != NULL);
}

/* A key with a blank and no value: a description's continuation that
 * a comma in a flow mapping made a key of ("one at least": null). */
static const char *
stray_key(const ucl_object_t *o)
{
	const ucl_object_t	*v;
	ucl_object_iter_t	 it;
	const char		*k, *s;

	if (ucl_object_type(o) != UCL_OBJECT && ucl_object_type(o) != UCL_ARRAY)
		return (NULL);
	it = NULL;
	while ((v = ucl_object_iterate(o, &it, true)) != NULL) {
		k = ucl_object_type(o) == UCL_OBJECT ? ucl_object_key(v) : NULL;
		if (k != NULL && strchr(k, ' ') != NULL && ucl_object_type(v) ==
		    UCL_NULL)
			return (k);
		if ((s = stray_key(v)) != NULL)
			return (s);
	}
	return (NULL);
}

/* docs/openapi.yaml parses: a ": " or an apostrophe loose in a plain
 * scalar stops every YAML reader at that line, the app's included. */
ATF_TC_WITHOUT_HEAD(openapi);
ATF_TC_BODY(openapi, tc)
{
	ucl_object_t	*o;
	FILE		*fp;
	char		*text, err[256];
	long		 len;

	ATF_REQUIRE_MSG((fp = fopen(OPENAPI, "r")) != NULL, "%s", OPENAPI);
	ATF_REQUIRE(fseek(fp, 0, SEEK_END) == 0 && (len = ftell(fp)) > 0);
	rewind(fp);
	ATF_REQUIRE((text = malloc((size_t)len + 1)) != NULL);
	ATF_REQUIRE(fread(text, 1, (size_t)len, fp) == (size_t)len);
	text[len] = '\0';
	fclose(fp);
	err[0] = '\0';
	o = yaml_parse(text, err, sizeof(err));
	ATF_REQUIRE_MSG(o != NULL, "docs/openapi.yaml: %s", err);
	ATF_CHECK(ucl_object_lookup(o, "openapi") != NULL);
	ATF_CHECK(ucl_object_lookup(o, "paths") != NULL);
	ATF_CHECK(ucl_object_lookup(ucl_object_lookup(ucl_object_lookup(o,
	    "components"), "schemas"), "Run") != NULL);
	ATF_CHECK_MSG(stray_key(o) == NULL, "a description cut by a comma in a "
	    "flow mapping: \"%s\"", stray_key(o));
	ucl_object_unref(o);
	free(text);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, round_trip);
	ATF_TP_ADD_TC(tp, by_hand);
	ATF_TP_ADD_TC(tp, openapi);
	return (atf_no_error());
}
