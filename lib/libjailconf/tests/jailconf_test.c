/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

#include <sys/stat.h>

#include <atf-c.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "jailconf.h"

static void
put(const char *path, const char *text)
{
	FILE	*fp;

	ATF_REQUIRE((fp = fopen(path, "w")) != NULL);
	ATF_REQUIRE(fputs(text, fp) >= 0);
	ATF_REQUIRE(fclose(fp) == 0);
}

/*
 * Write text to jail.conf, edit one value of one jail and return the new
 * text, or NULL with the error in err.
 */
static char *
edit(const char *text, const char *jail, const char *key, const char *value,
    bool add, char *err, size_t errlen)
{
	struct jc_conf	 conf;
	struct jc_block	*b;
	struct jc_file	*f;
	size_t		 len;
	char		*out;

	put("jail.conf", text);
	ATF_REQUIRE_MSG(jc_load(&conf, "jail.conf") == 0, "load: %s",
	    conf.error);
	ATF_REQUIRE_MSG((b = jc_find(&conf, jail, &f)) != NULL,
	    "no jail %s", jail);
	out = NULL;
	err[0] = '\0';
	if (jc_edit(&conf, f, b, key, value, add, &out, &len, err,
	    errlen) == 0) {
		ATF_CHECK_EQ(strlen(out), len);
		ATF_CHECK_MSG(jc_verify("jail.conf", out, len, jail, key,
		    value, add), "edit does not verify");
	}
	jc_free(&conf);
	return (out);
}

#define	EDIT_OK(text, jail, key, value, add, want) do {			\
	char	 _err[256], *_out;					\
									\
	_out = edit(text, jail, key, value, add, _err, sizeof(_err));	\
	ATF_REQUIRE_MSG(_out != NULL, "%s", _err);			\
	ATF_CHECK_STREQ(want, _out);					\
	free(_out);							\
} while (0)

#define	EDIT_FAILS(text, jail, key, value, add, msg) do {		\
	char	 _err[256], *_out;					\
									\
	_out = edit(text, jail, key, value, add, _err, sizeof(_err));	\
	ATF_CHECK_MSG(_out == NULL, "edit succeeded");			\
	ATF_CHECK_MSG(strstr(_err, msg) != NULL, "error '%s' lacks '%s'",\
	    _err, msg);							\
	free(_out);							\
} while (0)

ATF_TC_WITHOUT_HEAD(add_extends_list);
ATF_TC_BODY(add_extends_list, tc)
{

	EDIT_OK("web {\n\tip4.addr = 10.0.0.10, \"10.0.0.11\";\n}\n",
	    "web", "ip4.addr", "10.0.0.12", true,
	    "web {\n\tip4.addr = 10.0.0.10, \"10.0.0.11\", "
	    "\"10.0.0.12\";\n}\n");
}

ATF_TC_WITHOUT_HEAD(add_keeps_quote_style);
ATF_TC_BODY(add_keeps_quote_style, tc)
{

	EDIT_OK("web {\n\tip4.addr = '10.0.0.10';\n}\n",
	    "web", "ip4.addr", "10.0.0.12", true,
	    "web {\n\tip4.addr = '10.0.0.10', '10.0.0.12';\n}\n");
}

ATF_TC_WITHOUT_HEAD(add_new_statement);
ATF_TC_BODY(add_new_statement, tc)
{

	EDIT_OK("# web server\nweb {\n    path = \"/j/web\";\n}\n",
	    "web", "ip6.addr", "2001:db8::12/64", true,
	    "# web server\nweb {\n    path = \"/j/web\";\n"
	    "    ip6.addr = \"2001:db8::12/64\";\n}\n");
}

ATF_TC_WITHOUT_HEAD(add_one_line_block);
ATF_TC_BODY(add_one_line_block, tc)
{

	EDIT_OK("cache { host.hostname = 'cache'; }\n",
	    "cache", "ip4.addr", "10.0.0.40", true,
	    "cache { host.hostname = 'cache'; ip4.addr = \"10.0.0.40\"; }\n");
}

ATF_TC_WITHOUT_HEAD(add_inherited_uses_append);
ATF_TC_BODY(add_inherited_uses_append, tc)
{

	EDIT_OK("ip4.addr = 10.1.0.1;\nx {\n\tpath = /;\n}\n",
	    "x", "ip4.addr", "10.1.0.2", true,
	    "ip4.addr = 10.1.0.1;\nx {\n\tpath = /;\n"
	    "\tip4.addr += \"10.1.0.2\";\n}\n");
}

ATF_TC_WITHOUT_HEAD(add_star_block_inherited);
ATF_TC_BODY(add_star_block_inherited, tc)
{

	EDIT_OK("* {\n\tip4.addr = 10.2.0.1;\n}\nx {\n\tpath = /;\n}\n",
	    "x", "ip4.addr", "10.2.0.2", true,
	    "* {\n\tip4.addr = 10.2.0.1;\n}\nx {\n\tpath = /;\n"
	    "\tip4.addr += \"10.2.0.2\";\n}\n");
}

ATF_TC_WITHOUT_HEAD(add_nested_child);
ATF_TC_BODY(add_nested_child, tc)
{

	EDIT_OK("p {\n\tip4.addr = 10.0.1.1;\n\tc {\n\t\tip4.addr = 10.0.1.2;"
	    "\n\t}\n}\n", "p.c", "ip4.addr", "10.0.1.3", true,
	    "p {\n\tip4.addr = 10.0.1.1;\n\tc {\n\t\tip4.addr = 10.0.1.2, "
	    "\"10.0.1.3\";\n\t}\n}\n");
}

ATF_TC_WITHOUT_HEAD(add_duplicate_refused);
ATF_TC_BODY(add_duplicate_refused, tc)
{

	EDIT_FAILS("web {\n\tip4.addr = \"em0|10.0.0.11/24\";\n}\n",
	    "web", "ip4.addr", "10.0.0.11", true, "already");
	EDIT_FAILS("ip4.addr = 10.1.0.1;\nx {\n\tpath = /;\n}\n",
	    "x", "ip4.addr", "10.1.0.1", true, "already");
}

ATF_TC_WITHOUT_HEAD(remove_first_value);
ATF_TC_BODY(remove_first_value, tc)
{

	EDIT_OK("web {\n\tip4.addr = 10.0.0.10, \"10.0.0.11\";\n}\n",
	    "web", "ip4.addr", "10.0.0.10", false,
	    "web {\n\tip4.addr = \"10.0.0.11\";\n}\n");
}

ATF_TC_WITHOUT_HEAD(remove_later_value);
ATF_TC_BODY(remove_later_value, tc)
{

	EDIT_OK("web {\n\tip4.addr = a, 10.0.0.10, 10.0.0.11;\n}\n",
	    "web", "ip4.addr", "10.0.0.10", false,
	    "web {\n\tip4.addr = a, 10.0.0.11;\n}\n");
}

ATF_TC_WITHOUT_HEAD(remove_last_value_drops_line);
ATF_TC_BODY(remove_last_value_drops_line, tc)
{

	EDIT_OK("db {\n\tpath = /j;\n\tip4.addr = \"em1|192.168.5.20/24\";  \n"
	    "\tpersist;\n}\n", "db", "ip4.addr", "192.168.5.20", false,
	    "db {\n\tpath = /j;\n\tpersist;\n}\n");
}

ATF_TC_WITHOUT_HEAD(remove_keeps_comment_line);
ATF_TC_BODY(remove_keeps_comment_line, tc)
{

	EDIT_OK("db {\n\tip4.addr = 10.0.0.1; # primary\n}\n",
	    "db", "ip4.addr", "10.0.0.1", false,
	    "db {\n\t # primary\n}\n");
}

ATF_TC_WITHOUT_HEAD(remove_inherited_refused);
ATF_TC_BODY(remove_inherited_refused, tc)
{

	EDIT_FAILS("ip4.addr = 10.1.0.1;\nx {\n\tpath = /;\n}\n",
	    "x", "ip4.addr", "10.1.0.1", false, "shared by all jails");
	EDIT_FAILS("x {\n\tpath = /;\n}\n", "x", "ip4.addr", "10.1.0.1",
	    false, "is not in ip4.addr");
}

ATF_TC_WITHOUT_HEAD(own_set_overrides_shared);
ATF_TC_BODY(own_set_overrides_shared, tc)
{

	/* The block's own "=" replaces the global value: it is not there. */
	EDIT_OK("ip4.addr = 10.1.0.1;\nx {\n\tip4.addr = 10.1.0.5;\n}\n",
	    "x", "ip4.addr", "10.1.0.1", true,
	    "ip4.addr = 10.1.0.1;\nx {\n\tip4.addr = 10.1.0.5, "
	    "\"10.1.0.1\";\n}\n");
}

ATF_TC_WITHOUT_HEAD(other_params_compare_text);
ATF_TC_BODY(other_params_compare_text, tc)
{

	EDIT_OK("w {\n\texec.start = \"/bin/sh /etc/rc\";\n}\n",
	    "w", "exec.start", "/usr/local/bin/app start", true,
	    "w {\n\texec.start = \"/bin/sh /etc/rc\", "
	    "\"/usr/local/bin/app start\";\n}\n");
}

ATF_TC_WITHOUT_HEAD(values_escaped);
ATF_TC_BODY(values_escaped, tc)
{

	EDIT_OK("w {\n\texec.start = 'a';\n}\n", "w", "exec.start",
	    "echo \"it's\" \\o/", true,
	    "w {\n\texec.start = 'a', 'echo \"it\\'s\" \\\\o/';\n}\n");
	EDIT_OK("w {\n}\n", "w", "exec.start", "say \"hi\"", true,
	    "w {\n\texec.start = \"say \\\"hi\\\"\";\n}\n");
}

ATF_TC_WITHOUT_HEAD(includes_followed);
ATF_TC_BODY(includes_followed, tc)
{
	struct jc_conf	 conf;
	struct jc_file	*f;

	put("a.inc", "mail { ip4.addr = 10.0.0.30; }\n");
	put("jail.conf", ".include \"*.inc\";\nweb { path = /; }\n");
	ATF_REQUIRE_MSG(jc_load(&conf, "jail.conf") == 0, "%s", conf.error);
	ATF_REQUIRE(jc_find(&conf, "mail", &f) != NULL);
	ATF_CHECK_STREQ("a.inc", f->path);
	ATF_REQUIRE(jc_find(&conf, "web", &f) != NULL);
	ATF_CHECK_STREQ("jail.conf", f->path);
	jc_free(&conf);
}

ATF_TC_WITHOUT_HEAD(lexical_forms);
ATF_TC_BODY(lexical_forms, tc)
{
	struct jc_conf	 conf;
	struct jc_block	*b;

	/* Comments of every kind, variables, concatenation, escapes. */
	put("jail.conf", "/* c */ $d = \"lab\"; // c\n# c\n"
	    "w { host.hostname = \"w.${d}\"x; path = /j/$name; "
	    "ip4.addr = 10.0.0.1/* c */, 'em0|10.0.0.2'; }\n");
	ATF_REQUIRE_MSG(jc_load(&conf, "jail.conf") == 0, "%s", conf.error);
	ATF_REQUIRE((b = jc_find(&conf, "w", NULL)) != NULL);
	ATF_CHECK_EQ(3, b->nstmts);
	ATF_CHECK(jc_block_has(b, "ip4.addr", "10.0.0.2"));
	ATF_CHECK(jc_block_has(b, "ip4.addr", "10.0.0.1/24"));
	ATF_CHECK(!jc_block_has(b, "ip4.addr", "10.0.0.3"));
	jc_free(&conf);
}

ATF_TC_WITHOUT_HEAD(parse_errors);
ATF_TC_BODY(parse_errors, tc)
{
	struct jc_conf	conf;

	put("jail.conf", "w {\n\tip4.addr = \"10.9.9.9;\n}\n");
	ATF_CHECK_EQ(-1, jc_load(&conf, "jail.conf"));
	ATF_CHECK_STREQ("jail.conf line 2: unterminated string", conf.error);
	jc_free(&conf);
	put("jail.conf", "w {\n\tpath = /;\n");
	ATF_CHECK_EQ(-1, jc_load(&conf, "jail.conf"));
	ATF_CHECK_MSG(strstr(conf.error, "end of file") != NULL, "%s",
	    conf.error);
	jc_free(&conf);
}

ATF_TC_WITHOUT_HEAD(addresses);
ATF_TC_BODY(addresses, tc)
{
	unsigned char	a[16];
	int		af, plen;

	ATF_CHECK(jc_addr_split("em0|10.0.0.1/24", &af, a, &plen));
	ATF_CHECK_EQ(24, plen);
	ATF_CHECK(jc_addr_split("2001:db8::1", &af, a, &plen));
	ATF_CHECK_EQ(-1, plen);
	ATF_CHECK(!jc_addr_split("10.0.0.300", &af, a, &plen));
	ATF_CHECK(!jc_addr_split("10.0.0.1/33", &af, a, &plen));
	ATF_CHECK(jc_value_equal("ip6.addr", "2001:db8:0::1/64",
	    "2001:db8::1"));
	ATF_CHECK(!jc_value_equal("ip4.addr", "10.0.0.1", "2001:db8::1"));
	ATF_CHECK(!jc_value_equal("path", "/a/", "/a"));
}

ATF_TC_WITHOUT_HEAD(diff_format);
ATF_TC_BODY(diff_format, tc)
{
	const char	*a = "1\n2\n3\n4\nx\n6\n7\n8\n9\n";
	const char	*b = "1\n2\n3\n4\ny\nz\n6\n7\n8\n9\n";
	char		*d;

	d = jc_diff("f", a, strlen(a), b, strlen(b));
	ATF_CHECK_STREQ("--- f\n+++ f\n@@ -2,7 +2,8 @@\n 2\n 3\n 4\n-x\n+y\n"
	    "+z\n 6\n 7\n 8\n", d);
	free(d);
}

ATF_TC_WITHOUT_HEAD(write_atomic);
ATF_TC_BODY(write_atomic, tc)
{
	struct stat	 sb;
	char		 err[256], buf[64];
	FILE		*fp;

	put("jail.conf", "old\n");
	ATF_REQUIRE(chmod("jail.conf", 0640) == 0);
	ATF_REQUIRE_MSG(jc_write("jail.conf", "new\n", 4, err,
	    sizeof(err)) == 0, "%s", err);
	ATF_REQUIRE(stat("jail.conf", &sb) == 0);
	ATF_CHECK_EQ(0640, sb.st_mode & 0777);
	ATF_REQUIRE((fp = fopen("jail.conf", "r")) != NULL);
	ATF_REQUIRE(fgets(buf, sizeof(buf), fp) != NULL);
	fclose(fp);
	ATF_CHECK_STREQ("new\n", buf);
	ATF_CHECK_EQ(-1, jc_write("missing.conf", "x", 1, err, sizeof(err)));
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, add_extends_list);
	ATF_TP_ADD_TC(tp, add_keeps_quote_style);
	ATF_TP_ADD_TC(tp, add_new_statement);
	ATF_TP_ADD_TC(tp, add_one_line_block);
	ATF_TP_ADD_TC(tp, add_inherited_uses_append);
	ATF_TP_ADD_TC(tp, add_star_block_inherited);
	ATF_TP_ADD_TC(tp, add_nested_child);
	ATF_TP_ADD_TC(tp, add_duplicate_refused);
	ATF_TP_ADD_TC(tp, remove_first_value);
	ATF_TP_ADD_TC(tp, remove_later_value);
	ATF_TP_ADD_TC(tp, remove_last_value_drops_line);
	ATF_TP_ADD_TC(tp, remove_keeps_comment_line);
	ATF_TP_ADD_TC(tp, remove_inherited_refused);
	ATF_TP_ADD_TC(tp, own_set_overrides_shared);
	ATF_TP_ADD_TC(tp, other_params_compare_text);
	ATF_TP_ADD_TC(tp, values_escaped);
	ATF_TP_ADD_TC(tp, includes_followed);
	ATF_TP_ADD_TC(tp, lexical_forms);
	ATF_TP_ADD_TC(tp, parse_errors);
	ATF_TP_ADD_TC(tp, addresses);
	ATF_TP_ADD_TC(tp, diff_format);
	ATF_TP_ADD_TC(tp, write_atomic);
	return (atf_no_error());
}
