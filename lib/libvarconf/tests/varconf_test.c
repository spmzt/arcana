/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * libvarconf against sh(1): each fixture read and written again byte for
 * byte, and every variable it settles the value sh(1) gives it; edits
 * that change the bytes of the value they are about and no other;
 * what reading cannot settle refused.
 */

#include <sys/param.h>
#include <sys/stat.h>

#include <atf-c.h>
#include <errno.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "fixtures.h"
#include "varconf.h"

static void
put(const char *path, const char *text, size_t len)
{
	FILE *fp;

	ATF_REQUIRE((fp = fopen(path, "w")) != NULL);
	ATF_REQUIRE(fwrite(text, 1, len, fp) == len);
	ATF_REQUIRE(fclose(fp) == 0);
}

static char *
slurp(const char *path, size_t *len)
{
	FILE *fp;
	char *s = NULL;
	size_t cap = 0, n;

	*len = 0;
	ATF_REQUIRE((fp = fopen(path, "r")) != NULL);
	for (;;) {
		if (*len + 4096 + 1 > cap) {
			cap = (*len + 4096 + 1) * 2;
			ATF_REQUIRE((s = realloc(s, cap)) != NULL);
		}
		if ((n = fread(s + *len, 1, 4096, fp)) == 0)
			break;
		*len += n;
	}
	fclose(fp);
	s[*len] = '\0';
	return (s);
}

static const struct fixture *
fixture(const char *name)
{

	for (const struct fixture *x = fixtures; x->name != NULL; x++)
		if (strcmp(x->name, name) == 0)
			return (x);
	ATF_REQUIRE_MSG(false, "no fixture %s", name);
	return (NULL);
}

static void
parse_d(struct vc_file *f, enum vc_dialect d, const char *text, size_t len)
{
	char err[256];

	ATF_REQUIRE_MSG(vc_parse(f, d, text, len, err, sizeof(err)) == 0,
	    "%s", err);
}

static void
parse(struct vc_file *f, const char *text, size_t len)
{

	parse_d(f, VC_SH, text, len);
}

/* A fixture's dialect, by its name. */
static enum vc_dialect
dialect(const char *name)
{

	return (strncmp(name, "loader-", 7) == 0 ? VC_LOADER :
	    strncmp(name, "sysctl-", 7) == 0 ? VC_SYSCTL : VC_SH);
}

/*
 * What sh(1) gives names after reading the file text: their values in
 * order, NUL-separated in *out.
 */
static char *
sh_values(const char *text, size_t len, const char *const *names, size_t n,
    size_t *outlen)
{
	static const char script[] =
	    ". \"$1\" >/dev/null 2>&1\n"
	    "shift\n"
	    "for __vc_n; do\n"
	    "\teval \"__vc_v=\\${$__vc_n}\"\n"
	    "\tprintf '%s\\0' \"$__vc_v\"\n"
	    "done\n";
	char *out, *cmd = NULL;
	size_t clen = 0;
	FILE *fp;

	put("values.sh", script, sizeof(script) - 1);
	put("input.conf", text, len);
	ATF_REQUIRE((fp = open_memstream(&cmd, &clen)) != NULL);
	fprintf(fp, "env -i /bin/sh ./values.sh ./input.conf");
	for (size_t i = 0; i < n; i++)
		fprintf(fp, " %s", names[i]);
	fprintf(fp, " > values.out");
	fclose(fp);
	ATF_REQUIRE_EQ(0, system(cmd));
	free(cmd);
	out = slurp("values.out", outlen);
	return (out);
}

/* Every name f settles, once, whose value sh(1) gives as f has it. */
static size_t
check_sh(const struct vc_file *f)
{
	const char **names;
	char *out, *p;
	size_t n = 0, outlen;

	ATF_REQUIRE((names = calloc(f->na + 1, sizeof(*names))) != NULL);
	for (size_t i = 0; i < f->na; i++) {
		const struct vc_assign *a = &f->a[i];
		bool seen = false;

		if (vc_get(f, a->name) != a || !vc_settled(f, a->name))
			continue;
		for (size_t j = 0; j < n; j++)
			seen = seen || strcmp(names[j], a->name) == 0;
		if (!seen)
			names[n++] = a->name;
	}
	out = sh_values(f->text, f->len, names, n, &outlen);
	p = out;
	for (size_t i = 0; i < n; i++) {
		const struct vc_assign *a = vc_get(f, names[i]);

		ATF_REQUIRE_MSG(p < out + outlen, "%s: sh(1) gave no value",
		    names[i]);
		ATF_CHECK_MSG(strcmp(a->value, p) == 0, "%s: \"%s\", sh(1) "
		    "\"%s\"", names[i], a->value, p);
		p += strlen(p) + 1;
	}
	free(out);
	free(names);
	return (n);
}

#define	FLUA		"/usr/libexec/flua"
#define	CONFIG_LUA	"/boot/lua/config.lua"

/*
 * The loader's own reading: config.lua's config.parse() run by flua, the
 * loader's functions stand-ins over a table, the names' values out, NUL
 * after each, \1 for none.
 */
static const char loader_lua[] =
    "package.path = \"/boot/lua/?.lua;\" .. package.path\n"
    "local env = {}\n"
    "print = function() end\n"
    "loader = {\n"
    "\tgetenv = function(k) return env[k] end,\n"
    "\tsetenv = function(k, v) env[k] = v; return 0 end,\n"
    "\tunsetenv = function(k) env[k] = nil; return 0 end,\n"
    "\tprintc = function() end,\n"
    "\tperform = function() return 0 end,\n"
    "\tcommand_error = function() return \"\" end,\n"
    "}\n"
    "function cli_execute_unparsed() return 0 end\n"
    "local config = require(\"config\")\n"
    "local f = assert(io.open(arg[1]))\n"
    "config.parse(f:read(\"a\"))\n"
    "f:close()\n"
    "for i = 2, #arg do\n"
    "\tlocal v = env[arg[i]]\n"
    "\tio.write(v == nil and \"\\1\" or v, \"\\0\")\n"
    "end\n";

/*
 * Every name f settles, once, whose value the loader gives as f has it
 * (but loader_conf_files, which config.lua keeps from the environment).
 * The loader's own reader, the base system's flua, is required.
 */
static size_t
check_loader(const struct vc_file *f)
{
	const char **names;
	char *out, *p, *cmd = NULL;
	size_t n = 0, outlen, clen = 0;
	FILE *fp;

	/* The base system's: every FreeBSD Arcana runs on has them. */
	ATF_REQUIRE_MSG(access(FLUA, X_OK) == 0 && access(CONFIG_LUA, R_OK) ==
	    0, "no " FLUA " or " CONFIG_LUA " to ask the loader with");
	ATF_REQUIRE((names = calloc(f->na + 1, sizeof(*names))) != NULL);
	for (size_t i = 0; i < f->na; i++) {
		const struct vc_assign *a = &f->a[i];
		bool seen = false;

		if (vc_get(f, a->name) != a || !vc_settled(f, a->name) ||
		    strcmp(a->name, "loader_conf_files") == 0)
			continue;
		for (size_t j = 0; j < n; j++)
			seen = seen || strcmp(names[j], a->name) == 0;
		if (!seen)
			names[n++] = a->name;
	}
	put("loader.lua", loader_lua, sizeof(loader_lua) - 1);
	put("input.conf", f->text, f->len);
	ATF_REQUIRE((fp = open_memstream(&cmd, &clen)) != NULL);
	fprintf(fp, FLUA " ./loader.lua ./input.conf");
	for (size_t i = 0; i < n; i++)
		fprintf(fp, " '%s'", names[i]);
	fprintf(fp, " > values.out");
	fclose(fp);
	ATF_REQUIRE_EQ(0, system(cmd));
	free(cmd);
	out = slurp("values.out", &outlen);
	p = out;
	for (size_t i = 0; i < n; i++) {
		const struct vc_assign *a = vc_get(f, names[i]);

		ATF_REQUIRE_MSG(p < out + outlen, "%s: the loader gave no "
		    "value", names[i]);
		ATF_CHECK_MSG(strcmp(a->value, p) == 0, "%s: \"%s\", the "
		    "loader \"%s\"", names[i], a->value, p);
		p += strlen(p) + 1;
	}
	free(out);
	free(names);
	return (n);
}

/*
 * Each fixture read and written byte for byte; sh(1) and the loader
 * agree with what is read of theirs.
 */
ATF_TC_WITHOUT_HEAD(fixtures);
ATF_TC_BODY(fixtures, tc)
{
	for (const struct fixture *x = fixtures; x->name != NULL; x++) {
		enum vc_dialect d = dialect(x->name);

		/* rtadvd.conf's are records, not assignments: below. */
		if (strncmp(x->name, "rtadvd-", 7) == 0)
			continue;
		struct vc_file f;
		char err[256], *back;
		size_t len, n;

		parse_d(&f, d, x->text, x->len);
		ATF_CHECK_EQ(x->len, f.len);
		ATF_CHECK(memcmp(x->text, f.text, x->len) == 0);
		ATF_REQUIRE_MSG(vc_write(&f, "back.conf", 0644, err,
		    sizeof(err)) == 0, "%s", err);
		back = slurp("back.conf", &len);
		ATF_CHECK_EQ_MSG(x->len, len, "%s", x->name);
		ATF_CHECK_MSG(memcmp(x->text, back, len) == 0, "%s", x->name);
		free(back);
		n = d == VC_SH ? check_sh(&f) : d == VC_LOADER ?
		    check_loader(&f) : f.na;
		ATF_CHECK_MSG(n >= 10, "%s: %zu settled", x->name, n);
		vc_free(&f);
	}
}

static const struct vc_assign *
must_get(const struct vc_file *f, const char *name)
{
	const struct vc_assign *a = vc_get(f, name);

	ATF_REQUIRE_MSG(a != NULL, "%s: not found", name);
	return (a);
}

static void
check_value(const struct vc_file *f, const char *name, const char *value)
{
	const struct vc_assign *a = must_get(f, name);

	ATF_CHECK_MSG(vc_settled(f, name), "%s: not settled", name);
	ATF_REQUIRE_MSG(a->value != NULL, "%s: no value", name);
	ATF_CHECK_MSG(strcmp(a->value, value) == 0, "%s: \"%s\"", name,
	    a->value);
}

static void
check_flags(const struct vc_file *f, const char *name, unsigned flags)
{
	const struct vc_assign *a = must_get(f, name);

	ATF_CHECK_MSG((a->flags & flags) == flags, "%s: flags %#x", name,
	    a->flags);
	ATF_CHECK(!vc_settled(f, name));
}

/* What edge.conf's lines are, each. */
ATF_TC_WITHOUT_HEAD(edge);
ATF_TC_BODY(edge, tc)
{
	const struct fixture *x = fixture("edge.conf");
	static const char *const computed[] = { "computed", "computed2",
	    "computed3", "computed4", "tilde", "tilde2" };
	static const char *const opaque[] = { "cmdenv", "incase", "inloop",
	    "amp", "amp2" };
	struct vc_file f;

	parse(&f, x->text, x->len);
	check_value(&f, "plain", "YES");
	check_value(&f, "dq", "a b  c");
	check_value(&f, "sq", "single $not expanded");
	check_value(&f, "mixed", "abc");
	check_value(&f, "empty", "");
	check_value(&f, "esc_dq", "a\"b\\c$d`e");
	check_value(&f, "esc_un", "a b#c");
	check_value(&f, "bs_other", "a\\nb");
	check_value(&f, "hash_in", "a#b");
	check_value(&f, "multi", "one\ntwo\nthree");
	check_value(&f, "cont", "continued");
	check_value(&f, "cont_un", "continued_too");
	check_value(&f, "three", "2");
	check_value(&f, "semi2", "2");
	check_value(&f, "indented", "yes");
	check_value(&f, "nottilde", "a~b");
	check_value(&f, "dollar_lit", "a$");
	check_value(&f, "dollar_lit2", "$ x");
	check_value(&f, "after_heredoc", "ok");
	check_value(&f, "last", "two");
	check_value(&f, "noeol", "end");
	for (size_t i = 0; i < nitems(computed); i++)
		check_flags(&f, computed[i], VC_COMPUTED);
	for (size_t i = 0; i < nitems(opaque); i++)
		check_flags(&f, opaque[i], VC_OPAQUE);
	check_flags(&f, "inif", VC_COND);
	check_flags(&f, "infn", VC_COND);
	/* A here-document's lines are data. */
	ATF_CHECK(vc_get(&f, "heredoc_var") == NULL);
	ATF_CHECK(vc_get(&f, "hd2") == NULL);
	ATF_CHECK_EQ(1, must_get(&f, "dq")->nstmt);
	ATF_CHECK_EQ(2, must_get(&f, "two")->nstmt);
	vc_free(&f);
}

/* The file f's text is was's with bytes [s, e) made r. */
static void
check_splice(const struct vc_file *f, const char *was, size_t wlen, size_t s,
    size_t e, const char *r)
{
	size_t rlen = strlen(r);

	ATF_REQUIRE_EQ_MSG(wlen - (e - s) + rlen, f->len, "%s", f->text);
	ATF_CHECK(memcmp(f->text, was, s) == 0);
	ATF_CHECK_MSG(memcmp(f->text + s, r, rlen) == 0, "%.*s",
	    (int)rlen, f->text + s);
	ATF_CHECK(memcmp(f->text + s + rlen, was + e, wlen - e) == 0);
}

static void
set(struct vc_file *f, const char *name, const char *value)
{
	char err[256];

	ATF_REQUIRE_MSG(vc_set(f, name, value, err, sizeof(err)) == 0,
	    "%s", err);
}

static void
unset(struct vc_file *f, const char *name)
{
	char err[256];

	ATF_REQUIRE_MSG(vc_unset(f, name, err, sizeof(err)) == 0, "%s",
	    err);
}

/* Edits of host.conf: each the bytes of its value or its line alone. */
ATF_TC_WITHOUT_HEAD(edits);
ATF_TC_BODY(edits, tc)
{
	const struct fixture *x = fixture("host.conf");
	const struct vc_assign *a;
	struct vc_file f;
	char *was;
	size_t wlen, s, e;

	parse(&f, x->text, x->len);
	/* A value replaced, its quotes and the rest of its line kept. */
	a = must_get(&f, "ifconfig_em1");
	s = a->voff;
	e = a->vend;
	set(&f, "ifconfig_em1", "inet 192.0.2.5/24");
	check_splice(&f, x->text, x->len, s, e, "\"inet 192.0.2.5/24\"");
	check_sh(&f);
	/* The same again: not a byte changed; and back: the file as it
	 * was. */
	ATF_REQUIRE((was = strndup(f.text, f.len)) != NULL);
	wlen = f.len;
	set(&f, "ifconfig_em1", "inet 192.0.2.5/24");
	ATF_CHECK(f.len == wlen && memcmp(f.text, was, wlen) == 0);
	free(was);
	set(&f, "ifconfig_em1", "inet 192.0.2.1/24");
	ATF_CHECK(f.len == x->len && memcmp(f.text, x->text, x->len) == 0);

	/* A line removed, a comment after it with it. */
	a = must_get(&f, "pf_enable");
	s = a->soff;
	e = a->send;
	unset(&f, "pf_enable");
	check_splice(&f, x->text, x->len, s, e, "");
	ATF_CHECK(vc_get(&f, "pf_enable") == NULL);
	ATF_CHECK(strstr(f.text, "pf.conf is not ready") == NULL);
	/* What is not there: nothing to remove. */
	unset(&f, "pf_enable");

	/* A new one at the end; one sh(1) reads with its quotes. */
	ATF_REQUIRE((was = strndup(f.text, f.len)) != NULL);
	wlen = f.len;
	set(&f, "ifconfig_em2", "inet 198.51.100.1/24");
	check_splice(&f, was, wlen, wlen, wlen,
	    "ifconfig_em2=\"inet 198.51.100.1/24\"\n");
	free(was);
	set(&f, "odd", "a\"b$c`d\\e 'f'");
	set(&f, "none", "");
	check_value(&f, "odd", "a\"b$c`d\\e 'f'");
	check_value(&f, "none", "");
	ATF_CHECK(check_sh(&f) >= 20);
	vc_free(&f);
}

/* Edits of edge.conf: quoting kept, lines shared, the end, refusals. */
ATF_TC_WITHOUT_HEAD(edits_edge);
ATF_TC_BODY(edits_edge, tc)
{
	const struct fixture *x = fixture("edge.conf");
	static const char *const busy[] = { "inif", "infn", "cmdenv",
	    "amp", "incase" };
	struct vc_file f;
	char err[256];

	parse(&f, x->text, x->len);
	/* The last line, no newline after it: none after the edit. */
	set(&f, "noeol", "fin");
	ATF_CHECK(f.text[f.len - 1] != '\n');
	ATF_CHECK(strcmp(f.text + f.len - 9, "noeol=fin") == 0);
	/* A new one: a newline first, its value quoted as sysrc(8) does. */
	set(&f, "added", "x");
	ATF_CHECK(strcmp(f.text + f.len - 20, "noeol=fin\nadded=\"x\"\n") ==
	    0);
	/* Single quotes kept, while they can be; a plain word too. */
	set(&f, "sq", "x y");
	ATF_CHECK(strstr(f.text, "sq='x y'\n") != NULL);
	set(&f, "sq", "it's");
	ATF_CHECK(strstr(f.text, "sq=\"it's\"\n") != NULL);
	set(&f, "plain", "NO");
	ATF_CHECK(strstr(f.text, "\nplain=NO\n") != NULL);
	set(&f, "plain", "a b");
	ATF_CHECK(strstr(f.text, "\nplain=\"a b\"\n") != NULL);
	/* One of two on a line: the other stays. */
	unset(&f, "two");
	ATF_CHECK(strstr(f.text, "\nthree=2\n") != NULL);
	unset(&f, "semi");
	ATF_CHECK(strstr(f.text, "\nsemi2=2\n") != NULL);
	/* Every assignment of it. */
	unset(&f, "last");
	ATF_CHECK(vc_get(&f, "last") == NULL);
	ATF_CHECK(strstr(f.text, "last=") == NULL);
	/* A computed one replaced: a literal now. */
	set(&f, "computed", "lit");
	check_value(&f, "computed", "lit");
	check_sh(&f);

	/* What reading does not settle, refused. */
	for (size_t i = 0; i < nitems(busy); i++) {
		ATF_CHECK_EQ(-1, vc_set(&f, busy[i], "1", err, sizeof(err)));
		ATF_CHECK_EQ(EBUSY, errno);
		ATF_CHECK_MSG(strstr(err, "by hand") != NULL, "%s", err);
		ATF_CHECK_EQ(-1, vc_unset(&f, busy[i], err, sizeof(err)));
	}
	ATF_CHECK(strstr(err, "line") != NULL);
	ATF_CHECK_EQ(-1, vc_set(&f, "1x", "1", err, sizeof(err)));
	ATF_CHECK_EQ(EINVAL, errno);
	ATF_CHECK_EQ(-1, vc_set(&f, "a-b", "1", err, sizeof(err)));
	ATF_CHECK_EQ(-1, vc_set(&f, "ok", "a\nb", err, sizeof(err)));
	ATF_CHECK_EQ(EINVAL, errno);
	vc_free(&f);
}

/* An assignment commented out where it is: the line kept under "#" with
 * the mark after it; one sharing its line on a line of its own before
 * it; what the mark says taken off gives the file again. */
ATF_TC_WITHOUT_HEAD(comments);
ATF_TC_BODY(comments, tc)
{
	const struct fixture *x = fixture("host.conf");
	const struct vc_assign *a;
	struct vc_file f;
	char err[256], *p;
	size_t s, e;

	parse(&f, x->text, x->len);
	a = must_get(&f, "pf_enable");
	s = a->soff;
	e = a->send;
	ATF_REQUIRE_MSG(vc_comment(&f, "pf_enable", "taken by Arcana", err,
	    sizeof(err)) == 0, "%s", err);
	check_splice(&f, x->text, x->len, s, e,
	    "#pf_enable=\"NO\"\t# pf.conf is not ready  # taken by Arcana\n");
	ATF_CHECK(vc_get(&f, "pf_enable") == NULL);
	/* Not there: nothing to do.  Back: "#" and the mark taken off. */
	ATF_REQUIRE_EQ(0, vc_comment(&f, "pf_enable", "taken by Arcana", err,
	    sizeof(err)));
	ATF_REQUIRE((p = strstr(f.text, "#pf_enable")) != NULL);
	memmove(p, p + 1, f.len - (size_t)(p - f.text));
	f.len--;
	ATF_REQUIRE((p = strstr(f.text, "  # taken by Arcana\n")) != NULL);
	memmove(p, p + 19, f.len - (size_t)(p + 19 - f.text) + 1);
	f.len -= 19;
	ATF_CHECK(f.len == x->len && memcmp(f.text, x->text, x->len) == 0);
	vc_free(&f);

	x = fixture("edge.conf");
	parse(&f, x->text, x->len);
	/* One of two on a line: on a line of its own; the other stays. */
	ATF_REQUIRE_MSG(vc_comment(&f, "three", "mark", err, sizeof(err)) ==
	    0, "%s", err);
	ATF_CHECK(strstr(f.text, "\n#three=2  # mark\ntwo=1 \n") != NULL);
	ATF_REQUIRE_MSG(vc_comment(&f, "semi", NULL, err, sizeof(err)) == 0,
	    "%s", err);
	ATF_CHECK(strstr(f.text, "\n#semi=1\nsemi2=2\n") != NULL);
	/* Every assignment of it. */
	ATF_REQUIRE_EQ(0, vc_comment(&f, "last", "m", err, sizeof(err)));
	ATF_CHECK(vc_get(&f, "last") == NULL);
	ATF_CHECK(strstr(f.text, "\n#last=one  # m\n#last=two  # m\n") != NULL);
	/* The last line, no newline after it: none after. */
	ATF_REQUIRE_EQ(0, vc_comment(&f, "noeol", "m", err, sizeof(err)));
	ATF_CHECK(f.text[f.len - 1] != '\n');
	ATF_CHECK(strcmp(f.text + f.len - 16, "\n#noeol=end  # m") == 0);
	check_value(&f, "two", "1");
	check_value(&f, "semi2", "2");
	/* What reading does not settle, refused. */
	ATF_CHECK_EQ(-1, vc_comment(&f, "inif", "m", err, sizeof(err)));
	ATF_CHECK_EQ(EBUSY, errno);
	check_sh(&f);
	vc_free(&f);
}

/* What sh(1) could not read: refused, the line said. */
ATF_TC_WITHOUT_HEAD(errors);
ATF_TC_BODY(errors, tc)
{
	static const char *const bad[] = { "x=\"abc\n", "a=1\nb=2\ny='a\n",
	    "z=$(echo\n", "w=`x\n" };
	static const char *const where[] = { "line 1", "line 3", "line 1",
	    "line 1" };
	struct vc_file f;
	char err[256];

	for (size_t i = 0; i < nitems(bad); i++) {
		ATF_CHECK_EQ(-1, vc_parse(&f, VC_SH, bad[i], strlen(bad[i]),
		    err, sizeof(err)));
		ATF_CHECK_EQ(EINVAL, errno);
		ATF_CHECK_MSG(strstr(err, where[i]) != NULL, "%s: %s", bad[i],
		    err);
	}
	ATF_CHECK_EQ(-1, vc_parse(&f, VC_SH, "a=1\0b=2\n", 8, err,
	    sizeof(err)));
	/* A file not there: empty. */
	ATF_REQUIRE_EQ(0, vc_read(&f, VC_SH, "nothing.conf", err,
	    sizeof(err)));
	ATF_CHECK_EQ(0, f.na);
	vc_free(&f);
}

/* rc.conf.d's fragments: a directory of the service's, not its file. */
ATF_TC_WITHOUT_HEAD(rcd);
ATF_TC_BODY(rcd, tc)
{
	struct stat sb;
	struct vc_file f;
	char path[1024], err[256];

	ATF_REQUIRE_EQ(0, mkdir("etc", 0755));
	ATF_REQUIRE_MSG(vc_rcd_path("etc", "netif", "arcana", path,
	    sizeof(path), err, sizeof(err)) == 0, "%s", err);
	ATF_CHECK_STREQ("etc/rc.conf.d/netif/arcana", path);
	ATF_REQUIRE_EQ(0, stat("etc/rc.conf.d/netif", &sb));
	ATF_CHECK(S_ISDIR(sb.st_mode));
	/* The fragment written, a new file of the mode asked. */
	ATF_REQUIRE_EQ(0, vc_read(&f, VC_SH, path, err, sizeof(err)));
	set(&f, "ifconfig_em1", "inet 192.0.2.1/24");
	ATF_REQUIRE_MSG(vc_write(&f, path, 0644, err, sizeof(err)) == 0,
	    "%s", err);
	ATF_REQUIRE_EQ(0, stat(path, &sb));
	ATF_CHECK_EQ(0644, sb.st_mode & 0777);
	vc_free(&f);
	/* The mode an old file has is kept. */
	ATF_REQUIRE_EQ(0, chmod(path, 0640));
	ATF_REQUIRE_EQ(0, vc_read(&f, VC_SH, path, err, sizeof(err)));
	set(&f, "ifconfig_em1", "inet 192.0.2.9/24");
	ATF_REQUIRE_EQ(0, vc_write(&f, path, 0644, err, sizeof(err)));
	ATF_REQUIRE_EQ(0, stat(path, &sb));
	ATF_CHECK_EQ(0640, sb.st_mode & 0777);
	vc_free(&f);
	/* The service's file, someone else's: refused. */
	put("etc/rc.conf.d/routing", "defaultrouter=x\n", 16);
	ATF_CHECK_EQ(-1, vc_rcd_path("etc", "routing", "arcana", path,
	    sizeof(path), err, sizeof(err)));
	ATF_CHECK_EQ(EEXIST, errno);
	ATF_CHECK_MSG(strstr(err, "reads alone") != NULL, "%s", err);
	ATF_CHECK_EQ(-1, vc_rcd_path("etc", "a/b", "arcana", path,
	    sizeof(path), err, sizeof(err)));
	ATF_CHECK_EQ(EINVAL, errno);
}

static void
puts_file(const char *path, const char *text)
{

	put(path, text, strlen(text));
}

/* The files of r's netif, as vc_rc_files() lists them, one a line. */
static char *
netif_files(char *err, size_t errlen, int *rc)
{
	char **paths, *out = NULL;
	size_t n, len = 0;
	FILE *fp;

	*rc = vc_rc_files("r", "/usr/local", "netif", "arcana", &paths, &n,
	    err, errlen);
	if (*rc == -1)
		return (NULL);
	ATF_REQUIRE((fp = open_memstream(&out, &len)) != NULL);
	for (size_t i = 0; i < n; i++)
		fprintf(fp, "%s\n", paths[i]);
	fclose(fp);
	vc_rc_files_free(paths, n);
	return (out);
}

static void
conflict(const char *name, const char *where)
{
	char **paths, err[256];
	size_t n;
	int rc;

	ATF_REQUIRE_MSG(vc_rc_files("r", "/usr/local", "netif", "arcana",
	    &paths, &n, err, sizeof(err)) == 0, "%s", err);
	rc = vc_conflict(paths, n, name, err, sizeof(err));
	if (where == NULL)
		ATF_CHECK_MSG(rc == 0, "%s: %s", name, err);
	else {
		ATF_CHECK_EQ_MSG(-1, rc, "%s", name);
		ATF_CHECK_EQ(EEXIST, errno);
		ATF_CHECK_MSG(strstr(err, where) != NULL, "%s: %s", name,
		    err);
	}
	vc_rc_files_free(paths, n);
}

/*
 * The conflict rule: the user's files of a service, as rc(8) reads
 * them, Arcana's fragment not among them; a variable any sets, refused.
 */
ATF_TC_WITHOUT_HEAD(conflicts);
ATF_TC_BODY(conflicts, tc)
{
	const struct fixture *d = fixture("defaults.conf");
	char err[256], *files;
	int rc;

	ATF_REQUIRE_EQ(0, system("mkdir -p r/etc/defaults "
	    "r/etc/rc.conf.d/netif r/usr/local/etc/rc.conf.d r/opt"));
	put("r/etc/defaults/rc.conf", d->text, d->len);
	puts_file("r/etc/rc.conf", "hostname=gw\n"
	    "ifconfig_em1=\"inet 192.0.2.1/24\"\n"
	    "rc_conf_files=\"/etc/rc.conf /etc/rc.conf.local "
	    "/etc/rc.conf.extra\"\n"
	    "env_x=1 true\n");
	puts_file("r/etc/rc.conf.local", "ifconfig_em2=up\n");
	puts_file("r/etc/rc.conf.extra", "\n\nifconfig_em3=up\n");
	puts_file("r/etc/rc.conf.d/netif/arcana", "ifconfig_em9=up\n");
	puts_file("r/etc/rc.conf.d/netif/zz-user", "ifconfig_em4=up\n");
	puts_file("r/etc/rc.conf.d/netif/.hidden", "ifconfig_em6=up\n");
	puts_file("r/etc/rc.conf.d/routing", "ifconfig_em7=up\n");
	puts_file("r/usr/local/etc/rc.conf.d/netif", "ifconfig_em5=up\n");

	files = netif_files(err, sizeof(err), &rc);
	ATF_REQUIRE_MSG(rc == 0, "%s", err);
	ATF_CHECK_STREQ("r/etc/rc.conf\nr/etc/rc.conf.local\n"
	    "r/etc/rc.conf.extra\nr/etc/rc.conf.d/netif/zz-user\n"
	    "r/usr/local/etc/rc.conf.d/netif\n", files);
	free(files);
	conflict("ifconfig_em1", "r/etc/rc.conf sets it too, line 2");
	conflict("ifconfig_em2", "r/etc/rc.conf.local sets it too, line 1");
	conflict("ifconfig_em3", "r/etc/rc.conf.extra sets it too, line 3");
	conflict("ifconfig_em4", "netif/zz-user sets it too");
	conflict("ifconfig_em5", "r/usr/local/etc/rc.conf.d/netif sets");
	/* A command's environment, a dot file, another service's, ours. */
	conflict("env_x", "line 4");
	conflict("ifconfig_em6", NULL);
	conflict("ifconfig_em7", NULL);
	conflict("ifconfig_em9", NULL);

	/* local_startup set: its directories, not localbase's. */
	puts_file("r/etc/rc.conf", "local_startup=\"/opt/rc.d\"\n");
	puts_file("r/opt/x", "");
	ATF_REQUIRE_EQ(0, system("mkdir -p r/opt/rc.conf.d/netif"));
	puts_file("r/opt/rc.conf.d/netif/a", "ifconfig_em8=up\n");
	files = netif_files(err, sizeof(err), &rc);
	ATF_REQUIRE_MSG(rc == 0, "%s", err);
	ATF_CHECK_STREQ("r/etc/rc.conf\nr/etc/rc.conf.local\n"
	    "r/etc/rc.conf.d/netif/zz-user\nr/opt/rc.conf.d/netif/a\n",
	    files);
	free(files);
	conflict("ifconfig_em8", "r/opt/rc.conf.d/netif/a");

	/* A list reading does not settle: the files cannot be told. */
	puts_file("r/etc/rc.conf", "rc_conf_files=\"${x} /etc/rc.conf\"\n");
	ATF_CHECK(netif_files(err, sizeof(err), &rc) == NULL);
	ATF_CHECK_EQ(-1, rc);
	ATF_CHECK_MSG(strstr(err, "cannot be told") != NULL, "%s", err);
}

static void
check_absent(const struct vc_file *f, const char *name)
{

	ATF_CHECK_MSG(vc_get(f, name) == NULL, "%s: read", name);
}

/* loader-edge.conf's lines, each. */
ATF_TC_WITHOUT_HEAD(loader);
ATF_TC_BODY(loader, tc)
{
	const struct fixture *x = fixture("loader-edge.conf");
	static const char *const malformed[] = { "bad", "also_bad", "-dash",
	    "open_quote" };
	struct vc_file f;

	parse_d(&f, VC_LOADER, x->text, x->len);
	check_value(&f, "autoboot_delay", "3");
	check_value(&f, "beastie_disable", "YES");
	check_value(&f, "spaced", "a b");
	check_value(&f, "word", "a-b.c_d");
	check_value(&f, "quoted_hash", "a#b");
	check_value(&f, "esc", "a\\b$c");
	check_value(&f, "if_bridge_load", "YES");
	/* A module's line: as it is, no escapes. */
	check_value(&f, "mod_name", "/boot/x \\\\y");
	check_value(&f, "kern.geom.label.disk_ident.enable", "0");
	check_value(&f, "hw.em.rxd", "4096");
	check_value(&f, "dup", "2");
	check_value(&f, "crlf", "v");
	check_value(&f, "indented", "yes");
	check_value(&f, "noeol", "end");
	check_flags(&f, "computed", VC_COMPUTED);
	check_flags(&f, "computed2", VC_COMPUTED);
	check_flags(&f, "exec", VC_OPAQUE);
	for (size_t i = 0; i < nitems(malformed); i++)
		check_absent(&f, malformed[i]);
	vc_free(&f);
}

/* sysctl-edge.conf's lines, each, as sysctl.c reads them. */
ATF_TC_WITHOUT_HEAD(sysctl);
ATF_TC_BODY(sysctl, tc)
{
	const struct fixture *x = fixture("sysctl-edge.conf");
	struct vc_file f;

	parse_d(&f, VC_SYSCTL, x->text, x->len);
	check_value(&f, "kern.ipc.somaxconn", "1024");
	check_value(&f, "net.inet.ip.forwarding", "1");
	check_value(&f, "net.inet6.ip6.forwarding", "1");
	check_value(&f, "security.bsd.see_other_uids", "0");
	check_value(&f, "vfs.zfs.arc_max", "4G");
	/* A quote before the "#": cut after the one closing it. */
	check_value(&f, "kern.hostname", "a host # not a comment");
	/* No quote closing it: the first dropped all the same. */
	check_value(&f, "kern.x", "half");
	/* "#" after a backslash: not a comment, the backslash kept. */
	check_value(&f, "kern.y", "a\\#b");
	/* A quote with none after it: no comment at all. */
	check_value(&f, "kern.z", "it's # still the value");
	check_value(&f, "net.inet.tcp.blackhole", "2");
	check_value(&f, "dup.a", "2");
	check_value(&f, "dev.em.0.%desc", "x");
	check_value(&f, "noeol.v", "end");
	check_absent(&f, "name.only");
	vc_free(&f);
}

/* Edits of loader.conf and sysctl.conf: their quoting, their refusals. */
ATF_TC_WITHOUT_HEAD(edits_lines);
ATF_TC_BODY(edits_lines, tc)
{
	const struct fixture *x;
	struct vc_file f;
	char err[256];

	x = fixture("loader-edge.conf");
	parse_d(&f, VC_LOADER, x->text, x->len);
	/* A bare word stays bare while it can; quotes kept. */
	set(&f, "beastie_disable", "NO");
	ATF_CHECK(strstr(f.text, "\nbeastie_disable=NO\n") != NULL);
	set(&f, "beastie_disable", "a b");
	ATF_CHECK(strstr(f.text, "\nbeastie_disable=\"a b\"\n") != NULL);
	set(&f, "spaced", "c");
	ATF_CHECK(strstr(f.text, "\nspaced   =   \"c\"   # a comment\n") !=
	    NULL);
	/* Escaped as the loader unescapes; a module's line as it is. */
	set(&f, "esc", "x\\y$z");
	ATF_CHECK(strstr(f.text, "\nesc=\"x\\\\y\\$z\"\n") != NULL);
	check_value(&f, "esc", "x\\y$z");
	set(&f, "mod_name", "/a\\b");
	ATF_CHECK(strstr(f.text, "\nmod_name=\"/a\\b\"\n") != NULL);
	set(&f, "zfs_load", "YES");
	ATF_CHECK(strstr(f.text, "\nzfs_load=\"YES\"\n") != NULL);
	unset(&f, "dup");
	check_absent(&f, "dup");
	/* The loader reads the edited file as it is read here. */
	ATF_CHECK(check_loader(&f) >= 10);
	ATF_CHECK_EQ(-1, vc_set(&f, "q", "a\"b", err, sizeof(err)));
	ATF_CHECK_EQ(EINVAL, errno);
	ATF_CHECK_EQ(-1, vc_set(&f, "exec", "x", err, sizeof(err)));
	/* A computed one replaced: a literal now. */
	set(&f, "computed", "x");
	check_value(&f, "computed", "x");
	vc_free(&f);

	x = fixture("sysctl-edge.conf");
	parse_d(&f, VC_SYSCTL, x->text, x->len);
	set(&f, "kern.ipc.somaxconn", "4096");
	ATF_CHECK(strstr(f.text, "\nkern.ipc.somaxconn=4096\n") != NULL);
	set(&f, "net.inet.ip.forwarding", "0");
	ATF_CHECK(strstr(f.text, "\nnet.inet.ip.forwarding = 0\n") != NULL);
	set(&f, "vfs.zfs.arc_max", "8G");
	ATF_CHECK(strstr(f.text, "\nvfs.zfs.arc_max=\"8G\"\n") != NULL);
	/* What a bare value cannot be: quoted. */
	set(&f, "kern.ipc.somaxconn", "a # b");
	check_value(&f, "kern.ipc.somaxconn", "a # b");
	set(&f, "kern.new", "1");
	ATF_CHECK(strstr(f.text, "noeol.v=end\nkern.new=1\n") != NULL);
	unset(&f, "dup.a");
	check_absent(&f, "dup.a");
	/* What sysctl(8) would not read back as given: refused. */
	ATF_CHECK_EQ(-1, vc_set(&f, "kern.w", "a'b#c'd", err, sizeof(err)));
	ATF_CHECK_EQ(EINVAL, errno);
	ATF_CHECK_MSG(strstr(err, "read back") != NULL, "%s", err);
	ATF_CHECK(vc_get(&f, "kern.w") == NULL);
	ATF_CHECK_EQ(-1, vc_set(&f, "kern.w", "'\"#", err, sizeof(err)));
	ATF_CHECK_EQ(-1, vc_set(&f, "kern w", "1", err, sizeof(err)));
	vc_free(&f);
}

#define	ADVCAP	"/usr/src/usr.sbin/rtadvd/advcap.c"

/*
 * rtadvd(8)'s own reading: its advcap.c, from the source tree, with a
 * main(): the record's getent(), then for each query line, "n:cap",
 * "s:cap" or "f:cap", agetnum(), agetstr() or agetflag(), NUL after each
 * answer, <absent> for none.
 */
static const char rtcap_c[] =
    "#include <stdint.h>\n#include <stdio.h>\n#include <string.h>\n"
    "const char *conffile;\n"
    "int agetent(char *, char *);\nint64_t agetnum(char *);\n"
    "int agetflag(char *);\nchar *agetstr(char *, char **);\n"
    "int\nmain(int argc, char **argv)\n{\n"
    "\tchar buf[1024], area[1024], q[512], *ap, *v;\n"
    "\tFILE *fp;\n\tint64_t n;\n\n"
    "\tconffile = argv[1];\n"
    "\tif (argc != 4 || agetent(buf, argv[2]) <= 0 ||\n"
    "\t    (fp = fopen(argv[3], \"r\")) == NULL)\n\t\treturn (1);\n"
    "\twhile (fgets(q, sizeof(q), fp) != NULL) {\n"
    "\t\tq[strcspn(q, \"\\n\")] = '\\0';\n"
    "\t\tif (q[0] == 'n') {\n"
    "\t\t\tif ((n = agetnum(q + 2)) < 0)\n"
    "\t\t\t\tfputs(\"<absent>\", stdout);\n"
    "\t\t\telse\n\t\t\t\tprintf(\"%jd\", (intmax_t)n);\n"
    "\t\t} else if (q[0] == 's') {\n"
    "\t\t\tap = area;\n"
    "\t\t\tv = agetstr(q + 2, &ap);\n"
    "\t\t\tfputs(v != NULL ? v : \"<absent>\", stdout);\n"
    "\t\t} else\n\t\t\tprintf(\"%d\", agetflag(q + 2));\n"
    "\t\tputchar('\\0');\n\t}\n\treturn (0);\n}\n";

/* rtadvd's own reader, from /usr/src: rtadvd_read's head requires it. */
static void
rtcap_built(void)
{

	if (access("rtcap", X_OK) == 0)
		return;
	put("rtcap.c", rtcap_c, sizeof(rtcap_c) - 1);
	ATF_REQUIRE_EQ(0, system("cc -w -I/usr/src/usr.sbin/rtadvd -o rtcap "
	    "rtcap.c " ADVCAP));
}

/*
 * Every capability of every record, and of those its tc= brings, read
 * by each getter as rtadvd(8) reads it.
 */
static size_t
check_rtadvd(const struct vc_capfile *f)
{
	size_t compared = 0;

	rtcap_built();
	put("input.conf", f->text, f->len);
	for (size_t i = 0; i < f->nr; i++) {
		const struct vc_record *r = &f->r[i], *t;
		const char *name = r->names[0];
		const char **caps = NULL;
		size_t ncaps = 0, outlen;
		char *out, *p, cmd[256];
		FILE *fp;
		int hops = 0;

		/* getent() finds the first of a name only. */
		if (vc_cap_record(f, name) != r)
			continue;
		for (t = r; t != NULL && hops++ < 32; t = t->tc != NULL ?
		    vc_cap_record(f, t->tc) : NULL)
			for (size_t j = 0; j < t->ncaps; j++) {
				bool seen = t->caps[j].name[0] == '\0' ||
				    strchr(t->caps[j].name, '\n') != NULL;

				for (size_t k = 0; k < ncaps && !seen; k++)
					seen = strcmp(caps[k],
					    t->caps[j].name) == 0;
				if (seen)
					continue;
				ATF_REQUIRE((caps = reallocarray(caps,
				    ncaps + 1, sizeof(*caps))) != NULL);
				caps[ncaps++] = t->caps[j].name;
			}
		ATF_REQUIRE((fp = fopen("queries", "w")) != NULL);
		for (size_t k = 0; k < ncaps; k++)
			fprintf(fp, "n:%s\ns:%s\nf:%s\n", caps[k], caps[k],
			    caps[k]);
		fclose(fp);
		snprintf(cmd, sizeof(cmd), "./rtcap input.conf '%s' queries "
		    "> rt.out", name);
		ATF_REQUIRE_EQ_MSG(0, system(cmd), "%s: rtadvd finds no "
		    "record", name);
		out = slurp("rt.out", &outlen);
		p = out;
		for (size_t k = 0; k < ncaps; k++) {
			const struct vc_cap *c;
			char want[64];

			for (int g = 0; g < 3; g++) {
				ATF_REQUIRE_MSG(p < out + outlen, "%s:%s: no "
				    "answer", name, caps[k]);
				c = vc_cap_get(f, name, caps[k], g == 0 ? '#' :
				    g == 1 ? '=' : 0);
				if (g == 2)
					snprintf(want, sizeof(want), "%d",
					    c != NULL);
				ATF_CHECK_MSG(strcmp(g == 2 ? want : c != NULL ?
				    c->value : "<absent>", p) == 0, "%s:%s, "
				    "%s: \"%s\", rtadvd(8) \"%s\"", name, caps[k],
				    g == 0 ? "number" : g == 1 ? "string" :
				    "flag", g == 2 ? want : c != NULL ? c->value :
				    "<absent>", p);
				p += strlen(p) + 1;
				compared++;
			}
		}
		free(out);
		free(caps);
	}
	return (compared);
}

static void
rtparse(struct vc_capfile *f, const char *text, size_t len)
{
	char err[256];

	ATF_REQUIRE_MSG(vc_cap_parse(f, text, len, err, sizeof(err)) == 0,
	    "%s", err);
}

/* rtadvd.conf: read and written byte for byte; rtadvd(8) agrees. */
ATF_TC_WITHOUT_HEAD(rtadvd);
ATF_TC_BODY(rtadvd, tc)
{
	static const char *const names[] = { "rtadvd-man.conf",
	    "rtadvd-edge.conf" };
	const struct vc_cap *c;
	struct vc_capfile f;

	for (size_t i = 0; i < nitems(names); i++) {
		const struct fixture *x = fixture(names[i]);
		char err[256], *back;
		size_t len;

		rtparse(&f, x->text, x->len);
		ATF_REQUIRE_MSG(vc_cap_write(&f, "back.conf", 0644, err,
		    sizeof(err)) == 0, "%s", err);
		back = slurp("back.conf", &len);
		ATF_CHECK(len == x->len && memcmp(back, x->text, len) == 0);
		free(back);
		vc_cap_free(&f);
	}
	/* What the edge's lines are, each, here too. */
	rtparse(&f, fixture("rtadvd-edge.conf")->text,
	    fixture("rtadvd-edge.conf")->len);
	ATF_CHECK(vc_cap_record(&f, "alias0") == vc_cap_record(&f, "x0"));
	ATF_REQUIRE((c = vc_cap_get(&f, "base", "mtu", '#')) != NULL);
	ATF_CHECK_STREQ("832", c->value);	/* 01500, octal */
	ATF_CHECK(vc_cap_get(&f, "x0", "mtu", '#') == NULL);
	ATF_CHECK(vc_cap_get(&f, "x0", "noifprefix", 0) != NULL);
	ATF_CHECK(vc_cap_get(&f, "x0", "gone", '#') == NULL);
	ATF_REQUIRE((c = vc_cap_get(&f, "x0", "twice", '#')) != NULL);
	ATF_CHECK_STREQ("1", c->value);
	ATF_REQUIRE((c = vc_cap_get(&f, "x0", "cat", '=')) != NULL);
	ATF_CHECK_STREQ("abcd", c->value);
	ATF_REQUIRE((c = vc_cap_get(&f, "x0", "ctl", '=')) != NULL);
	ATF_CHECK_STREQ("\001", c->value);
	ATF_CHECK(vc_cap_record(&f, "goes on") == NULL);
	vc_cap_free(&f);
}

/* rtadvd-man.conf with a field of each kind set, taken away and a
 * record added and removed, each edit's bytes checked. */
static void
rtadvd_edited(struct vc_capfile *f)
{
	const struct fixture *x = fixture("rtadvd-man.conf");
	static const char *const em9[] = { "addr=\"2001:db8:9::\"",
	    "prefixlen#64" };
	char err[256];

	rtparse(f, x->text, x->len);
	ATF_REQUIRE_EQ(0, vc_cap_set(f, "ef0", "prefixlen", '#', "48", err,
	    sizeof(err)));
	ATF_CHECK(strstr(f->text, "\nef0:\\\n\t:addr=\"2001:db8:ffff:1000::\""
	    ":prefixlen#48:\n") != NULL);
	/* A string with colons, replaced whole. */
	ATF_REQUIRE_EQ(0, vc_cap_set(f, "ef0", "addr", '=', "2001:db8:1::",
	    err, sizeof(err)));
	ATF_CHECK(strstr(f->text, "\t:addr=\"2001:db8:1::\":prefixlen#48:\n") !=
	    NULL);
	/* Before tc=, which stays last; a number with no leading 0. */
	ATF_REQUIRE_EQ(0, vc_cap_set(f, "ef1", "rltime", '#', "0600", err,
	    sizeof(err)));
	ATF_CHECK(strstr(f->text, ":prefixlen#64:rltime#600:tc=default:\n") !=
	    NULL);
	/* At a record's end; a flag. */
	ATF_REQUIRE_EQ(0, vc_cap_set(f, "ne0", "mtu", '#', "1280", err,
	    sizeof(err)));
	ATF_CHECK(strstr(f->text, "\t:rltime#0:mtu#1280:\n") != NULL);
	ATF_REQUIRE_EQ(0, vc_cap_set(f, "wlan0", "noifprefix", 0, NULL, err,
	    sizeof(err)));
	ATF_CHECK(strstr(f->text, ":pref64=\"64:ff9b::\":noifprefix:\n") !=
	    NULL);
	/* A string with colons removed, nothing of it left. */
	ATF_REQUIRE_EQ(0, vc_cap_unset(f, "wlan0", "rdnss", err,
	    sizeof(err)));
	ATF_CHECK(strstr(f->text, "ffff::10") == NULL);
	ATF_CHECK(strstr(f->text, "\t:\\\n\t:dnssl=") != NULL);
	ATF_REQUIRE_EQ(0, vc_cap_add_record(f, "em9", em9, 2, err,
	    sizeof(err)));
	ATF_CHECK(strstr(f->text, "\nem9:\\\n\t:addr=\"2001:db8:9::\":\\\n"
	    "\t:prefixlen#64:\n") != NULL);
	ATF_REQUIRE_EQ(0, vc_cap_remove_record(f, "ne0", err, sizeof(err)));
	ATF_CHECK(vc_cap_record(f, "ne0") == NULL);
	ATF_CHECK(strncmp(f->text, "# rtadvd.conf(5)'s examples.\nef0:", 33) ==
	    0);
}

/* rtadvd.conf's edits: a field's bytes, a record's lines, and no more. */
ATF_TC_WITHOUT_HEAD(rtadvd_edits);
ATF_TC_BODY(rtadvd_edits, tc)
{
	static const char *const em9[] = { "addr=\"2001:db8:9::\"",
	    "prefixlen#64" };
	struct vc_capfile f;
	char err[256];

	rtadvd_edited(&f);
	/* Refused. */
	ATF_CHECK_EQ(-1, vc_cap_set(&f, "ef0", "tc", '=', "x", err,
	    sizeof(err)));
	ATF_CHECK_EQ(-1, vc_cap_set(&f, "nothere", "mtu", '#', "1", err,
	    sizeof(err)));
	ATF_CHECK_EQ(ENOENT, errno);
	ATF_CHECK_EQ(-1, vc_cap_set(&f, "ef0", "mtu", '#', "-1", err,
	    sizeof(err)));
	ATF_CHECK_EQ(-1, vc_cap_add_record(&f, "ef0", em9, 2, err,
	    sizeof(err)));
	ATF_CHECK_EQ(EEXIST, errno);
	vc_cap_free(&f);
}

/* A record written whole: replaced where it is, its names kept, the
 * fields packed on lines of 72 columns; one not there added last. */
ATF_TC_WITHOUT_HEAD(rtadvd_record);
ATF_TC_BODY(rtadvd_record, tc)
{
	const struct fixture *x = fixture("rtadvd-edge.conf");
	static const char *const x0[] = { "maxinterval#600",
	    "mininterval#200", "chlim#64", "raflags=\"mo\"", "rltime#1800",
	    "rtime#0", "retrans#0", "noifprefix", "addr=\"2001:db8:1::\"",
	    "prefixlen#64", "pinfoflags=\"la\"", "vltime#2592000",
	    "pltime#604800", "mtu#1280", "tc=base" };
	static const char *const em9[] = { "rltime#0" };
	static const char *const empty[] = { "" };
	struct vc_capfile f;
	char *s, err[256];

	rtparse(&f, x->text, x->len);
	ATF_REQUIRE_EQ(0, vc_cap_set_record(&f, "alias0", x0, 15, err,
	    sizeof(err)));
	ATF_CHECK_MSG(strstr(f.text, "\nx0|alias0:\\\n"
	    "\t:maxinterval#600:mininterval#200:chlim#64:raflags=\"mo\":\\\n"
	    "\t:rltime#1800:rtime#0:retrans#0:noifprefix:addr=\"2001:db8:1::\""
	    ":\\\n"
	    "\t:prefixlen#64:pinfoflags=\"la\":vltime#2592000:pltime#604800:"
	    "\\\n"
	    "\t:mtu#1280:tc=base:\ny0:\\\n") != NULL, "%s", f.text);
	ATF_CHECK(strstr(f.text, "esc=") == NULL);
	ATF_CHECK(strstr(f.text, "goes on: this line is the comment's too.\n"
	    "base:\\\n") != NULL);
	ATF_CHECK_STREQ("600", vc_cap_get(&f, "x0", "maxinterval", '#')->value);
	ATF_REQUIRE_EQ(0, vc_cap_set_record(&f, "em9", em9, 1, err,
	    sizeof(err)));
	ATF_CHECK(strstr(f.text, "prefixlen0#48:\nem9:\\\n\t:rltime#0:\n") !=
	    NULL);
	ATF_REQUIRE_EQ(0, vc_cap_set_record(&f, "em9", NULL, 0, err,
	    sizeof(err)));
	ATF_CHECK(strstr(f.text, "prefixlen0#48:\nem9:\n") != NULL);
	ATF_CHECK_EQ(-1, vc_cap_set_record(&f, "em9", empty, 1, err,
	    sizeof(err)));
	ATF_CHECK_EQ(-1, vc_cap_set_record(&f, "bad name", x0, 1, err,
	    sizeof(err)));
	ATF_REQUIRE((s = vc_cap_field("addr", '=', "2001:db8::\"x")) != NULL);
	ATF_CHECK_STREQ("addr=\"2001:db8::\\\"x\"", s);
	free(s);
	ATF_CHECK(vc_cap_field("mtu", '#', "12a") == NULL);
	vc_cap_free(&f);
}

/*
 * rtadvd(8) reads the fixtures, and the file the edits made, as they
 * are read here: by its own advcap.c, from the system's sources.
 */
ATF_TC(rtadvd_read);
ATF_TC_HEAD(rtadvd_read, tc)
{

	atf_tc_set_md_var(tc, "descr", "rtadvd.conf read by rtadvd(8)'s "
	    "own advcap.c as libvarconf reads it");
	atf_tc_set_md_var(tc, "require.files", ADVCAP);
}
ATF_TC_BODY(rtadvd_read, tc)
{
	static const char *const names[] = { "rtadvd-man.conf",
	    "rtadvd-edge.conf" };
	struct vc_capfile f;
	size_t n;

	for (size_t i = 0; i < nitems(names); i++) {
		const struct fixture *x = fixture(names[i]);

		rtparse(&f, x->text, x->len);
		n = check_rtadvd(&f);
		ATF_CHECK_MSG(n >= 30, "%s: %zu", names[i], n);
		vc_cap_free(&f);
	}
	rtadvd_edited(&f);
	ATF_CHECK(check_rtadvd(&f) >= 30);
	vc_cap_free(&f);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, fixtures);
	ATF_TP_ADD_TC(tp, edge);
	ATF_TP_ADD_TC(tp, edits);
	ATF_TP_ADD_TC(tp, edits_edge);
	ATF_TP_ADD_TC(tp, comments);
	ATF_TP_ADD_TC(tp, errors);
	ATF_TP_ADD_TC(tp, rcd);
	ATF_TP_ADD_TC(tp, conflicts);
	ATF_TP_ADD_TC(tp, loader);
	ATF_TP_ADD_TC(tp, sysctl);
	ATF_TP_ADD_TC(tp, edits_lines);
	ATF_TP_ADD_TC(tp, rtadvd);
	ATF_TP_ADD_TC(tp, rtadvd_edits);
	ATF_TP_ADD_TC(tp, rtadvd_record);
	ATF_TP_ADD_TC(tp, rtadvd_read);
	return (atf_no_error());
}
