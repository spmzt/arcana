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
#include <stdlib.h>
#include <string.h>

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
parse(struct vc_file *f, const char *text, size_t len)
{
	char err[256];

	ATF_REQUIRE_MSG(vc_parse(f, VC_SH, text, len, err, sizeof(err)) == 0,
	    "%s", err);
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

/* Each fixture read and written byte for byte; sh(1) agrees. */
ATF_TC_WITHOUT_HEAD(fixtures);
ATF_TC_BODY(fixtures, tc)
{
	for (const struct fixture *x = fixtures; x->name != NULL; x++) {
		struct vc_file f;
		char err[256], *back;
		size_t len, n;

		parse(&f, x->text, x->len);
		ATF_CHECK_EQ(x->len, f.len);
		ATF_CHECK(memcmp(x->text, f.text, x->len) == 0);
		ATF_REQUIRE_MSG(vc_write(&f, "back.conf", 0644, err,
		    sizeof(err)) == 0, "%s", err);
		back = slurp("back.conf", &len);
		ATF_CHECK_EQ_MSG(x->len, len, "%s", x->name);
		ATF_CHECK_MSG(memcmp(x->text, back, len) == 0, "%s", x->name);
		free(back);
		n = check_sh(&f);
		ATF_CHECK_MSG(n >= 20, "%s: %zu settled", x->name, n);
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

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, fixtures);
	ATF_TP_ADD_TC(tp, edge);
	ATF_TP_ADD_TC(tp, edits);
	ATF_TP_ADD_TC(tp, edits_edge);
	ATF_TP_ADD_TC(tp, errors);
	ATF_TP_ADD_TC(tp, rcd);
	return (atf_no_error());
}
