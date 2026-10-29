/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * libvarconf: see varconf.h.
 *
 * sh(1)'s rules, as far as a file of assignments needs them (sh(1),
 * "Lexical Structure", "Quoting", "Simple Commands"): a line is a list
 * of commands; one made of NAME=word words only, each word read with
 * its quoting (single quotes literal; double quotes with \$ \` \" \\ and
 * \newline; outside them \c and \newline), sets those variables.  A
 * word with $ or ` in it, or ~ where it would expand, is computed.  A
 * line that is anything else is kept as it is: its words are looked at
 * only for the depth of compound commands (if, case, for, while, until,
 * braces, a function's body), inside which assignments may not run,
 * for here-documents, whose lines are data, and for NAME= words, which
 * are opaque assignments: their names are known, not their effect.
 */

#include <sys/param.h>
#include <sys/stat.h>

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "varconf.h"

#define	VC_MAX_SIZE	(4u << 20)	/* a file read, at most */
#define	VC_MAX_NAME	128

struct buf {
	char	*s;
	size_t	 len, cap;
};

static int
b_putc(struct buf *b, char c)
{
	char *s;

	if (b->len + 2 > b->cap) {
		size_t cap = b->cap > 0 ? b->cap * 2 : 32;

		if ((s = realloc(b->s, cap)) == NULL)
			return (-1);
		b->s = s;
		b->cap = cap;
	}
	b->s[b->len++] = c;
	b->s[b->len] = '\0';
	return (0);
}

static int
b_puts(struct buf *b, const char *s, size_t n)
{

	for (size_t i = 0; i < n; i++)
		if (b_putc(b, s[i]) == -1)
			return (-1);
	return (0);
}

static void
fail(char *err, size_t errlen, const char *fmt, ...)
{
	va_list ap;

	if (err == NULL || errlen == 0)
		return;
	va_start(ap, fmt);
	vsnprintf(err, errlen, fmt, ap);
	va_end(ap);
}

/*
 * Reading.
 */

struct lex {
	const char	*s;
	size_t		 len, i;
	int		 line;
	int		 depth;		/* compound commands open */
	char		*heredoc;	/* the delimiter awaited, or NULL */
	bool		 hd_tabs;	/* <<-: leading tabs stripped */
	struct vc_file	*f;
	char		*err;
	size_t		 errlen;
};

static int
at(const struct lex *l, size_t k)
{

	return (l->i + k < l->len ? (unsigned char)l->s[l->i + k] : -1);
}

/* Spaces, tabs and \newline. */
static void
skip_blank(struct lex *l)
{

	for (;;) {
		if (at(l, 0) == ' ' || at(l, 0) == '\t')
			l->i++;
		else if (at(l, 0) == '\\' && at(l, 1) == '\n') {
			l->i += 2;
			l->line++;
		} else
			return;
	}
}

static bool
name_start(int c)
{

	return (c == '_' || (c >= 0 && c < 0x80 && isalpha(c)));
}

static bool
name_char(int c)
{

	return (c == '_' || (c >= 0 && c < 0x80 && isalnum(c)));
}

/* A NAME= at l's place: its length, the '=' not counted; else 0. */
static size_t
assign_word(const struct lex *l)
{
	size_t n = 0;

	if (!name_start(at(l, 0)))
		return (0);
	while (name_char(at(l, n)))
		n++;
	return (at(l, n) == '=' && n <= VC_MAX_NAME ? n : 0);
}

static bool
word_end(int c)
{

	return (c == -1 || strchr(" \t\n;&|<>()", c) != NULL);
}

static int	skip_group(struct lex *, int, int);

/* A $ in a word: what it expands, skipped; true if an expansion. */
static int
dollar(struct lex *l, bool *computed)
{
	int c = at(l, 1);

	if (c == '(' || c == '{') {
		*computed = true;
		l->i++;
		return (skip_group(l, c, c == '(' ? ')' : '}'));
	}
	if (name_start(c) || (c >= '0' && c <= '9') ||
	    (c != -1 && strchr("@*#?$!-", c) != NULL)) {
		*computed = true;
		l->i += 2;
		while (name_start(c) && name_char(at(l, 0)))
			l->i++;
		return (0);
	}
	l->i++;			/* a literal $ */
	return (1);
}

/* Backquotes: to the one that ends them. */
static int
skip_backquote(struct lex *l)
{

	for (l->i++; at(l, 0) != '`'; l->i++) {
		if (at(l, 0) == -1)
			return (-1);
		if (at(l, 0) == '\\' && at(l, 1) != -1)
			l->i++;
		if (at(l, 0) == '\n')
			l->line++;
	}
	l->i++;
	return (0);
}

/* $( ... ) or ${ ... } from its opening: quotes and nesting minded. */
static int
skip_group(struct lex *l, int open, int close)
{
	int nest = 0;
	bool dummy;

	for (;;) {
		int c = at(l, 0);

		if (c == -1)
			return (-1);
		if (c == '\n')
			l->line++;
		if (c == '\\' && at(l, 1) != -1) {
			if (at(l, 1) == '\n')
				l->line++;
			l->i += 2;
			continue;
		}
		if (c == '\'') {
			for (l->i++; at(l, 0) != '\''; l->i++) {
				if (at(l, 0) == -1)
					return (-1);
				if (at(l, 0) == '\n')
					l->line++;
			}
			l->i++;
			continue;
		}
		if (c == '"') {
			for (l->i++; at(l, 0) != '"'; ) {
				if (at(l, 0) == -1)
					return (-1);
				if (at(l, 0) == '\\' && at(l, 1) != -1)
					l->i++;
				else if (at(l, 0) == '$' && (at(l, 1) == '(' ||
				    at(l, 1) == '{')) {
					if (dollar(l, &dummy) == -1)
						return (-1);
					continue;
				} else if (at(l, 0) == '`') {
					if (skip_backquote(l) == -1)
						return (-1);
					continue;
				}
				if (at(l, 0) == '\n')
					l->line++;
				l->i++;
			}
			l->i++;
			continue;
		}
		if (c == '`') {
			if (skip_backquote(l) == -1)
				return (-1);
			continue;
		}
		if (c == open)
			nest++;
		else if (c == close && --nest == 0) {
			l->i++;
			return (0);
		}
		l->i++;
	}
}

/*
 * A word from l's place: its literal value into v (if not NULL), as
 * sh(1) reads it; *computed if an expansion is in it.  -1: a quote, a
 * group not closed.
 */
static int
word(struct lex *l, struct buf *v, bool *computed, bool assign)
{
	size_t start = l->i;
	int r;

	*computed = false;
	for (;;) {
		int c = at(l, 0);

		if (word_end(c))
			return (0);
		switch (c) {
		case '\\':
			if (at(l, 1) == '\n') {
				l->i += 2;
				l->line++;
				continue;
			}
			if (at(l, 1) == -1) {
				l->i++;
				if (v != NULL && b_putc(v, '\\') == -1)
					return (-1);
				continue;
			}
			if (v != NULL && b_putc(v, l->s[l->i + 1]) == -1)
				return (-1);
			l->i += 2;
			continue;
		case '\'':
			for (l->i++; at(l, 0) != '\''; l->i++) {
				if (at(l, 0) == -1)
					return (-1);
				if (at(l, 0) == '\n')
					l->line++;
				if (v != NULL && b_putc(v, l->s[l->i]) == -1)
					return (-1);
			}
			l->i++;
			continue;
		case '"':
			for (l->i++; at(l, 0) != '"'; ) {
				int d = at(l, 0);

				if (d == -1)
					return (-1);
				if (d == '\\' && at(l, 1) == '\n') {
					l->i += 2;
					l->line++;
					continue;
				}
				if (d == '\\' && at(l, 1) != -1 &&
				    strchr("$`\"\\", at(l, 1)) != NULL) {
					if (v != NULL &&
					    b_putc(v, l->s[l->i + 1]) == -1)
						return (-1);
					l->i += 2;
					continue;
				}
				if (d == '$') {
					if ((r = dollar(l, computed)) == -1)
						return (-1);
					if (r == 1 && v != NULL &&
					    b_putc(v, '$') == -1)
						return (-1);
					continue;
				}
				if (d == '`') {
					*computed = true;
					if (skip_backquote(l) == -1)
						return (-1);
					continue;
				}
				if (d == '\n')
					l->line++;
				if (v != NULL && b_putc(v, (char)d) == -1)
					return (-1);
				l->i++;
			}
			l->i++;
			continue;
		case '$':
			if ((r = dollar(l, computed)) == -1)
				return (-1);
			if (r == 1 && v != NULL && b_putc(v, '$') == -1)
				return (-1);
			continue;
		case '`':
			*computed = true;
			if (skip_backquote(l) == -1)
				return (-1);
			continue;
		case '~':
			/* Tilde expansion: at a value's start or after a ':'
			 * in an assignment (sh(1), "Tilde Expansion"). */
			if (assign && (l->i == start ||
			    l->s[l->i - 1] == ':'))
				*computed = true;
			break;
		default:
			break;
		}
		if (v != NULL && b_putc(v, (char)c) == -1)
			return (-1);
		l->i++;
	}
}

static int
add(struct lex *l, const char *name, size_t nlen, char *value,
    unsigned flags, size_t off, int line, size_t voff, size_t vend)
{
	struct vc_file *f = l->f;
	struct vc_assign *a, *na;

	if ((na = reallocarray(f->a, f->na + 1, sizeof(*na))) == NULL)
		return (-1);
	f->a = na;
	a = &f->a[f->na];
	memset(a, 0, sizeof(*a));
	if ((a->name = strndup(name, nlen)) == NULL)
		return (-1);
	f->na++;
	a->value = value;
	a->flags = flags;
	a->off = off;
	a->line = line;
	a->voff = voff;
	a->vend = vend;
	return (0);
}

/* An assignment of a line dialect: one a line, alone on it. */
static int
vc_add(struct vc_file *f, char *name, char *value, unsigned flags,
    size_t off, int line, size_t voff, size_t vend, size_t soff,
    size_t send)
{
	struct vc_assign *na, *a;

	if ((na = reallocarray(f->a, f->na + 1, sizeof(*na))) == NULL)
		return (-1);
	f->a = na;
	a = &f->a[f->na++];
	memset(a, 0, sizeof(*a));
	a->name = name;
	a->value = value;
	a->flags = flags;
	a->line = line;
	a->off = off;
	a->voff = voff;
	a->vend = vend;
	a->soff = soff;
	a->send = send;
	a->nstmt = 1;
	return (0);
}

/* The keywords a compound command opens and closes with. */
static int
keyword_depth(const char *w)
{
	static const char *const open[] = { "if", "case", "for", "while",
	    "until", "{" };
	static const char *const close[] = { "fi", "esac", "done", "}" };

	for (size_t i = 0; i < nitems(open); i++)
		if (strcmp(w, open[i]) == 0)
			return (1);
	for (size_t i = 0; i < nitems(close); i++)
		if (strcmp(w, close[i]) == 0)
			return (-1);
	return (0);
}

/*
 * A line that is not assignments alone: to its end, quotes and groups
 * minded; its words looked at for compound commands, here-documents and
 * NAME= words.
 */
static int
other_line(struct lex *l, size_t soff)
{
	bool cmdpos = true, computed;
	struct buf w = { 0 };

	for (;;) {
		int c;

		skip_blank(l);
		c = at(l, 0);
		if (c == -1 || c == '\n') {
			if (c == '\n') {
				l->i++;
				l->line++;
			}
			break;
		}
		if (c == '#') {
			while (at(l, 0) != -1 && at(l, 0) != '\n')
				l->i++;
			continue;
		}
		if (c == '<' && at(l, 1) == '<') {
			bool tabs = at(l, 2) == '-';

			l->i += tabs ? 3 : 2;
			skip_blank(l);
			free(w.s);
			memset(&w, 0, sizeof(w));
			if (word(l, &w, &computed, false) == -1)
				goto bad;
			free(l->heredoc);
			l->heredoc = w.s != NULL ? w.s : strdup("");
			memset(&w, 0, sizeof(w));
			l->hd_tabs = tabs;
			if (l->heredoc == NULL)
				return (-1);
			cmdpos = false;
			continue;
		}
		if (strchr(";&|()", c) != NULL) {
			/*
			 * A command follows; "()" makes a function, whose
			 * body's "{" opens it.  A subshell's or a case's
			 * parentheses are not counted: what a subshell sets
			 * is a NAME= word at a command's place, opaque.
			 */
			l->i += c == '(' && at(l, 1) == ')' ? 2 : 1;
			cmdpos = true;
			continue;
		}
		if (c == '<' || c == '>') {
			l->i++;
			continue;
		}
		if (cmdpos && assign_word(l) > 0) {
			size_t n = assign_word(l), off = l->i;
			int line = l->line;

			if (add(l, l->s + l->i, n, NULL, VC_OPAQUE, off, line,
			    off + n + 1, off + n + 1) == -1)
				return (-1);
			l->f->a[l->f->na - 1].soff = soff;
			l->i += n + 1;
			if (word(l, NULL, &computed, true) == -1)
				goto bad;
			l->f->a[l->f->na - 1].vend = l->i;
			continue;
		}
		free(w.s);
		memset(&w, 0, sizeof(w));
		if (word(l, &w, &computed, false) == -1)
			goto bad;
		if (w.s != NULL && cmdpos) {
			int d = keyword_depth(w.s);

			l->depth += d;
			if (l->depth < 0)
				l->depth = 0;
			/* After a keyword, a command again: "then x". */
			cmdpos = d != 0 || strcmp(w.s, "then") == 0 ||
			    strcmp(w.s, "else") == 0 ||
			    strcmp(w.s, "elif") == 0 ||
			    strcmp(w.s, "do") == 0 || strcmp(w.s, "!") == 0;
		} else
			cmdpos = false;
	}
	free(w.s);
	/* The line's end, for its opaque assignments. */
	for (size_t k = l->f->na; k > 0 && l->f->a[k - 1].soff == soff &&
	    (l->f->a[k - 1].flags & VC_OPAQUE); k--)
		l->f->a[k - 1].send = l->i;
	return (0);
bad:
	free(w.s);
	fail(l->err, l->errlen, "line %d: a quote or a group not closed",
	    l->line);
	errno = EINVAL;
	return (-1);
}

/* A here-document's line: data, to its delimiter's. */
static void
heredoc_line(struct lex *l)
{
	size_t s = l->i, e;

	while (at(l, 0) != -1 && at(l, 0) != '\n')
		l->i++;
	e = l->i;
	if (at(l, 0) == '\n') {
		l->i++;
		l->line++;
	}
	if (l->hd_tabs)
		while (s < e && l->s[s] == '\t')
			s++;
	if (e - s == strlen(l->heredoc) &&
	    memcmp(l->s + s, l->heredoc, e - s) == 0) {
		free(l->heredoc);
		l->heredoc = NULL;
	}
}

/*
 * A line from its first byte: assignments alone (one or more, ";" or
 * blanks between them, a comment after), else another line.
 */
static int
line(struct lex *l)
{
	size_t soff = l->i, first = l->f->na, n;
	int sline = l->line, c;
	bool computed;

	skip_blank(l);
	c = at(l, 0);
	if (c == -1)
		return (0);
	if (c == '\n' || c == '#') {
		while (at(l, 0) != -1 && at(l, 0) != '\n')
			l->i++;
		if (at(l, 0) == '\n') {
			l->i++;
			l->line++;
		}
		return (0);
	}
	while ((n = assign_word(l)) > 0) {
		struct buf v = { 0 };
		size_t off = l->i, voff;
		int aline = l->line;

		l->i += n + 1;
		voff = l->i;
		if (word(l, &v, &computed, true) == -1) {
			free(v.s);
			fail(l->err, l->errlen, "line %d: a quote or a group "
			    "not closed", aline);
			errno = EINVAL;
			return (-1);
		}
		if (computed) {
			free(v.s);
			v.s = NULL;
		} else if (v.s == NULL && (v.s = strdup("")) == NULL)
			return (-1);
		if (add(l, l->s + off, n, v.s, (computed ? VC_COMPUTED : 0) |
		    (l->depth > 0 ? VC_COND : 0), off, aline, voff,
		    l->i) == -1) {
			free(v.s);
			return (-1);
		}
		skip_blank(l);
		if (at(l, 0) == ';' && at(l, 1) != ';') {
			l->i++;
			skip_blank(l);
		}
	}
	c = at(l, 0);
	if (l->f->na > first && (c == -1 || c == '\n' || c == '#')) {
		/* Assignments alone: they set the variables. */
		while (at(l, 0) != -1 && at(l, 0) != '\n')
			l->i++;
		if (at(l, 0) == '\n') {
			l->i++;
			l->line++;
		}
		for (size_t k = first; k < l->f->na; k++) {
			l->f->a[k].soff = soff;
			l->f->a[k].send = l->i;
			l->f->a[k].nstmt = l->f->na - first;
		}
		return (0);
	}
	/*
	 * Not assignments alone: those read so far are a command's
	 * environment, or run after "&&", in a pipeline...: the line is
	 * read again as another.
	 */
	for (size_t k = first; k < l->f->na; k++) {
		free(l->f->a[k].name);
		free(l->f->a[k].value);
	}
	l->f->na = first;
	l->i = soff;
	l->line = sline;
	return (other_line(l, soff));
}

/*
 * loader.conf, as the loader's config.lua reads it (config.parse()): a
 * line at a time, blanks around; a comment; NAME = VALUE, VALUE a
 * "string" without quotes in it or a word, then blanks or a comment;
 * anything else malformed, skipped.  NAME is a letter or a digit, then
 * those, "_", "." or "-".  A value is processEnvVar()'s (\c is c, $name
 * and ${name} expand), but a module's _load (made upper case), _name,
 * _type, _flags, _before, _after and _error, which are taken as they
 * are; exec="..." runs a command.
 */
static const char *const loader_module[] = { "_load", "_name", "_type",
    "_flags", "_before", "_after", "_error" };

static bool
lspace(int c)
{

	return (c == ' ' || c == '\t' || c == '\r' || c == '\v' || c == '\f');
}

static bool
lalnum(int c)
{

	return (c >= 0 && c < 0x80 && isalnum(c));
}

static bool
lword(int c, bool first)
{

	return (lalnum(c) || c == '-' || (!first && (c == '_' || c == '.')));
}

/* The suffix of a module's line it has, or -1. */
static int
loader_suffix(const char *name, size_t n)
{

	for (size_t i = 0; i < nitems(loader_module); i++) {
		size_t k = strlen(loader_module[i]);

		if (n > k && memcmp(name + n - k, loader_module[i], k) == 0)
			return ((int)i);
	}
	return (-1);
}

static int
loader_line(struct vc_file *f, size_t s, size_t eol, int line)
{
	const char *t = f->text;
	size_t i = s, n0, n1, v0, v1, c0, c1;
	struct buf v = { 0 };
	unsigned flags = 0;
	char *name;
	int suffix;

	while (i < eol && lspace(t[i]))
		i++;
	if (i == eol || t[i] == '#')
		return (0);
	n0 = i;
	while (i < eol && (lalnum(t[i]) || t[i] == '_' || t[i] == '.' ||
	    t[i] == '-'))
		i++;
	n1 = i;
	while (i < eol && lspace(t[i]))
		i++;
	if (n1 == n0 || i == eol || t[i] != '=')
		return (0);		/* malformed: skipped */
	suffix = loader_suffix(t + n0, n1 - n0);
	/* Not a module's line: a variable's name starts with one. */
	if (suffix == -1 && !lalnum(t[n0]))
		return (0);
	for (i++; i < eol && lspace(t[i]); i++)
		;
	v0 = i;
	if (i < eol && t[i] == '"') {
		for (i++; i < eol && t[i] != '"'; i++)
			;
		if (i == eol)
			return (0);
		c0 = v0 + 1;
		c1 = i++;
	} else {
		if (i == eol || !lword((unsigned char)t[i], true))
			return (0);
		for (i++; i < eol && lword((unsigned char)t[i], false); i++)
			;
		c0 = v0;
		c1 = i;
	}
	v1 = i;
	while (i < eol && lspace(t[i]))
		i++;
	if (i < eol && t[i] != '#')
		return (0);
	if ((name = strndup(t + n0, n1 - n0)) == NULL)
		return (-1);
	if (strcmp(name, "exec") == 0)
		flags = VC_OPAQUE;
	else if (suffix != -1) {
		for (size_t k = c0; k < c1; k++)
			if (b_putc(&v, suffix == 0 ? (char)toupper(
			    (unsigned char)t[k]) : t[k]) == -1)
				goto bad;
	} else {
		for (size_t k = c0; k < c1 && flags == 0; k++) {
			if (t[k] == '\\') {
				/* At the end: an error, the line not set. */
				if (k + 1 == c1)
					flags = VC_OPAQUE;
				else if (b_putc(&v, t[++k]) == -1)
					goto bad;
			} else if (t[k] == '$')
				flags = k + 1 == c1 ? VC_OPAQUE : VC_COMPUTED;
			else if (b_putc(&v, t[k]) == -1)
				goto bad;
		}
	}
	if (flags != 0) {
		free(v.s);
		v.s = NULL;
	} else if (v.s == NULL && (v.s = strdup("")) == NULL)
		goto bad;
	if (vc_add(f, name, v.s, flags, n0, line, v0, v1, s, eol) == -1) {
		free(name);
		free(v.s);
		return (-1);
	}
	return (0);
bad:
	free(name);
	free(v.s);
	return (-1);
}

/*
 * sysctl.conf, as sysctl(8)'s parsefile() and parse() read it: a line
 * at a time, cut at its first "#" not after a backslash, or after the
 * quote that closes one opened before it; trimmed; split at its first
 * "=" or ":", the name trimmed; of the value a leading quote dropped,
 * and the last character if it is the same.  Nothing is escaped.
 */
#define	VC_SYSCTL_LINE	1024		/* BUFSIZ: what fgets(3) reads */

static int
sysctl_line(struct vc_file *f, size_t s, size_t eol, int line, char *err,
    size_t errlen)
{
	const char *t = f->text, *pq, *pdq, *p;
	size_t cut = eol, b, e, d, n1, v0;
	char *name, *value;

	if (eol - s + 1 >= VC_SYSCTL_LINE) {
		fail(err, errlen, "line %d: longer than sysctl(8) reads",
		    line);
		errno = EINVAL;
		return (-1);
	}
	pq = memchr(t + s, '\'', eol - s);
	pdq = memchr(t + s, '"', eol - s);
	for (p = t + s; (p = memchr(p, '#', (size_t)(t + eol - p))) !=
	    NULL; p++) {
		if (pq != NULL && p > pq) {
			p = memchr(pq + 1, '\'', (size_t)(t + eol - pq - 1));
			if (p != NULL)
				cut = (size_t)(p - t) + 1;
			break;
		} else if (pdq != NULL && p > pdq) {
			p = memchr(pdq + 1, '"', (size_t)(t + eol - pdq - 1));
			if (p != NULL)
				cut = (size_t)(p - t) + 1;
			break;
		} else if (p == t + s || p[-1] != '\\') {
			cut = (size_t)(p - t);
			break;
		}
	}
	for (e = cut; e > s && isspace((unsigned char)t[e - 1]); e--)
		;
	for (b = s; b < e && isspace((unsigned char)t[b]); b++)
		;
	if (b == e)
		return (0);
	for (d = b; d < e && t[d] != '=' && t[d] != ':'; d++)
		;
	if (d == e)
		return (0);		/* a name alone: read, not set */
	for (n1 = d; n1 > b && isspace((unsigned char)t[n1 - 1]); n1--)
		;
	for (v0 = d + 1; v0 < e && isspace((unsigned char)t[v0]); v0++)
		;
	if (n1 == b)
		return (0);
	if (v0 < e && (t[v0] == '"' || t[v0] == '\'')) {
		size_t c1 = e - v0 >= 2 && t[e - 1] == t[v0] ? e - 1 : e;

		value = v0 + 1 <= c1 ? strndup(t + v0 + 1, c1 - v0 - 1) :
		    strdup("");
	} else
		value = strndup(t + v0, e - v0);
	if (value == NULL || (name = strndup(t + b, n1 - b)) == NULL) {
		free(value);
		return (-1);
	}
	if (vc_add(f, name, value, 0, b, line, v0, e, s, eol) == -1) {
		free(name);
		free(value);
		return (-1);
	}
	return (0);
}

/* A file of lines, each read by the dialect's line(). */
static int
lines(struct vc_file *f, char *err, size_t errlen)
{
	size_t s = 0;
	int line = 1, rc;

	while (s < f->len) {
		const char *nl = memchr(f->text + s, '\n', f->len - s);
		size_t eol = nl != NULL ? (size_t)(nl - f->text) : f->len;
		size_t send = nl != NULL ? eol + 1 : eol;

		rc = f->dialect == VC_LOADER ? loader_line(f, s, eol, line) :
		    sysctl_line(f, s, eol, line, err, errlen);
		if (rc == -1)
			return (-1);
		/* A line's end is past its newline. */
		if (f->na > 0 && f->a[f->na - 1].soff == s)
			f->a[f->na - 1].send = send;
		s = send;
		line++;
	}
	return (0);
}

int
vc_parse(struct vc_file *f, enum vc_dialect d, const char *text, size_t len,
    char *err, size_t errlen)
{
	struct lex l;
	int line_at;

	memset(f, 0, sizeof(*f));
	f->dialect = d;
	if (d != VC_SH && d != VC_LOADER && d != VC_SYSCTL) {
		fail(err, errlen, "a dialect not known");
		errno = EINVAL;
		return (-1);
	}
	if ((f->text = malloc(len + 1)) == NULL)
		return (-1);
	memcpy(f->text, text, len);
	f->text[len] = '\0';
	f->len = len;
	if (memchr(text, '\0', len) != NULL) {
		fail(err, errlen, "a NUL byte in the file");
		vc_free(f);
		errno = EINVAL;
		return (-1);
	}
	if (d != VC_SH) {
		if (lines(f, err, errlen) == -1) {
			vc_free(f);
			return (-1);
		}
		return (0);
	}
	memset(&l, 0, sizeof(l));
	l.s = f->text;
	l.len = len;
	l.line = 1;
	l.f = f;
	l.err = err;
	l.errlen = errlen;
	while (l.i < l.len) {
		size_t was = l.i;

		line_at = l.line;
		if (l.heredoc != NULL)
			heredoc_line(&l);
		else if (line(&l) == -1) {
			free(l.heredoc);
			vc_free(f);
			return (-1);
		}
		/* A line ends past its newline, or at the file's end. */
		if (l.i == was) {
			fail(err, errlen, "line %d: not read", line_at);
			free(l.heredoc);
			vc_free(f);
			errno = EINVAL;
			return (-1);
		}
	}
	free(l.heredoc);
	return (0);
}

int
vc_read(struct vc_file *f, enum vc_dialect d, const char *path, char *err,
    size_t errlen)
{
	struct stat sb;
	char *buf;
	ssize_t r;
	size_t len = 0;
	int fd, rc;

	if ((fd = open(path, O_RDONLY | O_CLOEXEC)) == -1) {
		if (errno == ENOENT)
			return (vc_parse(f, d, "", 0, err, errlen));
		fail(err, errlen, "%s: %s", path, strerror(errno));
		return (-1);
	}
	if (fstat(fd, &sb) == -1 || !S_ISREG(sb.st_mode) ||
	    sb.st_size > VC_MAX_SIZE) {
		fail(err, errlen, "%s: %s", path, !S_ISREG(sb.st_mode) ?
		    "not a file" : sb.st_size > VC_MAX_SIZE ? "too big" :
		    strerror(errno));
		close(fd);
		errno = EINVAL;
		return (-1);
	}
	if ((buf = malloc((size_t)sb.st_size + 1)) == NULL) {
		close(fd);
		return (-1);
	}
	while (len < (size_t)sb.st_size &&
	    (r = read(fd, buf + len, (size_t)sb.st_size - len)) > 0)
		len += (size_t)r;
	close(fd);
	rc = vc_parse(f, d, buf, len, err, errlen);
	free(buf);
	return (rc);
}

void
vc_free(struct vc_file *f)
{

	if (f == NULL)
		return;
	for (size_t i = 0; i < f->na; i++) {
		free(f->a[i].name);
		free(f->a[i].value);
	}
	free(f->a);
	free(f->text);
	memset(f, 0, sizeof(*f));
}

bool
vc_name_ok(enum vc_dialect d, const char *s)
{
	size_t n;

	if (s == NULL || *s == '\0')
		return (false);
	for (n = 0; s[n] != '\0'; n++) {
		int c = (unsigned char)s[n];

		switch (d) {
		case VC_SH:
			if (n == 0 ? !name_start(c) : !name_char(c))
				return (false);
			break;
		case VC_LOADER:
			if (!lalnum(c) && (n == 0 || (c != '_' && c != '.' &&
			    c != '-')))
				return (false);
			break;
		case VC_SYSCTL:
			if (!lalnum(c) && c != '_' && (n == 0 || (c != '.' &&
			    c != '%' && c != '-')))
				return (false);
			break;
		default:
			return (false);
		}
	}
	/* exec is the loader's command, not a variable. */
	if (d == VC_LOADER && strcmp(s, "exec") == 0)
		return (false);
	return (n <= VC_MAX_NAME);
}

/* The assignment that holds when the file is read: the last. */
const struct vc_assign *
vc_get(const struct vc_file *f, const char *name)
{

	for (size_t i = f->na; i > 0; i--)
		if (strcmp(f->a[i - 1].name, name) == 0)
			return (&f->a[i - 1]);
	return (NULL);
}

/*
 * Whether what the file does to name is known by reading it: no
 * assignment of it computed, conditional or opaque.
 */
bool
vc_settled(const struct vc_file *f, const char *name)
{

	for (size_t i = 0; i < f->na; i++)
		if (strcmp(f->a[i].name, name) == 0 && f->a[i].flags != 0)
			return (false);
	return (true);
}

/*
 * Whether name can be changed in the file: no assignment of it that
 * may not run, or is not one; a computed one is replaced or removed.
 */
static bool
editable(const struct vc_file *f, const char *name, char *err,
    size_t errlen)
{

	for (size_t i = 0; i < f->na; i++)
		if (strcmp(f->a[i].name, name) == 0 &&
		    (f->a[i].flags & (VC_COND | VC_OPAQUE)) != 0) {
			fail(err, errlen, (f->a[i].flags & VC_COND) ?
			    "%s: line %d may or may not set it (an if, a "
			    "loop, a function): change it by hand" :
			    "%s: line %d sets it in a way not read here (a "
			    "command's environment, a subshell): change it "
			    "by hand", name, f->a[i].line);
			errno = EBUSY;
			return (false);
		}
	return (true);
}

/*
 * Writing.
 */

static bool
plain(const char *v)
{

	if (*v == '\0')
		return (false);
	for (; *v != '\0'; v++)
		if (!isalnum((unsigned char)*v) && strchr("_./:,+@%=-",
		    *v) == NULL)
			return (false);
	return (true);
}

/* A value as a word of sh(1), quoted as was its old one when it can. */
static int
quoted(struct buf *b, const char *v, char was)
{

	if (was == 0 && plain(v))
		return (b_puts(b, v, strlen(v)));
	if (was == '\'' && strchr(v, '\'') == NULL) {
		if (b_putc(b, '\'') == -1 || b_puts(b, v, strlen(v)) == -1)
			return (-1);
		return (b_putc(b, '\''));
	}
	if (b_putc(b, '"') == -1)
		return (-1);
	for (; *v != '\0'; v++)
		if ((strchr("$`\"\\", *v) != NULL && b_putc(b, '\\') == -1) ||
		    b_putc(b, *v) == -1)
			return (-1);
	return (b_putc(b, '"'));
}

/*
 * A value in a dialect's quoting, as was's (its old quote, or 0 for a
 * bare word) where it can be.  -1, EINVAL and err: one it cannot hold.
 */
static int
render(enum vc_dialect d, const char *name, const char *v, char was,
    struct buf *b, char *err, size_t errlen)
{
	size_t n = strlen(v);
	bool word;
	char q;

	switch (d) {
	case VC_SH:
		return (quoted(b, v, was));
	case VC_LOADER:
		if (strchr(v, '"') != NULL) {
			fail(err, errlen, "%s: loader.conf cannot hold a \" in a "
			    "value", name);
			errno = EINVAL;
			return (-1);
		}
		word = n > 0 && lword((unsigned char)v[0], true);
		for (size_t i = 1; word && i < n; i++)
			word = lword((unsigned char)v[i], false);
		if (was == 0 && word)
			return (b_puts(b, v, n));
		if (b_putc(b, '"') == -1)
			return (-1);
		for (size_t i = 0; i < n; i++)
			/* A module's line is taken as it is. */
			if ((loader_suffix(name, strlen(name)) == -1 &&
			    (v[i] == '\\' || v[i] == '$') &&
			    b_putc(b, '\\') == -1) || b_putc(b, v[i]) == -1)
				return (-1);
		return (b_putc(b, '"'));
	case VC_SYSCTL:
		if (was == 0 && n > 0 && !isspace((unsigned char)v[0]) &&
		    !isspace((unsigned char)v[n - 1]) && v[0] != '"' &&
		    v[0] != '\'' && strchr(v, '#') == NULL)
			return (b_puts(b, v, n));
		q = was != 0 ? was : '"';
		if (strchr(v, q) != NULL)
			q = q == '"' ? '\'' : '"';
		if (strchr(v, q) != NULL) {
			fail(err, errlen, "%s: sysctl.conf cannot hold both "
			    "quotes in a value it must quote", name);
			errno = EINVAL;
			return (-1);
		}
		if (b_putc(b, q) == -1 || b_puts(b, v, n) == -1)
			return (-1);
		return (b_putc(b, q));
	default:
		errno = EINVAL;
		return (-1);
	}
}

/* What a dialect reads a value set as: loader.conf's _load upper. */
static bool
reads_as(enum vc_dialect d, const char *name, const char *got,
    const char *want)
{

	if (got == NULL)
		return (false);
	if (d == VC_LOADER && loader_suffix(name, strlen(name)) == 0)
		return (strcasecmp(got, want) == 0);
	return (strcmp(got, want) == 0);
}

/*
 * The file's text with bytes [s, e) replaced by r; and parsed again.
 * An edit of name's value to want: it must read back so, or is not made.
 */
static int
splice(struct vc_file *f, size_t s, size_t e, const char *r, size_t rlen,
    const char *name, const char *want, char *err, size_t errlen)
{
	struct vc_file nf;
	char *t;
	size_t len = f->len - (e - s) + rlen;
	int rc;

	if ((t = malloc(len + 1)) == NULL)
		return (-1);
	memcpy(t, f->text, s);
	memcpy(t + s, r, rlen);
	memcpy(t + s + rlen, f->text + e, f->len - e);
	t[len] = '\0';
	rc = vc_parse(&nf, f->dialect, t, len, err, errlen);
	free(t);
	if (rc == -1)
		return (-1);
	/* An edit of a value: it reads back as given, or is not made. */
	if (name != NULL && !reads_as(nf.dialect, name, vc_get(&nf, name) !=
	    NULL ? vc_get(&nf, name)->value : NULL, want)) {
		fail(err, errlen, "%s: its value would not read back as given",
		    name);
		vc_free(&nf);
		errno = EINVAL;
		return (-1);
	}
	vc_free(f);
	*f = nf;
	return (0);
}

static bool
value_ok(const char *v)
{

	for (; *v != '\0'; v++)
		if (((unsigned char)*v < 0x20 && *v != '\t') || *v == 0x7f)
			return (false);
	return (true);
}

/*
 * name set to value: the value of the assignment that holds replaced,
 * the rest of its line as it was; else a line appended.  Refused where
 * reading the file does not settle the name.
 */
int
vc_set(struct vc_file *f, const char *name, const char *value, char *err,
    size_t errlen)
{
	const struct vc_assign *a;
	struct buf b = { 0 };
	int rc;

	if (!vc_name_ok(f->dialect, name)) {
		fail(err, errlen, "%s: not a variable's name", name);
		errno = EINVAL;
		return (-1);
	}
	if (value == NULL || !value_ok(value)) {
		fail(err, errlen, "%s: a control character in its value",
		    name);
		errno = EINVAL;
		return (-1);
	}
	if (!editable(f, name, err, errlen))
		return (-1);
	if ((a = vc_get(f, name)) != NULL) {
		char was = f->text[a->voff];

		if ((was != '"' && was != '\'') || a->vend - a->voff < 2 ||
		    f->text[a->vend - 1] != was)
			was = 0;
		if (render(f->dialect, name, value, was, &b, err,
		    errlen) == -1) {
			free(b.s);
			return (-1);
		}
		/* The same bytes again: nothing to do. */
		if (b.len == a->vend - a->voff &&
		    memcmp(b.s, f->text + a->voff, b.len) == 0) {
			free(b.s);
			return (0);
		}
		rc = splice(f, a->voff, a->vend, b.s, b.len, name, value, err,
		    errlen);
		free(b.s);
		return (rc);
	}
	/* A new line: sh(1) and the loader's quoted, sysctl(8)'s bare. */
	if ((f->len > 0 && f->text[f->len - 1] != '\n' &&
	    b_putc(&b, '\n') == -1) || b_puts(&b, name, strlen(name)) == -1 ||
	    b_putc(&b, '=') == -1 || render(f->dialect, name, value,
	    f->dialect == VC_SYSCTL ? 0 : '"', &b, err, errlen) == -1 ||
	    b_putc(&b, '\n') == -1) {
		free(b.s);
		return (-1);
	}
	rc = splice(f, f->len, f->len, b.s, b.len, name, value, err, errlen);
	free(b.s);
	return (rc);
}

/*
 * Every assignment of name removed: its line, if alone on it (a comment
 * after it too), else it and the blanks after it.
 */
int
vc_unset(struct vc_file *f, const char *name, char *err, size_t errlen)
{

	if (!vc_name_ok(f->dialect, name)) {
		fail(err, errlen, "%s: not a variable's name", name);
		errno = EINVAL;
		return (-1);
	}
	if (!editable(f, name, err, errlen))
		return (-1);
	for (;;) {
		const struct vc_assign *a = vc_get(f, name);
		size_t s, e;

		if (a == NULL)
			return (0);
		if (a->nstmt == 1) {
			s = a->soff;
			e = a->send;
		} else {
			s = a->off;
			e = a->vend;
			while (e < f->len && (f->text[e] == ' ' ||
			    f->text[e] == '\t' || f->text[e] == ';'))
				e++;
		}
		if (splice(f, s, e, "", 0, NULL, NULL, err, errlen) == -1)
			return (-1);
	}
}

/*
 * Every assignment of name commented out where it is: its line, if it
 * is alone on it, with "#" before it and "  # mark" after (mark given);
 * else it taken off the line, as vc_unset() takes it, and a line of its
 * own, so commented, put before the line.  "#" and the mark taken off
 * give the assignment again.
 */
int
vc_comment(struct vc_file *f, const char *name, const char *mark, char *err,
    size_t errlen)
{

	if (!vc_name_ok(f->dialect, name)) {
		fail(err, errlen, "%s: not a variable's name", name);
		errno = EINVAL;
		return (-1);
	}
	if (!editable(f, name, err, errlen))
		return (-1);
	for (;;) {
		const struct vc_assign *a = vc_get(f, name);
		struct buf b = { 0 };
		size_t s, e, eol;
		int rc;

		if (a == NULL)
			return (0);
		eol = a->send > a->soff && f->text[a->send - 1] == '\n' ?
		    a->send - 1 : a->send;
		if (a->nstmt == 1) {
			s = a->soff;
			e = eol;
		} else {
			s = a->off;
			e = a->vend;
		}
		if (b_putc(&b, '#') == -1 || b_puts(&b, f->text + s, e - s) ==
		    -1 || (mark != NULL && (b_puts(&b, "  # ", 4) == -1 ||
		    b_puts(&b, mark, strlen(mark)) == -1))) {
			free(b.s);
			return (-1);
		}
		if (a->nstmt == 1) {
			if (eol < a->send && b_putc(&b, '\n') == -1) {
				free(b.s);
				return (-1);
			}
			rc = splice(f, a->soff, a->send, b.s, b.len, NULL,
			    NULL, err, errlen);
		} else {
			/* The line without it, and the blanks after it, under
			 * the comment line. */
			while (e < f->len && (f->text[e] == ' ' ||
			    f->text[e] == '\t' || f->text[e] == ';'))
				e++;
			if (b_putc(&b, '\n') == -1 || b_puts(&b, f->text +
			    a->soff, s - a->soff) == -1 || b_puts(&b, f->text +
			    e, a->send - e) == -1) {
				free(b.s);
				return (-1);
			}
			rc = splice(f, a->soff, a->send, b.s, b.len, NULL,
			    NULL, err, errlen);
		}
		free(b.s);
		if (rc == -1)
			return (-1);
	}
}

/*
 * vc_comment()'s inverse: every line that is "#", an assignment of name
 * and "  # mark" put back as the assignment, the rest of the line as it
 * was; a comment without the mark left alone.  One vc_comment() took
 * off a shared line comes back on its own line, before the rest, which
 * sh(1) reads the same.  Refused, the file as it was (EINVAL): a marked
 * line of name's that would not read back as that assignment alone,
 * plainly and with its value (another on it, an "if" or a here-document
 * around it now).  The lines put back, or -1.
 */
int
vc_uncomment(struct vc_file *f, const char *name, const char *mark,
    char *err, size_t errlen)
{
	struct vc_file	 nf, lf;
	struct buf	 b = { 0 };
	struct back {
		int	 line;
		char	*value;
	}		*bk = NULL;
	size_t		 mlen, nbk = 0, s, eol, e;
	int		 line = 1, rc = -1;

	if (!vc_name_ok(f->dialect, name) || mark == NULL || *mark == '\0') {
		fail(err, errlen, "%s: not a variable's name, or no mark",
		    name);
		errno = EINVAL;
		return (-1);
	}
	mlen = strlen(mark);
	for (s = 0; s < f->len; s = e, line++) {
		const char *t = f->text + s;
		size_t blen;
		bool ours = false;

		for (eol = s; eol < f->len && f->text[eol] != '\n'; eol++)
			;
		e = eol < f->len ? eol + 1 : eol;
		/* "#" body "  # " mark */
		if (eol - s >= 1 + 4 + mlen && t[0] == '#' &&
		    memcmp(f->text + eol - mlen - 4, "  # ", 4) == 0 &&
		    memcmp(f->text + eol - mlen, mark, mlen) == 0) {
			blen = eol - s - 1 - 4 - mlen;
			if (vc_parse(&lf, f->dialect, t + 1, blen, NULL, 0) ==
			    0) {
				for (size_t i = 0; i < lf.na; i++)
					if (strcmp(lf.a[i].name, name) == 0)
						ours = true;
				if (ours && (lf.na != 1 || (lf.a[0].flags &
				    (VC_COND | VC_OPAQUE)) != 0)) {
					fail(err, errlen, "%s: line %d: not one "
					    "assignment of it alone: restore it "
					    "by hand", name, line);
					vc_free(&lf);
					goto out;
				}
				if (ours) {
					struct back *nb;

					if ((nb = reallocarray(bk, nbk + 1,
					    sizeof(*bk))) == NULL) {
						vc_free(&lf);
						goto fail;
					}
					bk = nb;
					bk[nbk].line = line;
					bk[nbk].value = NULL;
					if (lf.a[0].value != NULL &&
					    (bk[nbk].value = strdup(
					    lf.a[0].value)) == NULL) {
						vc_free(&lf);
						goto fail;
					}
					nbk++;
				}
				vc_free(&lf);
			}
			if (ours) {
				if (b_puts(&b, t + 1, blen) == -1 ||
				    b_puts(&b, f->text + eol, e - eol) == -1)
					goto fail;
				continue;
			}
		}
		if (b_puts(&b, t, e - s) == -1)
			goto fail;
	}
	if (nbk == 0) {
		rc = 0;
		goto done;
	}
	if (vc_parse(&nf, f->dialect, b.s, b.len, err, errlen) == -1)
		goto done;
	/* Each where it was, as it was, as plainly. */
	for (size_t k = 0; k < nbk; k++) {
		const struct vc_assign *a = NULL;

		for (size_t i = 0; i < nf.na && a == NULL; i++)
			if (nf.a[i].line == bk[k].line &&
			    strcmp(nf.a[i].name, name) == 0)
				a = &nf.a[i];
		if (a == NULL || a->nstmt != 1 ||
		    (a->flags & (VC_COND | VC_OPAQUE)) != 0 ||
		    (a->value == NULL) != (bk[k].value == NULL) ||
		    (a->value != NULL && strcmp(a->value, bk[k].value) != 0)) {
			fail(err, errlen, "%s: line %d would not read back as "
			    "it was (an \"if\", a here-document around it?): "
			    "restore it by hand", name, bk[k].line);
			vc_free(&nf);
			goto out;
		}
	}
	vc_free(f);
	*f = nf;
	rc = (int)nbk;
	goto done;
fail:
	fail(err, errlen, "%s: %s", name, strerror(ENOMEM));
	errno = ENOMEM;
	goto done;
out:
	errno = EINVAL;
done:
	for (size_t k = 0; k < nbk; k++)
		free(bk[k].value);
	free(bk);
	free(b.s);
	return (rc);
}

/*
 * The file written to path atomically: a temporary file next to it,
 * the old one's mode and owner (mode for a new one), fsync, rename.
 */
int
vc_write(const struct vc_file *f, const char *path, mode_t mode, char *err,
    size_t errlen)
{
	struct stat sb;
	char tmp[MAXPATHLEN];
	size_t off;
	ssize_t w;
	bool old;
	int fd;

	if (!(old = stat(path, &sb) == 0) && errno != ENOENT) {
		fail(err, errlen, "stat %s: %s", path, strerror(errno));
		return (-1);
	}
	if (snprintf(tmp, sizeof(tmp), "%s.XXXXXX", path) >=
	    (int)sizeof(tmp)) {
		fail(err, errlen, "%s: path too long", path);
		errno = ENAMETOOLONG;
		return (-1);
	}
	if ((fd = mkstemp(tmp)) == -1) {
		fail(err, errlen, "mkstemp %s: %s", tmp, strerror(errno));
		return (-1);
	}
	for (off = 0; off < f->len; off += (size_t)w)
		if ((w = write(fd, f->text + off, f->len - off)) <= 0) {
			fail(err, errlen, "write %s: %s", tmp,
			    strerror(errno));
			goto bad;
		}
	if (fchmod(fd, old ? sb.st_mode & ALLPERMS : mode) == -1 ||
	    (old && geteuid() == 0 && fchown(fd, sb.st_uid, sb.st_gid) ==
	    -1) || fsync(fd) == -1) {
		fail(err, errlen, "%s: %s", tmp, strerror(errno));
		goto bad;
	}
	close(fd);
	if (rename(tmp, path) == -1) {
		fail(err, errlen, "rename %s: %s", path, strerror(errno));
		unlink(tmp);
		return (-1);
	}
	return (0);
bad:
	close(fd);
	unlink(tmp);
	return (-1);
}

/*
 * The fragment owner keeps of rc(8)'s service: etc/rc.conf.d/svc/owner,
 * which load_rc_config reads with every file of rc.conf.d/svc when it
 * is a directory.  Refused if rc.conf.d/svc is a file, someone else's:
 * rc(8) reads that one alone.  The directories are made if missing.
 */
int
vc_rcd_path(const char *etc, const char *svc, const char *owner, char *path,
    size_t len, char *err, size_t errlen)
{
	struct stat sb;
	char dir[MAXPATHLEN];

	if (!vc_name_ok(VC_SH, svc) || !vc_name_ok(VC_SH, owner)) {
		fail(err, errlen, "%s/%s: not a service's or an owner's name",
		    svc, owner);
		errno = EINVAL;
		return (-1);
	}
	if (snprintf(dir, sizeof(dir), "%s/rc.conf.d", etc) >=
	    (int)sizeof(dir) || snprintf(path, len, "%s/%s/%s", dir, svc,
	    owner) >= (int)len) {
		fail(err, errlen, "%s: path too long", etc);
		errno = ENAMETOOLONG;
		return (-1);
	}
	if (mkdir(dir, 0755) == -1 && errno != EEXIST) {
		fail(err, errlen, "mkdir %s: %s", dir, strerror(errno));
		return (-1);
	}
	strlcat(dir, "/", sizeof(dir));
	strlcat(dir, svc, sizeof(dir));
	if (lstat(dir, &sb) == 0 && !S_ISDIR(sb.st_mode)) {
		fail(err, errlen, "%s is a file, which rc(8) reads alone: "
		    "move it into a directory of that name for %s's to go "
		    "beside it", dir, owner);
		errno = EEXIST;
		return (-1);
	}
	if (mkdir(dir, 0755) == -1 && errno != EEXIST) {
		fail(err, errlen, "mkdir %s: %s", dir, strerror(errno));
		return (-1);
	}
	return (0);
}

/*
 * The files a list of paths adds, each once, under root.
 */
struct plist {
	char	**v;
	size_t	 n;
};

static bool
pl_has(const struct plist *p, const char *s)
{

	for (size_t i = 0; i < p->n; i++)
		if (strcmp(p->v[i], s) == 0)
			return (true);
	return (false);
}

static int
pl_add(struct plist *p, const char *root, const char *path)
{
	char buf[MAXPATHLEN], **v;

	if (snprintf(buf, sizeof(buf), "%s%s", root, path) >=
	    (int)sizeof(buf)) {
		errno = ENAMETOOLONG;
		return (-1);
	}
	if (pl_has(p, buf))
		return (0);
	if ((v = reallocarray(p->v, p->n + 1, sizeof(*v))) == NULL)
		return (-1);
	p->v = v;
	if ((p->v[p->n] = strdup(buf)) == NULL)
		return (-1);
	p->n++;
	return (0);
}

void
vc_rc_files_free(char **paths, size_t n)
{

	for (size_t i = 0; i < n; i++)
		free(paths[i]);
	free(paths);
}

/*
 * A list variable's value as the files read so far leave it (the last
 * assignment of it, in the files' order): dflt if none sets it; NULL,
 * err said, if one sets it in a way reading does not settle.
 */
static const char *
list_var(struct vc_file *files, size_t n, const char *name, const char *dflt,
    char *err, size_t errlen)
{
	const char *v = dflt;

	for (size_t i = 0; i < n; i++) {
		const struct vc_assign *a = vc_get(&files[i], name);

		if (a == NULL)
			continue;
		if (!vc_settled(&files[i], name)) {
			fail(err, errlen, "%s: set where reading does not "
			    "tell its value (line %d): the files rc(8) reads "
			    "cannot be told", name, a->line);
			errno = EINVAL;
			return (NULL);
		}
		v = a->value;
	}
	return (v);
}

/* Each word of a list, under root, read if it is there. */
static int
read_list(const char *root, const char *list, struct plist *seen,
    struct vc_file **files, size_t *nfiles, char *err, size_t errlen)
{
	char *copy, *p, *w;
	int rc = 0;

	if ((copy = strdup(list)) == NULL)
		return (-1);
	for (p = copy; rc == 0 && (w = strsep(&p, " \t")) != NULL; ) {
		struct vc_file *nf;
		size_t was = seen->n;

		if (*w == '\0')
			continue;
		if ((rc = pl_add(seen, root, w)) == -1 || seen->n == was ||
		    access(seen->v[seen->n - 1], R_OK) == -1)
			continue;
		if ((nf = reallocarray(*files, *nfiles + 1,
		    sizeof(*nf))) == NULL) {
			rc = -1;
			break;
		}
		*files = nf;
		if ((rc = vc_read(&nf[*nfiles], VC_SH, seen->v[seen->n - 1],
		    err, errlen)) == 0)
			(*nfiles)++;
	}
	free(copy);
	return (rc);
}

static int
by_name(const void *a, const void *b)
{

	return (strcmp(*(char *const *)a, *(char *const *)b));
}

/* rc.conf.d/svc of a directory: the file, or the directory's files. */
static int
rcd_files(struct plist *out, const char *root, const char *base,
    const char *svc, const char *skip)
{
	char path[MAXPATHLEN], **names = NULL;
	struct dirent *de;
	struct stat sb;
	size_t n = 0;
	DIR *d;
	int rc = 0;

	if (snprintf(path, sizeof(path), "%s/rc.conf.d/%s", base, svc) >=
	    (int)sizeof(path)) {
		errno = ENAMETOOLONG;
		return (-1);
	}
	{
		char full[MAXPATHLEN];

		snprintf(full, sizeof(full), "%s%s", root, path);
		if (stat(full, &sb) == -1)
			return (0);
		if (S_ISREG(sb.st_mode))
			return (pl_add(out, root, path));
		if (!S_ISDIR(sb.st_mode) || (d = opendir(full)) == NULL)
			return (0);
	}
	/* As sh(1)'s "*": no dot files, in order. */
	while ((de = readdir(d)) != NULL) {
		char **v;

		if (de->d_name[0] == '.')
			continue;
		if ((v = reallocarray(names, n + 1, sizeof(*v))) == NULL ||
		    (v[n] = strdup(de->d_name)) == NULL) {
			free(v != NULL ? v : names);
			closedir(d);
			return (-1);
		}
		names = v;
		n++;
	}
	closedir(d);
	qsort(names, n, sizeof(*names), by_name);
	for (size_t i = 0; i < n; i++) {
		char f[MAXPATHLEN], full[MAXPATHLEN];

		snprintf(f, sizeof(f), "%s/%s", path, names[i]);
		snprintf(full, sizeof(full), "%s%s", root, f);
		if (rc == 0 && (skip == NULL || strcmp(f, skip) != 0) &&
		    stat(full, &sb) == 0 && S_ISREG(sb.st_mode))
			rc = pl_add(out, root, f);
		free(names[i]);
	}
	free(names);
	return (rc);
}

/*
 * The user's files rc(8) reads for service svc, in its order, owner's
 * fragment (/etc/rc.conf.d/svc/owner) not among them; each path under
 * root ("" for the system).  load_rc_config reads /etc/defaults/rc.conf,
 * which is not the user's; its rc_conf_files, then those any of them
 * names anew (source_rc_confs reads them twice); and the rc.conf.d/svc,
 * file or directory, of /etc and of each local_startup directory less
 * its "/rc.d", local_startup ${localbase}/etc/rc.d unless the files set
 * it.  Refused where reading does not settle a list it needs.
 */
int
vc_rc_files(const char *root, const char *localbase, const char *svc,
    const char *owner, char ***paths, size_t *npaths, char *err,
    size_t errlen)
{
	struct plist seen = { 0 }, out = { 0 };
	struct vc_file *files = NULL, dflt;
	char path[MAXPATHLEN], skip[MAXPATHLEN], ls[MAXPATHLEN];
	const char *list, *startup;
	size_t nfiles = 0;
	char *copy = NULL, *p, *w;
	int rc = -1;

	*paths = NULL;
	*npaths = 0;
	if (!vc_name_ok(VC_SH, svc) || !vc_name_ok(VC_SH, owner)) {
		fail(err, errlen, "%s/%s: not a service's or an owner's name",
		    svc, owner);
		errno = EINVAL;
		return (-1);
	}
	snprintf(path, sizeof(path), "%s/etc/defaults/rc.conf", root);
	if (vc_read(&dflt, VC_SH, path, err, errlen) == -1)
		return (-1);
	if ((list = list_var(&dflt, 1, "rc_conf_files",
	    "/etc/rc.conf /etc/rc.conf.local", err, errlen)) == NULL ||
	    read_list(root, list, &seen, &files, &nfiles, err, errlen) == -1)
		goto out;
	/* Again, as rc_conf_files may now name others. */
	if ((list = list_var(files, nfiles, "rc_conf_files", list, err,
	    errlen)) == NULL ||
	    read_list(root, list, &seen, &files, &nfiles, err, errlen) == -1)
		goto out;
	/* The rc_conf_files read, in order: their paths. */
	for (size_t i = 0; i < seen.n; i++)
		if (access(seen.v[i], R_OK) == 0 &&
		    pl_add(&out, "", seen.v[i]) == -1)
			goto out;
	snprintf(ls, sizeof(ls), "%s/etc/rc.d", localbase);
	if ((startup = list_var(files, nfiles, "local_startup", ls, err,
	    errlen)) == NULL)
		goto out;
	snprintf(skip, sizeof(skip), "/etc/rc.conf.d/%s/%s", svc, owner);
	if (rcd_files(&out, root, "/etc", svc, skip) == -1 ||
	    (copy = strdup(startup)) == NULL)
		goto out;
	for (p = copy; (w = strsep(&p, " \t")) != NULL; ) {
		size_t len = strlen(w);

		if (len == 0)
			continue;
		if (len >= 5 && strcmp(w + len - 5, "/rc.d") == 0)
			w[len - 5] = '\0';
		if (strcmp(w, "/etc") != 0 &&
		    rcd_files(&out, root, w, svc, NULL) == -1)
			goto out;
	}
	*paths = out.v;
	*npaths = out.n;
	memset(&out, 0, sizeof(out));
	rc = 0;
out:
	if (rc == -1 && err != NULL && err[0] == '\0')
		fail(err, errlen, "%s", strerror(errno));
	free(copy);
	vc_rc_files_free(seen.v, seen.n);
	vc_rc_files_free(out.v, out.n);
	for (size_t i = 0; i < nfiles; i++)
		vc_free(&files[i]);
	free(files);
	vc_free(&dflt);
	return (rc);
}

/*
 * Whether one of the user's files sets name, as the conflict rule asks:
 * a fragment's variable another file of the
 * service sets too is read one way by the service and another by those
 * that read rc.conf alone.  Any assignment counts, conditional or
 * opaque ones too.  -1, EEXIST, the file and line said; 0: none.
 */
int
vc_conflict(char *const *paths, size_t n, const char *name, char *err,
    size_t errlen)
{

	for (size_t i = 0; i < n; i++) {
		struct vc_file f;

		if (vc_read(&f, VC_SH, paths[i], err, errlen) == -1)
			return (-1);
		for (size_t j = 0; j < f.na; j++)
			if (strcmp(f.a[j].name, name) == 0) {
				fail(err, errlen, "%s: %s sets it too, line "
				    "%d: remove it there to keep it here, or "
				    "the two are read differently", name,
				    paths[i], f.a[j].line);
				vc_free(&f);
				errno = EEXIST;
				return (-1);
			}
		vc_free(&f);
	}
	return (0);
}
