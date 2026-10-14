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

int
vc_parse(struct vc_file *f, enum vc_dialect d, const char *text, size_t len,
    char *err, size_t errlen)
{
	struct lex l;
	int line_at;

	memset(f, 0, sizeof(*f));
	f->dialect = d;
	if (d != VC_SH) {
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

	if (d != VC_SH || s == NULL || !name_start((unsigned char)*s))
		return (false);
	for (n = 0; s[n] != '\0'; n++)
		if (!name_char((unsigned char)s[n]))
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

/* The file's text with bytes [s, e) replaced by r; and parsed again. */
static int
splice(struct vc_file *f, size_t s, size_t e, const char *r, size_t rlen,
    char *err, size_t errlen)
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
		if (quoted(&b, value, was) == -1) {
			free(b.s);
			return (-1);
		}
		/* The same bytes again: nothing to do. */
		if (b.len == a->vend - a->voff &&
		    memcmp(b.s, f->text + a->voff, b.len) == 0) {
			free(b.s);
			return (0);
		}
		rc = splice(f, a->voff, a->vend, b.s, b.len, err, errlen);
		free(b.s);
		return (rc);
	}
	if ((f->len > 0 && f->text[f->len - 1] != '\n' &&
	    b_putc(&b, '\n') == -1) || b_puts(&b, name, strlen(name)) == -1 ||
	    b_putc(&b, '=') == -1 || quoted(&b, value, '"') == -1 ||
	    b_putc(&b, '\n') == -1) {
		free(b.s);
		return (-1);
	}
	rc = splice(f, f->len, f->len, b.s, b.len, err, errlen);
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
		if (splice(f, s, e, "", 0, err, errlen) == -1)
			return (-1);
	}
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
