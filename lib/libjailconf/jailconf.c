/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 *
 * jail.conf(5) editing with byte offsets.  See jailconf.h.
 *
 * The lexical rules follow usr.sbin/jail/jaillex.l: adjacent pieces
 * without intervening whitespace form one string, '#', '//' and C
 * comments are whitespace, nested blocks get hierarchical names.
 */

#include <sys/param.h>
#include <sys/socket.h>
#include <sys/stat.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <ctype.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <glob.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "jailconf.h"

#define	CONF_MAXSIZE	(4 * 1024 * 1024)
#define	INCLUDE_DEPTH	8

enum tok {
	T_EOF,
	T_VAL,
	T_PLEQ,
	T_ERR,
	T_COMMA = ',',
	T_SEMI = ';',
	T_EQ = '=',
	T_LBRACE = '{',
	T_RBRACE = '}',
};

struct token {
	enum tok	 type;
	struct jc_value	 val;
	size_t		 off;
	int		 line;
};

struct lexer {
	struct jc_conf	*conf;
	struct jc_file	*f;
	const char	*buf;
	size_t		 len;
	size_t		 pos;
	int		 line;
	int		 depth;
	bool		 failed;
};

struct strbuf {
	char	*s;
	size_t	 len;
	size_t	 cap;
};

static void	sb_putn(struct strbuf *, const char *, size_t);
static void	sb_puts(struct strbuf *, const char *);
static void	sb_putc(struct strbuf *, char);
static void	sb_putq(struct strbuf *, const char *, char);
static char	*sb_take(struct strbuf *);
static void	conf_error(struct jc_conf *, const char *, int, const char *,
		    ...) __printflike(4, 5);
static bool	is_atomic(int);
static void	skip_ws(struct lexer *);
static int	lex_escape(struct lexer *, struct strbuf *);
static void	value_add(struct jc_value *, bool, struct strbuf *);
static bool	at_var(const struct lexer *);
static bool	lex_var(struct lexer *, struct jc_value *, struct strbuf *,
		    bool);
static bool	lex_value(struct lexer *, struct jc_value *);
static void	next_token(struct lexer *, struct token *);
static void	value_free(struct jc_value *);
static char	*jc_value_text(const struct jc_value *);
static void	stmt_free(struct jc_stmt *);
static void	stmt_push(struct jc_stmt **, size_t *, struct jc_stmt *);
static int	parse_list(struct lexer *, struct jc_stmt *);
static int	parse_body(struct lexer *, ssize_t, const char *);
static void	do_include(struct lexer *, struct jc_stmt *);
static int	load_file(struct jc_conf *, const char *, int);
static int	add_file(struct jc_conf *, struct jc_file *, int);
static bool	file_loaded(const struct jc_conf *, const char *);
static bool	stmts_have(const struct jc_stmt *, size_t, const char *,
		    const char *, size_t *, size_t *);
static bool	block_has(const struct jc_block *, const char *, const char *);
static size_t	count_lines(const char *, size_t, size_t);
static void	emit_lines(struct strbuf *, const char *, size_t, size_t,
		    char);

static void
sb_putn(struct strbuf *sb, const char *s, size_t n)
{

	if (sb->len + n + 1 > sb->cap) {
		sb->cap = MAX(sb->cap * 2, sb->len + n + 64);
		if ((sb->s = realloc(sb->s, sb->cap)) == NULL)
			err(1, "realloc");
	}
	memcpy(sb->s + sb->len, s, n);
	sb->len += n;
	sb->s[sb->len] = '\0';
}

static void
sb_puts(struct strbuf *sb, const char *s)
{

	sb_putn(sb, s, strlen(s));
}

static void
sb_putc(struct strbuf *sb, char c)
{

	sb_putn(sb, &c, 1);
}

/* A value inside quote q, escaped the way jaillex.l decodes it. */
static void
sb_putq(struct strbuf *sb, const char *s, char q)
{

	sb_putc(sb, q);
	for (; *s != '\0'; s++) {
		if (*s == q || *s == '\\')
			sb_putc(sb, '\\');
		if (*s == '\n') {
			sb_puts(sb, "\\n");
			continue;
		}
		sb_putc(sb, *s);
	}
	sb_putc(sb, q);
}

static char *
sb_take(struct strbuf *sb)
{
	char	*s;

	if (sb->s == NULL)
		sb_putn(sb, "", 0);
	s = sb->s;
	memset(sb, 0, sizeof(*sb));
	return (s);
}

/* Keep the first error as "file line N: message". */
static void
conf_error(struct jc_conf *conf, const char *file, int line,
    const char *fmt, ...)
{
	va_list	 ap;
	char	*msg;

	if (conf->error != NULL)
		return;
	va_start(ap, fmt);
	if (vasprintf(&msg, fmt, ap) == -1)
		err(1, "vasprintf");
	va_end(ap);
	if (asprintf(&conf->error, "%s line %d: %s", file, line, msg) == -1)
		err(1, "asprintf");
	free(msg);
}

/* Characters that make up unquoted strings (jaillex.l). */
static bool
is_atomic(int c)
{

	return (isalnum(c) || strchr("_!%&()-.:<>?@[]^`|~", c) != NULL);
}

static void
skip_ws(struct lexer *lx)
{
	const char	*b;
	int		 start;

	b = lx->buf;
	while (lx->pos < lx->len) {
		if (b[lx->pos] == '\n') {
			lx->line++;
			lx->pos++;
		} else if (b[lx->pos] == ' ' || b[lx->pos] == '\t' ||
		    b[lx->pos] == '\r') {
			lx->pos++;
		} else if (b[lx->pos] == '#' || (b[lx->pos] == '/' &&
		    lx->pos + 1 < lx->len && b[lx->pos + 1] == '/')) {
			while (lx->pos < lx->len && b[lx->pos] != '\n')
				lx->pos++;
		} else if (b[lx->pos] == '/' && lx->pos + 1 < lx->len &&
		    b[lx->pos + 1] == '*') {
			start = lx->line;
			lx->pos += 2;
			while (lx->pos + 1 < lx->len &&
			    !(b[lx->pos] == '*' && b[lx->pos + 1] == '/')) {
				if (b[lx->pos] == '\n')
					lx->line++;
				lx->pos++;
			}
			if (lx->pos + 1 >= lx->len) {
				conf_error(lx->conf, lx->f->path, start,
				    "unterminated comment");
				lx->failed = true;
				lx->pos = lx->len;
				return;
			}
			lx->pos += 2;
		} else
			break;
	}
}

/* Decode a backslash escape at lx->pos into sb.  Returns -1 at EOF. */
static int
lex_escape(struct lexer *lx, struct strbuf *sb)
{
	const char	*b;
	int		 c, i, v;

	b = lx->buf;
	if (++lx->pos >= lx->len)
		return (-1);
	c = b[lx->pos++];
	switch (c) {
	case 'n':
		sb_putc(sb, '\n');
		break;
	case 't':
		sb_putc(sb, '\t');
		break;
	case 'r':
		sb_putc(sb, '\r');
		break;
	case '\n':
		lx->line++;		/* line continuation */
		break;
	case 'x':
		for (i = v = 0; i < 2 && lx->pos < lx->len &&
		    isxdigit((unsigned char)b[lx->pos]); i++, lx->pos++)
			v = v * 16 + (isdigit((unsigned char)b[lx->pos]) ?
			    b[lx->pos] - '0' :
			    tolower((unsigned char)b[lx->pos]) - 'a' + 10);
		sb_putc(sb, (char)v);
		break;
	default:
		if (c >= '0' && c <= '7') {
			v = c - '0';
			for (i = 1; i < 3 && lx->pos < lx->len &&
			    b[lx->pos] >= '0' && b[lx->pos] <= '7';
			    i++, lx->pos++)
				v = v * 8 + b[lx->pos] - '0';
			sb_putc(sb, (char)v);
		} else
			sb_putc(sb, (char)c);
		break;
	}
	return (0);
}

/* Append a literal or variable part, merging adjacent literals. */
static void
value_add(struct jc_value *v, bool isvar, struct strbuf *sb)
{
	struct jc_part	*p;

	if (!isvar && sb->len == 0)
		return;
	if (!isvar && v->nparts > 0 && !v->parts[v->nparts - 1].isvar) {
		p = &v->parts[v->nparts - 1];
		if ((p->s = realloc(p->s, strlen(p->s) + sb->len + 1)) == NULL)
			err(1, "realloc");
		strcat(p->s, sb->s);
		free(sb_take(sb));
		return;
	}
	if ((v->parts = reallocarray(v->parts, v->nparts + 1,
	    sizeof(*v->parts))) == NULL)
		err(1, "reallocarray");
	p = &v->parts[v->nparts++];
	p->isvar = isvar;
	p->s = sb_take(sb);
}

/* True if a variable reference starts at pos ('$' then name or '{'). */
static bool
at_var(const struct lexer *lx)
{
	const char	*b;

	b = lx->buf;
	return (b[lx->pos] == '$' && lx->pos + 1 < lx->len &&
	    (b[lx->pos + 1] == '{' || b[lx->pos + 1] == '_' ||
	    isalpha((unsigned char)b[lx->pos + 1])));
}

/*
 * Read "$name" or "${name}" at lx->pos into a variable part.  Inside
 * double quotes a bracketed name may not contain '"'.
 */
static bool
lex_var(struct lexer *lx, struct jc_value *v, struct strbuf *sb, bool dq)
{
	const char	*b;

	b = lx->buf;
	value_add(v, false, sb);
	lx->pos++;
	if (b[lx->pos] == '{') {
		lx->pos++;
		while (lx->pos < lx->len && b[lx->pos] != '}' &&
		    b[lx->pos] != '\n' && !(dq && b[lx->pos] == '"'))
			sb_putc(sb, b[lx->pos++]);
		if (lx->pos >= lx->len || b[lx->pos] != '}') {
			conf_error(lx->conf, lx->f->path, lx->line,
			    "unterminated variable");
			return (false);
		}
		lx->pos++;
	} else {
		while (lx->pos < lx->len && (b[lx->pos] == '_' ||
		    isalnum((unsigned char)b[lx->pos])))
			sb_putc(sb, b[lx->pos++]);
	}
	value_add(v, true, sb);
	return (true);
}

/*
 * Read one string: a run of adjacent unquoted, quoted and variable
 * pieces.  Returns false on a lexical error.
 */
static bool
lex_value(struct lexer *lx, struct jc_value *v)
{
	struct strbuf	 sb;
	const char	*b;
	int		 c, q, start;
	bool		 first;

	memset(v, 0, sizeof(*v));
	memset(&sb, 0, sizeof(sb));
	b = lx->buf;
	v->off = lx->pos;
	for (first = true; lx->pos < lx->len; first = false) {
		c = (unsigned char)b[lx->pos];
		if (isspace(c) || strchr(",;={}#", c) != NULL)
			break;
		if (c == '/' && lx->pos + 1 < lx->len &&
		    (b[lx->pos + 1] == '/' || b[lx->pos + 1] == '*'))
			break;
		if (c == '+' && lx->pos + 1 < lx->len && b[lx->pos + 1] == '=')
			break;
		if (c == '\'' || c == '"') {
			if (first)
				v->quote = (char)c;
			q = c;
			start = lx->line;
			lx->pos++;
			while (lx->pos < lx->len && b[lx->pos] != q) {
				if (b[lx->pos] == '\\') {
					if (lex_escape(lx, &sb) == -1)
						break;
				} else if (q == '"' && at_var(lx)) {
					if (!lex_var(lx, v, &sb, true))
						goto fail;
				} else {
					if (b[lx->pos] == '\n')
						lx->line++;
					sb_putc(&sb, b[lx->pos++]);
				}
			}
			if (lx->pos >= lx->len) {
				conf_error(lx->conf, lx->f->path, start,
				    "unterminated string");
				goto fail;
			}
			lx->pos++;
		} else if (at_var(lx)) {
			if (!lex_var(lx, v, &sb, false))
				goto fail;
		} else if (c == '\\') {
			if (lex_escape(lx, &sb) == -1)
				break;
		} else if (is_atomic(c)) {
			while (lx->pos < lx->len &&
			    is_atomic((unsigned char)b[lx->pos]))
				sb_putc(&sb, b[lx->pos++]);
		} else if (c == '$' || c == '*' || c == '+' || c == '/') {
			sb_putc(&sb, (char)c);
			lx->pos++;
		} else
			break;
	}
	value_add(v, false, &sb);
	v->end = lx->pos;
	return (true);

fail:
	free(sb.s);
	value_free(v);
	memset(v, 0, sizeof(*v));
	return (false);
}

static void
next_token(struct lexer *lx, struct token *t)
{
	int	c;

	memset(t, 0, sizeof(*t));
	skip_ws(lx);
	t->off = lx->pos;
	t->line = lx->line;
	if (lx->failed) {
		t->type = T_ERR;
		return;
	}
	if (lx->pos >= lx->len) {
		t->type = T_EOF;
		return;
	}
	c = (unsigned char)lx->buf[lx->pos];
	if (c == '+' && lx->pos + 1 < lx->len && lx->buf[lx->pos + 1] == '=') {
		lx->pos += 2;
		t->type = T_PLEQ;
		return;
	}
	if (strchr(",;={}", c) != NULL) {
		lx->pos++;
		t->type = (enum tok)c;
		return;
	}
	if (!lex_value(lx, &t->val)) {
		lx->failed = true;
		t->type = T_ERR;
		return;
	}
	if (t->val.end == t->val.off) {
		conf_error(lx->conf, lx->f->path, lx->line,
		    "unexpected character '%c'", isprint(c) ? c : '?');
		lx->failed = true;
		t->type = T_ERR;
		return;
	}
	t->type = T_VAL;
}

static void
value_free(struct jc_value *v)
{
	size_t	i;

	for (i = 0; i < v->nparts; i++)
		free(v->parts[i].s);
	free(v->parts);
}

static void
stmt_free(struct jc_stmt *s)
{
	size_t	i;

	free(s->key);
	for (i = 0; i < s->nvals; i++)
		value_free(&s->vals[i]);
	free(s->vals);
}

static void
stmt_push(struct jc_stmt **arr, size_t *n, struct jc_stmt *s)
{

	if ((*arr = reallocarray(*arr, *n + 1, sizeof(**arr))) == NULL)
		err(1, "reallocarray");
	(*arr)[(*n)++] = *s;
}

/* Text of a value without expansion; variables render as ${name}. */
static char *
jc_value_text(const struct jc_value *v)
{
	struct strbuf	sb;
	size_t		i;

	memset(&sb, 0, sizeof(sb));
	for (i = 0; i < v->nparts; i++) {
		if (v->parts[i].isvar) {
			sb_puts(&sb, "${");
			sb_puts(&sb, v->parts[i].s);
			sb_puts(&sb, "}");
		} else
			sb_puts(&sb, v->parts[i].s);
	}
	return (sb_take(&sb));
}

/* Read ", value"* up to ';', the first value is already in st. */
static int
parse_list(struct lexer *lx, struct jc_stmt *st)
{
	struct token	t;

	for (;;) {
		next_token(lx, &t);
		if (t.type == T_SEMI) {
			st->end = lx->pos;
			return (0);
		}
		if (t.type != T_COMMA) {
			if (t.type != T_ERR)
				conf_error(lx->conf, lx->f->path, t.line,
				    "expected ',' or ';' after value of '%s'",
				    st->key);
			value_free(&t.val);
			return (-1);
		}
		next_token(lx, &t);
		if (t.type != T_VAL) {
			if (t.type != T_ERR)
				conf_error(lx->conf, lx->f->path, t.line,
				    "expected a value after ','");
			return (-1);
		}
		if ((st->vals = reallocarray(st->vals, st->nvals + 1,
		    sizeof(*st->vals))) == NULL)
			err(1, "reallocarray");
		st->vals[st->nvals++] = t.val;
	}
}

static bool
file_loaded(const struct jc_conf *conf, const char *path)
{
	size_t	i;

	for (i = 0; i < conf->nfiles; i++)
		if (strcmp(conf->files[i]->path, path) == 0)
			return (true);
	return (false);
}

static void
do_include(struct lexer *lx, struct jc_stmt *st)
{
	glob_t	 g;
	size_t	 i, j;
	char	*pat;
	int	 rc;

	for (i = 0; i < st->nvals; i++) {
		if (st->vals[i].nparts != 1 || st->vals[i].parts[0].isvar) {
			conf_error(lx->conf, lx->f->path, st->line,
			    "variables not permitted in '.include' filename");
			continue;
		}
		pat = st->vals[i].parts[0].s;
		memset(&g, 0, sizeof(g));
		rc = glob(pat, 0, NULL, &g);
		if (rc == GLOB_NOMATCH) {
			globfree(&g);
			continue;
		}
		if (rc != 0) {
			conf_error(lx->conf, lx->f->path, st->line,
			    "glob '%s' failed", pat);
			globfree(&g);
			continue;
		}
		for (j = 0; j < g.gl_pathc; j++) {
			if (lx->depth >= INCLUDE_DEPTH) {
				conf_error(lx->conf, lx->f->path, st->line,
				    "includes nested too deeply");
				break;
			}
			if (!file_loaded(lx->conf, g.gl_pathv[j]))
				load_file(lx->conf, g.gl_pathv[j],
				    lx->depth + 1);
		}
		globfree(&g);
	}
}

/*
 * Parse statements and blocks until '}' (block >= 0) or EOF (block < 0).
 * Blocks are stored flat in f->blocks and referenced by index because
 * nested blocks may reallocate the array.
 */
static int
parse_body(struct lexer *lx, ssize_t block, const char *prefix)
{
	struct jc_file	*f;
	struct jc_block	*b;
	struct jc_stmt	 st;
	struct token	 t, t2;
	ssize_t		 nb;
	char		*name;

	f = lx->f;
	for (;;) {
		next_token(lx, &t);
		switch (t.type) {
		case T_ERR:
			return (-1);
		case T_EOF:
			if (block >= 0) {
				conf_error(lx->conf, f->path, t.line,
				    "unexpected end of file in block '%s'",
				    f->blocks[block].name);
				return (-1);
			}
			return (0);
		case T_RBRACE:
			if (block < 0) {
				conf_error(lx->conf, f->path, t.line,
				    "unexpected '}'");
				return (-1);
			}
			f->blocks[block].close = t.off;
			return (0);
		case T_SEMI:
			continue;
		case T_VAL:
			break;
		default:
			conf_error(lx->conf, f->path, t.line,
			    "unexpected '%c'", (char)t.type);
			return (-1);
		}

		memset(&st, 0, sizeof(st));
		st.off = t.off;
		st.line = t.line;
		if (t.val.nparts == 1 && t.val.parts[0].isvar) {
			st.keyvar = true;
			st.key = strdup(t.val.parts[0].s);
		} else
			st.key = jc_value_text(&t.val);
		if (st.key == NULL)
			err(1, "strdup");

		next_token(lx, &t2);
		switch (t2.type) {
		case T_LBRACE:
			value_free(&t.val);
			if (prefix != NULL) {
				if (asprintf(&name, "%s.%s", prefix,
				    st.key) == -1)
					err(1, "asprintf");
				free(st.key);
			} else
				name = st.key;
			if ((f->blocks = reallocarray(f->blocks,
			    f->nblocks + 1, sizeof(*f->blocks))) == NULL)
				err(1, "reallocarray");
			nb = (ssize_t)f->nblocks++;
			b = &f->blocks[nb];
			memset(b, 0, sizeof(*b));
			b->name = name;
			b->open = t2.off;
			b->line = t.line;
			if (parse_body(lx, nb, name) == -1)
				return (-1);
			continue;
		case T_SEMI:
			value_free(&t.val);
			st.op = JC_FLAG;
			st.end = lx->pos;
			break;
		case T_EQ:
		case T_PLEQ:
			value_free(&t.val);
			st.op = t2.type == T_EQ ? JC_SET : JC_APPEND;
			next_token(lx, &t);
			if (t.type != T_VAL) {
				if (t.type != T_ERR)
					conf_error(lx->conf, f->path, t.line,
					    "expected a value for '%s'",
					    st.key);
				stmt_free(&st);
				return (-1);
			}
			if ((st.vals = calloc(1, sizeof(*st.vals))) == NULL)
				err(1, "calloc");
			st.vals[0] = t.val;
			st.nvals = 1;
			if (parse_list(lx, &st) == -1) {
				stmt_free(&st);
				return (-1);
			}
			break;
		case T_VAL:
			value_free(&t.val);
			st.op = JC_NAMEVAL;
			if ((st.vals = calloc(1, sizeof(*st.vals))) == NULL)
				err(1, "calloc");
			st.vals[0] = t2.val;
			st.nvals = 1;
			if (parse_list(lx, &st) == -1) {
				stmt_free(&st);
				return (-1);
			}
			break;
		default:
			value_free(&t.val);
			if (t2.type != T_ERR)
				conf_error(lx->conf, f->path, t2.line,
				    "unexpected token after '%s'", st.key);
			stmt_free(&st);
			return (-1);
		}

		if (st.op == JC_NAMEVAL && strcmp(st.key, ".include") == 0) {
			do_include(lx, &st);
			stmt_free(&st);
			continue;
		}
		/* A global statement is parsed, not kept: what a jail
		 * inherits is jail(8)'s to say. */
		if (block >= 0)
			stmt_push(&f->blocks[block].stmts,
			    &f->blocks[block].nstmts, &st);
		else
			stmt_free(&st);
	}
}

static int
load_file(struct jc_conf *conf, const char *path, int depth)
{
	struct jc_file	*f;
	struct stat	 sb;
	ssize_t		 r;
	size_t		 off;
	int		 fd;

	if ((fd = open(path, O_RDONLY | O_CLOEXEC)) == -1) {
		conf_error(conf, path, 0, "%s", strerror(errno));
		return (-1);
	}
	if (fstat(fd, &sb) == -1 || !S_ISREG(sb.st_mode) ||
	    sb.st_size > CONF_MAXSIZE) {
		conf_error(conf, path, 0, "not a regular file or too large");
		close(fd);
		return (-1);
	}
	if ((f = calloc(1, sizeof(*f))) == NULL ||
	    (f->path = strdup(path)) == NULL ||
	    (f->buf = malloc((size_t)sb.st_size + 1)) == NULL)
		err(1, "malloc");
	for (off = 0; off < (size_t)sb.st_size; off += (size_t)r) {
		r = read(fd, f->buf + off, (size_t)sb.st_size - off);
		if (r <= 0)
			break;
	}
	close(fd);
	f->len = off;
	f->buf[f->len] = '\0';
	return (add_file(conf, f, depth));
}

/* Take ownership of f, parse it and the files it includes. */
static int
add_file(struct jc_conf *conf, struct jc_file *f, int depth)
{
	struct lexer	lx;

	if ((conf->files = reallocarray(conf->files, conf->nfiles + 1,
	    sizeof(*conf->files))) == NULL)
		err(1, "reallocarray");
	conf->files[conf->nfiles++] = f;

	memset(&lx, 0, sizeof(lx));
	lx.conf = conf;
	lx.f = f;
	lx.buf = f->buf;
	lx.len = f->len;
	lx.line = 1;
	lx.depth = depth;
	return (parse_body(&lx, -1, NULL));
}

/*
 * Parse one configuration file and those it includes: the blocks of
 * all, for jc_find() to tell which file holds a jail's.
 */
int
jc_load(struct jc_conf *conf, const char *path)
{

	memset(conf, 0, sizeof(*conf));
	return (load_file(conf, path, 0));
}

/*
 * Parse text as if it were the file path, without following includes:
 * used to check an edit before it is written.
 */
int
jc_load_buf(struct jc_conf *conf, const char *path, const char *buf,
    size_t len)
{
	struct jc_file	*f;

	memset(conf, 0, sizeof(*conf));
	if ((f = calloc(1, sizeof(*f))) == NULL ||
	    (f->path = strdup(path)) == NULL ||
	    (f->buf = malloc(len + 1)) == NULL)
		err(1, "malloc");
	memcpy(f->buf, buf, len);
	f->buf[len] = '\0';
	f->len = len;
	return (add_file(conf, f, INCLUDE_DEPTH));
}

void
jc_free(struct jc_conf *conf)
{
	struct jc_file	*f;
	size_t		 i, j, k;

	for (i = 0; i < conf->nfiles; i++) {
		f = conf->files[i];
		for (j = 0; j < f->nblocks; j++) {
			for (k = 0; k < f->blocks[j].nstmts; k++)
				stmt_free(&f->blocks[j].stmts[k]);
			free(f->blocks[j].stmts);
			free(f->blocks[j].name);
		}
		free(f->blocks);
		free(f->buf);
		free(f->path);
		free(f);
	}
	free(conf->files);
	free(conf->error);
	memset(conf, 0, sizeof(*conf));
}

/* The jail's block, and in *fp the file it is in, or NULL. */
struct jc_block *
jc_find(const struct jc_conf *conf, const char *name, struct jc_file **fp)
{
	struct jc_file	*f;
	size_t		 i, j;

	for (i = 0; i < conf->nfiles; i++) {
		f = conf->files[i];
		for (j = 0; j < f->nblocks; j++) {
			if (strcmp(f->blocks[j].name, name) == 0) {
				if (fp != NULL)
					*fp = f;
				return (&f->blocks[j]);
			}
		}
	}
	return (NULL);
}

/*
 * Parse "[iface|]address[/prefixlen]" as jail.conf allows in ip4.addr and
 * ip6.addr.  *plen is -1 when no prefix length is given.
 */
bool
jc_addr_split(const char *spec, int *af, void *addr, int *plen)
{
	char		 buf[INET6_ADDRSTRLEN + 8], *slash, *end;
	const char	*p;
	long		 l;

	if ((p = strchr(spec, '|')) != NULL)
		spec = p + 1;
	if (strlcpy(buf, spec, sizeof(buf)) >= sizeof(buf))
		return (false);
	*plen = -1;
	if ((slash = strchr(buf, '/')) != NULL) {
		*slash++ = '\0';
		l = strtol(slash, &end, 10);
		if (!isdigit((unsigned char)*slash) || *end != '\0' ||
		    l > 128)
			return (false);
		*plen = (int)l;
	}
	if (inet_pton(AF_INET, buf, addr) == 1) {
		*af = AF_INET;
		return (*plen <= 32);
	}
	if (inet_pton(AF_INET6, buf, addr) == 1) {
		*af = AF_INET6;
		return (true);
	}
	return (false);
}

/*
 * Do two values of key mean the same thing?  Addresses compare by
 * address, ignoring an interface prefix and a prefix length; anything
 * else compares as text.
 */
bool
jc_value_equal(const char *key, const char *a, const char *b)
{
	unsigned char	aa[sizeof(struct in6_addr)];
	unsigned char	ba[sizeof(struct in6_addr)];
	int		af1, af2, l1, l2;

	if (strcmp(key, "ip4.addr") != 0 && strcmp(key, "ip6.addr") != 0)
		return (strcmp(a, b) == 0);
	if (!jc_addr_split(a, &af1, aa, &l1) ||
	    !jc_addr_split(b, &af2, ba, &l2) || af1 != af2)
		return (false);
	return (memcmp(aa, ba, af1 == AF_INET ? sizeof(struct in_addr) :
	    sizeof(struct in6_addr)) == 0);
}

/* Does one of the statements set key to a value equal to value? */
static bool
stmts_have(const struct jc_stmt *st, size_t n, const char *key,
    const char *value, size_t *si, size_t *vi)
{
	size_t	 i, j;
	char	*text;
	bool	 match;

	for (i = 0; i < n; i++) {
		if (st[i].keyvar || strcmp(st[i].key, key) != 0)
			continue;
		for (j = 0; j < st[i].nvals; j++) {
			text = jc_value_text(&st[i].vals[j]);
			match = jc_value_equal(key, text, value);
			free(text);
			if (match) {
				if (si != NULL)
					*si = i;
				if (vi != NULL)
					*vi = j;
				return (true);
			}
		}
	}
	return (false);
}

/* Is the value among the block's own values for key? */
static bool
block_has(const struct jc_block *b, const char *key, const char *value)
{

	return (stmts_have(b->stmts, b->nstmts, key, value, NULL, NULL));
}

/*
 * Add or remove one value of key in the jail's block b of file f,
 * changing as few bytes as possible.  have[0..nhave-1] are the jail's
 * values of key as jail(8) reads them ("jail -f file -e sep"): with
 * them the values the block sets are told from those it inherits, from
 * global statements, "*" blocks or variables.  The new contents of f
 * are returned in *outp; nothing is written.
 */
int
jc_edit(struct jc_file *f, struct jc_block *b, const char *key,
    const char *value, bool add, const char *const *have, size_t nhave,
    char **outp, size_t *outlenp, char *errbuf, size_t errlen)
{
	const struct jc_stmt	*st, *last;
	const struct jc_value	*lv;
	struct strbuf		 ins, out;
	size_t			 cut_from, cut_to, at, ls, i, si, vi;
	bool			 had;
	char			 q;

	memset(&ins, 0, sizeof(ins));
	memset(&out, 0, sizeof(out));
	last = NULL;
	for (i = 0; i < b->nstmts; i++) {
		st = &b->stmts[i];
		if (!st->keyvar && strcmp(st->key, key) == 0 &&
		    st->nvals > 0 && (st->op == JC_SET || st->op == JC_APPEND))
			last = st;
	}
	had = false;
	for (i = 0; i < nhave; i++)
		if (jc_value_equal(key, have[i], value))
			had = true;

	if (add) {
		if (block_has(b, key, value) || had) {
			snprintf(errbuf, errlen, "%s is already in %s of "
			    "jail '%s'", value, key, b->name);
			return (-1);
		}
		if (last != NULL) {
			/* Extend the existing list in place. */
			lv = &last->vals[last->nvals - 1];
			q = lv->quote != 0 ? lv->quote : '"';
			at = lv->end;
			sb_puts(&ins, ", ");
			sb_putq(&ins, value, q);
		} else {
			/* Find the start of the line holding the '}'. */
			for (ls = b->close; ls > b->open &&
			    (f->buf[ls - 1] == ' ' || f->buf[ls - 1] == '\t');
			    ls--)
				;
			if (ls > b->open && f->buf[ls - 1] == '\n') {
				/* New statement on its own line, indented
				 * like the block's first statement. */
				at = ls;
				if (b->nstmts > 0) {
					st = &b->stmts[0];
					for (i = st->off; i > 0 &&
					    (f->buf[i - 1] == ' ' ||
					    f->buf[i - 1] == '\t'); i--)
						;
					if (i == 0 || f->buf[i - 1] == '\n')
						sb_putn(&ins, f->buf + i,
						    st->off - i);
					else
						sb_putc(&ins, '\t');
				} else
					sb_putc(&ins, '\t');
				sb_puts(&ins, key);
				sb_puts(&ins, nhave > 0 ? " += " : " = ");
				sb_putq(&ins, value, '"');
				sb_puts(&ins, ";\n");
			} else {
				/* The block is written on one line. */
				at = b->close;
				sb_puts(&ins, key);
				sb_puts(&ins, nhave > 0 ? " += " : " = ");
				sb_putq(&ins, value, '"');
				sb_puts(&ins, "; ");
			}
		}
		sb_putn(&out, f->buf, at);
		sb_putn(&out, ins.s, ins.len);
		sb_putn(&out, f->buf + at, f->len - at);
		free(ins.s);
	} else {
		if (!stmts_have(b->stmts, b->nstmts, key, value, &si, &vi)) {
			if (had)
				snprintf(errbuf, errlen, "%s is not set by "
				    "jail '%s' itself but comes from a "
				    "statement all jails share or a variable; "
				    "edit that instead", value, b->name);
			else
				snprintf(errbuf, errlen, "%s is not in %s of "
				    "jail '%s'", value, key, b->name);
			return (-1);
		}
		st = &b->stmts[si];
		if (st->nvals > 1) {
			if (vi > 0) {
				cut_from = st->vals[vi - 1].end;
				cut_to = st->vals[vi].end;
			} else {
				cut_from = st->vals[0].off;
				cut_to = st->vals[1].off;
			}
		} else {
			/* Last value: drop the statement and, if it had the
			 * line to itself, the line. */
			cut_from = st->off;
			cut_to = st->end;
			for (i = cut_from; i > 0 && (f->buf[i - 1] == ' ' ||
			    f->buf[i - 1] == '\t'); i--)
				;
			if (i == 0 || f->buf[i - 1] == '\n') {
				for (at = cut_to; at < f->len &&
				    (f->buf[at] == ' ' || f->buf[at] == '\t');
				    at++)
					;
				if (at >= f->len || f->buf[at] == '\n') {
					cut_from = i;
					cut_to = at < f->len ? at + 1 : at;
				}
			}
		}
		sb_putn(&out, f->buf, cut_from);
		sb_putn(&out, f->buf + cut_to, f->len - cut_to);
	}
	*outlenp = out.len;
	*outp = sb_take(&out);
	return (0);
}

/*
 * Set key to one value in the jail's block b of file f, or take it out:
 * every statement of key the block has goes, a bare one ("allow.x;")
 * too, and with a value a "key = value;" statement comes where the
 * first was, else on a line of its own last in the block; a value of
 * letters, digits and _ . - + / : is written bare, any other quoted;
 * an empty value is a bare statement, a boolean set.  The new contents
 * of f are returned in *outp; nothing is written.  The number of
 * statements taken out, or -1.
 */
int
jc_replace(struct jc_file *f, const struct jc_block *b, const char *key,
    const char *value, char **outp, size_t *outlenp)
{
	const struct jc_stmt	*st;
	struct strbuf		 out, ins;
	size_t			 i, j, from, to, at, ls, copied;
	int			 n;
	bool			 bare, placed;

	memset(&out, 0, sizeof(out));
	memset(&ins, 0, sizeof(ins));
	if (value != NULL) {
		bare = true;
		for (i = 0; value[i] != '\0'; i++)
			if (!isalnum((unsigned char)value[i]) && strchr("_.-+/:",
			    value[i]) == NULL)
				bare = false;
		sb_puts(&ins, key);
		if (value[0] != '\0') {
			sb_puts(&ins, " = ");
			if (bare)
				sb_puts(&ins, value);
			else
				sb_putq(&ins, value, '"');
		}
		sb_putc(&ins, ';');
	}
	n = 0;
	copied = 0;
	placed = false;
	for (i = 0; i < b->nstmts; i++) {
		st = &b->stmts[i];
		if (st->keyvar || strcmp(st->key, key) != 0 || st->off < copied)
			continue;
		/* The statement, with its line when it has it to itself. */
		from = st->off;
		to = st->end;
		for (j = from; j > 0 && (f->buf[j - 1] == ' ' || f->buf[j - 1] ==
		    '\t'); j--)
			;
		for (at = to; at < f->len && (f->buf[at] == ' ' || f->buf[at] ==
		    '\t'); at++)
			;
		sb_putn(&out, f->buf + copied, from - copied);
		if (value != NULL && !placed) {
			/* In its place, the first time. */
			sb_putn(&out, ins.s, ins.len);
			placed = true;
		} else if ((j == 0 || f->buf[j - 1] == '\n') && (at >= f->len ||
		    f->buf[at] == '\n')) {
			/* Its line goes: the indentation before it was
			 * copied already, so back over it. */
			out.len -= from - j;
			to = at < f->len ? at + 1 : at;
		}
		copied = to;
		n++;
	}
	if (value != NULL && !placed) {
		/* New, before the closing brace, as jc_edit puts one. */
		for (ls = b->close; ls > b->open && (f->buf[ls - 1] == ' ' ||
		    f->buf[ls - 1] == '\t'); ls--)
			;
		if (ls > b->open && f->buf[ls - 1] == '\n') {
			at = ls;
			sb_putn(&out, f->buf + copied, at - copied);
			if (b->nstmts > 0) {
				st = &b->stmts[0];
				for (i = st->off; i > 0 && (f->buf[i - 1] == ' ' ||
				    f->buf[i - 1] == '\t'); i--)
					;
				if (i == 0 || f->buf[i - 1] == '\n')
					sb_putn(&out, f->buf + i, st->off - i);
				else
					sb_putc(&out, '\t');
			} else
				sb_putc(&out, '\t');
			sb_putn(&out, ins.s, ins.len);
			sb_putc(&out, '\n');
		} else {
			at = b->close;
			sb_putn(&out, f->buf + copied, at - copied);
			sb_putn(&out, ins.s, ins.len);
			sb_putc(&out, ' ');
		}
		copied = at;
	}
	sb_putn(&out, f->buf + copied, f->len - copied);
	free(ins.s);
	*outlenp = out.len;
	*outp = sb_take(&out);
	return (n);
}

/*
 * Check an edit before writing it: the new text of path still parses and
 * jail's block now does (add) or does not (remove) hold the value.
 */
bool
jc_verify(const char *path, const char *buf, size_t len, const char *jail,
    const char *key, const char *value, bool add)
{
	struct jc_conf	 conf;
	struct jc_block	*b;
	bool		 ok;

	ok = jc_load_buf(&conf, path, buf, len) == 0 &&
	    (b = jc_find(&conf, jail, NULL)) != NULL &&
	    block_has(b, key, value) == add;
	jc_free(&conf);
	return (ok);
}

/* Number of lines that start in [from, to). */
static size_t
count_lines(const char *buf, size_t from, size_t to)
{
	size_t	i, n;

	for (n = 0, i = from; i < to; i++)
		if (buf[i] == '\n')
			n++;
	if (to > from && buf[to - 1] != '\n')
		n++;
	return (n);
}

/* Append lines in [from, to) of buf, each prefixed with mark. */
static void
emit_lines(struct strbuf *sb, const char *buf, size_t from, size_t to,
    char mark)
{
	size_t	s, e;

	for (s = from; s < to; s = e) {
		for (e = s; e < to && buf[e] != '\n'; e++)
			;
		sb_putc(sb, mark);
		sb_putn(sb, buf + s, e - s);
		sb_putc(sb, '\n');
		if (e < to)
			e++;
	}
}

/* A unified diff of a single contiguous change, with 3 lines context. */
char *
jc_diff(const char *path, const char *a, size_t alen, const char *b,
    size_t blen)
{
	struct strbuf	sb;
	size_t		pre, sa, sbn, ctx, end_a, end_b, line, i;
	char		hdr[128];

	memset(&sb, 0, sizeof(sb));
	/* Common prefix and suffix, widened to whole lines. */
	for (pre = 0; pre < alen && pre < blen && a[pre] == b[pre]; pre++)
		;
	while (pre > 0 && a[pre - 1] != '\n')
		pre--;
	for (sa = alen, sbn = blen; sa > pre && sbn > pre &&
	    a[sa - 1] == b[sbn - 1]; sa--, sbn--)
		;
	while (sa < alen && sa > 0 && a[sa - 1] != '\n') {
		sa++;
		sbn++;
	}

	for (ctx = pre, i = 0; ctx > 0 && i < 3; i++) {
		ctx--;
		while (ctx > 0 && a[ctx - 1] != '\n')
			ctx--;
	}
	for (end_a = sa, i = 0; end_a < alen && i < 3; i++) {
		while (end_a < alen && a[end_a] != '\n')
			end_a++;
		if (end_a < alen)
			end_a++;
	}
	end_b = sbn + (end_a - sa);
	line = 1 + count_lines(a, 0, ctx) - (ctx > 0 && a[ctx - 1] != '\n');

	sb_puts(&sb, "--- ");
	sb_puts(&sb, path);
	sb_puts(&sb, "\n+++ ");
	sb_puts(&sb, path);
	snprintf(hdr, sizeof(hdr), "\n@@ -%zu,%zu +%zu,%zu @@\n", line,
	    count_lines(a, ctx, end_a), line, count_lines(b, ctx, end_b));
	sb_puts(&sb, hdr);
	emit_lines(&sb, a, ctx, pre, ' ');
	emit_lines(&sb, a, pre, sa, '-');
	emit_lines(&sb, b, pre, sbn, '+');
	emit_lines(&sb, a, sa, end_a, ' ');
	return (sb_take(&sb));
}

/*
 * Replace path atomically: write a temporary file next to it with the
 * same mode and owner, fsync, rename.  With jc_write_at() the file is
 * in the directory dfd is open on, path's last name: what a process in
 * capability mode (capsicum(4)) can still do.
 */
int
jc_write(const char *path, const char *buf, size_t len, char *errbuf,
    size_t errlen)
{
	const char	*slash;
	char		 dir[MAXPATHLEN];
	int		 dfd, rc;

	if ((slash = strrchr(path, '/')) == NULL)
		snprintf(dir, sizeof(dir), ".");
	else
		snprintf(dir, sizeof(dir), "%.*s", slash == path ? 1 :
		    (int)(slash - path), path);
	if ((dfd = open(dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC)) == -1) {
		snprintf(errbuf, errlen, "%s: %s", dir, strerror(errno));
		return (-1);
	}
	rc = jc_write_at(dfd, path, buf, len, errbuf, errlen);
	close(dfd);
	return (rc);
}

int
jc_write_at(int dfd, const char *path, const char *buf, size_t len,
    char *errbuf, size_t errlen)
{
	struct stat	 sb;
	const char	*base;
	char		 tmp[MAXPATHLEN];
	size_t		 off;
	ssize_t		 w;
	int		 fd;

	base = strrchr(path, '/') != NULL ? strrchr(path, '/') + 1 : path;
	if (fstatat(dfd, base, &sb, 0) == -1) {
		snprintf(errbuf, errlen, "stat %s: %s", path, strerror(errno));
		return (-1);
	}
	if (snprintf(tmp, sizeof(tmp), "%s.XXXXXX", base) >=
	    (int)sizeof(tmp)) {
		snprintf(errbuf, errlen, "%s: path too long", path);
		return (-1);
	}
	if ((fd = mkostempsat(dfd, tmp, 0, O_CLOEXEC)) == -1) {
		snprintf(errbuf, errlen, "mkstemp %s: %s", tmp,
		    strerror(errno));
		return (-1);
	}
	for (off = 0; off < len; off += (size_t)w) {
		if ((w = write(fd, buf + off, len - off)) <= 0) {
			snprintf(errbuf, errlen, "write %s: %s", tmp,
			    strerror(errno));
			goto fail;
		}
	}
	if (fchmod(fd, sb.st_mode & ALLPERMS) == -1 ||
	    (geteuid() == 0 && fchown(fd, sb.st_uid, sb.st_gid) == -1) ||
	    fsync(fd) == -1) {
		snprintf(errbuf, errlen, "%s: %s", tmp, strerror(errno));
		goto fail;
	}
	close(fd);
	if (renameat(dfd, tmp, dfd, base) == -1) {
		snprintf(errbuf, errlen, "rename %s: %s", path,
		    strerror(errno));
		(void)unlinkat(dfd, tmp, 0);
		return (-1);
	}
	return (0);

fail:
	close(fd);
	(void)unlinkat(dfd, tmp, 0);
	return (-1);
}
