/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * YAML, written and read: what the panel shows or saves as JSON, also
 * as YAML, and what it takes in as JSON, also as YAML.
 *
 * Written: YAML 1.2, block style: a mapping's keys
 * in their order, a sequence's items each after "- ".  A string is
 * plain where it reads back as that string, and as nothing else (a
 * number, a boolean, null, a key or a comment); else double-quoted,
 * or, when it is lines of text (a configuration file), a literal block.
 * libucl's own YAML is flow style, and leaves keys such as yes bare.
 */

#include <sys/param.h>

#include <ctype.h>
#include <math.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include <ucl.h>
#include <yaml.h>

char		*yaml_emit(const ucl_object_t *);
ucl_object_t	*yaml_parse(const char *, char *, size_t);

struct ybuf {
	char	*p;
	size_t	 len, cap;
};

static void
yput(struct ybuf *b, const char *s, size_t n)
{
	char	*np;

	if (b->len + n + 1 > b->cap) {
		b->cap = (b->len + n + 1) * 2 + 256;
		if ((np = realloc(b->p, b->cap)) == NULL)
			abort();
		b->p = np;
	}
	memcpy(b->p + b->len, s, n);
	b->len += n;
	b->p[b->len] = '\0';
}

static void
ys(struct ybuf *b, const char *s)
{

	yput(b, s, strlen(s));
}

static void
yindent(struct ybuf *b, int n)
{

	while (n-- > 0)
		yput(b, " ", 1);
}

/* Would s, unquoted, read back as the string s? */
static bool
yplain(const char *s)
{
	static const char *const words[] = { "y", "n", "yes", "no", "true",
	    "false", "on", "off", "null", "~", ".nan", ".inf", "-.inf" };
	size_t	i, n = strlen(s);

	if (n == 0 || n > 200 || isspace((unsigned char)s[0]) ||
	    isspace((unsigned char)s[n - 1]))
		return (false);
	/* A number, or what one may take for one. */
	if (isdigit((unsigned char)s[0]) || strchr("+-.", s[0]) != NULL)
		return (false);
	/* What begins something else in YAML. */
	if (strchr("?:,[]{}#&*!|>'\"%@`=~", s[0]) != NULL)
		return (false);
	for (i = 0; i < sizeof(words) / sizeof(words[0]); i++)
		if (strcasecmp(s, words[i]) == 0)
			return (false);
	for (i = 0; i < n; i++) {
		if ((unsigned char)s[i] < 0x20 || s[i] == 0x7f)
			return (false);
		if ((s[i] == ':' && (s[i + 1] == ' ' || s[i + 1] == '\0')) ||
		    (s[i] == '#' && s[i - 1] == ' '))
			return (false);
	}
	return (true);
}

/* Lines of text, as a literal block keeps them: no other control. */
static bool
ylines(const char *s)
{
	const char	*p;

	if (strchr(s, '\n') == NULL)
		return (false);
	for (p = s; *p != '\0'; p++)
		if (((unsigned char)*p < 0x20 && *p != '\n' && *p != '\t') ||
		    *p == 0x7f)
			return (false);
	return (true);
}

static void
yquoted(struct ybuf *b, const char *s)
{
	char	e[8];

	ys(b, "\"");
	for (; *s != '\0'; s++) {
		if (*s == '"' || *s == '\\') {
			e[0] = '\\';
			e[1] = *s;
			yput(b, e, 2);
		} else if (*s == '\n')
			ys(b, "\\n");
		else if (*s == '\t')
			ys(b, "\\t");
		else if ((unsigned char)*s < 0x20 || *s == 0x7f) {
			snprintf(e, sizeof(e), "\\x%02x", (unsigned char)*s);
			ys(b, e);
		} else
			yput(b, s, 1);
	}
	ys(b, "\"");
}

/* A string after "key:" or "- ", at a block's indent. */
static void
ystring(struct ybuf *b, const char *s, int indent)
{
	const char	*p, *nl, *end;
	size_t		 n = strlen(s), k;

	if (yplain(s)) {
		ys(b, " ");
		ys(b, s);
		return;
	}
	if (!ylines(s)) {
		ys(b, " ");
		yquoted(b, s);
		return;
	}
	/* |- none at the end, | one, |+ more; 2: its first line begins
	 * with a space. */
	for (k = 0; k < n && s[n - 1 - k] == '\n'; k++)
		;
	ys(b, " |");
	if (s[0] == ' ')
		ys(b, "2");
	ys(b, k == 0 ? "-" : k == 1 ? "" : "+");
	/* Each line, the empty ones too, up to the last newline. */
	end = s + n - (k > 0 ? 1 : 0);
	for (p = s;; p = nl + 1) {
		if ((nl = memchr(p, '\n', (size_t)(end - p))) == NULL)
			nl = end;
		ys(b, "\n");
		if (nl > p)
			yindent(b, indent + 2);
		yput(b, p, (size_t)(nl - p));
		if (nl == end)
			break;
	}
}

static void	yvalue(struct ybuf *, const ucl_object_t *, int);

static void
ykey(struct ybuf *b, const char *k)
{

	if (yplain(k))
		ys(b, k);
	else
		yquoted(b, k);
	ys(b, ":");
}

/* The value after "key:" or "- "; indent: the block's. */
static void
yvalue(struct ybuf *b, const ucl_object_t *o, int indent)
{
	const ucl_object_t	*v;
	ucl_object_iter_t	 it;
	char			 num[64];
	bool			 first;

	switch (ucl_object_type(o)) {
	case UCL_OBJECT:
		if (ucl_object_iterate(o, &(ucl_object_iter_t){ NULL }, true) ==
		    NULL) {
			ys(b, " {}");
			return;
		}
		it = NULL;
		while ((v = ucl_object_iterate(o, &it, true)) != NULL) {
			ys(b, "\n");
			yindent(b, indent + 2);
			ykey(b, ucl_object_key(v));
			yvalue(b, v, indent + 2);
		}
		return;
	case UCL_ARRAY:
		if (ucl_array_size(o) == 0) {
			ys(b, " []");
			return;
		}
		it = NULL;
		while ((v = ucl_object_iterate(o, &it, true)) != NULL) {
			ys(b, "\n");
			yindent(b, indent + 2);
			ys(b, "-");
			if (ucl_object_type(v) != UCL_OBJECT ||
			    ucl_object_iterate(v, &(ucl_object_iter_t){ NULL },
			    true) == NULL) {
				yvalue(b, v, indent + 2);
				continue;
			}
			/* A mapping's first key on the line of its "-". */
			{
				const ucl_object_t	*w;
				ucl_object_iter_t	 wit = NULL;

				first = true;
				while ((w = ucl_object_iterate(v, &wit, true)) !=
				    NULL) {
					if (first)
						ys(b, " ");
					else {
						ys(b, "\n");
						yindent(b, indent + 4);
					}
					first = false;
					ykey(b, ucl_object_key(w));
					yvalue(b, w, indent + 4);
				}
			}
		}
		return;
	case UCL_INT:
		snprintf(num, sizeof(num), " %lld", (long long)
		    ucl_object_toint(o));
		ys(b, num);
		return;
	case UCL_FLOAT:
	case UCL_TIME:
		snprintf(num, sizeof(num), " %.15g", ucl_object_todouble(o));
		if (strpbrk(num, ".eEn") == NULL)
			strlcat(num, ".0", sizeof(num));
		ys(b, num);
		return;
	case UCL_BOOLEAN:
		ys(b, ucl_object_toboolean(o) ? " true" : " false");
		return;
	case UCL_NULL:
		ys(b, " null");
		return;
	default:
		ystring(b, ucl_object_tostring_forced(o), indent);
		return;
	}
}

/* o as a YAML document; free() it. */
char *
yaml_emit(const ucl_object_t *o)
{
	struct ybuf	 b = { NULL, 0, 0 };

	ys(&b, "---");
	if (ucl_object_type(o) == UCL_OBJECT || ucl_object_type(o) ==
	    UCL_ARRAY) {
		/* The top's keys or items at no indent: one level less. */
		yvalue(&b, o, -2);
	} else
		yvalue(&b, o, 0);
	ys(&b, "\n");
	return (b.p);
}

/*
 * Read: libyaml's (base's private library, its source compiled with
 * the panel's as libucl's is) events made the object JSON would be.
 * A plain scalar is what YAML 1.2's core schema says it is: null, a
 * boolean, an integer or a float, else a string; a quoted one or a
 * block is a string.  Only the first document; an alias is refused,
 * which a document of ours never has and a hostile one would expand.
 */

static bool
yint(const char *s, long long *v)
{
	char	*e;
	int	 base = 10;

	if (s[0] == '0' && s[1] == 'o') {
		s += 2;
		base = 8;
	} else if (s[0] == '0' && s[1] == 'x') {
		s += 2;
		base = 16;
	} else if (!isdigit((unsigned char)s[s[0] == '-' || s[0] == '+'])) {
		return (false);
	}
	if (*s == '\0')
		return (false);
	*v = strtoll(s, &e, base);
	return (*e == '\0');
}

static ucl_object_t *
yscalar(const yaml_event_t *ev)
{
	const char	*s = (const char *)ev->data.scalar.value;
	long long	 i;
	double		 d;
	char		*e;

	if (ev->data.scalar.style != YAML_PLAIN_SCALAR_STYLE)
		return (ucl_object_fromstring_common(s,
		    ev->data.scalar.length, 0));
	if (s[0] == '\0' || strcmp(s, "~") == 0 || strcmp(s, "null") == 0 ||
	    strcmp(s, "Null") == 0 || strcmp(s, "NULL") == 0)
		return (ucl_object_typed_new(UCL_NULL));
	if (strcmp(s, "true") == 0 || strcmp(s, "True") == 0 ||
	    strcmp(s, "TRUE") == 0)
		return (ucl_object_frombool(true));
	if (strcmp(s, "false") == 0 || strcmp(s, "False") == 0 ||
	    strcmp(s, "FALSE") == 0)
		return (ucl_object_frombool(false));
	if (yint(s, &i))
		return (ucl_object_fromint(i));
	if ((isdigit((unsigned char)s[0]) || ((s[0] == '-' || s[0] == '+' ||
	    s[0] == '.') && isdigit((unsigned char)s[1]))) &&
	    strspn(s, "0123456789+-.eE") == strlen(s)) {
		/* One out of a double's range is a word that looks like a
		 * number, a host's id (933e5390): kept as written. */
		d = strtod(s, &e);
		if (*e == '\0' && isfinite(d))
			return (ucl_object_fromdouble(d));
	}
	return (ucl_object_fromstring_common(s, ev->data.scalar.length, 0));
}

#define	YDEPTH	64

/* text's first document as an object; NULL, with why in err. */
ucl_object_t *
yaml_parse(const char *text, char *err, size_t errlen)
{
	yaml_parser_t	 p;
	yaml_event_t	 ev;
	ucl_object_t	*stack[YDEPTH], *top, *v;
	char		*keys[YDEPTH];
	bool		 want_key[YDEPTH];
	int		 depth;
	bool		 done;

	err[0] = '\0';
	if (!yaml_parser_initialize(&p)) {
		snprintf(err, errlen, "no memory");
		return (NULL);
	}
	yaml_parser_set_input_string(&p, (const unsigned char *)text,
	    strlen(text));
	top = NULL;
	depth = 0;
	done = false;
	memset(keys, 0, sizeof(keys));
	while (!done) {
		if (!yaml_parser_parse(&p, &ev)) {
			snprintf(err, errlen, "YAML, line %zu: %s",
			    p.problem_mark.line + 1, p.problem != NULL ?
			    p.problem : "not read");
			goto fail;
		}
		v = NULL;
		switch (ev.type) {
		case YAML_ALIAS_EVENT:
			snprintf(err, errlen, "YAML, line %zu: an alias (*%s) "
			    "is not taken", ev.start_mark.line + 1,
			    (const char *)ev.data.alias.anchor);
			yaml_event_delete(&ev);
			goto fail;
		case YAML_SCALAR_EVENT:
			/* A mapping's key: kept for its value. */
			if (depth > 0 && want_key[depth - 1]) {
				free(keys[depth - 1]);
				keys[depth - 1] = strdup((const char *)
				    ev.data.scalar.value);
				want_key[depth - 1] = false;
				break;
			}
			v = yscalar(&ev);
			break;
		case YAML_SEQUENCE_START_EVENT:
		case YAML_MAPPING_START_EVENT:
			if (depth == YDEPTH) {
				snprintf(err, errlen, "YAML, line %zu: nested "
				    "more than %d deep", ev.start_mark.line + 1,
				    YDEPTH);
				yaml_event_delete(&ev);
				goto fail;
			}
			if (depth > 0 && want_key[depth - 1]) {
				snprintf(err, errlen, "YAML, line %zu: a key "
				    "is a string here", ev.start_mark.line + 1);
				yaml_event_delete(&ev);
				goto fail;
			}
			stack[depth] = ucl_object_typed_new(ev.type ==
			    YAML_MAPPING_START_EVENT ? UCL_OBJECT : UCL_ARRAY);
			want_key[depth] = ev.type == YAML_MAPPING_START_EVENT;
			keys[depth] = NULL;
			depth++;
			break;
		case YAML_SEQUENCE_END_EVENT:
		case YAML_MAPPING_END_EVENT:
			depth--;
			v = stack[depth];
			free(keys[depth]);
			keys[depth] = NULL;
			break;
		case YAML_DOCUMENT_END_EVENT:
		case YAML_STREAM_END_EVENT:
			done = true;
			break;
		default:
			break;
		}
		yaml_event_delete(&ev);
		if (v == NULL)
			continue;
		if (depth == 0) {
			if (top != NULL)
				ucl_object_unref(top);
			top = v;
			continue;
		}
		if (ucl_object_type(stack[depth - 1]) == UCL_ARRAY)
			ucl_array_append(stack[depth - 1], v);
		else {
			ucl_object_insert_key(stack[depth - 1], v,
			    keys[depth - 1], 0, true);
			free(keys[depth - 1]);
			keys[depth - 1] = NULL;
			want_key[depth - 1] = true;
		}
	}
	yaml_parser_delete(&p);
	if (top == NULL)
		snprintf(err, errlen, "YAML: no document");
	return (top);
fail:
	while (depth > 0) {
		depth--;
		free(keys[depth]);
		ucl_object_unref(stack[depth]);
	}
	if (top != NULL)
		ucl_object_unref(top);
	yaml_parser_delete(&p);
	return (NULL);
}
