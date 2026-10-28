/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * rtadvd.conf(5), read as rtadvd(8)'s advcap.c reads it and changed in
 * place.  A record is a line, with its "\" newlines taken out; names
 * before the first ":", "|" between them; then fields, which advcap.c's
 * tskip() separates at every ":", quotes or not, a "\" skipping the
 * character after it and one more.  A field is a capability: name#number
 * (a leading 0 octal), name=string (tdecode(): quotes, ^X, \E \^ \\ \:
 * \n \r \t \b \f \", \ooo), name@ (cancelled), or name alone (a flag).
 * The first field of a name that a getter takes holds; a "tc=name" as
 * the last field brings another record's fields in after the record's.
 */

#include <sys/types.h>

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "varconf.h"

#define	CAP_BUFSIZ	1024		/* advcap.c's BUFSIZ: a record, less */
#define	CAP_MAXHOP	32		/* tc= indirections */

static void
cfail(char *err, size_t errlen, const char *fmt, ...)
{
	va_list ap;

	if (err == NULL || errlen == 0)
		return;
	va_start(ap, fmt);
	vsnprintf(err, errlen, fmt, ap);
	va_end(ap);
}

/*
 * A record's logical text, its "\" newlines out, each byte's place in
 * the file kept.
 */
struct logical {
	char	*s;
	size_t	*at;		/* the file offset of s[i]; at[len]: end */
	size_t	 len;
};

/* tskip(): from field start i, the next field's start. */
static size_t
skip(const char *s, size_t len, size_t i)
{

	while (i < len) {
		switch (s[i]) {
		case ':':
			return (i + 1);
		case '\\':
			i++;
			if (i < len && isdigit((unsigned char)s[i])) {
				while (i < len && isdigit((unsigned char)s[i++]))
					;
			} else
				i++;
			/* FALLTHROUGH: advcap.c's missing break */
		case '"':
			i++;
			break;
		default:
			i++;
			break;
		}
	}
	return (len);
}

/* tdecode() of the string at s[i]: malloc'd; *endp where it stopped. */
static char *
decode(const char *s, size_t len, size_t i, size_t *endp)
{
	static const char esc[] = "E\033^^\\\\::n\nr\rt\tb\bf\f\"\"";
	char *out, *o, term = ':';
	int c;

	if ((out = malloc(len - i + 1)) == NULL)
		return (NULL);
	o = out;
again:
	if (i < len && s[i] == '"') {
		term = '"';
		i++;
	}
	for (c = -1; i < len && (c = (unsigned char)s[i++]) != term; ) {
		if (c == '^')
			c = i < len ? (unsigned char)s[i++] & 037 : 0;
		else if (c == '\\') {
			const char *dp;

			c = i < len ? (unsigned char)s[i++] : 0;
			for (dp = esc; *dp != '\0'; dp += 2)
				if (*dp == c) {
					c = (unsigned char)dp[1];
					break;
				}
			if (*dp == '\0' && isdigit(c)) {
				int k = 2;

				c -= '0';
				do
					c = (c << 3) | (i < len ? s[i++] - '0' :
					    0);
				while (--k && i < len &&
				    isdigit((unsigned char)s[i]));
			}
		}
		*o++ = (char)c;
		c = -1;
	}
	if (c == term && term != ':') {
		term = ':';
		goto again;
	}
	*o = '\0';
	/* Its ":" not its own. */
	*endp = c == ':' ? i - 1 : i;
	return (out);
}

static void
cap_free_record(struct vc_record *r)
{

	for (size_t i = 0; i < r->nnames; i++)
		free(r->names[i]);
	free(r->names);
	for (size_t i = 0; i < r->ncaps; i++) {
		free(r->caps[i].name);
		free(r->caps[i].value);
	}
	free(r->caps);
	free(r->tc);
}

void
vc_cap_free(struct vc_capfile *f)
{

	if (f == NULL)
		return;
	for (size_t i = 0; i < f->nr; i++)
		cap_free_record(&f->r[i]);
	free(f->r);
	free(f->text);
	memset(f, 0, sizeof(*f));
}

/* A record's fields: names, then capabilities. */
static int
fields(struct vc_record *r, const struct logical *lg)
{
	const char *s = lg->s;
	size_t len = lg->len, i = 0, n0, e, strend = 0;

	/* The names: to the first ":". */
	for (n0 = 0; i <= len; i++)
		if (i == len || s[i] == ':' || s[i] == '|') {
			char **v;

			if ((v = reallocarray(r->names, r->nnames + 1,
			    sizeof(*v))) == NULL)
				return (-1);
			r->names = v;
			if ((v[r->nnames] = strndup(s + n0, i - n0)) == NULL)
				return (-1);
			r->nnames++;
			n0 = i + 1;
			if (i == len || s[i] == ':')
				break;
		}
	i = i < len ? i + 1 : len;
	for (; i < len; i = e) {
		struct vc_cap *c, *v;
		size_t k;

		e = skip(s, len, i);
		/* The field, less the ":" that ends it. */
		k = i;
		while (k < e && s[k] != '#' && s[k] != '=' && s[k] != '@' &&
		    s[k] != ':')
			k++;
		if ((v = reallocarray(r->caps, r->ncaps + 1,
		    sizeof(*v))) == NULL)
			return (-1);
		r->caps = v;
		c = &r->caps[r->ncaps];
		memset(c, 0, sizeof(*c));
		if ((c->name = strndup(s + i, k - i)) == NULL)
			return (-1);
		r->ncaps++;
		c->type = k < e && s[k] != ':' ? s[k] : 0;
		c->off = lg->at[i];
		c->end = lg->at[e > i && s[e - 1] == ':' ? e - 1 : e];
		c->inner = i < strend;
		if (c->type == '=') {
			size_t d;

			if ((c->value = decode(s, len, k + 1, &d)) == NULL)
				return (-1);
			/* The string's end, past colons in it. */
			if (!c->inner) {
				c->end = lg->at[d];
				strend = d;
			}
		} else if (c->type == '#') {
			int64_t num = 0;
			int base = k + 1 < len && s[k + 1] == '0' ? 8 : 10;

			for (size_t d = k + 1; d < len &&
			    isdigit((unsigned char)s[d]); d++)
				num = num * base + (s[d] - '0');
			if (asprintf(&c->value, "%jd", (intmax_t)num) == -1) {
				c->value = NULL;
				return (-1);
			}
		}
	}
	/* tc=, the last field: another record's after this one's. */
	if (r->ncaps > 0 && strcmp(r->caps[r->ncaps - 1].name, "tc") == 0 &&
	    r->caps[r->ncaps - 1].type == '=' &&
	    (r->tc = strdup(r->caps[r->ncaps - 1].value)) == NULL)
		return (-1);
	return (0);
}

int
vc_cap_parse(struct vc_capfile *f, const char *text, size_t len, char *err,
    size_t errlen)
{
	struct logical lg = { 0 };
	size_t i = 0;
	int line = 1, rc = -1;

	memset(f, 0, sizeof(*f));
	if (memchr(text, '\0', len) != NULL) {
		cfail(err, errlen, "a NUL byte in the file");
		errno = EINVAL;
		return (-1);
	}
	if ((f->text = malloc(len + 1)) == NULL ||
	    (lg.s = malloc(len + 1)) == NULL ||
	    (lg.at = calloc(len + 2, sizeof(*lg.at))) == NULL)
		goto out;
	memcpy(f->text, text, len);
	f->text[len] = '\0';
	f->len = len;
	while (i < len) {
		struct vc_record *r, *nr;
		size_t start = i;
		int first = line;

		/* A line, "\" newlines taken out, as getent() reads it. */
		lg.len = 0;
		for (; i < len; i++) {
			if (text[i] == '\n') {
				line++;
				if (lg.len > 0 && lg.s[lg.len - 1] == '\\') {
					lg.len--;
					continue;
				}
				i++;
				break;
			}
			lg.at[lg.len] = i;
			lg.s[lg.len++] = text[i];
		}
		lg.at[lg.len] = i > start && text[i - 1] == '\n' ? i - 1 : i;
		if (lg.len + 1 >= CAP_BUFSIZ) {
			cfail(err, errlen, "line %d: a record longer than "
			    "rtadvd(8) reads", first);
			errno = EINVAL;
			goto out;
		}
		/* A comment, or nothing: not a record. */
		if (lg.len == 0 || lg.s[0] == '#')
			continue;
		if ((nr = reallocarray(f->r, f->nr + 1, sizeof(*nr))) == NULL)
			goto out;
		f->r = nr;
		r = &f->r[f->nr++];
		memset(r, 0, sizeof(*r));
		r->off = start;
		r->end = i;
		r->line = first;
		if (fields(r, &lg) == -1)
			goto out;
	}
	rc = 0;
out:
	free(lg.s);
	free(lg.at);
	if (rc == -1)
		vc_cap_free(f);
	return (rc);
}

int
vc_cap_read(struct vc_capfile *f, const char *path, char *err, size_t errlen)
{
	struct stat sb;
	char *buf;
	size_t len = 0;
	ssize_t n;
	int fd, rc;

	if ((fd = open(path, O_RDONLY | O_CLOEXEC)) == -1) {
		if (errno == ENOENT)
			return (vc_cap_parse(f, "", 0, err, errlen));
		cfail(err, errlen, "%s: %s", path, strerror(errno));
		return (-1);
	}
	if (fstat(fd, &sb) == -1 || !S_ISREG(sb.st_mode) ||
	    sb.st_size > (4 << 20)) {
		cfail(err, errlen, "%s: not a file, or too big", path);
		close(fd);
		errno = EINVAL;
		return (-1);
	}
	if ((buf = malloc((size_t)sb.st_size + 1)) == NULL) {
		close(fd);
		return (-1);
	}
	while (len < (size_t)sb.st_size &&
	    (n = read(fd, buf + len, (size_t)sb.st_size - len)) > 0)
		len += (size_t)n;
	close(fd);
	rc = vc_cap_parse(f, buf, len, err, errlen);
	free(buf);
	return (rc);
}

/* The first record named name, as getent() finds it. */
const struct vc_record *
vc_cap_record(const struct vc_capfile *f, const char *name)
{

	for (size_t i = 0; i < f->nr; i++)
		for (size_t j = 0; j < f->r[i].nnames; j++)
			if (strcmp(f->r[i].names[j], name) == 0)
				return (&f->r[i]);
	return (NULL);
}

/*
 * The field a getter of type takes for cap in record name, following
 * tc=: the first of that name and type, or cancelled; NULL if none.
 */
const struct vc_cap *
vc_cap_get(const struct vc_capfile *f, const char *name, const char *cap,
    char type)
{
	const struct vc_record *r;
	int hops = 0;

	for (r = vc_cap_record(f, name); r != NULL && hops <= CAP_MAXHOP;
	    hops++) {
		size_t n = r->ncaps - (r->tc != NULL ? 1 : 0);

		for (size_t i = 0; i < n; i++) {
			const struct vc_cap *c = &r->caps[i];

			if (strcmp(c->name, cap) != 0)
				continue;
			if (c->type == '@')
				return (NULL);
			if (c->type == type)
				return (c);
		}
		if (r->tc == NULL)
			return (NULL);
		r = vc_cap_record(f, r->tc);
	}
	return (NULL);
}

static bool
cap_name_ok(const char *s)
{

	if (s == NULL || *s == '\0')
		return (false);
	for (; *s != '\0'; s++)
		if (!isalnum((unsigned char)*s) && *s != '_' && *s != '-' &&
		    *s != '.')
			return (false);
	return (true);
}

/* The file's text with [s, e) made r, parsed again. */
static int
cap_splice(struct vc_capfile *f, size_t s, size_t e, const char *r,
    size_t rlen, char *err, size_t errlen)
{
	struct vc_capfile nf;
	char *t;
	size_t len = f->len - (e - s) + rlen;
	int rc;

	if ((t = malloc(len + 1)) == NULL)
		return (-1);
	memcpy(t, f->text, s);
	memcpy(t + s, r, rlen);
	memcpy(t + s + rlen, f->text + e, f->len - e);
	t[len] = '\0';
	rc = vc_cap_parse(&nf, t, len, err, errlen);
	free(t);
	if (rc == -1)
		return (-1);
	vc_cap_free(f);
	*f = nf;
	return (0);
}

/* A field as rtadvd.conf holds it: name#n, name="s", name. */
static char *
render_cap(const char *cap, char type, const char *value)
{
	char *out = NULL, *p;
	size_t n;

	if (type == '#') {
		char *end;
		unsigned long long v;

		/* Decimal, no leading 0: advcap.c reads that as octal. */
		errno = 0;
		v = strtoull(value, &end, 10);
		if (*value == '\0' || *end != '\0' || errno != 0 ||
		    *value == '-' || *value == '+')
			return (NULL);
		if (asprintf(&out, "%s#%llu", cap, v) == -1)
			return (NULL);
		return (out);
	}
	if (type == 0)
		return (strdup(cap));
	n = strlen(cap) + 4 + 2 * strlen(value);
	if ((out = malloc(n)) == NULL)
		return (NULL);
	p = out + sprintf(out, "%s=\"", cap);
	for (; *value != '\0'; value++) {
		if (*value == '"' || *value == '\\' || *value == '^')
			*p++ = '\\';
		*p++ = *value;
	}
	*p++ = '"';
	*p = '\0';
	return (out);
}

/*
 * cap of record name (its own, not one tc= brings in) set: the field of
 * its name, the first, replaced, a cancelling one too; else one added
 * before the record's end, or its tc=.  type '#' a number, '=' a string,
 * 0 a flag.  A record not there is refused: vc_cap_add_record() first.
 */
int
vc_cap_set(struct vc_capfile *f, const char *name, const char *cap,
    char type, const char *value, char *err, size_t errlen)
{
	const struct vc_record *r;
	char *field;
	size_t at;
	int rc;

	if (!cap_name_ok(cap) || strcmp(cap, "tc") == 0 ||
	    (type != '#' && type != '=' && type != 0) ||
	    (type != 0 && value == NULL)) {
		cfail(err, errlen, "%s: not a capability to set", cap);
		errno = EINVAL;
		return (-1);
	}
	if (value != NULL)
		for (const char *v = value; *v != '\0'; v++)
			if ((unsigned char)*v < 0x20 || *v == 0x7f) {
				cfail(err, errlen, "%s: a control character "
				    "in its value", cap);
				errno = EINVAL;
				return (-1);
			}
	if ((r = vc_cap_record(f, name)) == NULL) {
		cfail(err, errlen, "%s: no such record", name);
		errno = ENOENT;
		return (-1);
	}
	if ((field = render_cap(cap, type, value)) == NULL) {
		cfail(err, errlen, "%s: not a number", cap);
		errno = EINVAL;
		return (-1);
	}
	for (size_t i = 0; i < r->ncaps; i++)
		if (!r->caps[i].inner && strcmp(r->caps[i].name, cap) == 0) {
			rc = cap_splice(f, r->caps[i].off, r->caps[i].end,
			    field, strlen(field), err, errlen);
			free(field);
			return (rc);
		}
	/*
	 * Added: before a tc=, which must stay last; else after the last
	 * ":" of the record, or with one, before its newline.
	 */
	if (r->tc != NULL) {
		char *s;

		at = r->caps[r->ncaps - 1].off;
		if (asprintf(&s, "%s:", field) == -1) {
			free(field);
			return (-1);
		}
		free(field);
		rc = cap_splice(f, at, at, s, strlen(s), err, errlen);
		free(s);
		return (rc);
	}
	at = r->end;
	if (at > r->off && f->text[at - 1] == '\n')
		at--;
	{
		char *s;

		if (asprintf(&s, "%s%s:", at > r->off &&
		    f->text[at - 1] == ':' ? "" : ":", field) == -1) {
			free(field);
			return (-1);
		}
		free(field);
		rc = cap_splice(f, at, at, s, strlen(s), err, errlen);
		free(s);
	}
	return (rc);
}

/* Every field of cap in record name removed, with its ":". */
int
vc_cap_unset(struct vc_capfile *f, const char *name, const char *cap,
    char *err, size_t errlen)
{

	if (!cap_name_ok(cap) || strcmp(cap, "tc") == 0) {
		cfail(err, errlen, "%s: not a capability to remove", cap);
		errno = EINVAL;
		return (-1);
	}
	for (;;) {
		const struct vc_record *r = vc_cap_record(f, name);
		const struct vc_cap *c = NULL;
		size_t e;

		if (r == NULL)
			return (0);
		for (size_t i = 0; i < r->ncaps && c == NULL; i++)
			if (!r->caps[i].inner &&
			    strcmp(r->caps[i].name, cap) == 0)
				c = &r->caps[i];
		if (c == NULL)
			return (0);
		/* The field and the ":" after it. */
		e = c->end;
		if (e < f->len && f->text[e] == ':')
			e++;
		if (cap_splice(f, c->off, e, "", 0, err, errlen) == -1)
			return (-1);
	}
}

/*
 * A record added at the end: name, then each field given ("addr=...",
 * "prefixlen#64", a flag), a line each, "\" at the end of the others.
 */
int
vc_cap_add_record(struct vc_capfile *f, const char *name,
    const char *const *caps, size_t n, char *err, size_t errlen)
{
	char *s = NULL;
	size_t len = 0;
	FILE *fp;
	int rc;

	if (!cap_name_ok(name) || vc_cap_record(f, name) != NULL) {
		cfail(err, errlen, "%s: %s", name, cap_name_ok(name) ?
		    "a record of that name is there" : "not a record's name");
		errno = cap_name_ok(name) ? EEXIST : EINVAL;
		return (-1);
	}
	if ((fp = open_memstream(&s, &len)) == NULL)
		return (-1);
	if (f->len > 0 && f->text[f->len - 1] != '\n')
		fputc('\n', fp);
	fprintf(fp, "%s:", name);
	for (size_t i = 0; i < n; i++) {
		if (strchr(caps[i], '\n') != NULL) {
			fclose(fp);
			free(s);
			cfail(err, errlen, "%s: a newline in a field", name);
			errno = EINVAL;
			return (-1);
		}
		fprintf(fp, "\\\n\t:%s:", caps[i]);
	}
	fputc('\n', fp);
	fclose(fp);
	rc = cap_splice(f, f->len, f->len, s, len, err, errlen);
	free(s);
	return (rc);
}

/* render_cap() for a caller that writes whole records: NULL where the
 * number is not one, or the type not a field's. */
char *
vc_cap_field(const char *cap, char type, const char *value)
{

	if (!cap_name_ok(cap) || (type != '#' && type != '=' && type != 0) ||
	    (type != 0 && value == NULL))
		return (NULL);
	return (render_cap(cap, type, value));
}

/*
 * The record named name written whole, as rtadvd.conf(5)'s examples
 * are: its names line, then its fields packed on tab-indented lines of
 * at most 72 columns, each line's ":" continued by "\".  One there is
 * replaced where it is, its names kept; else the record is added at the
 * end.  The caller orders the fields: a tc= last.
 */
int
vc_cap_set_record(struct vc_capfile *f, const char *name,
    const char *const *caps, size_t n, char *err, size_t errlen)
{
	const struct vc_record *r = vc_cap_record(f, name);
	char *s = NULL;
	size_t len = 0, col = 0, s0, e0;
	FILE *fp;
	int rc;

	if (!cap_name_ok(name)) {
		cfail(err, errlen, "%s: not a record's name", name);
		errno = EINVAL;
		return (-1);
	}
	for (size_t i = 0; i < n; i++)
		if (caps[i][0] == '\0' || strchr(caps[i], '\n') != NULL) {
			cfail(err, errlen, "%s: an empty field, or one with a "
			    "newline", name);
			errno = EINVAL;
			return (-1);
		}
	if ((fp = open_memstream(&s, &len)) == NULL)
		return (-1);
	if (r == NULL && f->len > 0 && f->text[f->len - 1] != '\n')
		fputc('\n', fp);
	if (r != NULL)
		for (size_t i = 0; i < r->nnames; i++)
			fprintf(fp, "%s%s", i > 0 ? "|" : "", r->names[i]);
	else
		fputs(name, fp);
	fputc(':', fp);
	for (size_t i = 0; i < n; i++) {
		size_t w = strlen(caps[i]) + 1;

		if (col == 0 || col + w > 72) {
			fprintf(fp, "\\\n\t:");
			col = 9;
		}
		fprintf(fp, "%s:", caps[i]);
		col += w;
	}
	fputc('\n', fp);
	fclose(fp);
	if (r != NULL) {
		s0 = r->off;
		e0 = r->end;
	} else
		s0 = e0 = f->len;
	rc = cap_splice(f, s0, e0, s, len, err, errlen);
	free(s);
	return (rc);
}

/* The first record named name removed, its lines all. */
int
vc_cap_remove_record(struct vc_capfile *f, const char *name, char *err,
    size_t errlen)
{
	const struct vc_record *r = vc_cap_record(f, name);

	if (r == NULL)
		return (0);
	return (cap_splice(f, r->off, r->end, "", 0, err, errlen));
}

int
vc_cap_write(const struct vc_capfile *f, const char *path, mode_t mode,
    char *err, size_t errlen)
{
	struct vc_file vf;

	/* vc_write() takes a vc_file: the text is all it writes. */
	memset(&vf, 0, sizeof(vf));
	vf.text = f->text;
	vf.len = f->len;
	return (vc_write(&vf, path, mode, err, errlen));
}
