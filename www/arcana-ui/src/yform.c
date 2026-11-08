/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Forms made from a host's YANG modules (PLAN-SDN-YANG 4.8.3): a module
 * as the host's YANG library names it (module@revision), described by
 * the console (/yang/<module>@<revision>.json, its ymodule.c), drawn as
 * the form of a container or of a list's entry, new or one there:
 * the key leaves first, the mandatory marked; a boolean or an empty a
 * checkbox; an enumeration or an identityref a choice of its values; a
 * number an input with its range; a string with its pattern and length
 * said; a leaf-list one value a line; a container a fieldset; a list
 * below it its entries, added and taken away; a choice its cases to
 * pick; what is not configuration left out; each description the help
 * under its field.  What the host's library has not (another module's
 * augment) is left out too.
 *
 * An entry there is read from the host's running datastore and filled
 * in.  Saved as RFC 7951 JSON through ycommit.c: a new entry POSTed into
 * the candidate's parent (409 where it is there), one there or a
 * container PUT, then committed confirmed and confirmed.  The obvious is
 * checked here first (mandatory, range, length, pattern, an enum's
 * name), the rest is the host's: an ietf-restconf error's path said at
 * its field where the form has it.
 *
 * And the host's modules, on its System tab's Models: its library as a
 * table, a module's configuration lists as tables of their entries (each
 * edited by its form) with New, its containers with Edit.  The Jails
 * tab's "New jail (from its model)" opens arcana-jails' jail.
 */

#include <regex.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "app.h"

#define	YF_DOCS		12
#define	YF_PATH		512

/* The modules described, by module@revision. */
static struct {
	char		 key[96];
	ucl_object_t	*doc;
	bool		 loading;
	char		 why[256];
} docs[YF_DOCS];
static int	ndocs;

static struct {
	/* The host's YANG library: its modules, {name, revision} each. */
	char		 lib_sid[16];
	ucl_object_t	*lib;
	bool		 lib_loading;
	char		 lib_why[256];

	/* The form. */
	char		 sid[16];
	char		 module[64];
	char		 path[YF_PATH];		/* the node's schema path */
	char		 key[256];		/* an entry there: its key */
	bool		 isnew;
	bool		 reading;
	ucl_object_t	*val;			/* what the form holds */
	ucl_object_t	*orig;			/* the entry as read */
	ucl_object_t	*sel;			/* the cases picked */
	ucl_object_t	*errs;			/* the fields' errors */
	char		 error[512];
	struct ycommit	 yc;

	/* System's Models: the module shown, its configuration read. */
	char		 mv_sid[16];
	char		 mv_module[64];
	ucl_object_t	*mv_data;
	int		 mv_pending;		/* its reads on their way */
	unsigned	 mv_gen;
	char		 mv_why[256];
} yf;

static void	saved(struct ycommit *, int);

static struct server *
host_of(const char *sid)
{

	for (int i = 0; i < app.nservers; i++)
		if (strcmp(app.servers[i].id, sid) == 0)
			return (&app.servers[i]);
	return (NULL);
}

/* ---- The descriptions and the library ----------------------------------- */

static void
doc_cb(int status, const ucl_object_t *o, const char *err, void *arg)
{
	char	*key = arg;
	int	 i;

	/* By its key: the table may have moved meanwhile. */
	for (i = 0; i < ndocs; i++)
		if (strcmp(docs[i].key, key) == 0)
			break;
	free(key);
	if (i == ndocs)
		return;
	docs[i].loading = false;
	if (status == 200 && o != NULL && jget(o, "nodes") != NULL)
		docs[i].doc = ucl_object_ref((ucl_object_t *)(uintptr_t)o);
	else
		snprintf(docs[i].why, sizeof(docs[i].why), "%s", rc_why(o,
		    err));
	render();
}

/* The description of module@rev: NULL while it is read or where it is
 * not (why then says why). */
static const ucl_object_t *
doc_of(const char *module, const char *rev, const char **why)
{
	char	key[96], url[160];
	int	i;

	*why = NULL;
	snprintf(key, sizeof(key), "%s@%s", module, rev);
	for (i = 0; i < ndocs; i++)
		if (strcmp(docs[i].key, key) == 0) {
			if (docs[i].why[0] != '\0')
				*why = docs[i].why;
			return (docs[i].doc);
		}
	if (ndocs == YF_DOCS) {
		/* The oldest given up. */
		if (docs[0].doc != NULL)
			ucl_object_unref(docs[0].doc);
		memmove(&docs[0], &docs[1], (YF_DOCS - 1) * sizeof(docs[0]));
		ndocs--;
	}
	i = ndocs++;
	memset(&docs[i], 0, sizeof(docs[i]));
	snprintf(docs[i].key, sizeof(docs[i].key), "%s", key);
	docs[i].loading = true;
	snprintf(url, sizeof(url), "/yang/%s.json", key);
	api("GET", url, NULL, doc_cb, strdup(key));
	return (NULL);
}

static void
lib_cb(int status, const ucl_object_t *o, const char *err, void *arg)
{
	const ucl_object_t	*set, *m;
	ucl_object_iter_t	 it = NULL, mit;
	ucl_object_t		*mods, *e;

	(void)arg;
	yf.lib_loading = false;
	if (status != 200 || o == NULL) {
		snprintf(yf.lib_why, sizeof(yf.lib_why), "%s", status == 404 ?
		    "the host's agent serves no YANG library" : rc_why(o,
		    err));
		render();
		return;
	}
	mods = ucl_object_typed_new(UCL_ARRAY);
	while ((set = ucl_object_iterate(jget(o, "ietf-yang-library:"
	    "yang-library.module-set"), &it, true)) != NULL) {
		mit = NULL;
		while ((m = ucl_object_iterate(jget(set, "module"), &mit,
		    true)) != NULL) {
			e = ucl_object_typed_new(UCL_OBJECT);
			ucl_object_insert_key(e, ucl_object_fromstring(jstr(m,
			    "name")), "name", 0, false);
			ucl_object_insert_key(e, ucl_object_fromstring(
			    jstr(m, "revision") != NULL ? jstr(m, "revision") :
			    ""), "revision", 0, false);
			ucl_object_insert_key(e, ucl_object_fromstring(
			    strncmp(jstr(m, "name"), "arcana-", 7) == 0 ?
			    "Arcana" : "standard"), "kind", 0, false);
			ucl_array_append(mods, e);
		}
	}
	if (yf.lib != NULL)
		ucl_object_unref(yf.lib);
	yf.lib = mods;
	yf.lib_why[0] = '\0';
	render();
}

/* The host's library, read where it is another host's or not yet. */
static const ucl_object_t *
lib_of(const char *sid)
{
	char	url[200];

	if (strcmp(yf.lib_sid, sid) == 0 && (yf.lib != NULL ||
	    yf.lib_loading || yf.lib_why[0] != '\0'))
		return (yf.lib);
	if (yf.lib != NULL)
		ucl_object_unref(yf.lib);
	yf.lib = NULL;
	yf.lib_why[0] = '\0';
	snprintf(yf.lib_sid, sizeof(yf.lib_sid), "%s", sid);
	yf.lib_loading = true;
	rc_h(url, sizeof(url), sid, "ietf-yang-library:yang-library");
	api("GET", url, NULL, lib_cb, NULL);
	return (NULL);
}

/* A module of the host's library: its revision, NULL where it has not. */
static const char *
lib_rev(const char *module)
{
	const ucl_object_t	*m;
	ucl_object_iter_t	 it = NULL;

	while ((m = ucl_object_iterate(yf.lib, &it, true)) != NULL)
		if (jstr(m, "name") != NULL && strcmp(jstr(m, "name"),
		    module) == 0)
			return (jstr(m, "revision"));
	return (NULL);
}

/* ---- The description's nodes --------------------------------------------- */

static const char *
str(const ucl_object_t *o, const char *key)
{
	const ucl_object_t	*v;

	if (o == NULL || (v = ucl_object_lookup(o, key)) == NULL)
		return (NULL);
	return (ucl_object_tostring_forced(v));
}

static bool
is(const ucl_object_t *o, const char *key, const char *want)
{
	const char	*v = str(o, key);

	return (v != NULL && strcmp(v, want) == 0);
}

static bool
flag(const ucl_object_t *o, const char *key)
{
	const ucl_object_t	*v;

	return (o != NULL && (v = ucl_object_lookup(o, key)) != NULL &&
	    ucl_object_toboolean(v));
}

/* The node at schema path path, below nodes, choices and cases. */
static const ucl_object_t *
node_at(const ucl_object_t *nodes, const char *path)
{
	const ucl_object_t	*n, *f, *v;
	ucl_object_iter_t	 it = NULL;

	while ((n = ucl_object_iterate(nodes, &it, true)) != NULL) {
		if (is(n, "path", path))
			return (n);
		if ((v = ucl_object_lookup(n, "path")) != NULL && strncmp(path,
		    ucl_object_tostring(v), strlen(ucl_object_tostring(v))) !=
		    0 && !is(n, "kind", "choice") && !is(n, "kind", "case"))
			continue;
		if ((f = node_at(ucl_object_lookup(n, "children"), path)) !=
		    NULL || (f = node_at(ucl_object_lookup(n, "cases"), path)) !=
		    NULL)
			return (f);
	}
	return (NULL);
}

/* In the host's library (all are, while it is not read). */
static bool
known(const ucl_object_t *n)
{

	return (yf.lib == NULL || str(n, "module") == NULL ||
	    lib_rev(str(n, "module")) != NULL);
}

/* Configuration a form shows: a data node that is config, or a choice
 * or a case with such a node below. */
static bool
editable(const ucl_object_t *n)
{
	const ucl_object_t	*c;
	ucl_object_iter_t	 it = NULL;
	const char		*k = str(n, "kind");

	if (k == NULL || !known(n) || is(n, "status", "obsolete"))
		return (false);
	if (strcmp(k, "leaf") == 0 || strcmp(k, "leaf-list") == 0)
		return (flag(n, "config"));
	if (strcmp(k, "container") == 0 || strcmp(k, "list") == 0) {
		if (!flag(n, "config"))
			return (false);
	} else if (strcmp(k, "choice") != 0 && strcmp(k, "case") != 0)
		return (false);
	while ((c = ucl_object_iterate(jget(n, strcmp(k, "choice") == 0 ?
	    "cases" : "children"), &it, true)) != NULL)
		if (editable(c))
			return (true);
	/* A presence container is configuration by being there. */
	return (flag(n, "presence"));
}

/* Its member name: qualified where its module is not its parent's. */
static void
member(char *buf, size_t len, const ucl_object_t *n, const char *pmod)
{
	const char	*m = str(n, "module");

	if (m != NULL && (pmod == NULL || strcmp(m, pmod) != 0))
		snprintf(buf, len, "%s:%s", m, str(n, "name"));
	else
		snprintf(buf, len, "%s", str(n, "name"));
}

static void
join(char *buf, size_t len, const char *inst, const char *seg)
{

	if (inst[0] == '\0')
		snprintf(buf, len, "%s", seg);
	else
		snprintf(buf, len, "%s/%s", inst, seg);
}

/* ---- What the form holds ------------------------------------------------- */

static bool
digits(const char *s)
{

	return (s[0] != '\0' && s[strspn(s, "0123456789")] == '\0');
}

static ucl_object_t *
nth(const ucl_object_t *a, unsigned i)
{

	return ((ucl_object_t *)(uintptr_t)ucl_array_find_index(a, i));
}

static unsigned
count(const ucl_object_t *a)
{
	ucl_object_iter_t	it = NULL;
	unsigned		n = 0;

	if (a == NULL || ucl_object_type(a) != UCL_ARRAY)
		return (0);
	while (ucl_object_iterate(a, &it, true) != NULL)
		n++;
	return (n);
}

/* The value at an instance path ("param/0/name"), below root; what is
 * not there made, an object or an array as the next part says, with
 * make. */
static ucl_object_t *
at(ucl_object_t *root, const char *path, bool make)
{
	ucl_object_t	*o = root, *x;
	char		 buf[YF_PATH], *p, *next;

	if (root == NULL || path[0] == '\0')
		return (root);
	snprintf(buf, sizeof(buf), "%s", path);
	for (p = buf; o != NULL && p != NULL; p = next) {
		if ((next = strchr(p, '/')) != NULL)
			*next++ = '\0';
		if (ucl_object_type(o) == UCL_ARRAY)
			x = digits(p) ? nth(o, (unsigned)atoi(p)) : NULL;
		else if (ucl_object_type(o) == UCL_OBJECT) {
			x = (ucl_object_t *)(uintptr_t)ucl_object_lookup(o, p);
			if (x == NULL && make) {
				x = ucl_object_typed_new(next != NULL &&
				    next[0] >= '0' && next[0] <= '9' ?
				    UCL_ARRAY : UCL_OBJECT);
				ucl_object_insert_key(o, x, p, 0, true);
			}
		} else
			x = NULL;
		o = x;
	}
	return (o);
}

/* The object a path's last member is in, and that member's name. */
static ucl_object_t *
holder(const char *path, const char **name, bool make)
{
	char		 parent[YF_PATH];
	const char	*sl = strrchr(path, '/');
	ucl_object_t	*o;

	if (sl == NULL) {
		*name = path;
		return (yf.val);
	}
	snprintf(parent, sizeof(parent), "%.*s", (int)(sl - path), path);
	*name = sl + 1;
	o = at(yf.val, parent, make);
	return (o != NULL && ucl_object_type(o) == UCL_OBJECT ? o : NULL);
}

static const char *
val_str(const char *path)
{
	const ucl_object_t	*v = at(yf.val, path, false);

	return (v != NULL && ucl_object_type(v) == UCL_STRING ?
	    ucl_object_tostring(v) : NULL);
}

/* A field's value set: the member made at its parent. */
static void
val_set(const char *path, const char *text)
{
	const char	*name;
	ucl_object_t	*o;

	if ((o = holder(path, &name, true)) != NULL)
		ucl_object_replace_key(o, ucl_object_fromstring(text), name, 0,
		    true);
}

/* The form's values of what was read: text each, a leaf-list's a line
 * a value, a boolean "true" or "false", an empty "true". */
static ucl_object_t *
as_text(const ucl_object_t *o)
{
	const ucl_object_t	*v, *x;
	ucl_object_iter_t	 it = NULL, xit;
	ucl_object_t		*out, *arr;
	struct html		 b;
	bool			 scalars;

	switch (ucl_object_type(o)) {
	case UCL_OBJECT:
		out = ucl_object_typed_new(UCL_OBJECT);
		while ((v = ucl_object_iterate(o, &it, true)) != NULL)
			ucl_object_insert_key(out, as_text(v),
			    ucl_object_key(v), 0, true);
		return (out);
	case UCL_ARRAY:
		/* [null]: an empty's value; else scalars or entries. */
		x = ucl_array_find_index(o, 0);
		if (x != NULL && ucl_object_type(x) == UCL_NULL)
			return (ucl_object_fromstring("true"));
		scalars = x == NULL || (ucl_object_type(x) != UCL_OBJECT &&
		    ucl_object_type(x) != UCL_ARRAY);
		if (scalars) {
			memset(&b, 0, sizeof(b));
			xit = NULL;
			while ((x = ucl_object_iterate(o, &xit, true)) != NULL) {
				if (b.len > 0)
					h_raw(&b, "\n");
				h_raw(&b, ucl_object_tostring_forced(x));
			}
			out = ucl_object_fromstring(b.s != NULL ? b.s : "");
			free(b.s);
			return (out);
		}
		arr = ucl_object_typed_new(UCL_ARRAY);
		xit = NULL;
		while ((x = ucl_object_iterate(o, &xit, true)) != NULL)
			ucl_array_append(arr, as_text(x));
		return (arr);
	case UCL_BOOLEAN:
		return (ucl_object_fromstring(ucl_object_toboolean(o) ? "true" :
		    "false"));
	default:
		return (ucl_object_fromstring(ucl_object_tostring_forced(o)));
	}
}

static void
err_set(const char *path, const char *msg)
{

	if (yf.errs == NULL)
		yf.errs = ucl_object_typed_new(UCL_OBJECT);
	if (ucl_object_lookup(yf.errs, path) == NULL)
		ucl_object_insert_key(yf.errs, ucl_object_fromstring(msg), path,
		    0, true);
}

static void
form_drop(void)
{

	if (yf.val != NULL)
		ucl_object_unref(yf.val);
	if (yf.orig != NULL)
		ucl_object_unref(yf.orig);
	if (yf.sel != NULL)
		ucl_object_unref(yf.sel);
	if (yf.errs != NULL)
		ucl_object_unref(yf.errs);
	yf.val = yf.orig = yf.sel = yf.errs = NULL;
}

/* ---- Drawn ---------------------------------------------------------------- */

/* A description's first paragraph, cut where it is long. */
static void
help(struct html *h, const ucl_object_t *n)
{
	const char	*d = str(n, "description"), *end;
	char		 buf[260];
	size_t		 len;

	if (d == NULL)
		return;
	end = strstr(d, "\n\n");
	len = end != NULL ? (size_t)(end - d) : strlen(d);
	if (len >= sizeof(buf) - 4) {
		len = sizeof(buf) - 4;
		while (len > 0 && (d[len] & 0xc0) == 0x80)
			len--;
	}
	memcpy(buf, d, len);
	buf[len] = '\0';
	if (len < strlen(d))
		(void)strlcat(buf, "…", sizeof(buf));
	for (char *p = buf; *p != '\0'; p++)
		if (*p == '\n')
			*p = ' ';
	h_raw(h, "<small class=\"dim yf-help\"");
	h_attr(h, "title", d);
	h_raw(h, ">");
	h_txt(h, buf);
	h_raw(h, "</small>");
}

static const ucl_object_t *
type_of(const ucl_object_t *n)
{

	return (n != NULL ? ucl_object_lookup(n, "type") : NULL);
}

/* The bounds of a range or a length, in a few words. */
static void
bounds(char *buf, size_t len, const ucl_object_t *r)
{
	const ucl_object_t	*p;
	ucl_object_iter_t	 it = NULL;
	size_t			 o = 0;

	buf[0] = '\0';
	while ((p = ucl_object_iterate(r, &it, true)) != NULL && o < len) {
		const char *lo = ucl_object_tostring_forced(nth(p, 0));
		char tmp[64];

		snprintf(tmp, sizeof(tmp), "%s", lo);
		o += (size_t)snprintf(buf + o, len - o, "%s%s", o > 0 ? " | " :
		    "", tmp);
		if (o < len && strcmp(tmp, ucl_object_tostring_forced(nth(p,
		    1))) != 0)
			o += (size_t)snprintf(buf + o, len - o, "..%s",
			    ucl_object_tostring_forced(nth(p, 1)));
	}
}

/* What a field takes, said under it. */
static void
hint(struct html *h, const ucl_object_t *n, const ucl_object_t *t)
{
	const ucl_object_t	*v;
	char			 b[160];
	const char		*base = str(t, "base");
	bool			 any = false;

	h_raw(h, "<small class=\"dim yf-type\">");
#define	SEP() do { if (any) h_raw(h, "; "); any = true; } while (0)
	if (str(n, "typedef") != NULL) {
		SEP();
		h_txt(h, str(n, "typedef"));
	} else if (base != NULL && strcmp(base, "boolean") != 0 &&
	    strcmp(base, "enumeration") != 0 && strcmp(base, "identityref") !=
	    0) {
		SEP();
		h_txt(h, base);
	}
	if ((v = ucl_object_lookup(t, "range")) != NULL) {
		bounds(b, sizeof(b), v);
		SEP();
		h_raw(h, "range ");
		h_txt(h, b);
	}
	if ((v = ucl_object_lookup(t, "length")) != NULL) {
		bounds(b, sizeof(b), v);
		SEP();
		h_raw(h, "length ");
		h_txt(h, b);
	}
	if ((v = ucl_object_lookup(t, "pattern")) != NULL &&
	    str(nth(v, 0), "pattern") != NULL) {
		SEP();
		h_raw(h, "pattern <code>");
		h_fit(h, str(nth(v, 0), "pattern"), 60);
		h_raw(h, "</code>");
	}
	if ((v = ucl_object_lookup(t, "leafref")) != NULL &&
	    str(v, "target") != NULL) {
		SEP();
		h_raw(h, "→ ");
		h_txt(h, str(v, "target"));
	}
	if (str(n, "units") != NULL) {
		SEP();
		h_txt(h, str(n, "units"));
	}
	if (str(n, "default") != NULL) {
		SEP();
		h_raw(h, "default ");
		h_txt(h, str(n, "default"));
	}
#undef	SEP
	h_raw(h, "</small>");
}

static void
field_err(struct html *h, const char *ipath)
{
	const ucl_object_t	*e;

	if (yf.errs != NULL && (e = ucl_object_lookup(yf.errs, ipath)) !=
	    NULL) {
		h_raw(h, "<small class=\"err yf-err\">");
		h_txt(h, ucl_object_tostring(e));
		h_raw(h, "</small>");
	}
}

/* The integer bounds of a range for an input's min and max. */
static void
num_attrs(struct html *h, const ucl_object_t *t)
{
	static const struct {
		const char	*base, *min, *max;
	} lim[] = {
		{ "int8", "-128", "127" }, { "int16", "-32768", "32767" },
		{ "int32", "-2147483648", "2147483647" },
		{ "uint8", "0", "255" }, { "uint16", "0", "65535" },
		{ "uint32", "0", "4294967295" },
	};
	const ucl_object_t	*r = ucl_object_lookup(t, "range");
	const char		*lo = NULL, *hi = NULL;

	for (size_t i = 0; i < nitems(lim); i++)
		if (is(t, "base", lim[i].base)) {
			lo = lim[i].min;
			hi = lim[i].max;
		}
	if (r != NULL && count(r) > 0) {
		lo = ucl_object_tostring_forced(nth(nth(r, 0), 0));
		hi = ucl_object_tostring_forced(nth(nth(r, count(r) - 1), 1));
	}
	if (lo != NULL)
		h_attr(h, "min", lo);
	if (hi != NULL)
		h_attr(h, "max", hi);
}

static bool
is_int(const char *base)
{

	return (base != NULL && (strcmp(base, "int8") == 0 || strcmp(base,
	    "int16") == 0 || strcmp(base, "int32") == 0 || strcmp(base,
	    "uint8") == 0 || strcmp(base, "uint16") == 0 || strcmp(base,
	    "uint32") == 0));
}

/* A leaf or a leaf-list: its label, its input, what it takes, its help. */
static void
leaf(struct html *h, const ucl_object_t *n, const char *ipath, bool key,
    bool fixed)
{
	const ucl_object_t	*t = type_of(n), *e;
	ucl_object_iter_t	 it = NULL;
	const char		*base = str(t, "base"), *v = val_str(ipath);
	bool			 req = key || flag(n, "mandatory");

	if (base == NULL)
		base = "string";
	if (strcmp(base, "boolean") == 0 || strcmp(base, "empty") == 0) {
		bool on = v != NULL ? strcmp(v, "true") == 0 :
		    is(n, "default", "true");

		h_raw(h, "<label class=\"check yf-field\"><span><input "
		    "type=\"checkbox\" data-input=\"yf\"");
		h_attr(h, "name", ipath);
		h_attr(h, "data-arg", ipath);
		h_raw(h, on ? " checked>" : ">");
		h_raw(h, " ");
		h_txt(h, str(n, "name"));
		h_raw(h, "</span>");
		help(h, n);
		field_err(h, ipath);
		h_raw(h, "</label>");
		return;
	}
	h_raw(h, "<label class=\"yf-field\"><span>");
	h_txt(h, str(n, "name"));
	if (req)
		h_raw(h, " <b class=\"yf-req\" title=\"Mandatory\">*</b>");
	if (is(n, "kind", "leaf-list"))
		h_raw(h, " <span class=\"dim\">(one a line)</span>");
	h_raw(h, "</span>");
	if (is(n, "kind", "leaf-list")) {
		h_raw(h, "<textarea "
		    "rows=\"3\" spellcheck=\"false\" data-input=\"yf\"");
		h_attr(h, "name", ipath);
		h_attr(h, "data-arg", ipath);
		h_raw(h, ">");
		h_txt(h, v != NULL ? v : "");
		h_raw(h, "</textarea>");
	} else if (strcmp(base, "enumeration") == 0 || strcmp(base,
	    "identityref") == 0) {
		bool ident = strcmp(base, "identityref") == 0;
		char dflt[160];

		h_raw(h, "<select data-input=\"yf\"");
		h_attr(h, "name", ipath);
		h_attr(h, "data-arg", ipath);
		h_raw(h, req ? " required>" : ">");
		snprintf(dflt, sizeof(dflt), "%s%s%s", str(n, "default") !=
		    NULL ? "— its default, " : "—", str(n, "default") != NULL ?
		    str(n, "default") : "", "");
		h_raw(h, "<option value=\"\">");
		h_txt(h, dflt);
		h_raw(h, "</option>");
		while ((e = ucl_object_iterate(jget(t, ident ? "identities" :
		    "enum"), &it, true)) != NULL) {
			const char *name = str(e, "name");
			const char *colon = ident ? strchr(name, ':') : NULL;
			char mod[64];

			/* An identity of a module the host has not. */
			if (colon != NULL && yf.lib != NULL) {
				snprintf(mod, sizeof(mod), "%.*s", (int)(colon -
				    name), name);
				if (lib_rev(mod) == NULL)
					continue;
			}
			h_raw(h, "<option");
			h_attr(h, "value", name);
			h_attr(h, "title", str(e, "description"));
			if (v != NULL && strcmp(v, name) == 0)
				h_raw(h, " selected");
			h_raw(h, ">");
			h_txt(h, name);
			h_raw(h, "</option>");
		}
		h_raw(h, "</select>");
	} else {
		h_raw(h, "<input spellcheck=\"false\" autocomplete=\"off\" "
		    "data-input=\"yf\"");
		h_attr(h, "name", ipath);
		h_attr(h, "data-arg", ipath);
		if (is_int(base)) {
			h_raw(h, " type=\"number\"");
			num_attrs(h, t);
		} else if (strcmp(base, "decimal64") == 0 || strcmp(base,
		    "int64") == 0 || strcmp(base, "uint64") == 0)
			h_raw(h, " inputmode=\"decimal\"");
		h_attr(h, "value", v != NULL ? v : "");
		h_attr(h, "placeholder", str(n, "default"));
		if (req)
			h_raw(h, " required");
		if (fixed)
			h_raw(h, " readonly title=\"An entry's key stays: a "
			    "new entry for another\"");
		h_raw(h, ">");
	}
	hint(h, n, t);
	help(h, n);
	field_err(h, ipath);
	h_raw(h, "</label>");
}

static void	fields(struct html *, const ucl_object_t *, const char *,
		    const char *, const ucl_object_t *, bool);

/* The case picked of a choice at inst: as picked, else the one a value
 * is in, else its default. */
static const char *
case_of(const ucl_object_t *ch, const char *inst, const char *pmod)
{
	const ucl_object_t	*c, *k, *v;
	ucl_object_iter_t	 it = NULL, kit;
	char			 id[YF_PATH + 80], mem[160], ip[YF_PATH];

	snprintf(id, sizeof(id), "%s|%s", inst, str(ch, "name"));
	if (yf.sel != NULL && (v = ucl_object_lookup(yf.sel, id)) != NULL)
		return (ucl_object_tostring(v));
	while ((c = ucl_object_iterate(jget(ch, "cases"), &it, true)) != NULL) {
		kit = NULL;
		while ((k = ucl_object_iterate(jget(c, "children"), &kit,
		    true)) != NULL) {
			member(mem, sizeof(mem), k, pmod);
			join(ip, sizeof(ip), inst, mem);
			if (at(yf.val, ip, false) != NULL)
				return (str(c, "name"));
		}
	}
	return (str(ch, "default"));
}

static void
choice(struct html *h, const ucl_object_t *ch, const char *inst,
    const char *pmod)
{
	const ucl_object_t	*c, *picked = NULL;
	ucl_object_iter_t	 it = NULL;
	const char		*now = case_of(ch, inst, pmod);
	char			 id[YF_PATH + 80];

	snprintf(id, sizeof(id), "?%s|%s", inst, str(ch, "name"));
	h_raw(h, "<fieldset class=\"yf-choice\"><legend>");
	h_txt(h, str(ch, "name"));
	h_raw(h, "</legend><label class=\"yf-field\">Which<select "
	    "data-input=\"yf-case\"");
	h_attr(h, "name", id);
	h_attr(h, "data-arg", id + 1);
	h_raw(h, ">");
	if (!flag(ch, "mandatory"))
		h_raw(h, "<option value=\"\">— none</option>");
	while ((c = ucl_object_iterate(jget(ch, "cases"), &it, true)) != NULL) {
		if (!editable(c))
			continue;
		h_raw(h, "<option");
		h_attr(h, "value", str(c, "name"));
		h_attr(h, "title", str(c, "description"));
		if (now != NULL && is(c, "name", now)) {
			h_raw(h, " selected");
			picked = c;
		}
		h_raw(h, ">");
		h_txt(h, str(c, "name"));
		h_raw(h, "</option>");
	}
	h_raw(h, "</select>");
	help(h, ch);
	h_raw(h, "</label>");
	if (picked != NULL)
		fields(h, jget(picked, "children"), inst, pmod, NULL, false);
	h_raw(h, "</fieldset>");
}

static void
list_entries(struct html *h, const ucl_object_t *n, const char *ipath)
{
	const ucl_object_t	*arr = at(yf.val, ipath, false);
	unsigned		 i, k = count(arr);
	char			 ep[YF_PATH];

	h_raw(h, "<fieldset class=\"yf-list\"><legend>");
	h_txt(h, str(n, "name"));
	h_raw(h, " <span class=\"dim\">(a list)</span></legend>");
	help(h, n);
	for (i = 0; i < k; i++) {
		snprintf(ep, sizeof(ep), "%s/%u", ipath, i);
		h_raw(h, "<fieldset class=\"yf-entry\"><legend>");
		h_txt(h, str(n, "name"));
		h_fmt(h, " %u <button type=\"button\" class=\"icon\" "
		    "data-act=\"yf-del\" title=\"Take this entry away\"", i + 1);
		h_attr(h, "data-arg", ep);
		h_raw(h, ">×</button></legend>");
		fields(h, jget(n, "children"), ep, str(n, "module"),
		    jget(n, "keys"), false);
		h_raw(h, "</fieldset>");
	}
	h_raw(h, "<button type=\"button\" class=\"ghost small\" "
	    "data-act=\"yf-add\"");
	h_attr(h, "data-arg", ipath);
	h_raw(h, ">+ ");
	h_txt(h, str(n, "name"));
	h_raw(h, "</button>");
	field_err(h, ipath);
	h_raw(h, "</fieldset>");
}

static bool
key_of(const ucl_object_t *keys, const char *name)
{
	const ucl_object_t	*k;
	ucl_object_iter_t	 it = NULL;

	while ((k = ucl_object_iterate(keys, &it, true)) != NULL)
		if (strcmp(ucl_object_tostring(k), name) == 0)
			return (true);
	return (false);
}

/* The fields of nodes kids, the members of the object at inst. */
static void
fields(struct html *h, const ucl_object_t *kids, const char *inst,
    const char *pmod, const ucl_object_t *keys, bool fixkeys)
{
	const ucl_object_t	*n;
	ucl_object_iter_t	 it = NULL;
	char			 mem[160], ip[YF_PATH];
	const char		*k;

	while ((n = ucl_object_iterate(kids, &it, true)) != NULL) {
		if (!editable(n) || (k = str(n, "kind")) == NULL)
			continue;
		if (strcmp(k, "choice") == 0) {
			choice(h, n, inst, pmod);
			continue;
		}
		member(mem, sizeof(mem), n, pmod);
		join(ip, sizeof(ip), inst, mem);
		if (strcmp(k, "leaf") == 0 || strcmp(k, "leaf-list") == 0) {
			bool key = strcmp(k, "leaf") == 0 &&
			    key_of(keys, str(n, "name"));

			leaf(h, n, ip, key, key && fixkeys);
		} else if (strcmp(k, "list") == 0)
			list_entries(h, n, ip);
		else if (strcmp(k, "container") == 0) {
			h_raw(h, "<fieldset class=\"yf-container\"><legend>");
			h_txt(h, str(n, "name"));
			h_raw(h, "</legend>");
			help(h, n);
			if (flag(n, "presence")) {
				h_raw(h, "<label class=\"check\"><span><input "
				    "type=\"checkbox\" data-input=\"yf-pres\"");
				h_attr(h, "data-arg", ip);
				h_raw(h, at(yf.val, ip, false) != NULL ?
				    " checked> There" : "> There");
				h_raw(h, "</span></label>");
			}
			if (!flag(n, "presence") || at(yf.val, ip, false) !=
			    NULL)
				fields(h, jget(n, "children"), ip, str(n,
				    "module"), NULL, false);
			h_raw(h, "</fieldset>");
		}
	}
}

/* The node the form is of, in its module's description. */
static const ucl_object_t *
form_node(const char **why)
{
	const ucl_object_t	*doc;
	const char		*rev;

	*why = NULL;
	if (lib_of(yf.sid) == NULL) {
		*why = yf.lib_why[0] != '\0' ? yf.lib_why : NULL;
		return (NULL);
	}
	if ((rev = lib_rev(yf.module)) == NULL) {
		*why = "The host's YANG library has not this module: its "
		    "agent is older than the console.";
		return (NULL);
	}
	if ((doc = doc_of(yf.module, rev, why)) == NULL)
		return (NULL);
	if (node_at(jget(doc, "nodes"), yf.path) == NULL)
		*why = "The module has no such node.";
	return (node_at(jget(doc, "nodes"), yf.path));
}

bool
yform_modal(struct html *h)
{
	const ucl_object_t	*n;
	const char		*why;
	bool			 list;

	if (app.modal != MODAL_YFORM)
		return (false);
	n = form_node(&why);
	list = n != NULL && is(n, "kind", "list");
	h_raw(h, "<form data-form=\"ymf\" class=\"wide yform\" novalidate><h2>");
	if (n == NULL)
		h_txt(h, yf.path);
	else {
		h_txt(h, yf.isnew ? "New " : list ? "Edit " : "");
		h_txt(h, str(n, "name"));
		if (!yf.isnew && yf.key[0] != '\0') {
			h_raw(h, " ");
			h_txt(h, yf.key);
		}
		h_raw(h, " <span class=\"dim\">from its model</span>");
	}
	h_raw(h, "</h2><p class=\"dim\">");
	h_txt(h, yf.module);
	h_raw(h, " · <code>");
	h_txt(h, yf.path);
	h_raw(h, "</code>: drawn from the module the host's YANG library "
	    "names, saved in its candidate and committed confirmed.</p>");
	if (n == NULL || yf.reading) {
		if (why != NULL) {
			h_raw(h, "<p class=\"err\">");
			h_txt(h, why);
			h_raw(h, "</p>");
		} else
			h_raw(h, "<div class=\"loader\"></div>");
		return (true);
	}
	if (yf.error[0] != '\0') {
		h_raw(h, "<p class=\"err\">");
		h_txt(h, yf.error);
		h_raw(h, "</p>");
	}
	help(h, n);
	if (list)
		fields(h, jget(n, "children"), "", str(n, "module"),
		    jget(n, "keys"), !yf.isnew);
	else
		fields(h, jget(n, "children"), "", str(n, "module"), NULL,
		    false);
	ycommit_note(h, &yf.yc);
	return (true);
}

void
yform_modal_buttons(struct html *h)
{
	const char	*why;

	h_fmt(h, "<button class=\"primary\"%s>%s</button>", yf.yc.busy ||
	    yf.reading || form_node(&why) == NULL ? " disabled" : "",
	    yf.isnew ? "Create" : "Save");
}

/* ---- Saved ---------------------------------------------------------------- */

static int
re_match(const char *ere, const char *s)
{
	regex_t	re;
	int	r;

	if (regcomp(&re, ere, REG_EXTENDED | REG_NOSUB) != 0)
		return (-1);
	r = regexec(&re, s, 0, NULL, 0) == 0;
	regfree(&re);
	return (r);
}

static size_t
chars(const char *s)
{
	size_t	n = 0;

	for (; *s != '\0'; s++)
		if (((unsigned char)*s & 0xc0) != 0x80)
			n++;
	return (n);
}

/* Is v within a range's or a length's bounds? */
static bool
within(const ucl_object_t *r, double v)
{
	const ucl_object_t	*p;
	ucl_object_iter_t	 it = NULL;

	if (r == NULL)
		return (true);
	while ((p = ucl_object_iterate(r, &it, true)) != NULL)
		if (v >= strtod(ucl_object_tostring_forced(nth(p, 0)), NULL) &&
		    v <= strtod(ucl_object_tostring_forced(nth(p, 1)), NULL))
			return (true);
	return (false);
}

/*
 * A value of type t from its text: RFC 7951's JSON (a number for an
 * integer of 32 bits or fewer, a string for one of 64 and a decimal64),
 * or NULL and why where it is not one.
 */
static ucl_object_t *
typed(const ucl_object_t *t, const char *s, char *why, size_t len)
{
	const char		*base = str(t, "base");
	const ucl_object_t	*v;
	ucl_object_iter_t	 it = NULL;
	char			*end;
	double			 d;

	if (base == NULL)
		base = "string";
	if (strcmp(base, "boolean") == 0) {
		if (strcmp(s, "true") == 0 || strcmp(s, "false") == 0)
			return (ucl_object_frombool(strcmp(s, "true") == 0));
		snprintf(why, len, "true or false");
		return (NULL);
	}
	if (strcmp(base, "empty") == 0) {
		ucl_object_t *a = ucl_object_typed_new(UCL_ARRAY);

		ucl_array_append(a, ucl_object_typed_new(UCL_NULL));
		return (a);
	}
	if (is_int(base) || strcmp(base, "int64") == 0 || strcmp(base,
	    "uint64") == 0 || strcmp(base, "decimal64") == 0) {
		d = strtod(s, &end);
		if (*s == '\0' || *end != '\0' || (strcmp(base, "decimal64") !=
		    0 && strchr(s, '.') != NULL) || (base[0] == 'u' &&
		    s[0] == '-')) {
			snprintf(why, len, "not a%s number", strcmp(base,
			    "decimal64") == 0 ? "" : " whole");
			return (NULL);
		}
		if (!within(jget(t, "range"), d)) {
			char b[120];

			bounds(b, sizeof(b), jget(t, "range"));
			snprintf(why, len, "out of its range, %s", b);
			return (NULL);
		}
		if (is_int(base))
			return (ucl_object_fromint(strtoll(s, NULL, 10)));
		return (ucl_object_fromstring(s));
	}
	if (strcmp(base, "enumeration") == 0) {
		while ((v = ucl_object_iterate(jget(t, "enum"), &it, true)) !=
		    NULL)
			if (is(v, "name", s))
				return (ucl_object_fromstring(s));
		snprintf(why, len, "not one of its values");
		return (NULL);
	}
	if (strcmp(base, "union") == 0) {
		char	w[128];

		while ((v = ucl_object_iterate(jget(t, "members"), &it,
		    true)) != NULL) {
			ucl_object_t *o = typed(v, s, w, sizeof(w));

			if (o != NULL)
				return (o);
		}
		snprintf(why, len, "none of its types takes it");
		return (NULL);
	}
	if (strcmp(base, "string") == 0) {
		if (!within(jget(t, "length"), (double)chars(s))) {
			char b[120];

			bounds(b, sizeof(b), jget(t, "length"));
			snprintf(why, len, "its length is not %s", b);
			return (NULL);
		}
		while ((v = ucl_object_iterate(jget(t, "pattern"), &it,
		    true)) != NULL) {
			int m;

			if (str(v, "ere") == NULL || (m = re_match(str(v,
			    "ere"), s)) == -1)
				continue;
			if (m == (int)flag(v, "invert")) {
				snprintf(why, len, "%s", str(v,
				    "error-message") != NULL ? str(v,
				    "error-message") : "not as its pattern has "
				    "it");
				return (NULL);
			}
		}
	}
	return (ucl_object_fromstring(s));
}

static bool
was_set(const char *ipath)
{

	return (yf.orig != NULL && at(yf.orig, ipath, false) != NULL);
}

static ucl_object_t	*built(const ucl_object_t *, const char *,
			    const char *, const ucl_object_t *, bool *);

static void
build_leaf(ucl_object_t *out, const ucl_object_t *n, const char *mem,
    const char *ip, bool key, bool *any)
{
	const ucl_object_t	*t = type_of(n);
	const char		*s = val_str(ip), *base = str(t, "base");
	ucl_object_t		*v, *arr;
	char			 why[200], *dup, *p, *line;

	if (is(n, "kind", "leaf-list")) {
		arr = ucl_object_typed_new(UCL_ARRAY);
		dup = strdup(s != NULL ? s : "");
		for (p = dup; (line = strsep(&p, "\n")) != NULL;) {
			while (*line == ' ' || *line == '\t' || *line == '\r')
				line++;
			for (size_t l = strlen(line); l > 0 && (line[l - 1] ==
			    ' ' || line[l - 1] == '\t' || line[l - 1] == '\r');)
				line[--l] = '\0';
			if (*line == '\0')
				continue;
			if ((v = typed(t, line, why, sizeof(why))) == NULL) {
				char m[260];

				snprintf(m, sizeof(m), "%s: %s", line, why);
				err_set(ip, m);
				continue;
			}
			ucl_array_append(arr, v);
		}
		free(dup);
		if (count(arr) > 0) {
			ucl_object_insert_key(out, arr, mem, 0, true);
			*any = true;
		} else {
			ucl_object_unref(arr);
			if (jint(n, "min-elements", 0) > 0)
				err_set(ip, "at least one value");
		}
		return;
	}
	/* A box not ticked: false where that is not its default or it was
	 * so, else not said. */
	if (base != NULL && (strcmp(base, "boolean") == 0 || strcmp(base,
	    "empty") == 0) && s != NULL && strcmp(s, "false") == 0) {
		if (strcmp(base, "boolean") == 0 && (is(n, "default", "true") ||
		    was_set(ip))) {
			ucl_object_insert_key(out, ucl_object_frombool(false),
			    mem, 0, true);
			*any = true;
		}
		return;
	}
	if (s == NULL || s[0] == '\0') {
		if (key || flag(n, "mandatory"))
			err_set(ip, key ? "the entry's key: mandatory" :
			    "mandatory");
		return;
	}
	if ((v = typed(t, s, why, sizeof(why))) == NULL) {
		err_set(ip, why);
		return;
	}
	ucl_object_insert_key(out, v, mem, 0, true);
	*any = true;
}

/* The members of nodes kids from the object at inst, typed. */
static void
build_into(ucl_object_t *out, const ucl_object_t *kids, const char *inst,
    const char *pmod, const ucl_object_t *keys, bool *any)
{
	const ucl_object_t	*n, *c;
	ucl_object_iter_t	 it = NULL, cit;
	char			 mem[160], ip[YF_PATH];
	const char		*k, *now;
	ucl_object_t		*o, *arr;
	bool			 sub;

	while ((n = ucl_object_iterate(kids, &it, true)) != NULL) {
		if (!editable(n) || (k = str(n, "kind")) == NULL)
			continue;
		if (strcmp(k, "choice") == 0) {
			now = case_of(n, inst, pmod);
			if (now == NULL) {
				if (flag(n, "mandatory"))
					err_set(inst, "a case of a choice is "
					    "mandatory");
				continue;
			}
			cit = NULL;
			while ((c = ucl_object_iterate(jget(n, "cases"), &cit,
			    true)) != NULL)
				if (is(c, "name", now))
					build_into(out, jget(c, "children"),
					    inst, pmod, NULL, any);
			continue;
		}
		member(mem, sizeof(mem), n, pmod);
		join(ip, sizeof(ip), inst, mem);
		if (strcmp(k, "leaf") == 0 || strcmp(k, "leaf-list") == 0)
			build_leaf(out, n, mem, ip, strcmp(k, "leaf") == 0 &&
			    key_of(keys, str(n, "name")), any);
		else if (strcmp(k, "container") == 0) {
			if (flag(n, "presence") && at(yf.val, ip, false) ==
			    NULL)
				continue;
			sub = false;
			o = built(jget(n, "children"), ip, str(n, "module"),
			    NULL, &sub);
			if (sub || flag(n, "presence")) {
				ucl_object_insert_key(out, o, mem, 0, true);
				*any = true;
			} else
				ucl_object_unref(o);
		} else if (strcmp(k, "list") == 0) {
			arr = ucl_object_typed_new(UCL_ARRAY);
			for (unsigned i = 0; i < count(at(yf.val, ip, false));
			    i++) {
				char ep[YF_PATH];

				snprintf(ep, sizeof(ep), "%s/%u", ip, i);
				sub = false;
				o = built(jget(n, "children"), ep, str(n,
				    "module"), jget(n, "keys"), &sub);
				if (sub)
					ucl_array_append(arr, o);
				else
					ucl_object_unref(o);
			}
			if (count(arr) > 0) {
				ucl_object_insert_key(out, arr, mem, 0, true);
				*any = true;
			} else {
				ucl_object_unref(arr);
				if (jint(n, "min-elements", 0) > 0)
					err_set(ip, "at least one entry");
			}
		}
	}
}

static ucl_object_t *
built(const ucl_object_t *kids, const char *inst, const char *pmod,
    const ucl_object_t *keys, bool *any)
{
	ucl_object_t	*o = ucl_object_typed_new(UCL_OBJECT);

	build_into(o, kids, inst, pmod, keys, any);
	return (o);
}

/* The api-path of the form's node, its entry's key when one is there:
 * its schema path is one, as no list is above it. */
static void
api_path(char *buf, size_t len, const ucl_object_t *n, bool parent)
{
	char	p[YF_PATH], *slash;

	snprintf(p, sizeof(p), "%s", yf.path + (yf.path[0] == '/'));
	if (parent) {
		if ((slash = strrchr(p, '/')) != NULL)
			*slash = '\0';
		else
			p[0] = '\0';
	}
	if (!parent && is(n, "kind", "list") && yf.key[0] != '\0')
		snprintf(buf, len, "%s=%s", p, rc_key(yf.key));
	else
		snprintf(buf, len, "%s", p);
}

/* An error's path (an instance-identifier) as the form's field, the
 * entries known by their keys. */
static void
err_at(const char *epath, const char *msg)
{
	const ucl_object_t	*n, *kids, *c, *found, *cs;
	ucl_object_iter_t	 it, cit;
	char			 buf[YF_PATH], ip[YF_PATH], mem[160], *p, *seg;
	char			*pred, *next;
	const char		*why, *pmod;
	int			 skip = 0;

	if (epath == NULL || (n = form_node(&why)) == NULL)
		return;
	for (const char *q = yf.path; *q != '\0'; q++)
		if (*q == '/')
			skip++;
	snprintf(buf, sizeof(buf), "%s", epath);
	ip[0] = '\0';
	kids = jget(n, "children");
	pmod = str(n, "module");
	for (p = buf + (buf[0] == '/'); p != NULL && *p != '\0'; p = next) {
		/* A segment ends at a / outside its predicates. */
		int depth = 0;

		for (next = p; *next != '\0' && (depth > 0 || *next != '/');
		    next++)
			depth += *next == '[' ? 1 : *next == ']' ? -1 : 0;
		if (*next == '/')
			*next++ = '\0';
		else
			next = NULL;
		if (--skip > 0)
			continue;
		if (skip == 0)
			continue;	/* the form's own node */
		seg = p;
		if ((pred = strchr(seg, '[')) != NULL)
			*pred++ = '\0';
		found = NULL;
		/* The node of that name, choices and cases passed. */
		it = NULL;
		while (found == NULL && (c = ucl_object_iterate(kids, &it,
		    true)) != NULL) {
			if (is(c, "kind", "choice")) {
				cit = NULL;
				while (found == NULL && (cs = ucl_object_iterate(
				    jget(c, "cases"), &cit, true)) != NULL) {
					const ucl_object_t *x;
					ucl_object_iter_t xit = NULL;

					while ((x = ucl_object_iterate(jget(cs,
					    "children"), &xit, true)) != NULL) {
						member(mem, sizeof(mem), x, pmod);
						if (strcmp(mem, seg) == 0 ||
						    strcmp(str(x, "name"), seg) == 0)
							found = x;
					}
				}
				continue;
			}
			member(mem, sizeof(mem), c, pmod);
			if (strcmp(mem, seg) == 0 || is(c, "name", seg))
				found = c;
		}
		if (found == NULL)
			break;
		member(mem, sizeof(mem), found, pmod);
		{
			char t[YF_PATH];

			join(t, sizeof(t), ip, mem);
			snprintf(ip, sizeof(ip), "%s", t);
		}
		if (is(found, "kind", "list")) {
			/* [k='v']: the entry whose key k has v. */
			unsigned i = 0, nent = count(at(yf.val, ip, false));
			char k[80] = "", v[160] = "";

			if (pred != NULL)
				(void)sscanf(pred, "%79[^=]='%159[^']'", k, v);
			for (i = 0; i < nent; i++) {
				char kp[YF_PATH];
				const char *have;

				snprintf(kp, sizeof(kp), "%s/%u/%s", ip, i, k);
				if ((have = val_str(kp)) != NULL && strcmp(have,
				    v) == 0)
					break;
			}
			if (i == nent)
				break;
			snprintf(ip + strlen(ip), sizeof(ip) - strlen(ip),
			    "/%u", i);
		}
		kids = jget(found, "children");
		pmod = str(found, "module");
	}
	err_set(ip, msg);
}

static void
saved(struct ycommit *yc, int how)
{
	struct server	*s;

	(void)yc;
	if (how == YC_REFUSED) {
		err_at(yf.yc.errpath, yf.yc.note);
		return;
	}
	if (how != YC_SAVED)
		return;
	toast(false, "%s", yf.isnew ? "Created and committed." :
	    "Saved and committed.");
	if (app.modal == MODAL_YFORM)
		app.modal = MODAL_NONE;
	if ((s = host_of(yf.sid)) != NULL) {
		if (strcmp(yf.module, "arcana-jails") == 0)
			refresh_jails(s, false);
		/* The module's tables read again. */
		if (strcmp(yf.mv_sid, yf.sid) == 0 && strcmp(yf.mv_module,
		    yf.module) == 0 && yf.mv_data != NULL) {
			ucl_object_unref(yf.mv_data);
			yf.mv_data = NULL;
		}
	}
}

static void
submit(void)
{
	const ucl_object_t	*n;
	const char		*why;
	ucl_object_t		*body, *entry, *arr;
	char			 url[YF_PATH + 200], path[YF_PATH], mem[160];
	char			*json;
	bool			 any = false, list;

	if ((n = form_node(&why)) == NULL || yf.yc.busy)
		return;
	if (yf.errs != NULL)
		ucl_object_unref(yf.errs);
	yf.errs = NULL;
	yf.error[0] = '\0';
	list = is(n, "kind", "list");
	entry = built(jget(n, "children"), "", str(n, "module"), list ?
	    jget(n, "keys") : NULL, &any);
	if (yf.errs != NULL) {
		ucl_object_unref(entry);
		snprintf(yf.error, sizeof(yf.error), "Not sent: what is said "
		    "at its field first.");
		return;
	}
	/* The node by its qualified name, in the module's own. */
	snprintf(mem, sizeof(mem), "%s:%s", str(n, "module"), str(n, "name"));
	body = ucl_object_typed_new(UCL_OBJECT);
	if (list) {
		arr = ucl_object_typed_new(UCL_ARRAY);
		ucl_array_append(arr, entry);
		ucl_object_insert_key(body, arr, mem, 0, true);
	} else
		ucl_object_insert_key(body, entry, mem, 0, true);
	json = (char *)ucl_object_emit(body, UCL_EMIT_JSON_COMPACT);
	ucl_object_unref(body);
	yf.yc.act = "yf-yc";
	yf.yc.saved = yf.isnew ? "Created and committed." : "Saved and "
	    "committed.";
	yf.yc.done = saved;
	if (yf.isnew && list) {
		/* Into its parent: refused where an entry of that key is. */
		api_path(path, sizeof(path), n, true);
		rc_ds(url, sizeof(url), "candidate", yf.sid, path);
		(void)ycommit_save(&yf.yc, yf.sid, "POST", url, json);
	} else {
		api_path(path, sizeof(path), n, false);
		rc_ds(url, sizeof(url), "candidate", yf.sid, path);
		(void)ycommit_save(&yf.yc, yf.sid, "PUT", url, json);
	}
	free(json);
}

/* ---- Opened ---------------------------------------------------------------- */

static void
read_cb(int status, const ucl_object_t *o, const char *err, void *arg)
{
	const ucl_object_t	*v = NULL, *x;
	ucl_object_iter_t	 it = NULL;
	ucl_object_t		*t;

	(void)arg;
	yf.reading = false;
	if (status == 200 && o != NULL) {
		/* The one member, an entry's array of one. */
		while ((x = ucl_object_iterate(o, &it, true)) != NULL)
			v = x;
		if (v != NULL && ucl_object_type(v) == UCL_ARRAY)
			v = ucl_array_find_index(v, 0);
	}
	if (v == NULL && status != 404) {
		snprintf(yf.error, sizeof(yf.error), "Not read: %s", rc_why(o,
		    err));
		render();
		return;
	}
	if (v != NULL) {
		t = as_text(v);
		if (yf.val != NULL)
			ucl_object_unref(yf.val);
		yf.val = t;
		yf.orig = ucl_object_ref(t);
	}
	render();
}

/* The form of node path of module, for host sid: a new entry (key
 * NULL) or the one of key; a container's (key ""). */
void
yform_open(const char *sid, const char *module, const char *path,
    const char *key)
{
	char	url[YF_PATH + 200], ap[YF_PATH];

	form_drop();
	memset(&yf.yc, 0, sizeof(yf.yc));
	snprintf(yf.sid, sizeof(yf.sid), "%s", sid);
	snprintf(yf.module, sizeof(yf.module), "%s", module);
	snprintf(yf.path, sizeof(yf.path), "%s", path);
	snprintf(yf.key, sizeof(yf.key), "%s", key != NULL ? key : "");
	yf.isnew = key == NULL;
	yf.error[0] = '\0';
	yf.val = ucl_object_typed_new(UCL_OBJECT);
	yf.sel = ucl_object_typed_new(UCL_OBJECT);
	yf.reading = false;
	app.modal_error[0] = '\0';
	app.modal = MODAL_YFORM;
	(void)lib_of(sid);
	if (key != NULL) {
		/* Read from running: its configuration alone. */
		snprintf(ap, sizeof(ap), "%s", path + (path[0] == '/'));
		if (key[0] != '\0')
			snprintf(ap + strlen(ap), sizeof(ap) - strlen(ap),
			    "=%s", rc_key(key));
		rc_ds(url, sizeof(url), "running", sid, ap);
		(void)strlcat(url, "?content=config", sizeof(url));
		yf.reading = true;
		api("GET", url, NULL, read_cb, NULL);
	}
	render();
}

/* ---- System's Models -------------------------------------------------------- */

static void
mv_cb(int status, const ucl_object_t *o, const char *err, void *arg)
{
	const ucl_object_t	*v;
	ucl_object_iter_t	 it = NULL;

	/* A reply of a module shown before. */
	if ((unsigned)(uintptr_t)arg != yf.mv_gen)
		return;
	if (yf.mv_pending > 0)
		yf.mv_pending--;
	if (status == 200 && o != NULL && yf.mv_data != NULL) {
		while ((v = ucl_object_iterate(o, &it, true)) != NULL)
			ucl_object_replace_key(yf.mv_data, as_text(v),
			    ucl_object_key(v), 0, true);
	} else if (status != 404)
		snprintf(yf.mv_why, sizeof(yf.mv_why), "%s", rc_why(o, err));
	render();
}

/* A module's configuration from running: each of its top containers
 * and lists, read at once into one. */
static void
mv_read(const char *sid, const ucl_object_t *doc)
{
	const ucl_object_t	*n;
	ucl_object_iter_t	 it = NULL;
	char			 url[400], ap[200];

	if (yf.mv_data != NULL || yf.mv_why[0] != '\0')
		return;
	yf.mv_data = ucl_object_typed_new(UCL_OBJECT);
	yf.mv_gen++;
	while ((n = ucl_object_iterate(jget(doc, "nodes"), &it, true)) !=
	    NULL) {
		if ((!is(n, "kind", "container") && !is(n, "kind", "list")) ||
		    !editable(n))
			continue;
		snprintf(ap, sizeof(ap), "%s:%s", str(n, "module"), str(n,
		    "name"));
		rc_ds(url, sizeof(url), "running", sid, ap);
		(void)strlcat(url, "?content=config", sizeof(url));
		yf.mv_pending++;
		api("GET", url, NULL, mv_cb, (void *)(uintptr_t)yf.mv_gen);
	}
}

/* The entries of list n, at its instance path in what was read. */
static void
mv_list(struct html *h, const ucl_object_t *n, const char *ipath)
{
	struct tcol		 cols[4];
	const ucl_object_t	*arr, *k, **rows, *kn;
	ucl_object_iter_t	 it = NULL;
	char			 id[24], arg[YF_PATH + 100];
	int			 nc = 0;
	size_t			 i;

	arr = yf.mv_data != NULL ? at(yf.mv_data, ipath, false) : NULL;
	h_raw(h, "<div class=\"yf-mlist\"><h4>");
	h_txt(h, str(n, "name"));
	h_raw(h, " <span class=\"dim\">");
	h_txt(h, str(n, "path"));
	h_raw(h, "</span> <button class=\"ghost small\" data-act=\"yf-new\"");
	snprintf(arg, sizeof(arg), "%s|%s", str(n, "module"), str(n, "path"));
	h_attr(h, "data-arg", arg);
	h_raw(h, ">+ New</button></h4>");
	help(h, n);
	while ((k = ucl_object_iterate(jget(n, "keys"), &it, true)) != NULL &&
	    nc < 3) {
		cols[nc].title = ucl_object_tostring(k);
		cols[nc].key = ucl_object_tostring(k);
		cols[nc++].num = false;
	}
	if (nc == 0)
		return;
	/* A table a list: its id from its place among those drawn. */
	snprintf(id, sizeof(id), "yf-%.20s", str(n, "name"));
	h_raw(h, "<table class=\"net\">");
	tbl_head(h, id, cols, nc, 1);
	h_raw(h, "<tbody>");
	rows = tbl_rows(id, arr, cols, nc, app.filter);
	kn = jget(n, "keys");
	for (i = 0; rows[i] != NULL; i++) {
		h_raw(h, "<tr>");
		for (int c = 0; c < nc; c++) {
			h_raw(h, "<td>");
			h_txt(h, str(rows[i], cols[c].key) != NULL ?
			    str(rows[i], cols[c].key) : "");
			h_raw(h, "</td>");
		}
		/* One key to edit by: a list of several is edited from its
		 * parent's form. */
		h_raw(h, "<td>");
		if (count(kn) == 1) {
			h_raw(h, "<button class=\"ghost small\" data-act=\""
			    "yf-edit\"");
			snprintf(arg, sizeof(arg), "%s|%s|%s", str(n, "module"),
			    str(n, "path"), str(rows[i], cols[0].key));
			h_attr(h, "data-arg", arg);
			h_raw(h, ">Edit</button>");
		}
		h_raw(h, "</td></tr>");
	}
	if (i == 0)
		h_fmt(h, "<tr><td colspan=\"%d\" class=\"dim\">None.</td></tr>",
		    nc + 1);
	free(rows);
	h_raw(h, "</tbody></table></div>");
}

/* A module's lists below its containers (no list above), and its
 * containers with leaves of their own. */
static void
mv_nodes(struct html *h, const ucl_object_t *kids, const char *inst,
    const char *pmod, int depth)
{
	const ucl_object_t	*n, *c;
	ucl_object_iter_t	 it = NULL, cit;
	char			 mem[160], ip[YF_PATH], arg[YF_PATH + 100];
	bool			 leaves;

	while ((n = ucl_object_iterate(kids, &it, true)) != NULL) {
		if (!editable(n))
			continue;
		member(mem, sizeof(mem), n, pmod);
		join(ip, sizeof(ip), inst, mem);
		if (is(n, "kind", "list"))
			mv_list(h, n, ip);
		else if (is(n, "kind", "container") && depth < 4) {
			leaves = false;
			cit = NULL;
			while ((c = ucl_object_iterate(jget(n, "children"),
			    &cit, true)) != NULL)
				if (editable(c) && !is(c, "kind", "list") &&
				    !is(c, "kind", "container"))
					leaves = true;
			if (leaves) {
				h_raw(h, "<div class=\"yf-mlist\"><h4>");
				h_txt(h, str(n, "name"));
				h_raw(h, " <span class=\"dim\">");
				h_txt(h, str(n, "path"));
				h_raw(h, "</span> <button class=\"ghost small\" "
				    "data-act=\"yf-edit\"");
				snprintf(arg, sizeof(arg), "%s|%s|", str(n,
				    "module"), str(n, "path"));
				h_attr(h, "data-arg", arg);
				h_raw(h, ">Edit</button></h4>");
				help(h, n);
				h_raw(h, "</div>");
			}
			mv_nodes(h, jget(n, "children"), ip, str(n, "module"),
			    depth + 1);
		}
	}
}

void
view_models(struct html *h, struct server *s)
{
	static const struct tcol cols[] = { { "Module", "name", false },
	    { "Revision", "revision", false }, { "Of", "kind", false } };
	const ucl_object_t	**rows, *doc;
	const char		*rev, *why;
	size_t			 i;

	h_raw(h, "<section class=\"sysview yf-models\"><h3 class=\"secsub\">"
	    "Its YANG modules</h3><p class=\"dim\">The modules the host's "
	    "YANG library (RFC 8525) names; an Arcana module's configuration "
	    "edited by forms drawn from the module itself, saved in the "
	    "host's candidate and committed confirmed.</p>");
	if (lib_of(s->id) == NULL) {
		if (yf.lib_why[0] != '\0') {
			h_raw(h, "<p class=\"err\">");
			h_txt(h, yf.lib_why);
			h_raw(h, "</p>");
		} else
			h_raw(h, "<div class=\"loader\"></div>");
		h_raw(h, "</section>");
		return;
	}
	if (strcmp(yf.mv_sid, s->id) == 0 && yf.mv_module[0] != '\0' &&
	    (rev = lib_rev(yf.mv_module)) != NULL) {
		h_raw(h, "<h4><button class=\"ghost small\" data-act=\""
		    "yf-mod\" data-arg=\"\">← Modules</button> ");
		h_txt(h, yf.mv_module);
		h_raw(h, "@");
		h_txt(h, rev);
		h_raw(h, "</h4>");
		if ((doc = doc_of(yf.mv_module, rev, &why)) == NULL) {
			if (why != NULL) {
				h_raw(h, "<p class=\"err\">");
				h_txt(h, why);
				h_raw(h, "</p>");
			} else
				h_raw(h, "<div class=\"loader\"></div>");
			h_raw(h, "</section>");
			return;
		}
		help(h, doc);
		mv_read(s->id, doc);
		if (yf.mv_pending > 0)
			h_raw(h, "<div class=\"loader\"></div>");
		if (yf.mv_why[0] != '\0') {
			h_raw(h, "<p class=\"err\">Not read: ");
			h_txt(h, yf.mv_why);
			h_raw(h, "</p>");
		}
		mv_nodes(h, jget(doc, "nodes"), "", NULL, 0);
		h_raw(h, "</section>");
		return;
	}
	h_raw(h, "<table class=\"net\">");
	tbl_head(h, "yf-mods", cols, 3, 1);
	h_raw(h, "<tbody>");
	rows = tbl_rows("yf-mods", yf.lib, cols, 3, app.filter);
	for (i = 0; rows[i] != NULL; i++) {
		h_raw(h, "<tr><td>");
		h_txt(h, str(rows[i], "name"));
		h_raw(h, "</td><td>");
		h_txt(h, str(rows[i], "revision"));
		h_raw(h, "</td><td>");
		h_txt(h, str(rows[i], "kind"));
		h_raw(h, "</td><td>");
		if (is(rows[i], "kind", "Arcana")) {
			h_raw(h, "<button class=\"ghost small\" data-act=\""
			    "yf-mod\"");
			h_attr(h, "data-arg", str(rows[i], "name"));
			h_raw(h, ">Open</button>");
		}
		h_raw(h, "</td></tr>");
	}
	if (i == 0)
		h_raw(h, "<tr><td colspan=\"4\" class=\"dim\">None.</td></tr>");
	free(rows);
	h_raw(h, "</tbody></table></section>");
}

/* ---- Actions ----------------------------------------------------------------- */

/* "module|path[|key]": the form's node, and an entry's key. */
static bool
split_arg(const char *arg, char *mod, size_t mlen, char *path, size_t plen,
    char *key, size_t klen, bool *haskey)
{
	const char	*a, *b;

	if ((a = strchr(arg, '|')) == NULL || (size_t)(a - arg) >= mlen)
		return (false);
	snprintf(mod, mlen, "%.*s", (int)(a - arg), arg);
	a++;
	if ((b = strchr(a, '|')) != NULL) {
		snprintf(path, plen, "%.*s", (int)(b - a), a);
		snprintf(key, klen, "%s", b + 1);
		*haskey = true;
	} else {
		snprintf(path, plen, "%s", a);
		key[0] = '\0';
		*haskey = false;
	}
	return (mod[0] != '\0' && path[0] == '/');
}

bool
yform_action(const char *act, const char *arg, const char *value)
{
	struct server	*s;
	char		 mod[64], path[YF_PATH], key[256];
	const char	*name;
	bool		 haskey;
	ucl_object_t	*a, *o;

	if (strncmp(act, "yf-yc-", 6) == 0)
		return (ycommit_action(&yf.yc, act));
	if (strcmp(act, "input:yf") == 0) {
		val_set(arg, value);
		/* Typing draws nothing new, but the field's error gone. */
		if (yf.errs != NULL && ucl_object_lookup(yf.errs, arg) != NULL)
			ucl_object_delete_key(yf.errs, arg);
		else
			app.no_draw = true;
		return (true);
	}
	if (strcmp(act, "input:yf-case") == 0) {
		if (yf.sel == NULL)
			yf.sel = ucl_object_typed_new(UCL_OBJECT);
		ucl_object_replace_key(yf.sel, ucl_object_fromstring(value),
		    arg, 0, true);
		return (true);
	}
	if (strcmp(act, "input:yf-pres") == 0) {
		/* A presence container there, or not. */
		if ((o = holder(arg, &name, strcmp(value, "true") == 0)) ==
		    NULL)
			return (true);
		if (strcmp(value, "true") == 0)
			ucl_object_replace_key(o, ucl_object_typed_new(
			    UCL_OBJECT), name, 0, true);
		else
			ucl_object_delete_key(o, name);
		return (true);
	}
	if (strcmp(act, "yf-add") == 0) {
		if ((a = at(yf.val, arg, false)) == NULL) {
			if ((o = holder(arg, &name, true)) == NULL)
				return (true);
			a = ucl_object_typed_new(UCL_ARRAY);
			ucl_object_insert_key(o, a, name, 0, true);
		}
		if (ucl_object_type(a) == UCL_ARRAY)
			ucl_array_append(a, ucl_object_typed_new(UCL_OBJECT));
		return (true);
	}
	if (strcmp(act, "yf-del") == 0) {
		char parent[YF_PATH], *sl;

		snprintf(parent, sizeof(parent), "%s", arg);
		if ((sl = strrchr(parent, '/')) == NULL || !digits(sl + 1))
			return (true);
		*sl++ = '\0';
		if ((a = at(yf.val, parent, false)) != NULL &&
		    ucl_object_type(a) == UCL_ARRAY) {
			ucl_object_t *x = nth(a, (unsigned)atoi(sl));

			if (x != NULL)
				ucl_object_unref(ucl_array_delete(a, x));
		}
		/* The errors were of the fields' places. */
		if (yf.errs != NULL)
			ucl_object_unref(yf.errs);
		yf.errs = NULL;
		return (true);
	}
	if (strcmp(act, "yf-new") == 0 || strcmp(act, "yf-edit") == 0) {
		if ((s = cur_server()) == NULL || !split_arg(arg, mod,
		    sizeof(mod), path, sizeof(path), key, sizeof(key), &haskey))
			return (true);
		yform_open(s->id, mod, path, strcmp(act, "yf-new") == 0 ? NULL :
		    key);
		return (true);
	}
	if (strcmp(act, "yf-mod") == 0) {
		if ((s = cur_server()) == NULL)
			return (true);
		snprintf(yf.mv_sid, sizeof(yf.mv_sid), "%s", s->id);
		snprintf(yf.mv_module, sizeof(yf.mv_module), "%s", arg);
		if (yf.mv_data != NULL)
			ucl_object_unref(yf.mv_data);
		yf.mv_data = NULL;
		yf.mv_why[0] = '\0';
		yf.mv_pending = 0;
		return (true);
	}
	return (false);
}

/* The form sent: its fields' values taken as they are now, then saved. */
bool
yform_form(const char *form, const ucl_object_t *f)
{
	const ucl_object_t	*v;
	ucl_object_iter_t	 it = NULL;
	const char		*k;

	if (strcmp(form, "ymf") != 0)
		return (false);
	while ((v = ucl_object_iterate(f, &it, true)) != NULL) {
		k = ucl_object_key(v);
		if (k == NULL || strncmp(k, "__", 2) == 0)
			continue;
		if (k[0] == '?') {
			if (yf.sel == NULL)
				yf.sel = ucl_object_typed_new(UCL_OBJECT);
			ucl_object_replace_key(yf.sel, ucl_object_fromstring(
			    ucl_object_tostring_forced(v)), k + 1, 0, true);
		} else if (ucl_object_type(v) == UCL_BOOLEAN)
			val_set(k, ucl_object_toboolean(v) ? "true" : "false");
		else
			val_set(k, ucl_object_tostring_forced(v));
	}
	submit();
	return (true);
}

void
yform_tick(double now)
{

	if (app.modal == MODAL_YFORM)
		ycommit_tick(&yf.yc, now);
}
