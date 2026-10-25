/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Configuration templates: a host's setup kept by the console under a
 * name, for other hosts to be made the same.  A template is a host's
 * bundle (config-export's: the files Arcana manages, the packages put
 * there by hand, the hardware it needs) whose text has {{name}} where
 * each host has a value of its own, its hostname above all:
 *
 *	{"description": "an edge router",
 *	 "files": [{"path": "/etc/rc.conf", "mode": "0644",
 *	            "owner": "root", "group": "wheel",
 *	            "text": "hostname=\"{{hostname}}\"\n..."}],
 *	 "packages": [{"name": "bird3", "origin": "net/bird3"}],
 *	 "facts": {"arch": "amd64", "interfaces": [{"name": "vtnet0"}]},
 *	 "variables": {"hostname": {"description": "...", "default": ""}}}
 *
 * {{ }} and not ${ }, which rc.conf, jail.conf and the shell use for
 * their own.  A template carries no secrets: a key is the host's own.
 *
 * Applied (POST /api/servers/<id>/config with template and values),
 * each placeholder is given its value, or its default, and the result
 * goes to the host as config-apply's bundle: checked first (what each
 * file would become, what the hardware lacks), and only then written,
 * as a bundle is.  One without a value refuses the whole.
 *
 * GET /api/templates lists them, GET, PUT and DELETE
 * /api/templates/<name> read, keep and forget one.  Kept in
 * templates.json, under flock(2): workers change it one at a time.
 */

#include <sys/param.h>
#include <sys/file.h>

#include <ctype.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#include "console.h"

#define	TEMPLATES_FILE	"templates.json"
#define	TEMPLATES_LOCK	"templates.lock"
#define	TEMPLATES_MAX	200
#define	FILES_MAX	512		/* as the agent's bundle */
#define	TEXT_MAX	(1024 * 1024)	/* a file's */
#define	VARS_MAX	64

/* key's value v, in place of one it had. */
static void
put(ucl_object_t *o, const char *key, ucl_object_t *v)
{

	ucl_object_replace_key(o, v, key, 0, true);
}

static const char *
str(const ucl_object_t *o, const char *key)
{
	const ucl_object_t	*v;

	return ((v = ucl_object_lookup(o, key)) != NULL &&
	    ucl_object_type(v) == UCL_STRING ? ucl_object_tostring(v) : NULL);
}

/* How many keys an object has. */
static size_t
obj_len(const ucl_object_t *o)
{
	ucl_object_iter_t	it = NULL;
	size_t			n = 0;

	while (ucl_object_iterate(o, &it, true) != NULL)
		n++;
	return (n);
}

/* A template's name: letters, digits, . _ -, 64 at most. */
bool
template_name_ok(const char *s)
{
	size_t	n;

	if (s == NULL || (n = strlen(s)) == 0 || n > 64 || s[0] == '.')
		return (false);
	return (strspn(s, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	    "0123456789._-") == n);
}

/* A placeholder's name: a letter or _, then letters, digits and _. */
static bool
var_ok(const char *s, size_t n)
{
	size_t	i;

	if (n == 0 || n > 32 || !(isalpha((unsigned char)s[0]) || s[0] == '_'))
		return (false);
	for (i = 1; i < n; i++)
		if (!isalnum((unsigned char)s[i]) && s[i] != '_')
			return (false);
	return (true);
}

/* The placeholders of text into set, each once ({{name}}). */
static void
vars_of(const char *text, ucl_object_t *set)
{
	const char	*p, *e;
	char		 name[40];

	for (p = text; p != NULL && (p = strstr(p, "{{")) != NULL; p = e + 2) {
		if ((e = strstr(p + 2, "}}")) == NULL)
			break;
		if (!var_ok(p + 2, (size_t)(e - p - 2)))
			continue;
		snprintf(name, sizeof(name), "%.*s", (int)(e - p - 2), p + 2);
		if (ucl_object_lookup(set, name) == NULL)
			put(set, name, ucl_object_frombool(true));
	}
}

/*
 * text with each {{name}} its value (values', else the variable's
 * default).  NULL, and the first without one in missing, when one has
 * none.  malloc(3)ed.
 */
static char *
render(const char *text, const ucl_object_t *values,
    const ucl_object_t *variables, char *missing, size_t mlen)
{
	struct buf	*b;
	const char	*p, *q, *e, *v;
	char		 name[40], *out;

	b = buf_alloc(strlen(text) + 64);
	for (p = text; (q = strstr(p, "{{")) != NULL; ) {
		if ((e = strstr(q + 2, "}}")) == NULL ||
		    !var_ok(q + 2, (size_t)(e - q - 2))) {
			/* Not a placeholder: as it is. */
			buf_append(b, p, (size_t)(q + 2 - p));
			p = q + 2;
			continue;
		}
		snprintf(name, sizeof(name), "%.*s", (int)(e - q - 2), q + 2);
		if ((v = str(values, name)) == NULL)
			v = str(ucl_object_lookup(variables, name), "default");
		if (v == NULL || v[0] == '\0') {
			snprintf(missing, mlen, "%s", name);
			buf_free(b);
			return (NULL);
		}
		buf_append(b, p, (size_t)(q - p));
		buf_append(b, v, strlen(v));
		p = e + 2;
	}
	buf_append(b, p, strlen(p));
	if ((out = malloc(b->offset + 1)) == NULL) {
		buf_free(b);
		return (NULL);
	}
	memcpy(out, b->data, b->offset);
	out[b->offset] = '\0';
	buf_free(b);
	return (out);
}

/* The lock all workers take to change the file; -1 when not had. */
static int
lock_take(void)
{
	char	path[MAXPATHLEN];
	int	fd;

	snprintf(path, sizeof(path), "%s/%s", cfg.datadir, TEMPLATES_LOCK);
	if ((fd = open(path, O_RDWR | O_CREAT | O_CLOEXEC, 0600)) == -1)
		return (-1);
	(void)flock(fd, LOCK_EX);
	/* And of the cluster's other nodes, when it is one. */
	(void)cluster_lock(TEMPLATES_LOCK);
	return (fd);
}

static void
lock_give(int fd)
{

	if (fd != -1) {
		cluster_unlock(TEMPLATES_LOCK);
		close(fd);
	}
}

/* {"templates": {name: template}}, an empty one when there is none. */
static ucl_object_t *
all_load(void)
{
	ucl_object_t	*o;

	if ((o = store_load(TEMPLATES_FILE)) == NULL ||
	    ucl_object_type(o) != UCL_OBJECT) {
		if (o != NULL)
			ucl_object_unref(o);
		o = ucl_object_typed_new(UCL_OBJECT);
	}
	if (ucl_object_lookup(o, "templates") == NULL)
		put(o, "templates", ucl_object_typed_new(UCL_OBJECT));
	return (o);
}

/* A template, a copy; NULL when there is none of that name. */
ucl_object_t *
template_get(const char *name)
{
	ucl_object_t		*all, *t;
	const ucl_object_t	*v;

	all = all_load();
	v = ucl_object_lookup(ucl_object_lookup(all, "templates"), name);
	t = v != NULL ? ucl_object_copy(v) : NULL;
	ucl_object_unref(all);
	return (t);
}

/*
 * Is t a template that may be kept?  NULL, or what is wrong with it.
 * Its files each a path (absolute, no ..), a mode, an owner and a group
 * and its text, no secret; the agent checks again, against the paths a
 * bundle may carry, when it is applied.
 */
static const char *
check(const ucl_object_t *t, char *why, size_t wlen)
{
	const ucl_object_t	*f, *v, *vars;
	ucl_object_iter_t	 it;
	const char		*path, *mode;
	size_t			 n;

	if (t == NULL || ucl_object_type(t) != UCL_OBJECT)
		return ("a template is a JSON object");
	if ((v = ucl_object_lookup(t, "description")) != NULL &&
	    (ucl_object_type(v) != UCL_STRING || strlen(ucl_object_tostring(
	    v)) > 512))
		return ("its description is a line of text, 512 at most");
	if ((v = ucl_object_lookup(t, "files")) == NULL ||
	    ucl_object_type(v) != UCL_ARRAY || ucl_array_size(v) == 0 ||
	    ucl_array_size(v) > FILES_MAX)
		return ("its files are a list, 1 to 256 of them");
	n = 0;
	it = NULL;
	while ((f = ucl_object_iterate(v, &it, true)) != NULL) {
		n++;
		path = str(f, "path");
		mode = str(f, "mode");
		if (path == NULL || path[0] != '/' || strstr(path, "/../") !=
		    NULL || strlen(path) > 255) {
			snprintf(why, wlen, "file %zu: its path is absolute, "
			    "without ..", n);
			return (why);
		}
		if (ucl_object_toboolean(ucl_object_lookup(f, "secret"))) {
			snprintf(why, wlen, "%s: a template carries no secrets: "
			    "a host's key is its own", path);
			return (why);
		}
		if (mode == NULL || strlen(mode) < 3 || strlen(mode) > 4 ||
		    strspn(mode, "01234567") != strlen(mode) || str(f,
		    "owner") == NULL || str(f, "group") == NULL) {
			snprintf(why, wlen, "%s: its mode (octal), owner and "
			    "group", path);
			return (why);
		}
		if (str(f, "text") == NULL || strlen(str(f, "text")) >
		    TEXT_MAX) {
			snprintf(why, wlen, "%s: its text, 1 MB at most", path);
			return (why);
		}
	}
	if ((v = ucl_object_lookup(t, "packages")) != NULL) {
		if (ucl_object_type(v) != UCL_ARRAY)
			return ("its packages are a list, each with its name, as "
			    "config-export's");
		it = NULL;
		while ((f = ucl_object_iterate(v, &it, true)) != NULL)
			if (ucl_object_type(f) != UCL_OBJECT || str(f, "name") ==
			    NULL)
				return ("its packages are a list, each with its "
				    "name, as config-export's");
	}
	if ((v = ucl_object_lookup(t, "facts")) != NULL &&
	    ucl_object_type(v) != UCL_OBJECT)
		return ("its facts are an object, as config-export's");
	if ((vars = ucl_object_lookup(t, "variables")) != NULL) {
		if (ucl_object_type(vars) != UCL_OBJECT || obj_len(
		    vars) > VARS_MAX)
			return ("its variables are an object, 64 at most");
		it = NULL;
		while ((f = ucl_object_iterate(vars, &it, true)) != NULL)
			if (!var_ok(ucl_object_key(f), strlen(ucl_object_key(f)))
			    || ucl_object_type(f) != UCL_OBJECT) {
				snprintf(why, wlen, "variable %s: named as a "
				    "placeholder is ({{name}}), an object of its "
				    "description and default", ucl_object_key(f));
				return (why);
			}
	}
	return (NULL);
}

/* The placeholders its files have, beside the variables it says. */
static ucl_object_t *
placeholders(const ucl_object_t *t)
{
	const ucl_object_t	*f;
	ucl_object_iter_t	 it;
	ucl_object_t		*set, *arr;

	set = ucl_object_typed_new(UCL_OBJECT);
	it = NULL;
	while ((f = ucl_object_iterate(ucl_object_lookup(t, "files"), &it,
	    true)) != NULL)
		vars_of(str(f, "text"), set);
	arr = ucl_object_typed_new(UCL_ARRAY);
	it = NULL;
	while ((f = ucl_object_iterate(set, &it, true)) != NULL)
		ucl_array_append(arr, ucl_object_fromstring(ucl_object_key(f)));
	ucl_object_unref(set);
	return (arr);
}

/*
 * The template name made a host's bundle with values: config-apply's,
 * JSON, malloc(3)ed; NULL and why when there is no such template or a
 * placeholder has no value.
 */
char *
template_render(const char *name, const ucl_object_t *values, char *why,
    size_t wlen)
{
	ucl_object_t		*t, *b, *files, *nf;
	const ucl_object_t	*f, *vars, *v;
	ucl_object_iter_t	 it;
	unsigned char		*json;
	char			 missing[40], *text;

	if ((t = template_get(name)) == NULL) {
		snprintf(why, wlen, "no template %s", name);
		return (NULL);
	}
	vars = ucl_object_lookup(t, "variables");
	b = ucl_object_typed_new(UCL_OBJECT);
	put(b, "arcana", ucl_object_fromstring("host"));
	put(b, "format", ucl_object_fromint(1));
	files = ucl_object_typed_new(UCL_ARRAY);
	it = NULL;
	while ((f = ucl_object_iterate(ucl_object_lookup(t, "files"), &it,
	    true)) != NULL) {
		if ((text = render(str(f, "text"), values, vars, missing,
		    sizeof(missing))) == NULL) {
			snprintf(why, wlen, "%s: {{%s}} has no value", str(f,
			    "path"), missing);
			ucl_object_unref(files);
			ucl_object_unref(b);
			ucl_object_unref(t);
			return (NULL);
		}
		nf = ucl_object_copy(f);
		put(nf, "text", ucl_object_fromstring(text));
		free(text);
		ucl_array_append(files, nf);
	}
	put(b, "files", files);
	if ((v = ucl_object_lookup(t, "packages")) != NULL)
		put(b, "packages", ucl_object_copy(v));
	if ((v = ucl_object_lookup(t, "facts")) != NULL)
		put(b, "facts", ucl_object_copy(v));
	json = ucl_object_emit(b, UCL_EMIT_JSON_COMPACT);
	ucl_object_unref(b);
	ucl_object_unref(t);
	return ((char *)json);
}

/* GET /api/templates: each, briefly. */
int
api_templates(struct http_request *req)
{
	ucl_object_t		*all, *arr, *e, *top;
	const ucl_object_t	*t;
	ucl_object_iter_t	 it;

	if (!guard(req, false))
		return (WEB_OK);
	all = all_load();
	arr = ucl_object_typed_new(UCL_ARRAY);
	it = NULL;
	while ((t = ucl_object_iterate(ucl_object_lookup(all, "templates"),
	    &it, true)) != NULL) {
		e = ucl_object_typed_new(UCL_OBJECT);
		put(e, "name", ucl_object_fromstring(ucl_object_key(t)));
		put(e, "description", ucl_object_fromstring(str(t,
		    "description") != NULL ? str(t, "description") : ""));
		put(e, "files", ucl_object_fromint((int64_t)ucl_array_size(
		    ucl_object_lookup(t, "files"))));
		put(e, "packages", ucl_object_fromint((int64_t)ucl_array_size(
		    ucl_object_lookup(t, "packages"))));
		put(e, "placeholders", placeholders(t));
		if (str(t, "from") != NULL)
			put(e, "from", ucl_object_fromstring(str(t, "from")));
		put(e, "updated", ucl_object_fromint(ucl_object_toint(
		    ucl_object_lookup(t, "updated"))));
		ucl_array_append(arr, e);
	}
	ucl_object_unref(all);
	top = ucl_object_typed_new(UCL_OBJECT);
	put(top, "templates", arr);
	return (reply_json(req, 200, top));
}

/* GET, PUT, DELETE /api/templates/<name>. */
int
api_template(struct http_request *req)
{
	ucl_object_t		*all, *t, *body, *top;
	ucl_object_t		*tmpls;
	const char		*name, *e;
	char			 why[300];
	int			 fd, rc;

	name = req->path + strlen("/api/templates/");
	if (!template_name_ok(name))
		return (reply_error(req, 400, "invalid", "a template is named "
		    "with letters, digits, . _ and -"));
	switch (req->method) {
	case HTTP_METHOD_GET:
		if (!guard(req, false))
			return (WEB_OK);
		if ((t = template_get(name)) == NULL)
			return (reply_error(req, 404, "not_found", "no template "
			    "%s", name));
		put(t, "name", ucl_object_fromstring(name));
		put(t, "placeholders", placeholders(t));
		return (reply_json(req, 200, t));
	case HTTP_METHOD_PUT:
		if (!guard(req, true))
			return (WEB_OK);
		if ((body = read_json(req)) == NULL)
			return (reply_error(req, 400, "invalid", "a template, "
			    "a JSON object"));
		if ((e = check(body, why, sizeof(why))) != NULL) {
			ucl_object_unref(body);
			return (reply_error(req, 400, "invalid", "%s", e));
		}
		/* What the server says of it, not the body. */
		(void)ucl_object_delete_key(body, "name");
		(void)ucl_object_delete_key(body, "placeholders");
		put(body, "updated", ucl_object_fromint(time(NULL)));
		fd = lock_take();
		all = all_load();
		tmpls = (ucl_object_t *)(uintptr_t)ucl_object_lookup(all,
		    "templates");
		if (ucl_object_lookup(tmpls, name) == NULL &&
		    obj_len(tmpls) >= TEMPLATES_MAX) {
			ucl_object_unref(all);
			ucl_object_unref(body);
			lock_give(fd);
			return (reply_error(req, 400, "invalid", "%d templates "
			    "at most", TEMPLATES_MAX));
		}
		(void)ucl_object_delete_key(tmpls, name);
		ucl_object_insert_key(tmpls, body, name, 0, true);
		rc = store_save(TEMPLATES_FILE, all);
		ucl_object_unref(all);
		lock_give(fd);
		if (rc != 0)
			return (reply_error(req, 500, "store", "the template "
			    "was not kept"));
		log_msg(LOG_NOTICE, "template %s kept by %s", name,
		    session_who(req) != NULL ? session_who(req) : "?");
		top = ucl_object_typed_new(UCL_OBJECT);
		put(top, "ok", ucl_object_frombool(true));
		return (reply_json(req, 200, top));
	case HTTP_METHOD_DELETE:
		if (!guard(req, true))
			return (WEB_OK);
		fd = lock_take();
		all = all_load();
		tmpls = (ucl_object_t *)(uintptr_t)ucl_object_lookup(all,
		    "templates");
		if (ucl_object_lookup(tmpls, name) == NULL) {
			ucl_object_unref(all);
			lock_give(fd);
			return (reply_error(req, 404, "not_found", "no template "
			    "%s", name));
		}
		(void)ucl_object_delete_key(tmpls, name);
		rc = store_save(TEMPLATES_FILE, all);
		ucl_object_unref(all);
		lock_give(fd);
		if (rc != 0)
			return (reply_error(req, 500, "store", "not forgotten"));
		log_msg(LOG_NOTICE, "template %s forgotten by %s", name,
		    session_who(req) != NULL ? session_who(req) : "?");
		top = ucl_object_typed_new(UCL_OBJECT);
		put(top, "ok", ucl_object_frombool(true));
		return (reply_json(req, 200, top));
	default:
		return (reply_error(req, 405, "method", "GET, PUT or DELETE"));
	}
}
