/*-
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Prefix lists of the console's: a named list of IPv4 and IPv6
 * prefixes, kept once and used on any host, where the pages take
 * prefixes: an ipfw table filled from one, a BIRD set (define) made of
 * one, an SD-WAN zone's or list's prefixes.  prefix-lists.json in the
 * data directory, {"lists": {name: {"description", "prefixes": [...]}}},
 * under prefix-lists.lock while it is changed.  GET /api/prefix-lists
 * gives them all; PUT /api/prefix-lists/<name> keeps one, DELETE takes
 * it away.  The same as arcana-console's prefix-lists (cyang.c),
 * through pfx_apply().
 */

#include <sys/param.h>
#include <sys/file.h>
#include <sys/socket.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <ctype.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include "console.h"

#define	PFX_FILE	"prefix-lists.json"
#define	PFX_LOCK	"prefix-lists.lock"
#define	PFX_LISTS_MAX	512
#define	PFX_MAX		8192		/* prefixes in one list */
#define	PFX_DESCR_MAX	200

static void
put(ucl_object_t *o, const char *key, ucl_object_t *v)
{

	ucl_object_replace_key(o, v, key, 0, true);
}

static size_t
obj_len(const ucl_object_t *o)
{
	const ucl_object_t	*e;
	ucl_object_iter_t	 it = NULL;
	size_t			 n = 0;

	while ((e = ucl_object_iterate(o, &it, true)) != NULL)
		n++;
	return (n);
}

static int
lock_take(void)
{
	char	path[MAXPATHLEN];
	int	fd;

	snprintf(path, sizeof(path), "%s/%s", cfg.datadir, PFX_LOCK);
	if ((fd = open(path, O_RDWR | O_CREAT | O_CLOEXEC, 0600)) == -1)
		return (-1);
	(void)flock(fd, LOCK_EX);
	/* And of the cluster's other nodes, when it is one. */
	(void)cluster_lock(PFX_LOCK);
	return (fd);
}

static void
lock_give(int fd)
{

	if (fd != -1) {
		cluster_unlock(PFX_LOCK);
		close(fd);
	}
}

static ucl_object_t *
all_load(void)
{
	ucl_object_t	*o;

	if ((o = store_load(PFX_FILE)) == NULL || ucl_object_type(o) !=
	    UCL_OBJECT) {
		if (o != NULL)
			ucl_object_unref(o);
		o = ucl_object_typed_new(UCL_OBJECT);
	}
	if (ucl_object_lookup(o, "lists") == NULL)
		put(o, "lists", ucl_object_typed_new(UCL_OBJECT));
	return (o);
}

/* A list's name: letters, digits, _ and -, 32 at most. */
static bool
name_ok(const char *s)
{
	size_t	n;

	n = strlen(s);
	return (n > 0 && n <= 32 && strspn(s, "abcdefghijklmnopqrstuvwxyz"
	    "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-") == n);
}

/* a.b.c.d/n or x::y/n, with no host bits set. */
static bool
prefix_ok(const char *s)
{
	char		 buf[64], *slash, *end;
	unsigned char	 a[16];
	long		 len;
	int		 af, bits, i;

	if (strlen(s) >= sizeof(buf))
		return (false);
	snprintf(buf, sizeof(buf), "%s", s);
	if ((slash = strchr(buf, '/')) == NULL)
		return (false);
	*slash = '\0';
	len = strtol(slash + 1, &end, 10);
	if (end == slash + 1 || *end != '\0' || len < 0)
		return (false);
	if (inet_pton(AF_INET, buf, a) == 1) {
		af = AF_INET;
		bits = 32;
	} else if (inet_pton(AF_INET6, buf, a) == 1) {
		af = AF_INET6;
		bits = 128;
	} else
		return (false);
	(void)af;
	if (len > bits)
		return (false);
	for (i = (int)len; i < bits; i++)
		if (a[i / 8] & (0x80 >> (i % 8)))
			return (false);
	return (true);
}

/* Is l a list that may be kept?  NULL, or what is wrong with it. */
static const char *
check(const ucl_object_t *l)
{
	const ucl_object_t	*v, *e;
	ucl_object_iter_t	 it;
	const char		*s;
	size_t			 n;

	if (ucl_object_type(l) != UCL_OBJECT)
		return ("a list is an object");
	if ((s = ucl_str(l, "description")) != NULL) {
		if (strlen(s) > PFX_DESCR_MAX)
			return ("a description is 200 characters at most");
		for (; *s != '\0'; s++)
			if ((unsigned char)*s < 0x20 || *s == 0x7f)
				return ("a description has no control characters");
	}
	v = ucl_object_lookup(l, "prefixes");
	if (v == NULL || ucl_object_type(v) != UCL_ARRAY)
		return ("prefixes is a list");
	if ((n = ucl_array_size(v)) > PFX_MAX)
		return ("a list holds 8192 prefixes at most");
	it = NULL;
	while ((e = ucl_object_iterate(v, &it, true)) != NULL)
		if (ucl_object_type(e) != UCL_STRING || !prefix_ok(
		    ucl_object_tostring(e)))
			return ("a prefix is a.b.c.d/n or x::/n, with no host "
			    "bits");
	return (NULL);
}

/* The prefixes of the list named, a copy, or NULL. */
ucl_object_t *
prefix_list_get(const char *name)
{
	ucl_object_t		*all, *out;
	const ucl_object_t	*l;

	all = all_load();
	l = ucl_object_lookup(ucl_object_lookup(all, "lists"), name);
	out = l != NULL && ucl_object_lookup(l, "prefixes") != NULL ?
	    ucl_object_copy(ucl_object_lookup(l, "prefixes")) : NULL;
	ucl_object_unref(all);
	return (out);
}

/* GET /api/prefix-lists. */
int
api_prefix_lists(struct http_request *req)
{

	if (req->method != HTTP_METHOD_GET)
		return (reply_error(req, 405, "method", "GET"));
	if (!guard(req, false))
		return (WEB_OK);
	return (reply_json(req, 200, all_load()));
}

/*
 * The lists changed as set says, {name: list, or null to take it away},
 * each checked before any is kept; the lists then into *allp when asked.
 * 0, or the HTTP status and why.
 */
static int
pfx_apply(const ucl_object_t *set, ucl_object_t **allp, char *why,
    size_t len)
{
	ucl_object_t		*all, *lists, *l;
	const ucl_object_t	*v;
	ucl_object_iter_t	 it;
	const char		*e;
	int			 fd, rc;

	it = NULL;
	while ((v = ucl_object_iterate(set, &it, true)) != NULL) {
		if (!name_ok(ucl_object_key(v))) {
			snprintf(why, len, "a list is named by letters, digits, "
			    "_ and -, 32 at most");
			return (400);
		}
		if (ucl_object_type(v) != UCL_NULL && (e = check(v)) != NULL) {
			snprintf(why, len, "%s", e);
			return (400);
		}
	}
	fd = lock_take();
	all = all_load();
	lists = (ucl_object_t *)(uintptr_t)ucl_object_lookup(all, "lists");
	it = NULL;
	while ((v = ucl_object_iterate(set, &it, true)) != NULL) {
		if (ucl_object_type(v) == UCL_NULL) {
			(void)ucl_object_delete_key(lists, ucl_object_key(v));
			continue;
		}
		if (ucl_object_lookup(lists, ucl_object_key(v)) == NULL &&
		    obj_len(lists) >= PFX_LISTS_MAX) {
			lock_give(fd);
			ucl_object_unref(all);
			snprintf(why, len, "%d lists at most", PFX_LISTS_MAX);
			return (400);
		}
		l = ucl_object_typed_new(UCL_OBJECT);
		if (ucl_str(v, "description") != NULL)
			put(l, "description", ucl_object_fromstring(ucl_str(v,
			    "description")));
		put(l, "prefixes", ucl_object_copy(ucl_object_lookup(v,
		    "prefixes")));
		put(lists, ucl_object_key(v), l);
	}
	rc = store_save(PFX_FILE, all);
	lock_give(fd);
	if (rc != 0) {
		ucl_object_unref(all);
		snprintf(why, len, "the prefix lists could not be written");
		return (500);
	}
	it = NULL;
	while ((v = ucl_object_iterate(set, &it, true)) != NULL)
		log_msg(LOG_NOTICE, "prefix list %s %s", ucl_object_key(v),
		    ucl_object_type(v) != UCL_NULL ? "kept" : "taken away");
	cyang_changed("prefix-lists");
	if (allp != NULL)
		*allp = all;
	else
		ucl_object_unref(all);
	return (0);
}

/* PUT or DELETE /api/prefix-lists/<name>. */
int
api_prefix_list(struct http_request *req)
{
	ucl_object_t	*body, *all, *set;
	const char	*name;
	char		 why[128];
	int		 rc;

	name = req->path + strlen("/api/prefix-lists/");
	if (!name_ok(name))
		return (reply_error(req, 400, "invalid", "a list is named by "
		    "letters, digits, _ and -, 32 at most"));
	if (req->method != HTTP_METHOD_PUT && req->method != HTTP_METHOD_DELETE)
		return (reply_error(req, 405, "method", "PUT or DELETE"));
	if (!guard(req, true))
		return (WEB_OK);
	body = NULL;
	if (req->method == HTTP_METHOD_PUT && (body = read_json(req)) == NULL)
		return (reply_error(req, 400, "invalid", "a list, as "
		    "{\"description\", \"prefixes\": [...]}"));
	set = ucl_object_typed_new(UCL_OBJECT);
	put(set, name, body != NULL ? body : ucl_object_typed_new(UCL_NULL));
	rc = pfx_apply(set, &all, why, sizeof(why));
	ucl_object_unref(set);
	if (rc != 0)
		return (reply_error(req, rc, rc == 400 ? "invalid" : "store",
		    "%s", why));
	return (reply_json(req, 200, all));
}

/* ---- arcana-console's prefix lists (cyang.c) ------------------------- */

/* arcana-console:prefix-lists's value. */
ucl_object_t *
pfxlists_yang(void)
{
	ucl_object_t		*all, *arr, *e, *o;
	const ucl_object_t	*l, *p;
	ucl_object_iter_t	 it;

	all = all_load();
	arr = ucl_object_typed_new(UCL_ARRAY);
	it = NULL;
	while ((l = ucl_object_iterate(ucl_object_lookup(all, "lists"), &it,
	    true)) != NULL) {
		e = ucl_object_typed_new(UCL_OBJECT);
		put(e, "name", ucl_object_fromstring(ucl_object_key(l)));
		if (ucl_str(l, "description") != NULL)
			put(e, "description", ucl_object_fromstring(ucl_str(l,
			    "description")));
		if ((p = ucl_object_lookup(l, "prefixes")) != NULL &&
		    ucl_array_size(p) > 0)
			put(e, "prefix", ucl_object_copy(p));
		ucl_array_append(arr, e);
	}
	ucl_object_unref(all);
	o = ucl_object_typed_new(UCL_OBJECT);
	put(o, "prefix-list", arr);
	return (o);
}

/*
 * The lists changed from was to now, kept by pfx_apply() at once: 0, or
 * the HTTP status and why.
 */
int
pfxlists_yang_set(const ucl_object_t *was, const ucl_object_t *now,
    char *why, size_t len)
{
	ucl_object_t		*set, *l;
	const ucl_object_t	*e, *o, *p;
	ucl_object_iter_t	 it;
	int			 rc;

	set = ucl_object_typed_new(UCL_OBJECT);
	it = NULL;
	while ((e = ucl_object_iterate(ucl_object_lookup(now, "prefix-list"),
	    &it, true)) != NULL) {
		o = cyang_entry(ucl_object_lookup(was, "prefix-list"), "name",
		    ucl_str(e, "name"));
		if (o != NULL && cyang_same(o, e))
			continue;
		l = ucl_object_typed_new(UCL_OBJECT);
		if (ucl_str(e, "description") != NULL)
			put(l, "description", ucl_object_fromstring(ucl_str(e,
			    "description")));
		put(l, "prefixes", (p = ucl_object_lookup(e, "prefix")) !=
		    NULL ? ucl_object_copy(p) : ucl_object_typed_new(
		    UCL_ARRAY));
		put(set, ucl_str(e, "name"), l);
	}
	it = NULL;
	while ((o = ucl_object_iterate(ucl_object_lookup(was, "prefix-list"),
	    &it, true)) != NULL)
		if (cyang_entry(ucl_object_lookup(now, "prefix-list"), "name",
		    ucl_str(o, "name")) == NULL)
			put(set, ucl_str(o, "name"), ucl_object_typed_new(
			    UCL_NULL));
	rc = set->len > 0 ? pfx_apply(set, NULL, why, len) : 0;
	ucl_object_unref(set);
	return (rc);
}
