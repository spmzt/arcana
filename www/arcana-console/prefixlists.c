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
 * it away.
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

/* PUT or DELETE /api/prefix-lists/<name>. */
int
api_prefix_list(struct http_request *req)
{
	ucl_object_t	*body, *all, *lists, *l;
	const char	*name, *e;
	int		 fd, rc;

	name = req->path + strlen("/api/prefix-lists/");
	if (!name_ok(name))
		return (reply_error(req, 400, "invalid", "a list is named by "
		    "letters, digits, _ and -, 32 at most"));
	if (req->method != HTTP_METHOD_PUT && req->method != HTTP_METHOD_DELETE)
		return (reply_error(req, 405, "method", "PUT or DELETE"));
	if (!guard(req, true))
		return (WEB_OK);
	body = NULL;
	if (req->method == HTTP_METHOD_PUT) {
		if ((body = read_json(req)) == NULL)
			return (reply_error(req, 400, "invalid", "a list, as "
			    "{\"description\", \"prefixes\": [...]}"));
		if ((e = check(body)) != NULL) {
			ucl_object_unref(body);
			return (reply_error(req, 400, "invalid", "%s", e));
		}
	}
	fd = lock_take();
	all = all_load();
	lists = (ucl_object_t *)(uintptr_t)ucl_object_lookup(all, "lists");
	if (body == NULL)
		(void)ucl_object_delete_key(lists, name);
	else {
		if (ucl_object_lookup(lists, name) == NULL && obj_len(lists) >=
		    PFX_LISTS_MAX) {
			lock_give(fd);
			ucl_object_unref(all);
			ucl_object_unref(body);
			return (reply_error(req, 400, "invalid", "%d lists at "
			    "most", PFX_LISTS_MAX));
		}
		l = ucl_object_typed_new(UCL_OBJECT);
		if (ucl_str(body, "description") != NULL)
			put(l, "description", ucl_object_fromstring(ucl_str(body,
			    "description")));
		put(l, "prefixes", ucl_object_copy(ucl_object_lookup(body,
		    "prefixes")));
		put(lists, name, l);
	}
	rc = store_save(PFX_FILE, all);
	lock_give(fd);
	if (body != NULL)
		ucl_object_unref(body);
	if (rc != 0) {
		ucl_object_unref(all);
		return (reply_error(req, 500, "store", "the prefix lists could "
		    "not be written"));
	}
	log_msg(LOG_NOTICE, "prefix list %s %s", name, req->method ==
	    HTTP_METHOD_PUT ? "kept" : "taken away");
	return (reply_json(req, 200, all));
}
