/*-
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Labels on interfaces: a tag of the console's own for an interface of
 * a host ("the UCS to the IXP", "uplink A"), kept here, not on the
 * host, so that it names the link whatever the interface's own
 * description says and survives the host's reinstall.  labels.json in
 * the data directory, {"labels": {"server/interface": "text"}}, under
 * labels.lock while it is changed; GET /api/labels gives them all,
 * PUT /api/labels/<server>/<interface> {"label": "text"} sets one,
 * an empty text takes it away.  The same as arcana-console's labels
 * (cyang.c), through labels_apply().
 */

#include <sys/param.h>
#include <sys/file.h>

#include <ctype.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include "console.h"

#define	LABELS_FILE	"labels.json"
#define	LABELS_LOCK	"labels.lock"
#define	LABEL_MAX	64
#define	LABELS_MAX	4096

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

	snprintf(path, sizeof(path), "%s/%s", cfg.datadir, LABELS_LOCK);
	if ((fd = open(path, O_RDWR | O_CREAT | O_CLOEXEC, 0600)) == -1)
		return (-1);
	(void)flock(fd, LOCK_EX);
	/* And of the cluster's other nodes, when it is one. */
	(void)cluster_lock(LABELS_LOCK);
	return (fd);
}

static void
lock_give(int fd)
{

	if (fd != -1) {
		cluster_unlock(LABELS_LOCK);
		close(fd);
	}
}

/* {"labels": {...}}, an empty one when there is none. */
static ucl_object_t *
all_load(void)
{
	ucl_object_t	*o;

	if ((o = store_load(LABELS_FILE)) == NULL || ucl_object_type(o) !=
	    UCL_OBJECT) {
		if (o != NULL)
			ucl_object_unref(o);
		o = ucl_object_typed_new(UCL_OBJECT);
	}
	if (ucl_object_lookup(o, "labels") == NULL)
		put(o, "labels", ucl_object_typed_new(UCL_OBJECT));
	return (o);
}

/* A label: printable, no control character, LABEL_MAX at most. */
static bool
label_ok(const char *s)
{
	size_t	i;

	if (s == NULL || strlen(s) > LABEL_MAX)
		return (false);
	for (i = 0; s[i] != '\0'; i++)
		if ((unsigned char)s[i] < 0x20 || s[i] == 0x7f)
			return (false);
	return (true);
}

/* The label of an interface of a server, or NULL. */
const char *
label_of(const char *sid, const char *ifname, char *buf, size_t len)
{
	ucl_object_t		*all;
	const ucl_object_t	*v;
	char			 key[96];

	snprintf(key, sizeof(key), "%s/%s", sid, ifname);
	all = all_load();
	v = ucl_object_lookup(ucl_object_lookup(all, "labels"), key);
	if (v == NULL || ucl_object_type(v) != UCL_STRING) {
		ucl_object_unref(all);
		return (NULL);
	}
	snprintf(buf, len, "%s", ucl_object_tostring(v));
	ucl_object_unref(all);
	return (buf);
}

/* GET /api/labels: every label, by server/interface. */
int
api_labels(struct http_request *req)
{
	ucl_object_t	*all;

	if (req->method != HTTP_METHOD_GET)
		return (reply_error(req, 405, "method", "GET"));
	if (!guard(req, false))
		return (WEB_OK);
	all = all_load();
	return (reply_json(req, 200, all));
}

/*
 * The labels changed as set says, {"server/interface": "text"}, an empty
 * text taking one away, each checked before any is kept; the labels
 * then into *allp when asked.  0, or the HTTP status and why.
 */
static int
labels_apply(const ucl_object_t *set, ucl_object_t **allp, char *why,
    size_t len)
{
	ucl_object_t		*all, *labels;
	const ucl_object_t	*v;
	ucl_object_iter_t	 it;
	const char		*label;
	int			 fd, rc;

	it = NULL;
	while ((v = ucl_object_iterate(set, &it, true)) != NULL)
		if (!label_ok(ucl_object_tostring(v))) {
			snprintf(why, len, "a label is text of %d characters at "
			    "most, no control characters", LABEL_MAX);
			return (400);
		}
	fd = lock_take();
	all = all_load();
	labels = (ucl_object_t *)(uintptr_t)ucl_object_lookup(all, "labels");
	it = NULL;
	while ((v = ucl_object_iterate(set, &it, true)) != NULL) {
		label = ucl_object_tostring(v);
		if (label[0] == '\0') {
			(void)ucl_object_delete_key(labels, ucl_object_key(v));
			continue;
		}
		if (ucl_object_lookup(labels, ucl_object_key(v)) == NULL &&
		    obj_len(labels) >= LABELS_MAX) {
			lock_give(fd);
			ucl_object_unref(all);
			snprintf(why, len, "%d labels at most", LABELS_MAX);
			return (400);
		}
		put(labels, ucl_object_key(v), ucl_object_fromstring(label));
	}
	rc = store_save(LABELS_FILE, all);
	lock_give(fd);
	if (rc != 0) {
		ucl_object_unref(all);
		snprintf(why, len, "the labels could not be written");
		return (500);
	}
	it = NULL;
	while ((v = ucl_object_iterate(set, &it, true)) != NULL)
		log_msg(LOG_NOTICE, "label of %s %s", ucl_object_key(v),
		    ucl_object_tostring(v)[0] != '\0' ? "set" : "taken away");
	cyang_changed("labels");
	if (allp != NULL)
		*allp = all;
	else
		ucl_object_unref(all);
	return (0);
}

/* PUT /api/labels/<server>/<interface> {"label": "text"}. */
int
api_label(struct http_request *req)
{
	ucl_object_t	*body, *all, *set;
	const char	*p, *label;
	char		 sid[17], ifname[17], key[40], why[128];
	size_t		 n;
	int		 rc;

	if (req->method != HTTP_METHOD_PUT)
		return (reply_error(req, 405, "method", "PUT"));
	/* The path: /api/labels/<server>/<interface>. */
	p = req->path + strlen("/api/labels/");
	n = strcspn(p, "/");
	if (n == 0 || n > 16 || p[n] != '/' || strlen(p + n + 1) == 0 ||
	    strlen(p + n + 1) > 15)
		return (reply_error(req, 400, "invalid", "a label is of "
		    "/api/labels/<server>/<interface>"));
	snprintf(sid, sizeof(sid), "%.*s", (int)n, p);
	snprintf(ifname, sizeof(ifname), "%s", p + n + 1);
	if (!guard(req, true) || !host_allowed(req, sid, true, false))
		return (WEB_OK);
	if ((body = read_json(req)) == NULL)
		return (reply_error(req, 400, "invalid", "{\"label\": \"text\"}; "
		    "empty to take it away"));
	label = ucl_str(body, "label");
	snprintf(key, sizeof(key), "%s/%s", sid, ifname);
	set = ucl_object_typed_new(UCL_OBJECT);
	put(set, key, ucl_object_fromstring(label != NULL ? label : ""));
	ucl_object_unref(body);
	rc = labels_apply(set, &all, why, sizeof(why));
	ucl_object_unref(set);
	if (rc != 0)
		return (reply_error(req, rc, rc == 400 ? "invalid" : "store",
		    "%s", why));
	return (reply_json(req, 200, all));
}

/* ---- arcana-console's labels (cyang.c) ------------------------------- */

/* arcana-console:labels's value: each label by its host and interface. */
ucl_object_t *
labels_yang(void)
{
	ucl_object_t		*all, *arr, *e, *o;
	const ucl_object_t	*v;
	ucl_object_iter_t	 it;
	const char		*k;
	size_t			 n;

	all = all_load();
	arr = ucl_object_typed_new(UCL_ARRAY);
	it = NULL;
	while ((v = ucl_object_iterate(ucl_object_lookup(all, "labels"), &it,
	    true)) != NULL) {
		k = ucl_object_key(v);
		if (ucl_object_type(v) != UCL_STRING || (n = strcspn(k, "/")) ==
		    0 || k[n] != '/' || k[n + 1] == '\0')
			continue;
		e = ucl_object_typed_new(UCL_OBJECT);
		put(e, "host", ucl_object_fromlstring(k, n));
		put(e, "interface", ucl_object_fromstring(k + n + 1));
		put(e, "text", ucl_object_fromstring(ucl_object_tostring(v)));
		ucl_array_append(arr, e);
	}
	ucl_object_unref(all);
	o = ucl_object_typed_new(UCL_OBJECT);
	put(o, "label", arr);
	return (o);
}

/* The label of e, changed into set, if the request may change its host:
 * 0, or the HTTP status and why. */
static int
label_change(struct http_request *req, ucl_object_t *set,
    const ucl_object_t *e, const char *text, char *why, size_t len)
{
	const char	*sid;
	char		 key[40];

	sid = ucl_str(e, "host");
	if (!host_role_ok(req, sid, true, false)) {
		snprintf(why, len, "host %s is not one you may change", sid);
		return (user_host(session_user(req), sid) == ROLE_NONE ? 404 :
		    403);
	}
	snprintf(key, sizeof(key), "%s/%s", sid, ucl_str(e, "interface"));
	put(set, key, ucl_object_fromstring(text));
	return (0);
}

/*
 * The labels changed from was to now, each of a host the request may
 * change, kept by labels_apply() at once.  0, or the HTTP status and
 * why.
 */
int
labels_yang_set(struct http_request *req, const ucl_object_t *was,
    const ucl_object_t *now, char *why, size_t len)
{
	ucl_object_t		*set;
	const ucl_object_t	*e, *o, *l;
	ucl_object_iter_t	 it, oit;
	int			 rc;

	set = ucl_object_typed_new(UCL_OBJECT);
	rc = 0;
	it = NULL;
	while (rc == 0 && (e = ucl_object_iterate(ucl_object_lookup(now,
	    "label"), &it, true)) != NULL) {
		oit = NULL;
		while ((o = ucl_object_iterate(ucl_object_lookup(was, "label"),
		    &oit, true)) != NULL)
			if (strcmp(ucl_str(o, "host"), ucl_str(e, "host")) == 0 &&
			    strcmp(ucl_str(o, "interface"), ucl_str(e,
			    "interface")) == 0)
				break;
		if (o == NULL || !cyang_same(o, e))
			rc = label_change(req, set, e, ucl_str(e, "text"), why,
			    len);
	}
	it = NULL;
	while (rc == 0 && (o = ucl_object_iterate(ucl_object_lookup(was,
	    "label"), &it, true)) != NULL) {
		oit = NULL;
		while ((l = ucl_object_iterate(ucl_object_lookup(now, "label"),
		    &oit, true)) != NULL)
			if (strcmp(ucl_str(o, "host"), ucl_str(l, "host")) == 0 &&
			    strcmp(ucl_str(o, "interface"), ucl_str(l,
			    "interface")) == 0)
				break;
		if (l == NULL)
			rc = label_change(req, set, o, "", why, len);
	}
	if (rc == 0 && set->len > 0)
		rc = labels_apply(set, NULL, why, len);
	ucl_object_unref(set);
	return (rc);
}
