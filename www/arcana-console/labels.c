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
 * an empty text takes it away.
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
	return (fd);
}

static void
lock_give(int fd)
{

	if (fd != -1)
		close(fd);
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
		return (KORE_RESULT_OK);
	all = all_load();
	return (reply_json(req, 200, all));
}

/* PUT /api/labels/<server>/<interface> {"label": "text"}. */
int
api_label(struct http_request *req)
{
	ucl_object_t	*body, *all, *labels;
	const char	*p, *label;
	char		 sid[17], ifname[17], key[40];
	size_t		 n;
	int		 fd, rc;

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
		return (KORE_RESULT_OK);
	if ((body = read_json(req)) == NULL)
		return (reply_error(req, 400, "invalid", "{\"label\": \"text\"}; "
		    "empty to take it away"));
	label = ucl_str(body, "label");
	if (!label_ok(label != NULL ? label : "")) {
		ucl_object_unref(body);
		return (reply_error(req, 400, "invalid", "a label is text of %d "
		    "characters at most, no control characters", LABEL_MAX));
	}
	snprintf(key, sizeof(key), "%s/%s", sid, ifname);
	fd = lock_take();
	all = all_load();
	labels = (ucl_object_t *)(uintptr_t)ucl_object_lookup(all, "labels");
	if (label == NULL || label[0] == '\0')
		(void)ucl_object_delete_key(labels, key);
	else {
		if (ucl_object_lookup(labels, key) == NULL &&
		    obj_len(labels) >= LABELS_MAX) {
			lock_give(fd);
			ucl_object_unref(all);
			ucl_object_unref(body);
			return (reply_error(req, 400, "invalid", "%d labels at "
			    "most", LABELS_MAX));
		}
		put(labels, key, ucl_object_fromstring(label));
	}
	rc = store_save(LABELS_FILE, all);
	lock_give(fd);
	if (rc != 0) {
		ucl_object_unref(all);
		ucl_object_unref(body);
		return (reply_error(req, 500, "store", "the labels could not be "
		    "written"));
	}
	kore_log(LOG_NOTICE, "label of %s %s", key, label != NULL && label[0] !=
	    '\0' ? "set" : "taken away");
	ucl_object_unref(body);
	return (reply_json(req, 200, all));
}
