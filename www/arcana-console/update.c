/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Updates: the console asks the release feed, in a task thread, for the
 * newest version, remembers the answer for a while, and tells the UI
 * when a newer one exists.  It does not replace itself: the console runs
 * unprivileged, and how it is updated depends on how it was installed
 * (the package, or the container image); the UI says which.
 */

#include <sys/param.h>

#include <ctype.h>
#include <limits.h>
#include <stdio.h>
#include <fetch.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "console.h"

#define	UPDATE_CACHE	(6 * 60 * 60)
#define	UPDATE_MAX	(64 * 1024)

struct check {
	struct kore_task	 task;		/* first: Kore frees the check */
	char			 latest[64];
	char			 url[512];
	char			 error[256];
	char			 feed[1024];	/* asked of: cfg may change */
};

static struct {
	char	latest[64];
	char	url[512];
	char	error[256];
	time_t	checked;
} cache;

static int	 newer(const char *, const char *);
static int	 check_run(struct kore_task *);
static int	 reply(struct http_request *);

/* Is version a newer than b?  "v1.2.3" and "1.2.3" compare as numbers. */
static int
newer(const char *a, const char *b)
{
	char	*ea, *eb;
	long	x, y;

	if (*a == 'v')
		a++;
	if (*b == 'v')
		b++;
	for (;;) {
		x = strtol(a, &ea, 10);
		y = strtol(b, &eb, 10);
		if (x != y)
			return (x > y);
		if (*ea != '.' || *eb != '.')
			return (0);
		a = ea + 1;
		b = eb + 1;
	}
}

/* In a task thread: the release feed's newest tag. */
static int
check_run(struct kore_task *t)
{
	struct check		*c;
	struct ucl_parser	*p;
	ucl_object_t		*o;
	const char		*tag, *url;
	FILE			*fp;
	char			*buf;
	size_t			 len, n;

	c = (struct check *)t;
	if ((fp = fetchGetURL(c->feed, "")) == NULL) {
		snprintf(c->error, sizeof(c->error), "%s", fetchLastErrString);
		return (KORE_RESULT_OK);
	}
	if ((buf = malloc(UPDATE_MAX)) == NULL) {
		fclose(fp);
		snprintf(c->error, sizeof(c->error), "out of memory");
		return (KORE_RESULT_OK);
	}
	for (len = 0; len < UPDATE_MAX - 1; len += n)
		if ((n = fread(buf + len, 1, UPDATE_MAX - 1 - len, fp)) == 0)
			break;
	buf[len] = '\0';
	fclose(fp);
	p = ucl_parser_new(UCL_PARSER_NO_IMPLICIT_ARRAYS |
	    UCL_PARSER_DISABLE_MACRO | UCL_PARSER_NO_TIME);
	o = NULL;
	if (ucl_parser_add_string(p, buf, len))
		o = ucl_parser_get_object(p);
	ucl_parser_free(p);
	free(buf);
	tag = o != NULL ? ucl_str(o, "tag_name") : NULL;
	url = o != NULL ? ucl_str(o, "html_url") : NULL;
	if (tag == NULL || !isdigit((unsigned char)tag[*tag == 'v']))
		snprintf(c->error, sizeof(c->error), "%s: no release tag in "
		    "the answer", c->feed);
	else {
		strlcpy(c->latest, tag, sizeof(c->latest));
		strlcpy(c->url, url != NULL ? url : "", sizeof(c->url));
	}
	if (o != NULL)
		ucl_object_unref(o);
	return (KORE_RESULT_OK);
}

static int
reply(struct http_request *req)
{
	ucl_object_t	*o;

	o = ucl_object_typed_new(UCL_OBJECT);
	ucl_object_insert_key(o, ucl_object_fromstring(ARCW_VERSION), "current",
	    0, false);
	ucl_object_insert_key(o, ucl_object_frombool(cfg.update_url != NULL),
	    "enabled", 0, false);
	if (cache.latest[0] != '\0') {
		ucl_object_insert_key(o, ucl_object_fromstring(cache.latest),
		    "latest", 0, false);
		ucl_object_insert_key(o, ucl_object_fromstring(cache.url),
		    "url", 0, false);
		ucl_object_insert_key(o, ucl_object_frombool(newer(cache.latest,
		    ARCW_VERSION)), "newer", 0, false);
	}
	if (cache.error[0] != '\0')
		ucl_object_insert_key(o, ucl_object_fromstring(cache.error),
		    "error", 0, false);
	if (cache.checked != 0)
		ucl_object_insert_key(o, ucl_object_fromint(cache.checked),
		    "checked", 0, false);
	return (reply_json(req, 200, o));
}

/* GET /api/update: the newest release against this one. */
int
api_update(struct http_request *req)
{
	struct check	*c;

	if (req->hdlr_extra != NULL) {
		c = req->hdlr_extra;
		if (kore_task_state(&c->task) != KORE_TASK_STATE_FINISHED) {
			http_request_sleep(req);
			return (KORE_RESULT_RETRY);
		}
		cache.checked = time(NULL);
		strlcpy(cache.error, c->error, sizeof(cache.error));
		if (c->latest[0] != '\0') {
			strlcpy(cache.latest, c->latest, sizeof(cache.latest));
			strlcpy(cache.url, c->url, sizeof(cache.url));
		}
		return (reply(req));
	}
	if (!guard(req, false))
		return (KORE_RESULT_OK);
	if (cfg.update_url == NULL ||
	    time(NULL) - cache.checked < UPDATE_CACHE)
		return (reply(req));
	c = kore_calloc(1, sizeof(*c));
	strlcpy(c->feed, cfg.update_url, sizeof(c->feed));
	/* A feed that takes the connection and says nothing is given up. */
	fetchTimeout = 30;
	req->hdlr_extra = c;
	kore_task_create(&c->task, check_run);
	kore_task_bind_request(&c->task, req);
	kore_task_run(&c->task);
	return (KORE_RESULT_RETRY);
}
