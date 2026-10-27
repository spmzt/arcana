/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

#ifndef _ARCANA_RESTCONF_H_
#define	_ARCANA_RESTCONF_H_

#include <stdbool.h>
#include <stddef.h>

#include <cblink.h>
#include <ucl.h>

struct http_request;

/*
 * RESTCONF's reads (restconf.c).  restconf_errors(): an
 * ietf-restconf:errors body of status, malloc'd; restconf_host(): the
 * host's id of a path under one's entry; restconf_parse(): the path
 * below it and the query made a request of its agent (NULL: *why says
 * why not), run over conn by restconf_run(), its body in *json and its
 * status in *status.
 */
struct rcreq;

char		*restconf_errors(int status, const char *msg);
int		 restconf_error(struct http_request *req, int status,
		    const char *msg);
bool		 restconf_host(const char *path, char *sid, size_t len);
struct rcreq	*restconf_parse(const char *path, const char *query,
		    const char **why);
void		 restconf_free(struct rcreq *r);
void		 restconf_run(cbl_conn *conn, const struct rcreq *r,
		    const char *id, const char *name, char **json, int *status);
/* A reply of RFC 8040's media type, of top (consumed). */
int		 restconf_reply(struct http_request *req, ucl_object_t *top);
/* establish-subscription POSTed under host sid's entry (rcstream.c). */
int		 restconf_establish(struct http_request *req, const char *sid);

#endif	/* !_ARCANA_RESTCONF_H_ */
