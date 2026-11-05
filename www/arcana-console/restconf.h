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
 * RESTCONF (restconf.c).  restconf_errors(): an
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
/* The same with its error-tag (RFC 8040 section 7). */
int		 restconf_error_tag(struct http_request *req, int status,
		    const char *tag, const char *msg);
bool		 restconf_host(const char *path, char *sid, size_t len);
/* *why of a path naming what no module has (404, section 3.5.3). */
extern const char restconf_no_node[];
struct rcreq	*restconf_parse(const char *path, const char *query,
		    const char **why);
void		 restconf_free(struct rcreq *r);
/*
 * A request's checks before the host is asked (body kept, ctype its
 * media type): 0, or the status and *why; restconf_precondition(): its
 * conditions (If-Match and the others, section 3.4.1) against the
 * entity-tag of the host's (uri's) datastore, 0, 304 or 412;
 * restconf_refuse(): the reply of either's refusal; restconf_confirms():
 * it confirms a commit, over a connection of its own.
 */
int		 restconf_prepare(struct rcreq *r, int method,
		    const char *ctype, ucl_object_t *body, const char **why);
int		 restconf_precondition(struct http_request *req,
		    struct rcreq *r, const char *uri);
int		 restconf_refuse(struct http_request *req, struct rcreq *r,
		    const char *uri, int status, const char *why);
bool		 restconf_confirms(const struct rcreq *r);
void		 restconf_run(cbl_conn *conn, struct rcreq *r, const char *id,
		    const char *name, const char *uri, char **json,
		    int *status);
/* A reply's headers: a POST's Location, the datastore's ETag and
 * Last-Modified. */
void		 restconf_headers(struct http_request *req,
		    const struct rcreq *r, const char *uri, int status);
/* The host's (uri's) events, its agent's JSON: one that says its
 * configuration changed changes its datastores' entity-tags. */
void		 restconf_events(const char *uri, const char *json);
/* A reply of RFC 8040's media type, of top (consumed). */
int		 restconf_reply(struct http_request *req, ucl_object_t *top);
/*
 * The console's own datastore (l3nm.c): restconf_parse_own(), a path
 * below /restconf/data and the query as a request of it;
 * restconf_run_own(), it run on tree t (its strings in a), *changed when
 * t, edited and valid, is to be kept; restconf_own_changed(), kept, its
 * entity-tag (of uri) changed.
 */
struct cbl_dtree;
struct cbl_yarena;
struct rcreq	*restconf_parse_own(const char *path, const char *query,
		    const char **why);
void		 restconf_run_own(struct rcreq *r, struct cbl_dtree *t,
		    struct cbl_yarena *a, bool *changed, char **json,
		    int *status);
void		 restconf_own_changed(const char *uri);
/*
 * restconf_media(): the reply's media type as Accept says (RFC 9254's
 * application/yang-data+cbor, the agent's YANG-CBOR passed through, or
 * JSON); 0, or the status and *why.  restconf_body(): that reply's
 * bytes, when it is one.  restconf_agent_sids(): the console's
 * numbering of what an agent may serve, its tables less its own
 * datastore's modules (ysid.c).
 */
struct ysids;
int		 restconf_media(struct rcreq *r, const char *accept,
		    const char **why);
bool		 restconf_body(const struct rcreq *r, const void **p,
		    size_t *len);
const struct ysids *restconf_agent_sids(void);
/*
 * An action of a host's, or an rpc of its (PLAN-SDN-YANG 4.3.4):
 * restconf_act_role(), the role on the host it needs, RC_ACT_NONE where
 * r is none; restconf_act_input(), a body of YANG-CBOR, {SID: input} by
 * the host's numbering s, as the JSON body {"<module>:input": {...}}
 * (NULL: not one).
 */
enum { RC_ACT_NONE, RC_ACT_READ, RC_ACT_CHANGE, RC_ACT_ADMIN };

int		 restconf_act_role(const struct rcreq *r);
ucl_object_t	*restconf_act_input(const struct rcreq *r,
		    const struct ysids *s, const void *cbor, size_t len);
/* establish-subscription POSTed under host sid's entry (rcstream.c). */
int		 restconf_establish(struct http_request *req, const char *sid);

#endif	/* !_ARCANA_RESTCONF_H_ */
