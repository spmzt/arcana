/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

#ifndef _ARCANA_YXLATE_H_
#define	_ARCANA_YXLATE_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <cbl_schema.h>
#include <ucl.h>

/*
 * RFC 7951's JSON and RFC 9254's YANG-CBOR, each into the other by a
 * schema's SIDs as a peer numbers them (yxlate.c, PLAN-SDN-YANG 4.2.1,
 * 4.2.2): names from its .sid files, types from the console's tables
 * where they have the node (struct ysids).
 *
 * yx_json(): a map of top-level nodes keyed by their SIDs, as a GET's
 * reply or an EDIT has them, appended to b as one JSON object, each
 * member "module:name", annotations as RFC 7952 section 5.2 has them.
 * yx_json_member(): one top-level node's value (cbl_msg_sid_raw()'s), as
 * a member "module:name": value, with a comma before it unless *first.
 * yx_cbor(): a JSON object of top-level nodes made such a map;
 * yx_cbor_member(): top-level node it's JSON value v alone.  0, or an
 * errno, why, and *tag the RFC 8040 error-tag (unknown-element,
 * invalid-value, malformed-message).
 */
struct ysids;
struct ysid_item;

int	yx_json(const struct ysids *s, const void *cbor, size_t len,
	    struct cbl_ybuf *b, char *why, size_t whylen);
int	yx_json_member(const struct ysids *s, const struct ysid_item *it,
	    const void *cbor, size_t len, bool *first, struct cbl_ybuf *b,
	    char *why, size_t whylen);
int	yx_cbor(const struct ysids *s, const ucl_object_t *v,
	    struct cbl_ybuf *b, const char **tag, char *why, size_t whylen);
int	yx_cbor_member(const struct ysids *s, const struct ysid_item *it,
	    const ucl_object_t *v, struct cbl_ybuf *b, const char **tag,
	    char *why, size_t whylen);
/* An instance-identifier's XPath (RFC 7951 section 6.11) as YANG-CBOR's
 * (RFC 9254 section 6.13.1): its SID, or [SID, keys...]. */
int	yx_iid(const struct ysids *s, const char *path, struct cbl_ybuf *b,
	    char *why, size_t whylen);
/* The same of a JSON text (RFC 7951) or a reply to it. */
int	yx_cbor_text(const struct ysids *s, const char *json,
	    struct cbl_ybuf *b, const char **tag, char *why, size_t whylen);

/*
 * A CBOR reader of definite lengths: an item's head (major type, and its
 * argument: a length, an integer, a tag, a simple value), a text
 * string, an item passed over.  0, or EINVAL at what is not CBOR.
 */
struct yxrd {
	const uint8_t	*p;
	const uint8_t	*end;
};

int	yxrd_head(struct yxrd *r, int *major, uint64_t *arg);
int	yxrd_peek(const struct yxrd *r, int *major, uint64_t *arg);
int	yxrd_text(struct yxrd *r, const char **s, size_t *len);
int	yxrd_skip(struct yxrd *r);

/* A CBOR head appended to b. */
int	yx_put_head(struct cbl_ybuf *b, int major, uint64_t arg);

#endif	/* !_ARCANA_YXLATE_H_ */
