/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

#ifndef _ARCANA_YJSONIN_H_
#define	_ARCANA_YJSONIN_H_

/*
 * RFC 7951's JSON in (yjsonin.c), the console's and arcanactl's: top-level
 * node n's value v made into tree t (its strings and values in a); that
 * node's YANG-CBOR as an EDIT sends it, malloc'd; an EDIT of n to v (NULL:
 * n deleted) in datastore ds over conn, accepting those warnings: 0, or an
 * errno, err (the agent's words), *errsid (the node at fault) and tag (the
 * refusal's error-app-tag, a warning to accept).
 */
struct cbl_dtree;
int	yjson_member(struct cbl_dtree *t, const struct cbl_ynode *n,
	    const ucl_object_t *v, cbl_yarena *a, char *why, size_t len);
int	yjson_top_cbor(const struct cbl_dtree *t, const struct cbl_ynode *n,
	    uint8_t **pp, size_t *lenp);
int	yjson_edit(cbl_conn *conn, const struct cbl_ynode *n,
	    const ucl_object_t *v, enum cbl_yds_name ds,
	    const char *const *accept, size_t naccept, char *err,
	    size_t errlen, uint64_t *errsid, char *tag, size_t taglen);

#endif	/* !_ARCANA_YJSONIN_H_ */
