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
/*
 * The same of the top-level nodes tops (ntop of them), each whole as
 * tree t has it, deleted where t has none, in one EDIT: all or nothing.
 * yjson_node(): node n's value v (as a member of its parent's object
 * has it) made a child of parent, *made the node made, a list's or a
 * leaf-list's last entry; EINVAL, a value not of its node, ENOENT, a
 * member that names none.  yjson_text(): text (a key in a path) as leaf
 * or leaf-list n's value, in a.
 */
int	yjson_edit_tree(cbl_conn *conn, const struct cbl_dtree *t,
	    const struct cbl_ynode *const *tops, size_t ntop,
	    enum cbl_yds_name ds, const char *const *accept, size_t naccept,
	    char *err, size_t errlen, uint64_t *errsid, char *tag,
	    size_t taglen);
struct cbl_dnode;
int	yjson_node(struct cbl_dnode *parent, const struct cbl_ynode *n,
	    const ucl_object_t *v, cbl_yarena *a, struct cbl_dnode **made,
	    char *why, size_t len);
int	yjson_text(const struct cbl_ynode *n, const char *text, cbl_yarena *a,
	    void **out, char *why, size_t len);
/*
 * A subtree filter (RFC 6241 section 6) of schema s from its JSON v, an
 * object of the top-level nodes it names: null a selection node, an
 * object a containment node, a list an array of them, a leaf's value a
 * content match node (cblink's WIRE-FORMAT.md section 7.6.1, in JSON).
 * *out the filter, cbl_dfilter_free()'d by the caller.
 */
struct cbl_dfilter;
int	yjson_subtree(const struct cbl_yschema *s, const ucl_object_t *v,
	    struct cbl_dfilter **out, char *why, size_t len);

#endif	/* !_ARCANA_YJSONIN_H_ */
