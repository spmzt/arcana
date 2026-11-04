/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

#ifndef _ARCANA_YSID_H_
#define	_ARCANA_YSID_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <cbl_schema.h>
#include <ucl.h>

/*
 * A schema's SIDs as a peer numbers them (ysid.c, PLAN-SDN-YANG 4.2 and
 * 4.3): the items of its .sid files (RFC 9595), by SID and by
 * identifier, each resolved to the console's own node, identity or
 * annotation of the same identifier where its tables (types) have one;
 * and the modules its YANG library (RFC 8525) says.  The translator
 * (yxlate.c) names and types by it, a host's (ycache.c) by its agent's.
 *
 * ysids_new(): an empty one over tables types; ysids_file_cbor() adds a
 * .sid file as GET-SID sends it (the ietf-sid-file structure's value),
 * ysids_file_json() as RFC 9595's JSON has it ({"ietf-sid-file:sid-file":
 * ...}), ysids_tables() every item of the tables themselves (the
 * console's own numbering); ysids_module() a module of the library;
 * ysids_done() sorts and resolves them, after which it is read-only and
 * may be shared between threads.  0, or an errno and why.
 */
#define	YSID_NS_MODULE		0
#define	YSID_NS_IDENTITY	1
#define	YSID_NS_FEATURE		2
#define	YSID_NS_DATA		3
#define	YSID_NS_ANNOTATION	4	/* draft-ietf-core-yang-metadata's */

struct ysid_item {
	uint64_t	 sid;
	/* Data: the SID its key is a delta from, its parent's (an rpc's or
	 * an action's for what is in its input or output); 0 at the top. */
	uint64_t	 base;
	const char	*id;		/* as the file has it */
	const char	*module;	/* the file's */
	const char	*name;		/* the last name of id */
	const char	*nmod;		/* that name's module */
	/* The console's struct cbl_ynode, cbl_yident or cbl_yannot of the
	 * same identifier, or of the module struct cbl_ymodule; NULL: its
	 * tables have none. */
	const void	*what;
	uint8_t		 ns;		/* YSID_NS_* */
	bool		 obsolete;
	bool		 io;		/* an input or an output */
	bool		 top;		/* data at the top of its module */
};

struct ysid_mod {
	const char	*name;
	const char	*revision;	/* "": none */
	bool		 implemented;	/* else imported only */
};

struct ysids;

struct ysids	*ysids_new(const struct cbl_yschema *types);
void		 ysids_free(struct ysids *s);
int		 ysids_file_cbor(struct ysids *s, const void *cbor, size_t len,
		    char *why, size_t whylen);
int		 ysids_file_json(struct ysids *s, const ucl_object_t *file,
		    char *why, size_t whylen);
int		 ysids_tables(struct ysids *s);
int		 ysids_module(struct ysids *s, const char *name,
		    const char *revision, bool implemented);
int		 ysids_set_content_id(struct ysids *s, const char *id);
int		 ysids_done(struct ysids *s, char *why, size_t whylen);

/*
 * Lookups: the item of a SID; a data node's by its schema-node path
 * ("/m:a/b/n:c"); an identity's, an annotation's, a feature's or a
 * module's by module and name; the item resolved to the console's what.
 * NULL: none.  ysids_mod(): the library's module of that name, NULL:
 * none (or no library given); ysids_nmod() how many.
 */
const struct ysid_item *ysids_sid(const struct ysids *s, uint64_t sid);
const struct ysid_item *ysids_data(const struct ysids *s, const char *path);
const struct ysid_item *ysids_named(const struct ysids *s, int ns,
		    const char *module, const char *name);
const struct ysid_item *ysids_of(const struct ysids *s, const void *what);
const struct ysid_mod *ysids_mod(const struct ysids *s, const char *name);
size_t		 ysids_nmod(const struct ysids *s);
const struct ysid_mod *ysids_mod_at(const struct ysids *s, size_t i);
const char	*ysids_content_id(const struct ysids *s);
size_t		 ysids_count(const struct ysids *s);
const struct cbl_yschema *ysids_types(const struct ysids *s);
/* The SIDs of its top-level data nodes, max at most, by SID: how many. */
size_t		 ysids_tops(const struct ysids *s, uint64_t *out, size_t max);

/*
 * The schema-node path of the console's node n (RFC 9595's identifier:
 * each name qualified where its module is not its parent's), in buf;
 * false where it does not fit.
 */
bool		 ysids_node_path(const struct cbl_ynode *n, char *buf,
		    size_t len);

#endif	/* !_ARCANA_YSID_H_ */
