/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Each host's schema as its agent has it, for the fleet mount
 * (PLAN-SDN-YANG 4.3.1, 4.3.2): what its YANG library (RFC 8525) says it
 * implements and imports, and the SIDs of each module (GET-SID's .sid
 * files), resolved against the console's tables (ysid.c), kept by the
 * agent's URI.  RESTCONF names, types and checks a host's paths and data
 * by it: an agent of another release has modules, nodes and numbers of
 * its own.
 *
 * Kept until it may have changed: a new connection to the agent (a
 * restart, an agent-update) and the library's yang-library-update mark
 * it to be checked, and at its next use the library's content-id is read
 * again; the .sid files are read again only where it changed.  A view
 * in use is held by its users: one replaced goes when the last is done.
 */

#include <sys/param.h>

#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <cblink.h>
#include <cbl_schema.h>
#include <ucl.h>

#include "console.h"
#include "ycache.h"
#include "ymodel.h"
#include "ysid.h"
#include "ytrans.h"

struct yview {
	struct ysids	*s;
	atomic_int	 refs;
};

struct yentry {
	char		*uri;
	struct yview	*v;
	bool		 stale;
};

static pthread_mutex_t	 lock = PTHREAD_MUTEX_INITIALIZER;
static struct yentry	*ents;
static size_t		 nents;
static atomic_uint	 reads;

const struct ysids *
yview_sids(const struct yview *v)
{

	return (v != NULL ? v->s : NULL);
}

void
ycache_put(struct yview *v)
{

	if (v == NULL || atomic_fetch_sub(&v->refs, 1) != 1)
		return;
	ysids_free(v->s);
	free(v);
}

unsigned
ycache_reads(void)
{

	return (atomic_load(&reads));
}

/* uri's entry, the lock held; NULL: none. */
static struct yentry *
entry(const char *uri)
{

	for (size_t i = 0; i < nents; i++)
		if (strcmp(ents[i].uri, uri) == 0)
			return (&ents[i]);
	return (NULL);
}

struct yview *
ycache_peek(const char *uri)
{
	struct yentry	*e;
	struct yview	*v = NULL;

	pthread_mutex_lock(&lock);
	if ((e = entry(uri)) != NULL && (v = e->v) != NULL)
		atomic_fetch_add(&v->refs, 1);
	pthread_mutex_unlock(&lock);
	return (v);
}

void
ycache_stale(const char *uri)
{
	struct yentry	*e;

	pthread_mutex_lock(&lock);
	if ((e = entry(uri)) != NULL)
		e->stale = true;
	pthread_mutex_unlock(&lock);
}

/* ietf-yang-library's yang-library, of the console's tables. */
static const struct cbl_ynode *
library_node(void)
{

	for (uint32_t i = 0; i < ymodel_schema.nmod; i++) {
		const struct cbl_ymodule *m = ymodel_schema.mod[i];

		if (strcmp(m->name, "ietf-yang-library") != 0)
			continue;
		for (uint32_t k = 0; k < m->ntop; k++)
			if (strcmp(m->top[k]->name, "yang-library") == 0)
				return (m->top[k]);
	}
	return (NULL);
}

/*
 * The agent's YANG library over conn, in a: its content-id and modules.
 * The library's numbering is the IETF's, the same in every release.
 */
static int
read_library(cbl_conn *conn, cbl_yarena *a,
    const struct ietf_yang_library_yang_library **out, char *why,
    size_t whylen)
{
	const struct cbl_ynode	*n = library_node();
	struct ietf_yang_library *data;
	cbl_msg			*rep;
	uint64_t		 sid;
	int			 error;

	*out = NULL;
	if (n == NULL)
		return (ENOENT);
	sid = n->sid;
	if ((error = ytrans_get_msg(conn, &sid, 1, NULL, -1, false, &rep, why,
	    whylen, NULL)) != 0)
		return (error);
	if ((data = cbl_yarena_alloc(a, n->module->size)) == NULL)
		error = ENOMEM;
	else
		error = cbl_msg_ydecode_member(rep, n, data, a, 0, why,
		    whylen);
	cbl_msg_free(rep);
	if (error != 0)
		return (error);
	if ((*out = data->yang_library) == NULL) {
		snprintf(why, whylen, "the agent has no YANG library");
		return (ENOENT);
	}
	return (0);
}

/* The agent's .sid files and its library made a view. */
static int
read_view(cbl_conn *conn, const struct ietf_yang_library_yang_library *yl,
    struct yview **out, char *why, size_t whylen)
{
	const struct ietf_yang_library_yang_library_module_set *ms;
	struct ysids	*s;
	struct yview	*v;
	cbl_dump	*d = NULL;
	cbl_msg		*req, *item;
	const void	*p;
	size_t		 len, files = 0;
	int		 error;

	*out = NULL;
	if ((s = ysids_new(&ymodel_schema)) == NULL)
		return (ENOMEM);
	/* The console's own datastore's modules are never a host's. */
	ysids_skip(s, l3nm_module);
	if ((error = cbl_msg_new(cbl_conn_ctx(conn), CBL_YANG_FAMILY,
	    CBL_YCMD_GET_SID, CBL_F_DUMP, &req)) != 0 ||
	    (error = cbl_dump_start(conn, req, &d)) != 0) {
		snprintf(why, whylen, "GET-SID: %s", strerror(error));
		ysids_free(s);
		return (error);
	}
	while ((error = cbl_dump_next(d, &item)) == 0 && item != NULL) {
		if (cbl_msg_sid_raw(item, CBL_YSID_FILE, &p, &len) == 0) {
			error = ysids_file_cbor(s, p, len, why, whylen);
			files++;
		}
		cbl_msg_free(item);
		if (error != 0)
			break;
	}
	if (error == 0 && cbl_dump_error(d) != NULL)
		error = cbl_msg_error(cbl_dump_error(d)) != 0 ?
		    cbl_msg_error(cbl_dump_error(d)) : EIO;
	cbl_dump_free(d);
	if (error == 0 && files == 0) {
		snprintf(why, whylen, "the agent sends no .sid file");
		error = ENOENT;
	}
	for (size_t i = 0; error == 0 && i < yl->module_set.n; i++) {
		ms = &yl->module_set.v[i];
		for (size_t k = 0; error == 0 && k < ms->module.n; k++)
			error = ysids_module(s, ms->module.v[k].name,
			    ms->module.v[k].revision, true);
		for (size_t k = 0; error == 0 && k < ms->import_only_module.n;
		    k++) {
			__typeof__(*ms->import_only_module.v) *io =
			    &ms->import_only_module.v[k];

			error = ysids_module(s, io->name, io->revision.which ==
			    0 ? io->revision.v.m0 : "", false);
		}
	}
	if (error == 0 && yl->content_id != NULL)
		error = ysids_set_content_id(s, yl->content_id);
	if (error == 0)
		error = ysids_done(s, why, whylen);
	if (error != 0 || (v = calloc(1, sizeof(*v))) == NULL) {
		if (error == 0)
			error = ENOMEM;
		if (why[0] == '\0')
			snprintf(why, whylen, "%s", strerror(error));
		ysids_free(s);
		return (error);
	}
	v->s = s;
	atomic_init(&v->refs, 1);
	atomic_fetch_add(&reads, 1);
	*out = v;
	return (0);
}

/* v kept as uri's, checked now; the cache's reference. */
static void
keep(const char *uri, struct yview *v)
{
	struct yentry	*e, *ne;
	struct yview	*old = NULL;

	pthread_mutex_lock(&lock);
	if ((e = entry(uri)) == NULL && (ne = reallocarray(ents, nents + 1,
	    sizeof(*ents))) != NULL) {
		ents = ne;
		e = &ents[nents];
		if ((e->uri = strdup(uri)) != NULL) {
			e->v = NULL;
			nents++;
		} else
			e = NULL;
	}
	if (e != NULL) {
		old = e->v;
		e->v = v;
		e->stale = false;
		atomic_fetch_add(&v->refs, 1);
	}
	pthread_mutex_unlock(&lock);
	ycache_put(old);
}

struct yview *
ycache_get(cbl_conn *conn, const char *uri, char *why, size_t whylen)
{
	const struct ietf_yang_library_yang_library *yl;
	struct yentry	*e;
	struct yview	*v = NULL;
	cbl_yarena	*a;
	const char	*cid;
	bool		 check = false;

	why[0] = '\0';
	pthread_mutex_lock(&lock);
	if ((e = entry(uri)) != NULL && e->v != NULL) {
		v = e->v;
		atomic_fetch_add(&v->refs, 1);
		check = e->stale;
	}
	pthread_mutex_unlock(&lock);
	if (v != NULL && !check)
		return (v);
	if ((a = cbl_yarena_new()) == NULL) {
		snprintf(why, whylen, "out of memory");
		return (v);
	}
	if (read_library(conn, a, &yl, why, whylen) != 0) {
		/* Not read: what is kept, if anything, until it is. */
		cbl_yarena_free(a);
		return (v);
	}
	/* The same library: the same modules and SIDs. */
	cid = v != NULL ? ysids_content_id(v->s) : NULL;
	if (v != NULL && cid != NULL && yl->content_id != NULL &&
	    strcmp(cid, yl->content_id) == 0) {
		keep(uri, v);
		cbl_yarena_free(a);
		return (v);
	}
	ycache_put(v);
	v = NULL;
	if (read_view(conn, yl, &v, why, whylen) == 0) {
		keep(uri, v);
		log_msg(LOG_INFO, "%s: its schema read: %zu modules, %zu SIDs, "
		    "content-id %s", uri, ysids_nmod(v->s), ysids_count(v->s),
		    yl->content_id != NULL ? yl->content_id : "none");
	}
	cbl_yarena_free(a);
	return (v);
}
