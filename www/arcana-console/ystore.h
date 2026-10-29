/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

#ifndef _ARCANA_YSTORE_H_
#define	_ARCANA_YSTORE_H_

#include <stdbool.h>
#include <stdint.h>

#include <cblink.h>
#include <ucl.h>

/*
 * An agent's storage through arcana-storage (ystore.c), the console's
 * and arcanactl's, the JSON the storage and fstab operations gave kept.
 * Each takes conn and gives 0, or an errno and err (the agent's words).
 *
 * ystore_read(): part kind (ARC_STORAGE_KIND_*) by the read action, of
 * the dataset filter names and those under it, of what jail's zfs
 * sees, as {"disks": [...]} and the others; *total the rows on the
 * host where more than the reply's (*truncated).  ystore_fstab():
 * fstab(5)'s text and its SHA-256, malloc'd.  ystore_fstab_put(): text
 * put in its place, sha256 that of the one it was made from (only
 * checked with dry_run), *newsha the SHA-256 now, malloc'd.  ystore_key():
 * a dataset's key loaded (key), changed (new_key, loaded first with key
 * where it is not), or, with create (its encryption), the dataset made
 * encrypted with new_key.
 */
int	ystore_read(cbl_conn *conn, int kind, const char *filter,
	    const char *jail, ucl_object_t **data, uint64_t *total,
	    bool *truncated, char *err, size_t errlen);
int	ystore_fstab(cbl_conn *conn, char **text, char **sha256, char *err,
	    size_t errlen);
int	ystore_fstab_put(cbl_conn *conn, const char *text, const char *sha256,
	    bool dry_run, char **newsha, char *err, size_t errlen);
int	ystore_key(cbl_conn *conn, const char *dataset, const char *key,
	    const char *new_key, const char *create, char *err, size_t errlen);

#endif	/* !_ARCANA_YSTORE_H_ */
