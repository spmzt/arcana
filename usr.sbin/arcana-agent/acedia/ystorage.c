/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Acedia: the storage as arcana-storage has it (PLAN-SDN-YANG 3.1.5),
 * typed lists where the storage operation gives a JSON object of each
 * kind (storage.c, health.c): each kind's object read back and put in
 * its place; health's on its disk.  fstab(5)'s text and its SHA-256 are
 * the fstab operation's.
 */

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include <arcana.h>
#include <ucl.h>

#include "collect.h"

typedef struct arcana_storage_storage ystorage;

/* A string of o's, the arena's; NULL: none. */
static const char *
s(cbl_yarena *a, const ucl_object_t *o, const char *key)
{
	const ucl_object_t *v = ucl_object_lookup(o, key);
	const char *t;
	size_t len;
	char *p;

	if (v == NULL || ucl_object_type(v) != UCL_STRING ||
	    (t = ucl_object_tostring(v)) == NULL)
		return (NULL);
	len = strlen(t) + 1;
	if ((p = cbl_yarena_alloc(a, len)) != NULL)
		memcpy(p, t, len);
	return (p);
}

/* A number of o's; false: none. */
static bool
n(const ucl_object_t *o, const char *key, int64_t *v)
{
	const ucl_object_t *x = ucl_object_lookup(o, key);

	if (x == NULL || (ucl_object_type(x) != UCL_INT &&
	    ucl_object_type(x) != UCL_FLOAT))
		return (false);
	*v = ucl_object_toint(x);
	return (true);
}

#define	NUM(o, key, y, f)	do {					\
	int64_t v_;							\
									\
	if (((y)->has_##f = n((o), (key), &v_)))			\
		(y)->f = (__typeof__((y)->f))v_;			\
} while (0)

/* "yes", "on": true; "no", "off": false; else none. */
static bool
yes(const ucl_object_t *o, const char *key, bool *has)
{
	const ucl_object_t *x = ucl_object_lookup(o, key);
	const char *t;

	*has = false;
	if (x == NULL)
		return (false);
	if (ucl_object_type(x) == UCL_BOOLEAN) {
		*has = true;
		return (ucl_object_toboolean(x));
	}
	if ((t = ucl_object_tostring(x)) == NULL)
		return (false);
	if (strcmp(t, "yes") == 0 || strcmp(t, "on") == 0) {
		*has = true;
		return (true);
	}
	if (strcmp(t, "no") == 0 || strcmp(t, "off") == 0)
		*has = true;
	return (false);
}

static size_t
count(const ucl_object_t *arr)
{

	return (arr != NULL && ucl_object_type(arr) == UCL_ARRAY ?
	    arr->len : 0);
}

#define	EACH(arr, it, e)	\
	for ((it) = NULL; ((e) = ucl_object_iterate((arr), &(it), true)) != NULL;)

static int
disks(const ucl_object_t *top, cbl_yarena *a, ystorage *st)
{
	const ucl_object_t *arr = ucl_object_lookup(top, "disks"), *d, *p;
	struct arcana_storage_storage_disk *v;
	ucl_object_iter_t it, pit;
	size_t i = 0;

	if (count(arr) == 0)
		return (0);
	if ((v = cbl_yarena_alloc(a, count(arr) * sizeof(*v))) == NULL)
		return (ENOMEM);
	EACH(arr, it, d) {
		struct arcana_storage_storage_disk *y = &v[i++];
		struct arcana_storage_storage_disk_partition *pv = NULL;
		const ucl_object_t *parts = ucl_object_lookup(d, "parts");
		size_t k = 0;

		memset(y, 0, sizeof(*y));
		y->name = s(a, d, "name");
		NUM(d, "size", y, size);
		NUM(d, "sectorsize", y, sectorsize);
		y->ident = s(a, d, "ident");
		y->descr = s(a, d, "descr");
		y->rotation = s(a, d, "rotation");
		y->cam = s(a, d, "cam");
		y->scheme = s(a, d, "scheme");
		NUM(d, "first", y, first);
		NUM(d, "last", y, last);
		if (count(parts) > 0 && (pv = cbl_yarena_alloc(a, count(parts) *
		    sizeof(*pv))) == NULL)
			return (ENOMEM);
		EACH(parts, pit, p) {
			struct arcana_storage_storage_disk_partition *q =
			    &pv[k++];

			memset(q, 0, sizeof(*q));
			q->name = s(a, p, "name");
			NUM(p, "index", q, index);
			NUM(p, "size", q, size);
			q->type = s(a, p, "type");
			q->label = s(a, p, "label");
			NUM(p, "start", q, start);
			NUM(p, "end", q, end);
		}
		y->partition.n = k;
		y->partition.v = pv;
	}
	st->disk.n = i;
	st->disk.v = v;
	return (0);
}

/* Health's disks, each put on its disk; one not listed added. */
static int
health(const ucl_object_t *top, cbl_yarena *a, ystorage *st)
{
	const ucl_object_t *arr = ucl_object_lookup(top, "disks"), *d;
	struct arcana_storage_storage_disk *v;
	ucl_object_iter_t it;
	size_t nd = st->disk.n;

	if ((v = cbl_yarena_alloc(a, (nd + count(arr) + 1) * sizeof(*v))) ==
	    NULL)
		return (ENOMEM);
	if (nd > 0)
		memcpy(v, st->disk.v, nd * sizeof(*v));
	EACH(arr, it, d) {
		struct arcana_storage_storage_disk_health *h;
		const char *name = s(a, d, "name");
		size_t k;
		bool has;

		if (name == NULL)
			continue;
		for (k = 0; k < nd && strcmp(v[k].name, name) != 0; k++)
			;
		if (k == nd) {
			memset(&v[nd], 0, sizeof(v[nd]));
			v[nd++].name = name;
		}
		if ((h = cbl_yarena_alloc(a, sizeof(*h))) == NULL)
			return (ENOMEM);
		memset(h, 0, sizeof(*h));
		h->by = s(a, d, "by");
		h->ok = yes(d, "ok", &has);
		h->has_ok = has;
		NUM(d, "temperature", h, temperature);
		NUM(d, "power_on_hours", h, power_on_hours);
		NUM(d, "power_cycles", h, power_cycles);
		NUM(d, "used_pct", h, used_pct);
		NUM(d, "spare_pct", h, spare_pct);
		NUM(d, "media_errors", h, media_errors);
		NUM(d, "unsafe_shutdowns", h, unsafe_shutdowns);
		NUM(d, "reallocated", h, reallocated);
		NUM(d, "pending", h, pending);
		NUM(d, "uncorrectable", h, uncorrectable);
		NUM(d, "crc_errors", h, crc_errors);
		NUM(d, "wear_level", h, wear_level);
		NUM(d, "life_left", h, life_left);
		NUM(d, "media_wearout", h, media_wearout);
		h->note = s(a, d, "note");
		v[k].health = h;
	}
	st->disk.n = nd;
	st->disk.v = v;
	return (0);
}

static int
pools(const ucl_object_t *top, cbl_yarena *a, ystorage *st)
{
	const ucl_object_t *arr = ucl_object_lookup(top, "pools"), *p, *d;
	struct arcana_storage_storage_pool *v;
	ucl_object_iter_t it, vit;
	size_t i = 0;

	if (count(arr) == 0)
		return (0);
	if ((v = cbl_yarena_alloc(a, count(arr) * sizeof(*v))) == NULL)
		return (ENOMEM);
	EACH(arr, it, p) {
		struct arcana_storage_storage_pool *y = &v[i++];
		struct arcana_storage_storage_pool_vdev *dv = NULL;
		const ucl_object_t *vd = ucl_object_lookup(p, "vdevs");
		size_t k = 0;

		memset(y, 0, sizeof(*y));
		y->name = s(a, p, "name");
		NUM(p, "size", y, size);
		NUM(p, "alloc", y, alloc);
		NUM(p, "free", y, free);
		NUM(p, "frag", y, frag);
		NUM(p, "cap", y, cap);
		y->dedup = s(a, p, "dedup");
		y->health = s(a, p, "health");
		y->state = s(a, p, "state");
		y->status = s(a, p, "status");
		y->action = s(a, p, "action");
		y->scan = s(a, p, "scan");
		y->errors = s(a, p, "errors");
		y->see = s(a, p, "see");
		if (count(vd) > 0 && (dv = cbl_yarena_alloc(a, count(vd) *
		    sizeof(*dv))) == NULL)
			return (ENOMEM);
		EACH(vd, vit, d) {
			struct arcana_storage_storage_pool_vdev *q = &dv[k++];

			memset(q, 0, sizeof(*q));
			q->name = s(a, d, "name");
			NUM(d, "depth", q, depth);
			q->state = s(a, d, "state");
			q->read = s(a, d, "read");
			q->write = s(a, d, "write");
			q->cksum = s(a, d, "cksum");
			q->note = s(a, d, "note");
		}
		y->vdev.n = k;
		y->vdev.v = dv;
	}
	st->pool.n = i;
	st->pool.v = v;
	return (0);
}

static int
importable(const ucl_object_t *top, cbl_yarena *a, ystorage *st)
{
	const ucl_object_t *arr = ucl_object_lookup(top, "importable"), *p;
	struct arcana_storage_storage_importable *v;
	ucl_object_iter_t it;
	size_t i = 0;

	if (count(arr) == 0)
		return (0);
	if ((v = cbl_yarena_alloc(a, count(arr) * sizeof(*v))) == NULL)
		return (ENOMEM);
	EACH(arr, it, p) {
		memset(&v[i], 0, sizeof(v[i]));
		v[i].id = s(a, p, "id");
		v[i].name = s(a, p, "name");
		v[i].state = s(a, p, "state");
		v[i++].status = s(a, p, "status");
	}
	st->importable.n = i;
	st->importable.v = v;
	return (0);
}

/* "1.78" in hundredths. */
static bool
hundredths(const char *t, int64_t *v)
{
	char *end;
	double d;

	if (t == NULL)
		return (false);
	d = strtod(t, &end);
	if (end == t)
		return (false);
	*v = (int64_t)(d * 100 + (d < 0 ? -0.5 : 0.5));
	return (true);
}

static int
datasets(const ucl_object_t *top, cbl_yarena *a, ystorage *st,
    uint64_t total, bool truncated)
{
	const ucl_object_t *arr = ucl_object_lookup(top, "datasets"), *d;
	struct arcana_storage_storage_dataset *v;
	ucl_object_iter_t it;
	size_t i = 0;

	if ((st->has_datasets_total = truncated))
		st->datasets_total = total;
	if (count(arr) == 0)
		return (0);
	if ((v = cbl_yarena_alloc(a, count(arr) * sizeof(*v))) == NULL)
		return (ENOMEM);
	EACH(arr, it, d) {
		struct arcana_storage_storage_dataset *y = &v[i++];
		const char *t;
		bool has;

		memset(y, 0, sizeof(*y));
		y->name = s(a, d, "name");
		if ((t = s(a, d, "type")) != NULL) {
			y->has_type = strcmp(t, "filesystem") == 0 ||
			    strcmp(t, "volume") == 0;
			y->type = strcmp(t, "volume") == 0 ?
			    ARCANA_STORAGE_STORAGE_DATASET_TYPE_VOLUME :
			    ARCANA_STORAGE_STORAGE_DATASET_TYPE_FILESYSTEM;
		}
		NUM(d, "used", y, used);
		NUM(d, "avail", y, avail);
		NUM(d, "refer", y, refer);
		NUM(d, "quota", y, quota);
		NUM(d, "reservation", y, reservation);
		y->mountpoint = s(a, d, "mountpoint");
		y->mounted = yes(d, "mounted", &has);
		y->has_mounted = has;
		if ((t = s(a, d, "canmount")) != NULL) {
			y->has_canmount = true;
			y->canmount = strcmp(t, "off") == 0 ?
			    ARCANA_STORAGE_STORAGE_DATASET_CANMOUNT_OFF :
			    strcmp(t, "noauto") == 0 ?
			    ARCANA_STORAGE_STORAGE_DATASET_CANMOUNT_NOAUTO :
			    ARCANA_STORAGE_STORAGE_DATASET_CANMOUNT_ON;
		}
		y->compression = s(a, d, "compression");
		y->has_ratio = hundredths(s(a, d, "ratio"), &y->ratio);
		y->readonly = yes(d, "readonly", &has);
		y->has_readonly = has;
		y->encryption = s(a, d, "encryption");
		y->keylocation = s(a, d, "keylocation");
		y->jailed = yes(d, "jailed", &has);
		y->has_jailed = has;
		y->origin = s(a, d, "origin");
	}
	st->dataset.n = i;
	st->dataset.v = v;
	return (0);
}

static int
snapshots(const ucl_object_t *top, cbl_yarena *a, ystorage *st,
    uint64_t total, bool truncated)
{
	const ucl_object_t *arr = ucl_object_lookup(top, "snapshots"), *d;
	struct arcana_storage_storage_snapshot *v;
	ucl_object_iter_t it;
	size_t i = 0;

	if ((st->has_snapshots_total = truncated))
		st->snapshots_total = total;
	if (count(arr) == 0)
		return (0);
	if ((v = cbl_yarena_alloc(a, count(arr) * sizeof(*v))) == NULL)
		return (ENOMEM);
	EACH(arr, it, d) {
		struct arcana_storage_storage_snapshot *y = &v[i++];

		memset(y, 0, sizeof(*y));
		y->name = s(a, d, "name");
		NUM(d, "used", y, used);
		NUM(d, "refer", y, refer);
		NUM(d, "creation", y, creation);
	}
	st->snapshot.n = i;
	st->snapshot.v = v;
	return (0);
}

static int
mounts(const ucl_object_t *top, cbl_yarena *a, ystorage *st)
{
	const ucl_object_t *arr, *d;
	struct arcana_storage_storage_mount *mv = NULL;
	struct arcana_storage_storage_fstab_entry *fv = NULL;
	struct arcana_storage_storage_swap *sv = NULL;
	struct arcana_storage_storage_fstab *fs;
	ucl_object_iter_t it;
	size_t i;

	arr = ucl_object_lookup(top, "mounts");
	if (count(arr) > 0 && (mv = cbl_yarena_alloc(a, count(arr) *
	    sizeof(*mv))) == NULL)
		return (ENOMEM);
	i = 0;
	EACH(arr, it, d) {
		struct arcana_storage_storage_mount *y = &mv[i++];

		memset(y, 0, sizeof(*y));
		y->from = s(a, d, "from");
		y->on = s(a, d, "on");
		y->type = s(a, d, "type");
		y->options = s(a, d, "options");
		NUM(d, "size", y, size);
		NUM(d, "used", y, used);
		NUM(d, "avail", y, avail);
	}
	st->mount.n = i;
	st->mount.v = mv;
	arr = ucl_object_lookup(top, "fstab");
	if ((fs = cbl_yarena_alloc(a, sizeof(*fs))) == NULL ||
	    (count(arr) > 0 && (fv = cbl_yarena_alloc(a, count(arr) *
	    sizeof(*fv))) == NULL))
		return (ENOMEM);
	if (st->fstab != NULL)
		*fs = *st->fstab;
	else
		memset(fs, 0, sizeof(*fs));
	i = 0;
	EACH(arr, it, d) {
		struct arcana_storage_storage_fstab_entry *y = &fv[i++];
		bool has;

		memset(y, 0, sizeof(*y));
		y->spec = s(a, d, "spec");
		y->file = s(a, d, "file");
		y->vfstype = s(a, d, "vfstype");
		y->mntops = s(a, d, "mntops");
		y->type = s(a, d, "type");
		NUM(d, "freq", y, freq);
		NUM(d, "passno", y, passno);
		y->mounted = yes(d, "mounted", &has);
		y->has_mounted = has;
	}
	fs->entry.n = i;
	fs->entry.v = fv;
	st->fstab = fs;
	arr = ucl_object_lookup(top, "swap");
	if (count(arr) > 0 && (sv = cbl_yarena_alloc(a, count(arr) *
	    sizeof(*sv))) == NULL)
		return (ENOMEM);
	i = 0;
	EACH(arr, it, d) {
		struct arcana_storage_storage_swap *y = &sv[i++];

		memset(y, 0, sizeof(*y));
		y->device = s(a, d, "device");
		NUM(d, "size", y, size);
		NUM(d, "used", y, used);
	}
	st->swap.n = i;
	st->swap.v = sv;
	return (0);
}

/*
 * The storage operation's reply of kind (ARC_STORAGE_KIND_*), its JSON,
 * put in st (the others' parts kept); total and truncated as the reply
 * has them.  EINVAL: no JSON object.
 */
int
ystorage_from_json(int kind, const char *json, uint64_t total,
    bool truncated, cbl_yarena *a, struct arcana_storage_storage *st)
{
	struct ucl_parser *p;
	ucl_object_t *top;
	int error;

	if (json == NULL || (p = ucl_parser_new(UCL_PARSER_NO_TIME)) == NULL)
		return (EINVAL);
	if (!ucl_parser_add_string(p, json, 0) ||
	    (top = ucl_parser_get_object(p)) == NULL) {
		ucl_parser_free(p);
		return (EINVAL);
	}
	ucl_parser_free(p);
	switch (kind) {
	case ARC_STORAGE_KIND_DISKS:
		error = disks(top, a, st);
		break;
	case ARC_STORAGE_KIND_POOLS:
		error = pools(top, a, st);
		break;
	case ARC_STORAGE_KIND_DATASETS:
		error = datasets(top, a, st, total, truncated);
		break;
	case ARC_STORAGE_KIND_SNAPSHOTS:
		error = snapshots(top, a, st, total, truncated);
		break;
	case ARC_STORAGE_KIND_MOUNTS:
		error = mounts(top, a, st);
		break;
	case ARC_STORAGE_KIND_IMPORTABLE:
		error = importable(top, a, st);
		break;
	case ARC_STORAGE_KIND_HEALTH:
		error = health(top, a, st);
		break;
	default:
		error = EINVAL;
		break;
	}
	ucl_object_unref(top);
	return (error);
}

/* fstab(5)'s text and its SHA-256, as the fstab operation reads them. */
int
ystorage_fstab(const char *text, const char *sha256, cbl_yarena *a,
    struct arcana_storage_storage *st)
{
	struct arcana_storage_storage_fstab *fs;

	if ((fs = cbl_yarena_alloc(a, sizeof(*fs))) == NULL)
		return (ENOMEM);
	if (st->fstab != NULL)
		*fs = *st->fstab;
	else
		memset(fs, 0, sizeof(*fs));
	fs->text = text;
	fs->sha256 = sha256;
	st->fstab = fs;
	return (0);
}
