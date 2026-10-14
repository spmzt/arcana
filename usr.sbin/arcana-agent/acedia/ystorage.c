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

#include "collect.h"
#include "yjson.h"

typedef struct arcana_storage_storage ystorage;

static int
disks(const ucl_object_t *top, cbl_yarena *a, ystorage *st)
{
	const ucl_object_t *arr = ucl_object_lookup(top, "disks"), *d, *p;
	struct arcana_storage_storage_disk *v;
	ucl_object_iter_t it, pit;
	size_t i = 0;

	if (yj_count(arr) == 0)
		return (0);
	if ((v = cbl_yarena_alloc(a, yj_count(arr) * sizeof(*v))) == NULL)
		return (ENOMEM);
	YJ_EACH(arr, it, d) {
		struct arcana_storage_storage_disk *y = &v[i++];
		struct arcana_storage_storage_disk_partition *pv = NULL;
		const ucl_object_t *parts = ucl_object_lookup(d, "parts");
		size_t k = 0;

		memset(y, 0, sizeof(*y));
		y->name = yj_str(a, d, "name");
		YJ_NUM(d, "size", y, size);
		YJ_NUM(d, "sectorsize", y, sectorsize);
		y->ident = yj_str(a, d, "ident");
		y->descr = yj_str(a, d, "descr");
		y->rotation = yj_str(a, d, "rotation");
		y->cam = yj_str(a, d, "cam");
		y->scheme = yj_str(a, d, "scheme");
		YJ_NUM(d, "first", y, first);
		YJ_NUM(d, "last", y, last);
		if (yj_count(parts) > 0 && (pv = cbl_yarena_alloc(a, yj_count(parts) *
		    sizeof(*pv))) == NULL)
			return (ENOMEM);
		YJ_EACH(parts, pit, p) {
			struct arcana_storage_storage_disk_partition *q =
			    &pv[k++];

			memset(q, 0, sizeof(*q));
			q->name = yj_str(a, p, "name");
			YJ_NUM(p, "index", q, index);
			YJ_NUM(p, "size", q, size);
			q->type = yj_str(a, p, "type");
			q->label = yj_str(a, p, "label");
			YJ_NUM(p, "start", q, start);
			YJ_NUM(p, "end", q, end);
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

	if ((v = cbl_yarena_alloc(a, (nd + yj_count(arr) + 1) * sizeof(*v))) ==
	    NULL)
		return (ENOMEM);
	if (nd > 0)
		memcpy(v, st->disk.v, nd * sizeof(*v));
	YJ_EACH(arr, it, d) {
		struct arcana_storage_storage_disk_health *h;
		const char *name = yj_str(a, d, "name");
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
		h->by = yj_str(a, d, "by");
		h->ok = yj_yes(d, "ok", &has);
		h->has_ok = has;
		YJ_NUM(d, "temperature", h, temperature);
		YJ_NUM(d, "power_on_hours", h, power_on_hours);
		YJ_NUM(d, "power_cycles", h, power_cycles);
		YJ_NUM(d, "used_pct", h, used_pct);
		YJ_NUM(d, "spare_pct", h, spare_pct);
		YJ_NUM(d, "media_errors", h, media_errors);
		YJ_NUM(d, "unsafe_shutdowns", h, unsafe_shutdowns);
		YJ_NUM(d, "reallocated", h, reallocated);
		YJ_NUM(d, "pending", h, pending);
		YJ_NUM(d, "uncorrectable", h, uncorrectable);
		YJ_NUM(d, "crc_errors", h, crc_errors);
		YJ_NUM(d, "wear_level", h, wear_level);
		YJ_NUM(d, "life_left", h, life_left);
		YJ_NUM(d, "media_wearout", h, media_wearout);
		h->note = yj_str(a, d, "note");
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

	if (yj_count(arr) == 0)
		return (0);
	if ((v = cbl_yarena_alloc(a, yj_count(arr) * sizeof(*v))) == NULL)
		return (ENOMEM);
	YJ_EACH(arr, it, p) {
		struct arcana_storage_storage_pool *y = &v[i++];
		struct arcana_storage_storage_pool_vdev *dv = NULL;
		const ucl_object_t *vd = ucl_object_lookup(p, "vdevs");
		size_t k = 0;

		memset(y, 0, sizeof(*y));
		y->name = yj_str(a, p, "name");
		YJ_NUM(p, "size", y, size);
		YJ_NUM(p, "alloc", y, alloc);
		YJ_NUM(p, "free", y, free);
		YJ_NUM(p, "frag", y, frag);
		YJ_NUM(p, "cap", y, cap);
		y->dedup = yj_str(a, p, "dedup");
		y->health = yj_str(a, p, "health");
		y->state = yj_str(a, p, "state");
		y->status = yj_str(a, p, "status");
		y->action = yj_str(a, p, "action");
		y->scan = yj_str(a, p, "scan");
		y->errors = yj_str(a, p, "errors");
		y->see = yj_str(a, p, "see");
		if (yj_count(vd) > 0 && (dv = cbl_yarena_alloc(a, yj_count(vd) *
		    sizeof(*dv))) == NULL)
			return (ENOMEM);
		YJ_EACH(vd, vit, d) {
			struct arcana_storage_storage_pool_vdev *q = &dv[k++];

			memset(q, 0, sizeof(*q));
			q->name = yj_str(a, d, "name");
			YJ_NUM(d, "depth", q, depth);
			q->state = yj_str(a, d, "state");
			q->read = yj_str(a, d, "read");
			q->write = yj_str(a, d, "write");
			q->cksum = yj_str(a, d, "cksum");
			q->note = yj_str(a, d, "note");
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

	if (yj_count(arr) == 0)
		return (0);
	if ((v = cbl_yarena_alloc(a, yj_count(arr) * sizeof(*v))) == NULL)
		return (ENOMEM);
	YJ_EACH(arr, it, p) {
		memset(&v[i], 0, sizeof(v[i]));
		v[i].id = yj_str(a, p, "id");
		v[i].name = yj_str(a, p, "name");
		v[i].state = yj_str(a, p, "state");
		v[i++].status = yj_str(a, p, "status");
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
	if (yj_count(arr) == 0)
		return (0);
	if ((v = cbl_yarena_alloc(a, yj_count(arr) * sizeof(*v))) == NULL)
		return (ENOMEM);
	YJ_EACH(arr, it, d) {
		struct arcana_storage_storage_dataset *y = &v[i++];
		const char *t;
		bool has;

		memset(y, 0, sizeof(*y));
		y->name = yj_str(a, d, "name");
		if ((t = yj_str(a, d, "type")) != NULL) {
			y->has_type = strcmp(t, "filesystem") == 0 ||
			    strcmp(t, "volume") == 0;
			y->type = strcmp(t, "volume") == 0 ?
			    ARCANA_STORAGE_STORAGE_DATASET_TYPE_VOLUME :
			    ARCANA_STORAGE_STORAGE_DATASET_TYPE_FILESYSTEM;
		}
		YJ_NUM(d, "used", y, used);
		YJ_NUM(d, "avail", y, avail);
		YJ_NUM(d, "refer", y, refer);
		YJ_NUM(d, "quota", y, quota);
		YJ_NUM(d, "reservation", y, reservation);
		y->mountpoint = yj_str(a, d, "mountpoint");
		y->mounted = yj_yes(d, "mounted", &has);
		y->has_mounted = has;
		if ((t = yj_str(a, d, "canmount")) != NULL) {
			y->has_canmount = true;
			y->canmount = strcmp(t, "off") == 0 ?
			    ARCANA_STORAGE_STORAGE_DATASET_CANMOUNT_OFF :
			    strcmp(t, "noauto") == 0 ?
			    ARCANA_STORAGE_STORAGE_DATASET_CANMOUNT_NOAUTO :
			    ARCANA_STORAGE_STORAGE_DATASET_CANMOUNT_ON;
		}
		y->compression = yj_str(a, d, "compression");
		y->has_ratio = hundredths(yj_str(a, d, "ratio"), &y->ratio);
		y->readonly = yj_yes(d, "readonly", &has);
		y->has_readonly = has;
		y->encryption = yj_str(a, d, "encryption");
		y->keylocation = yj_str(a, d, "keylocation");
		y->jailed = yj_yes(d, "jailed", &has);
		y->has_jailed = has;
		y->origin = yj_str(a, d, "origin");
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
	if (yj_count(arr) == 0)
		return (0);
	if ((v = cbl_yarena_alloc(a, yj_count(arr) * sizeof(*v))) == NULL)
		return (ENOMEM);
	YJ_EACH(arr, it, d) {
		struct arcana_storage_storage_snapshot *y = &v[i++];

		memset(y, 0, sizeof(*y));
		y->name = yj_str(a, d, "name");
		YJ_NUM(d, "used", y, used);
		YJ_NUM(d, "refer", y, refer);
		YJ_NUM(d, "creation", y, creation);
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
	if (yj_count(arr) > 0 && (mv = cbl_yarena_alloc(a, yj_count(arr) *
	    sizeof(*mv))) == NULL)
		return (ENOMEM);
	i = 0;
	YJ_EACH(arr, it, d) {
		struct arcana_storage_storage_mount *y = &mv[i++];

		memset(y, 0, sizeof(*y));
		y->from = yj_str(a, d, "from");
		y->on = yj_str(a, d, "on");
		y->type = yj_str(a, d, "type");
		y->options = yj_str(a, d, "options");
		YJ_NUM(d, "size", y, size);
		YJ_NUM(d, "used", y, used);
		YJ_NUM(d, "avail", y, avail);
	}
	st->mount.n = i;
	st->mount.v = mv;
	arr = ucl_object_lookup(top, "fstab");
	if ((fs = cbl_yarena_alloc(a, sizeof(*fs))) == NULL ||
	    (yj_count(arr) > 0 && (fv = cbl_yarena_alloc(a, yj_count(arr) *
	    sizeof(*fv))) == NULL))
		return (ENOMEM);
	if (st->fstab != NULL)
		*fs = *st->fstab;
	else
		memset(fs, 0, sizeof(*fs));
	i = 0;
	YJ_EACH(arr, it, d) {
		struct arcana_storage_storage_fstab_entry *y = &fv[i++];
		bool has;

		memset(y, 0, sizeof(*y));
		y->spec = yj_str(a, d, "spec");
		y->file = yj_str(a, d, "file");
		y->vfstype = yj_str(a, d, "vfstype");
		y->mntops = yj_str(a, d, "mntops");
		y->type = yj_str(a, d, "type");
		YJ_NUM(d, "freq", y, freq);
		YJ_NUM(d, "passno", y, passno);
		y->mounted = yj_yes(d, "mounted", &has);
		y->has_mounted = has;
	}
	fs->entry.n = i;
	fs->entry.v = fv;
	st->fstab = fs;
	arr = ucl_object_lookup(top, "swap");
	if (yj_count(arr) > 0 && (sv = cbl_yarena_alloc(a, yj_count(arr) *
	    sizeof(*sv))) == NULL)
		return (ENOMEM);
	i = 0;
	YJ_EACH(arr, it, d) {
		struct arcana_storage_storage_swap *y = &sv[i++];

		memset(y, 0, sizeof(*y));
		y->device = yj_str(a, d, "device");
		YJ_NUM(d, "size", y, size);
		YJ_NUM(d, "used", y, used);
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
	ucl_object_t *top;
	int error;

	if ((top = yj_parse(json)) == NULL)
		return (EINVAL);
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
