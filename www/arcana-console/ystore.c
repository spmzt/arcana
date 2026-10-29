/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * An agent's storage through arcana-storage (PLAN-SDN-YANG 3.1.5), for
 * the console and arcanactl: a part of it by the storage's read action,
 * made the JSON the storage operation gave (the agent's storage.c and
 * health.c), so that the pages keep reading what they read; fstab(5)
 * read and put in place by its replace action; a dataset's key by its
 * load-key and change-key actions, or the storage's create-encrypted.
 */

#include <sys/param.h>

#include <errno.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <cblink.h>
#include <cbl_schema.h>
#include <ucl.h>

#include "ymodel.h"
#include "yqueue.h"
#include "ystore.h"

typedef struct arcana_storage_storage_read_output yread;

static void
put(ucl_object_t *o, const char *key, ucl_object_t *v)
{

	ucl_object_insert_key(o, v, key, 0, true);
}

static void
put_str(ucl_object_t *o, const char *key, const char *v)
{

	if (v != NULL)
		put(o, key, ucl_object_fromstring(v));
}

#define	PUT_NUM(o, key, y, m) do {					\
	if ((y)->has_##m)						\
		put((o), (key), ucl_object_fromint((int64_t)(y)->m));	\
} while (0)

static void
put_yes(ucl_object_t *o, const char *key, bool has, bool v, const char *yes,
    const char *no)
{

	if (has)
		put(o, key, ucl_object_fromstring(v ? yes : no));
}

static ucl_object_t *
disks_of(const yread *r)
{
	ucl_object_t	*arr, *o, *parts, *p;

	arr = ucl_object_typed_new(UCL_ARRAY);
	for (size_t i = 0; i < r->disk.n; i++) {
		const struct arcana_storage_disk *d = &r->disk.v[i];

		o = ucl_object_typed_new(UCL_OBJECT);
		put_str(o, "name", d->name);
		PUT_NUM(o, "size", d, size);
		PUT_NUM(o, "sectorsize", d, sectorsize);
		put_str(o, "ident", d->ident);
		put_str(o, "descr", d->descr);
		put_str(o, "rotation", d->rotation);
		put_str(o, "cam", d->cam);
		put_str(o, "scheme", d->scheme);
		PUT_NUM(o, "first", d, first);
		PUT_NUM(o, "last", d, last);
		parts = ucl_object_typed_new(UCL_ARRAY);
		for (size_t k = 0; k < d->partition.n; k++) {
			const struct arcana_storage_disk_partition *q =
			    &d->partition.v[k];

			p = ucl_object_typed_new(UCL_OBJECT);
			put_str(p, "name", q->name);
			PUT_NUM(p, "index", q, index);
			put_str(p, "type", q->type);
			put_str(p, "label", q->label);
			PUT_NUM(p, "start", q, start);
			PUT_NUM(p, "end", q, end);
			PUT_NUM(p, "size", q, size);
			put_str(p, "mounted", q->mounted);
			ucl_array_append(parts, p);
		}
		put(o, "parts", parts);
		ucl_array_append(arr, o);
	}
	return (arr);
}

/* How each disk says it is, health's own rows. */
static ucl_object_t *
health_of(const yread *r)
{
	ucl_object_t	*arr, *o;

	arr = ucl_object_typed_new(UCL_ARRAY);
	for (size_t i = 0; i < r->disk.n; i++) {
		const struct arcana_storage_disk_health *h =
		    r->disk.v[i].health;

		if (h == NULL)
			continue;
		o = ucl_object_typed_new(UCL_OBJECT);
		put_str(o, "name", r->disk.v[i].name);
		put_str(o, "by", h->by);
		if (h->has_ok)
			put(o, "ok", ucl_object_frombool(h->ok));
		PUT_NUM(o, "temperature", h, temperature);
		/* In the order each tool's reading put them. */
		if (h->by != NULL && strcmp(h->by, "nvmecontrol") == 0) {
			PUT_NUM(o, "spare_pct", h, spare_pct);
			PUT_NUM(o, "used_pct", h, used_pct);
			PUT_NUM(o, "power_on_hours", h, power_on_hours);
			PUT_NUM(o, "unsafe_shutdowns", h, unsafe_shutdowns);
			PUT_NUM(o, "media_errors", h, media_errors);
			PUT_NUM(o, "power_cycles", h, power_cycles);
		} else {
			PUT_NUM(o, "power_on_hours", h, power_on_hours);
			PUT_NUM(o, "power_cycles", h, power_cycles);
		}
		PUT_NUM(o, "reallocated", h, reallocated);
		PUT_NUM(o, "pending", h, pending);
		PUT_NUM(o, "uncorrectable", h, uncorrectable);
		PUT_NUM(o, "crc_errors", h, crc_errors);
		PUT_NUM(o, "wear_level", h, wear_level);
		PUT_NUM(o, "life_left", h, life_left);
		PUT_NUM(o, "media_wearout", h, media_wearout);
		put_str(o, "note", h->note);
		ucl_array_append(arr, o);
	}
	return (arr);
}

static ucl_object_t *
pools_of(const yread *r)
{
	ucl_object_t	*arr, *o, *vd, *v;

	arr = ucl_object_typed_new(UCL_ARRAY);
	for (size_t i = 0; i < r->pool.n; i++) {
		const struct arcana_storage_pool *p = &r->pool.v[i];

		o = ucl_object_typed_new(UCL_OBJECT);
		put_str(o, "name", p->name);
		PUT_NUM(o, "size", p, size);
		PUT_NUM(o, "alloc", p, alloc);
		PUT_NUM(o, "free", p, free);
		PUT_NUM(o, "frag", p, frag);
		PUT_NUM(o, "cap", p, cap);
		put_str(o, "dedup", p->dedup);
		put_str(o, "health", p->health);
		put_str(o, "state", p->state);
		put_str(o, "status", p->status);
		put_str(o, "action", p->action);
		put_str(o, "scan", p->scan);
		put_str(o, "errors", p->errors);
		put_str(o, "see", p->see);
		vd = ucl_object_typed_new(UCL_ARRAY);
		for (size_t k = 0; k < p->vdev.n; k++) {
			const struct arcana_storage_pool_vdev *d =
			    &p->vdev.v[k];

			v = ucl_object_typed_new(UCL_OBJECT);
			put_str(v, "name", d->name);
			PUT_NUM(v, "depth", d, depth);
			put_str(v, "state", d->state);
			put_str(v, "read", d->read);
			put_str(v, "write", d->write);
			put_str(v, "cksum", d->cksum);
			put_str(v, "note", d->note);
			ucl_array_append(vd, v);
		}
		put(o, "vdevs", vd);
		ucl_array_append(arr, o);
	}
	return (arr);
}

static ucl_object_t *
importable_of(const yread *r)
{
	ucl_object_t	*arr, *o;

	arr = ucl_object_typed_new(UCL_ARRAY);
	for (size_t i = 0; i < r->importable.n; i++) {
		o = ucl_object_typed_new(UCL_OBJECT);
		put_str(o, "name", r->importable.v[i].name);
		put_str(o, "id", r->importable.v[i].id);
		put_str(o, "state", r->importable.v[i].state);
		put_str(o, "status", r->importable.v[i].status);
		ucl_array_append(arr, o);
	}
	return (arr);
}

/*
 * The datasets, their words as zfs list -p prints them: mounted yes or
 * no, readonly and jailed on or off, the ratio with two digits.
 */
static ucl_object_t *
datasets_of(const yread *r)
{
	static const char *const canmount[] = { "on", "off", "noauto" };
	ucl_object_t	*arr, *o;
	char		 ratio[32];

	arr = ucl_object_typed_new(UCL_ARRAY);
	for (size_t i = 0; i < r->dataset.n; i++) {
		const struct arcana_storage_storage_read_output_dataset *d =
		    &r->dataset.v[i];

		o = ucl_object_typed_new(UCL_OBJECT);
		put_str(o, "name", d->name);
		if (d->has_type)
			put_str(o, "type", d->type ==
			    ARCANA_STORAGE_STORAGE_READ_OUTPUT_DATASET_TYPE_VOLUME ?
			    "volume" : "filesystem");
		PUT_NUM(o, "used", d, used);
		PUT_NUM(o, "avail", d, avail);
		PUT_NUM(o, "refer", d, refer);
		put_str(o, "mountpoint", d->mountpoint);
		put_str(o, "compression", d->compression);
		if (d->has_ratio) {
			snprintf(ratio, sizeof(ratio), "%" PRId64 ".%02" PRId64,
			    d->ratio / 100, d->ratio % 100);
			put_str(o, "ratio", ratio);
		}
		PUT_NUM(o, "quota", d, quota);
		PUT_NUM(o, "reservation", d, reservation);
		put_yes(o, "mounted", d->has_mounted, d->mounted, "yes", "no");
		if (d->has_canmount && (size_t)d->canmount < nitems(canmount))
			put_str(o, "canmount", canmount[d->canmount]);
		put_str(o, "origin", d->origin);
		PUT_NUM(o, "volsize", d, volsize);
		put_yes(o, "readonly", d->has_readonly, d->readonly, "on",
		    "off");
		put_str(o, "encryption", d->encryption);
		put_str(o, "keystatus", d->keystatus);
		put_str(o, "keylocation", d->keylocation);
		put_yes(o, "jailed", d->has_jailed, d->jailed, "on", "off");
		ucl_array_append(arr, o);
	}
	return (arr);
}

static ucl_object_t *
snapshots_of(const yread *r)
{
	ucl_object_t	*arr, *o;

	arr = ucl_object_typed_new(UCL_ARRAY);
	for (size_t i = 0; i < r->snapshot.n; i++) {
		const struct arcana_storage_storage_read_output_snapshot *s =
		    &r->snapshot.v[i];

		o = ucl_object_typed_new(UCL_OBJECT);
		put_str(o, "name", s->name);
		PUT_NUM(o, "used", s, used);
		PUT_NUM(o, "refer", s, refer);
		PUT_NUM(o, "creation", s, creation);
		ucl_array_append(arr, o);
	}
	return (arr);
}

/* What is mounted, what fstab(5) says to mount, the swap. */
static void
mounts_of(const yread *r, ucl_object_t *top)
{
	ucl_object_t	*arr, *o;

	arr = ucl_object_typed_new(UCL_ARRAY);
	for (size_t i = 0; i < r->mount.n; i++) {
		const struct arcana_storage_mount *m = &r->mount.v[i];

		o = ucl_object_typed_new(UCL_OBJECT);
		put_str(o, "from", m->from);
		put_str(o, "on", m->on);
		put_str(o, "type", m->type);
		put_str(o, "options", m->options);
		PUT_NUM(o, "size", m, size);
		PUT_NUM(o, "used", m, used);
		PUT_NUM(o, "avail", m, avail);
		ucl_array_append(arr, o);
	}
	put(top, "mounts", arr);
	arr = ucl_object_typed_new(UCL_ARRAY);
	for (size_t i = 0; r->fstab != NULL && i < r->fstab->entry.n; i++) {
		const struct arcana_storage_storage_read_output_fstab_entry
		    *e = &r->fstab->entry.v[i];

		o = ucl_object_typed_new(UCL_OBJECT);
		put_str(o, "spec", e->spec);
		put_str(o, "file", e->file);
		put_str(o, "vfstype", e->vfstype);
		put_str(o, "mntops", e->mntops);
		put_str(o, "type", e->type);
		PUT_NUM(o, "freq", e, freq);
		PUT_NUM(o, "passno", e, passno);
		if (e->has_mounted)
			put(o, "mounted", ucl_object_frombool(e->mounted));
		ucl_array_append(arr, o);
	}
	put(top, "fstab", arr);
	arr = ucl_object_typed_new(UCL_ARRAY);
	for (size_t i = 0; i < r->swap.n; i++) {
		o = ucl_object_typed_new(UCL_OBJECT);
		put_str(o, "device", r->swap.v[i].device);
		PUT_NUM(o, "size", &r->swap.v[i], size);
		PUT_NUM(o, "used", &r->swap.v[i], used);
		ucl_array_append(arr, o);
	}
	put(top, "swap", arr);
}

/* The storage's read of part kind into out, a's. */
static int
read_part(cbl_conn *conn, int kind, const char *filter, const char *jail,
    yread *out, cbl_yarena *a, char *err, size_t errlen)
{
	struct arcana_storage_storage_read_input	 in;
	const struct cbl_ynode				*n, *act;

	if ((n = yq_top("arcana-storage", "storage")) == NULL ||
	    (act = yq_child(n, "read")) == NULL) {
		snprintf(err, errlen, "arcana-storage has no read");
		return (ENOENT);
	}
	memset(&in, 0, sizeof(in));
	in.has_kind = true;
	in.kind = kind;
	in.filter = filter != NULL && filter[0] != '\0' ? filter : NULL;
	in.jail = jail != NULL && jail[0] != '\0' ? jail : NULL;
	memset(out, 0, sizeof(*out));
	return (yq_call(conn, n, NULL, act, &in, out, a, err, errlen));
}

int
ystore_read(cbl_conn *conn, int kind, const char *filter, const char *jail,
    ucl_object_t **data, uint64_t *total, bool *truncated, char *err,
    size_t errlen)
{
	yread		 r;
	ucl_object_t	*top;
	cbl_yarena	*a;
	int		 error;

	*data = NULL;
	*total = 0;
	*truncated = false;
	err[0] = '\0';
	if ((a = cbl_yarena_new()) == NULL)
		return (ENOMEM);
	if ((error = read_part(conn, kind, filter, jail, &r, a, err,
	    errlen)) != 0) {
		cbl_yarena_free(a);
		return (error);
	}
	top = ucl_object_typed_new(UCL_OBJECT);
	/* read's kind is the storage operation's storage-kind. */
	switch (kind) {
	case ARCANA_STORAGE_STORAGE_READ_INPUT_KIND_DISKS:
		put(top, "disks", disks_of(&r));
		break;
	case ARCANA_STORAGE_STORAGE_READ_INPUT_KIND_POOLS:
		put(top, "pools", pools_of(&r));
		break;
	case ARCANA_STORAGE_STORAGE_READ_INPUT_KIND_DATASETS:
		put(top, "datasets", datasets_of(&r));
		if ((*truncated = r.has_datasets_total))
			*total = r.datasets_total;
		break;
	case ARCANA_STORAGE_STORAGE_READ_INPUT_KIND_SNAPSHOTS:
		put(top, "snapshots", snapshots_of(&r));
		if ((*truncated = r.has_snapshots_total))
			*total = r.snapshots_total;
		break;
	case ARCANA_STORAGE_STORAGE_READ_INPUT_KIND_MOUNTS:
		mounts_of(&r, top);
		break;
	case ARCANA_STORAGE_STORAGE_READ_INPUT_KIND_IMPORTABLE:
		put(top, "importable", importable_of(&r));
		break;
	default:
		put(top, "disks", health_of(&r));
		break;
	}
	cbl_yarena_free(a);
	*data = top;
	return (0);
}

int
ystore_fstab(cbl_conn *conn, char **text, char **sha256, char *err,
    size_t errlen)
{
	yread		 r;
	cbl_yarena	*a;
	int		 error;

	*text = *sha256 = NULL;
	err[0] = '\0';
	if ((a = cbl_yarena_new()) == NULL)
		return (ENOMEM);
	if ((error = read_part(conn,
	    ARCANA_STORAGE_STORAGE_READ_INPUT_KIND_MOUNTS, NULL, NULL, &r, a,
	    err, errlen)) == 0 && r.fstab != NULL) {
		*text = r.fstab->text != NULL ? strdup(r.fstab->text) : NULL;
		*sha256 = r.fstab->sha256 != NULL ? strdup(r.fstab->sha256) :
		    NULL;
	}
	cbl_yarena_free(a);
	return (error);
}

int
ystore_fstab_put(cbl_conn *conn, const char *text, const char *sha256,
    bool dry_run, char **newsha, char *err, size_t errlen)
{
	struct arcana_storage_storage_fstab_replace_input	 in;
	struct arcana_storage_storage_fstab_replace_output	 out;
	const struct cbl_ynode					*n, *act;
	cbl_yarena						*a;
	int							 error;

	*newsha = NULL;
	err[0] = '\0';
	if ((n = yq_child(yq_top("arcana-storage", "storage"), "fstab")) ==
	    NULL || (act = yq_child(n, "replace")) == NULL) {
		snprintf(err, errlen, "arcana-storage has no fstab replace");
		return (ENOENT);
	}
	if ((a = cbl_yarena_new()) == NULL)
		return (ENOMEM);
	memset(&in, 0, sizeof(in));
	in.text = text;
	in.sha256 = sha256;
	in.has_dry_run = in.dry_run = dry_run;
	memset(&out, 0, sizeof(out));
	if ((error = yq_call(conn, n, NULL, act, &in, &out, a, err,
	    errlen)) == 0 && out.sha256 != NULL)
		*newsha = strdup(out.sha256);
	cbl_yarena_free(a);
	return (error);
}

int
ystore_key(cbl_conn *conn, const char *dataset, const char *key,
    const char *new_key, const char *create, char *err, size_t errlen)
{
	static const char *const ciphers[] = { "on", "aes-128-ccm",
	    "aes-192-ccm", "aes-256-ccm", "aes-128-gcm", "aes-192-gcm",
	    "aes-256-gcm" };
	const struct cbl_ynode	*n, *list, *act;
	cbl_yarena		*a;
	size_t			 i;
	int			 error;

	err[0] = '\0';
	n = yq_top("arcana-storage", "storage");
	list = yq_child(n, "dataset");
	if ((a = cbl_yarena_new()) == NULL)
		return (ENOMEM);
	if (create != NULL && create[0] != '\0') {
		struct arcana_storage_storage_create_encrypted_input ci;

		for (i = 0; i < nitems(ciphers) && strcmp(ciphers[i],
		    create) != 0; i++)
			;
		if (i == nitems(ciphers)) {
			snprintf(err, errlen, "encryption is on, or one of "
			    "aes-128-ccm, aes-192-ccm, aes-256-ccm, aes-128-gcm, "
			    "aes-192-gcm, aes-256-gcm");
			error = EINVAL;
		} else if ((act = yq_child(n, "create-encrypted")) == NULL) {
			snprintf(err, errlen, "arcana-storage has no "
			    "create-encrypted");
			error = ENOENT;
		} else {
			memset(&ci, 0, sizeof(ci));
			ci.dataset = dataset;
			ci.has_encryption = true;
			ci.encryption = i;
			ci.key = new_key;
			error = yq_call(conn, n, NULL, act, &ci, NULL, a, err,
			    errlen);
		}
	} else if (new_key != NULL) {
		struct arcana_storage_storage_dataset_change_key_input ki;

		memset(&ki, 0, sizeof(ki));
		ki.key = key;
		ki.new_key = new_key;
		error = (act = yq_child(list, "change-key")) == NULL ? ENOENT :
		    yq_call(conn, list, &dataset, act, &ki, NULL, a, err,
		    errlen);
	} else {
		struct arcana_storage_storage_dataset_load_key_input li;

		memset(&li, 0, sizeof(li));
		li.key = key;
		error = (act = yq_child(list, "load-key")) == NULL ? ENOENT :
		    yq_call(conn, list, &dataset, act, &li, NULL, a, err,
		    errlen);
	}
	cbl_yarena_free(a);
	return (error);
}
