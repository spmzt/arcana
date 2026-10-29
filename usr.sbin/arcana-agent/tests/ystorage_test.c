/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * ystorage: the storage operation's replies as arcana-storage has them
 * (ystorage.c), for agent_test.sh: each argument kind=file, the JSON of
 * that kind (disks, pools, datasets, snapshots, mounts, importable,
 * health; total=n for a truncated one), all put in one tree, written a
 * field a line, and through YANG-CBOR and back.
 */

#include <err.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <arcana.h>

#include "collect.h"

static const char *const kinds[] = { "disks", "pools", "datasets",
    "snapshots", "mounts", "importable", "health" };

static const char *
str(const char *s)
{

	return (s != NULL ? s : "-");
}

static char *
slurp(const char *path)
{
	static char buf[1 << 20];
	ssize_t r;
	int fd;

	if ((fd = open(path, O_RDONLY)) == -1)
		err(1, "%s", path);
	if ((r = read(fd, buf, sizeof(buf) - 1)) < 0)
		err(1, "%s", path);
	close(fd);
	buf[r] = '\0';
	return (strdup(buf));
}

#define	U(y, f)	((y)->has_##f ? (uintmax_t)(y)->f : 0)
#define	H(y, f)	((y)->has_##f ? "" : "-")

static void
show(const struct arcana_storage_storage *st)
{
	for (size_t i = 0; i < st->disk.n; i++) {
		const struct arcana_storage_disk *d = &st->disk.v[i];

		printf("disk %s size=%ju sectorsize=%ju ident=%s descr=%s "
		    "rotation=%s scheme=%s first=%ju last=%ju\n", d->name,
		    U(d, size), U(d, sectorsize), str(d->ident), str(d->descr),
		    str(d->rotation), str(d->scheme), U(d, first), U(d, last));
		for (size_t k = 0; k < d->partition.n; k++) {
			const struct arcana_storage_disk_partition *p =
			    &d->partition.v[k];

			printf("  partition %s index=%ju size=%ju type=%s "
			    "label=%s start=%ju end=%ju\n", p->name,
			    U(p, index), U(p, size), str(p->type),
			    str(p->label), U(p, start), U(p, end));
		}
		if (d->health != NULL)
			printf("  health by=%s ok=%s temperature=%jd "
			    "power-on-hours=%ju reallocated=%s note=%s\n",
			    str(d->health->by), d->health->has_ok ?
			    (d->health->ok ? "yes" : "no") : "-",
			    (intmax_t)d->health->temperature,
			    U(d->health, power_on_hours),
			    d->health->has_reallocated ? "yes" : "-",
			    str(d->health->note));
	}
	for (size_t i = 0; i < st->pool.n; i++) {
		const struct arcana_storage_pool *p = &st->pool.v[i];

		printf("pool %s size=%ju alloc=%ju free=%ju frag=%ju cap=%ju "
		    "dedup=%s health=%s state=%s status=%s scan=%s "
		    "errors=%s\n", p->name, U(p, size), U(p, alloc),
		    U(p, free), U(p, frag), U(p, cap), str(p->dedup),
		    str(p->health), str(p->state), str(p->status),
		    str(p->scan), str(p->errors));
		for (size_t k = 0; k < p->vdev.n; k++)
			printf("  vdev %s depth=%ju state=%s read=%s write=%s "
			    "cksum=%s note=%s\n", p->vdev.v[k].name,
			    U(&p->vdev.v[k], depth), str(p->vdev.v[k].state),
			    str(p->vdev.v[k].read), str(p->vdev.v[k].write),
			    str(p->vdev.v[k].cksum), str(p->vdev.v[k].note));
	}
	for (size_t i = 0; i < st->importable.n; i++)
		printf("importable %s name=%s state=%s\n",
		    st->importable.v[i].id, str(st->importable.v[i].name),
		    str(st->importable.v[i].state));
	if (st->has_datasets_total)
		printf("datasets-total %ju\n", (uintmax_t)st->datasets_total);
	for (size_t i = 0; i < st->dataset.n; i++) {
		const struct arcana_storage_storage_dataset *d =
		    &st->dataset.v[i];

		printf("dataset %s type=%s used=%ju avail=%ju refer=%ju "
		    "quota=%ju mountpoint=%s mounted=%s canmount=%s "
		    "compression=%s ratio=%s%jd readonly=%s encryption=%s "
		    "keylocation=%s jailed=%s origin=%s\n", d->name,
		    d->has_type ? (d->type == 0 ? "filesystem" : "volume") :
		    "-", U(d, used), U(d, avail), U(d, refer), U(d, quota),
		    str(d->mountpoint), d->has_mounted ? (d->mounted ? "yes" :
		    "no") : "-", d->has_canmount ? (d->canmount == 0 ? "on" :
		    d->canmount == 1 ? "off" : "noauto") : "-",
		    str(d->compression), H(d, ratio), (intmax_t)d->ratio,
		    d->has_readonly ? (d->readonly ? "yes" : "no") : "-",
		    str(d->encryption), str(d->keylocation), d->has_jailed ?
		    (d->jailed ? "yes" : "no") : "-", str(d->origin));
	}
	if (st->has_snapshots_total)
		printf("snapshots-total %ju\n",
		    (uintmax_t)st->snapshots_total);
	for (size_t i = 0; i < st->snapshot.n; i++)
		printf("snapshot %s used=%ju refer=%ju creation=%jd\n",
		    st->snapshot.v[i].name, U(&st->snapshot.v[i], used),
		    U(&st->snapshot.v[i], refer),
		    (intmax_t)st->snapshot.v[i].creation);
	for (size_t i = 0; i < st->mount.n; i++)
		printf("mount %s on=%s type=%s options=%s size=%ju\n",
		    str(st->mount.v[i].from), str(st->mount.v[i].on),
		    str(st->mount.v[i].type), str(st->mount.v[i].options),
		    U(&st->mount.v[i], size));
	if (st->fstab != NULL)
		for (size_t i = 0; i < st->fstab->entry.n; i++) {
			const struct arcana_storage_storage_fstab_entry *e =
			    &st->fstab->entry.v[i];

			printf("fstab %s file=%s vfstype=%s mntops=%s "
			    "type=%s freq=%d passno=%d mounted=%s\n",
			    str(e->spec), str(e->file), str(e->vfstype),
			    str(e->mntops), str(e->type), e->freq, e->passno,
			    e->has_mounted ? (e->mounted ? "yes" : "no") :
			    "-");
		}
	for (size_t i = 0; i < st->swap.n; i++)
		printf("swap %s size=%ju used=%ju\n", st->swap.v[i].device,
		    U(&st->swap.v[i], size), U(&st->swap.v[i], used));
}

int
main(int argc, char **argv)
{
	struct arcana_storage_storage st, back;
	struct cbl_ybuf b1 = { 0 }, b2 = { 0 };
	cbl_yarena *a;
	char why[256];
	uint64_t total = 0;
	int error;

	memset(&st, 0, sizeof(st));
	if ((a = cbl_yarena_new()) == NULL)
		err(1, "cbl_yarena_new");
	for (int i = 1; i < argc; i++) {
		char *eq = strchr(argv[i], '=');
		int k;

		if (eq == NULL)
			errx(2, "usage: ystorage kind=file ... [total=n]");
		*eq = '\0';
		if (strcmp(argv[i], "total") == 0) {
			total = strtoull(eq + 1, NULL, 10);
			continue;
		}
		for (k = 0; k < (int)(sizeof(kinds) / sizeof(kinds[0])); k++)
			if (strcmp(argv[i], kinds[k]) == 0)
				break;
		if (k == (int)(sizeof(kinds) / sizeof(kinds[0])))
			errx(2, "%s: no such kind", argv[i]);
		if ((error = ystorage_from_json(k, slurp(eq + 1), total,
		    total != 0, a, &st)) != 0)
			errc(1, error, "%s", argv[i]);
		total = 0;
	}
	show(&st);
	if (arcana_storage_storage_encode(&st, &b1) != 0)
		errx(1, "encode");
	if (arcana_storage_storage_decode(b1.p, b1.len, &back, a,
	    CBL_YD_STRICT, why, sizeof(why)) != 0)
		errx(1, "decode: %s", why);
	if (arcana_storage_storage_encode(&back, &b2) != 0)
		errx(1, "encode again");
	printf("yang-cbor %zu bytes, %s\n", b1.len, b1.len == b2.len &&
	    memcmp(b1.p, b2.p, b1.len) == 0 ? "the same back" : "not the same");
	printf("-- back\n");
	show(&back);
	cbl_ybuf_free(&b1);
	cbl_ybuf_free(&b2);
	cbl_yarena_free(a);
	return (0);
}
