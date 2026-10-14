/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * ysystem: the sysctl and kernel operations' JSON as arcana-sysctl and
 * arcana-kernel have them (ysystem.c), and their configuration written,
 * for agent_test.sh.
 *
 *	ysystem sysctl file [total]	the values and settings, a line each;
 *					total: a truncated reply's
 *	ysystem kernel file		the files, modules, memory
 *	ysystem -s sysctl.conf name=value ...
 *					sysctl.conf made to set those, in order
 *	ysystem -k rc.conf module ...	kld_list made those
 *
 * The first two through YANG-CBOR and back, the same bytes.
 */

#include <err.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <arcana.h>

#include "collect.h"
#include "varconf.h"

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
	return (buf);
}

static const char *
str(const char *s)
{

	return (s != NULL ? s : "-");
}

static void
same(const struct cbl_ybuf *b1, const struct cbl_ybuf *b2)
{

	printf("yang-cbor %zu bytes, %s\n", b1->len, b1->len == b2->len &&
	    memcmp(b1->p, b2->p, b1->len) == 0 ? "the same back" :
	    "not the same");
}

int
main(int argc, char **argv)
{
	struct cbl_ybuf b1 = { 0 }, b2 = { 0 };
	cbl_yarena *a;
	char why[256];
	int error;

	if ((a = cbl_yarena_new()) == NULL)
		err(1, "cbl_yarena_new");
	if (argc >= 3 && strcmp(argv[1], "sysctl") == 0) {
		struct arcana_sysctl_sysctl s, back;
		uint64_t total = argc > 3 ? strtoull(argv[3], NULL, 10) : 0;

		if ((error = ysysctl_from_json(slurp(argv[2]), total,
		    total != 0, a, &s)) != 0)
			errc(1, error, "ysysctl_from_json");
		if (s.has_total)
			printf("total %ju\n", (uintmax_t)s.total);
		for (size_t i = 0; i < s.value.n; i++)
			printf("value %s=%s type=%s writable=%s description=%s\n",
			    s.value.v[i].name, str(s.value.v[i].value),
			    str(s.value.v[i].type), s.value.v[i].has_writable ?
			    (s.value.v[i].writable ? "yes" : "no") : "-",
			    str(s.value.v[i].description));
		for (size_t i = 0; i < s.kept.n; i++)
			printf("kept %s=%s\n", s.kept.v[i].name,
			    s.kept.v[i].value);
		if (arcana_sysctl_sysctl_encode(&s, &b1) != 0 ||
		    arcana_sysctl_sysctl_decode(b1.p, b1.len, &back, a,
		    CBL_YD_STRICT, why, sizeof(why)) != 0 ||
		    arcana_sysctl_sysctl_encode(&back, &b2) != 0)
			errx(1, "the round trip: %s", why);
		same(&b1, &b2);
	} else if (argc == 3 && strcmp(argv[1], "kernel") == 0) {
		struct arcana_kernel_kernel k, back;
		const struct arcana_kernel_kernel_memory *m;

		if ((error = ykernel_from_json(slurp(argv[2]), a, &k)) != 0)
			errc(1, error, "ykernel_from_json");
		for (size_t i = 0; i < k.file.n; i++) {
			printf("file %u %s path=%s refs=%u size=%ju "
			    "address=%s modules=", k.file.v[i].id,
			    str(k.file.v[i].name), str(k.file.v[i].path),
			    k.file.v[i].refs, (uintmax_t)k.file.v[i].size,
			    str(k.file.v[i].address));
			for (size_t j = 0; j < k.file.v[i].module.n; j++)
				printf("%s%s", j > 0 ? "," : "",
				    k.file.v[i].module.v[j]);
			printf("\n");
		}
		for (size_t i = 0; i < k.available.n; i++)
			printf("available %s\n", k.available.v[i]);
		for (size_t i = 0; i < k.kept.n; i++)
			printf("kept %s\n", k.kept.v[i]);
		if ((m = k.memory) != NULL) {
			printf("memory files=%ju kmem-size=%ju map-size=%ju "
			    "map-free=%ju malloc-total=%ju\n",
			    (uintmax_t)m->files, (uintmax_t)m->kmem_size,
			    (uintmax_t)m->kmem_map_size,
			    (uintmax_t)m->kmem_map_free,
			    (uintmax_t)m->malloc_total);
			for (size_t i = 0; i < m->malloc.n; i++)
				printf("malloc %s bytes=%ju count=%ju "
				    "requests=%ju\n", m->malloc.v[i].name,
				    (uintmax_t)m->malloc.v[i].bytes,
				    (uintmax_t)m->malloc.v[i].count,
				    (uintmax_t)m->malloc.v[i].requests);
			for (size_t i = 0; i < m->zone.n; i++)
				printf("zone %s bytes=%ju free=%ju size=%ju\n",
				    m->zone.v[i].name,
				    (uintmax_t)m->zone.v[i].bytes,
				    (uintmax_t)m->zone.v[i].free,
				    (uintmax_t)m->zone.v[i].size);
		}
		if (arcana_kernel_kernel_encode(&k, &b1) != 0 ||
		    arcana_kernel_kernel_decode(b1.p, b1.len, &back, a,
		    CBL_YD_STRICT, why, sizeof(why)) != 0 ||
		    arcana_kernel_kernel_encode(&back, &b2) != 0)
			errx(1, "the round trip: %s", why);
		same(&b1, &b2);
	} else if (argc >= 3 && strcmp(argv[1], "-s") == 0) {
		struct arcana_sysctl_sysctl want;
		struct arcana_sysctl_sysctl_kept kv[16];
		struct vc_file f;
		int n = 0;

		memset(&want, 0, sizeof(want));
		for (int i = 3; i < argc && n < 16; i++) {
			char *eq = strchr(argv[i], '=');

			if (eq == NULL)
				errx(2, "%s: name=value", argv[i]);
			*eq = '\0';
			kv[n].name = argv[i];
			kv[n++].value = eq + 1;
		}
		want.kept.n = (size_t)n;
		want.kept.v = kv;
		if (vc_read(&f, VC_SYSCTL, argv[2], why, sizeof(why)) == -1 ||
		    ysysctl_conf_write(&f, &want, why, sizeof(why)) == -1 ||
		    vc_write(&f, argv[2], 0644, why, sizeof(why)) == -1)
			errx(1, "%s", why);
	} else if (argc >= 3 && strcmp(argv[1], "-k") == 0) {
		struct arcana_kernel_kernel want;
		struct vc_file f;

		memset(&want, 0, sizeof(want));
		want.kept.n = (size_t)(argc - 3);
		want.kept.v = (const char *const *)(argv + 3);
		if (vc_read(&f, VC_SH, argv[2], why, sizeof(why)) == -1 ||
		    ykernel_kld_write(&f, &want, why, sizeof(why)) == -1 ||
		    vc_write(&f, argv[2], 0644, why, sizeof(why)) == -1)
			errx(1, "%s", why);
	} else
		errx(2, "usage: ysystem sysctl file [total] | kernel file | "
		    "-s sysctl.conf name=value ... | -k rc.conf module ...");
	cbl_ybuf_free(&b1);
	cbl_ybuf_free(&b2);
	cbl_yarena_free(a);
	return (0);
}
