/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Superbia: the kernel's modules and memory as arcana-kernel has them,
 * from do_kernel()'s JSON (kernel.c); and the configuration of
 * arcana-sysctl and arcana-kernel written: sysctl.conf(5)'s settings,
 * rc.conf(5)'s kld_list, in place, every other line kept (libvarconf).
 * Served by ysysedit.c.
 */

#include <errno.h>
#include <stdio.h>
#include <string.h>

#include <arcana.h>

#include "collect.h"
#include "varconf.h"
#include "yjson.h"

int
ykernel_from_json(const char *json, cbl_yarena *a,
    struct arcana_kernel_kernel *out)
{
	const ucl_object_t *arr, *e, *mem;
	struct arcana_kernel_kernel_file *f = NULL;
	struct arcana_kernel_kernel_memory *m;
	ucl_object_iter_t it;
	ucl_object_t *top;
	size_t i;
	int error = ENOMEM;

	memset(out, 0, sizeof(*out));
	if ((top = yj_parse(json)) == NULL)
		return (EINVAL);
	arr = ucl_object_lookup(top, "files");
	if (yj_count(arr) > 0 && (f = cbl_yarena_alloc(a, yj_count(arr) *
	    sizeof(*f))) == NULL)
		goto out;
	i = 0;
	YJ_EACH(arr, it, e) {
		int64_t id = 0;

		memset(&f[i], 0, sizeof(f[i]));
		(void)yj_num(e, "id", &id);
		f[i].id = (uint32_t)id;
		f[i].name = yj_str(a, e, "name");
		f[i].path = yj_str(a, e, "path");
		YJ_NUM(e, "refs", &f[i], refs);
		YJ_NUM(e, "size", &f[i], size);
		f[i].address = yj_str(a, e, "address");
		if ((error = yj_strs(a, ucl_object_lookup(e, "modules"),
		    &f[i].module.n, &f[i].module.v)) != 0)
			goto out;
		i++;
	}
	out->file.n = i;
	out->file.v = f;
	if ((error = yj_strs(a, ucl_object_lookup(top, "available"),
	    &out->available.n, &out->available.v)) != 0 ||
	    (error = yj_strs(a, ucl_object_lookup(top, "kept"),
	    &out->kept.n, &out->kept.v)) != 0)
		goto out;
	error = ENOMEM;
	if ((mem = ucl_object_lookup(top, "memory")) != NULL) {
		struct arcana_kernel_kernel_memory_malloc *mv = NULL;
		struct arcana_kernel_kernel_memory_zone *zv = NULL;

		if ((m = cbl_yarena_alloc(a, sizeof(*m))) == NULL)
			goto out;
		memset(m, 0, sizeof(*m));
		YJ_NUM(mem, "files", m, files);
		YJ_NUM(mem, "kmem_size", m, kmem_size);
		YJ_NUM(mem, "kmem_map_size", m, kmem_map_size);
		YJ_NUM(mem, "kmem_map_free", m, kmem_map_free);
		YJ_NUM(mem, "malloc_total", m, malloc_total);
		arr = ucl_object_lookup(mem, "malloc");
		if (yj_count(arr) > 0 && (mv = cbl_yarena_alloc(a,
		    yj_count(arr) * sizeof(*mv))) == NULL)
			goto out;
		i = 0;
		YJ_EACH(arr, it, e) {
			memset(&mv[i], 0, sizeof(mv[i]));
			mv[i].name = yj_str(a, e, "name");
			YJ_NUM(e, "bytes", &mv[i], bytes);
			YJ_NUM(e, "count", &mv[i], count);
			YJ_NUM(e, "requests", &mv[i], requests);
			i++;
		}
		m->malloc.n = i;
		m->malloc.v = mv;
		arr = ucl_object_lookup(mem, "zones");
		if (yj_count(arr) > 0 && (zv = cbl_yarena_alloc(a,
		    yj_count(arr) * sizeof(*zv))) == NULL)
			goto out;
		i = 0;
		YJ_EACH(arr, it, e) {
			memset(&zv[i], 0, sizeof(zv[i]));
			zv[i].name = yj_str(a, e, "name");
			YJ_NUM(e, "bytes", &zv[i], bytes);
			YJ_NUM(e, "count", &zv[i], count);
			YJ_NUM(e, "free", &zv[i], free);
			YJ_NUM(e, "size", &zv[i], size);
			YJ_NUM(e, "requests", &zv[i], requests);
			i++;
		}
		m->zone.n = i;
		m->zone.v = zv;
		out->memory = m;
	}
	error = 0;
out:
	ucl_object_unref(top);
	return (error);
}

/*
 * sysctl.conf f (libvarconf's VC_SYSCTL) made to set want's kept: each
 * set in place or appended, in want's order; one f sets that want has
 * not taken out.  -1 and err: refused (what reading f does not settle).
 */
int
ysysctl_conf_write(struct vc_file *f, const struct arcana_sysctl_sysctl *want,
    char *err, size_t errlen)
{

	for (size_t i = 0; i < f->na; i++) {
		const char *name = f->a[i].name;
		bool keep = false;

		for (size_t k = 0; k < want->kept.n && !keep; k++)
			keep = strcmp(want->kept.v[k].name, name) == 0;
		if (!keep) {
			if (vc_unset(f, name, err, errlen) == -1)
				return (-1);
			i = (size_t)-1;		/* the file is another now */
		}
	}
	for (size_t k = 0; k < want->kept.n; k++)
		if (vc_set(f, want->kept.v[k].name, want->kept.v[k].value, err,
		    errlen) == -1)
			return (-1);
	return (0);
}

/*
 * rc.conf f (VC_SH) made to load want's kept at boot: kld_list, the
 * modules with blanks between; none, taken out.
 */
int
ykernel_kld_write(struct vc_file *f, const struct arcana_kernel_kernel *want,
    char *err, size_t errlen)
{
	char list[4096];
	size_t len = 0;

	list[0] = '\0';
	for (size_t i = 0; i < want->kept.n; i++) {
		len = strlcat(list, i > 0 ? " " : "", sizeof(list));
		len = strlcat(list, want->kept.v[i], sizeof(list));
	}
	if (len >= sizeof(list)) {
		snprintf(err, errlen, "kld_list: too long");
		errno = EINVAL;
		return (-1);
	}
	if (want->kept.n == 0)
		return (vc_get(f, "kld_list") != NULL ?
		    vc_unset(f, "kld_list", err, errlen) : 0);
	return (vc_set(f, "kld_list", list, err, errlen));
}
