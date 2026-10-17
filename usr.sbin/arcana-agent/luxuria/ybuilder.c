/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Luxuria: poudriere as YANG, arcana-builder: the builder and
 * builder-options operations' JSON (poudriere.c) read back into the
 * module's structs.
 */

#include <sys/param.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <arcana.h>

#include "collect.h"
#include "yjson.h"

static char *
datetime(cbl_yarena *a, int64_t t)
{
	char		buf[32], *p;
	struct tm	tm;
	time_t		tt = (time_t)t;

	if (gmtime_r(&tt, &tm) == NULL || strftime(buf, sizeof(buf),
	    "%Y-%m-%dT%H:%M:%SZ", &tm) == 0)
		return (NULL);
	if ((p = cbl_yarena_alloc(a, strlen(buf) + 1)) != NULL)
		memcpy(p, buf, strlen(buf) + 1);
	return (p);
}

#define	ALLOC_N(a, p, n)	(((p) = cbl_yarena_alloc((a), ((n) + 1) * \
	sizeof(*(p)))) != NULL)

/* A string of the arena's, a copy. */
static const char *
dup(cbl_yarena *a, const char *s)
{
	char	*d;

	if (s == NULL || (d = cbl_yarena_alloc(a, strlen(s) + 1)) == NULL)
		return (NULL);
	memcpy(d, s, strlen(s) + 1);
	return (d);
}

static int
build_ports(cbl_yarena *a, const ucl_object_t *b,
    struct arcana_builder_builder_build *y)
{
	struct arcana_builder_builder_build_failed_port		*fp;
	struct arcana_builder_builder_build_skipped_port	*sp;
	const ucl_object_t					*e;
	ucl_object_iter_t					 it;
	size_t							 k;

	if (!ALLOC_N(a, fp, yj_count(ucl_object_lookup(b, "failed_ports"))))
		return (ENOMEM);
	k = 0;
	YJ_EACH(ucl_object_lookup(b, "failed_ports"), it, e) {
		memset(&fp[k], 0, sizeof(fp[k]));
		if ((fp[k].package = yj_str(a, e, "package")) == NULL)
			continue;
		fp[k].origin = yj_str(a, e, "origin");
		fp[k].phase = yj_str(a, e, "phase");
		fp[k].reason = yj_str(a, e, "reason");
		YJ_NUM(e, "elapsed", &fp[k], elapsed);
		fp[k].log_file = yj_str(a, e, "log_file");
		fp[k].log = yj_str(a, e, "log");
		k++;
	}
	y->failed_port.n = k;
	y->failed_port.v = fp;
	if (!ALLOC_N(a, sp, yj_count(ucl_object_lookup(b, "skipped_ports"))))
		return (ENOMEM);
	k = 0;
	YJ_EACH(ucl_object_lookup(b, "skipped_ports"), it, e) {
		memset(&sp[k], 0, sizeof(sp[k]));
		if ((sp[k].package = yj_str(a, e, "package")) == NULL)
			continue;
		sp[k].origin = yj_str(a, e, "origin");
		sp[k].because = yj_str(a, e, "because");
		k++;
	}
	y->skipped_port.n = k;
	y->skipped_port.v = sp;
	return (0);
}

static int
options_dirs(cbl_yarena *a, const ucl_object_t *top,
    struct arcana_builder_builder *out)
{
	struct arcana_builder_builder_options		*od;
	struct arcana_builder_builder_options_port	*op;
	const ucl_object_t				*e, *p;
	ucl_object_iter_t				 it, pit;
	size_t						 k, m;

	if (!ALLOC_N(a, od, yj_count(ucl_object_lookup(top, "options"))))
		return (ENOMEM);
	k = 0;
	YJ_EACH(ucl_object_lookup(top, "options"), it, e) {
		memset(&od[k], 0, sizeof(od[k]));
		/* options itself is named "": a key all the same. */
		if ((od[k].name = yj_str(a, e, "name")) == NULL)
			continue;
		od[k].dir = yj_str(a, e, "dir");
		if (!ALLOC_N(a, op, yj_count(ucl_object_lookup(e, "ports"))))
			return (ENOMEM);
		m = 0;
		YJ_EACH(ucl_object_lookup(e, "ports"), pit, p) {
			memset(&op[m], 0, sizeof(op[m]));
			if ((op[m].name = yj_str(a, p, "name")) == NULL)
				continue;
			op[m].pkgname = yj_str(a, p, "pkgname");
			if (yj_strs(a, ucl_object_lookup(p, "set"), &op[m].set.n,
			    &op[m].set.v) != 0 || yj_strs(a,
			    ucl_object_lookup(p, "unset"), &op[m].unset.n,
			    &op[m].unset.v) != 0)
				return (ENOMEM);
			m++;
		}
		od[k].port.n = m;
		od[k].port.v = op;
		k++;
	}
	out->options.n = k;
	out->options.v = od;
	return (0);
}

static int
runs(cbl_yarena *a, const ucl_object_t *top,
    struct arcana_builder_builder *out)
{
	static const char *const states[] = { "running", "done", "failed",
	    "lost" };
	struct arcana_builder_builder_run	*r;
	const ucl_object_t			*e;
	ucl_object_iter_t			 it;
	const char				*st;
	int64_t					 n;
	size_t					 k, i;

	if (!ALLOC_N(a, r, yj_count(ucl_object_lookup(top, "runs"))))
		return (ENOMEM);
	k = 0;
	YJ_EACH(ucl_object_lookup(top, "runs"), it, e) {
		memset(&r[k], 0, sizeof(r[k]));
		if (!yj_num(e, "id", &n) || n < 1)
			continue;
		r[k].id = (uint32_t)n;
		r[k].title = yj_str(a, e, "title");
		if (yj_strs(a, ucl_object_lookup(e, "argv"), &r[k].argv.n,
		    &r[k].argv.v) != 0)
			return (ENOMEM);
		if (yj_num(e, "started", &n))
			r[k].started = datetime(a, n);
		if ((st = yj_str(a, e, "state")) != NULL)
			for (i = 0; i < nitems(states); i++)
				if (strcmp(st, states[i]) == 0) {
					r[k].has_state = true;
					r[k].state = (enum
					    arcana_builder_builder_run_state)i;
				}
		YJ_NUM(e, "pid", &r[k], pid);
		YJ_NUM(e, "exit", &r[k], exit);
		r[k].log_file = yj_str(a, e, "log_file");
		r[k].log = yj_str(a, e, "log");
		k++;
	}
	out->run.n = k;
	out->run.v = r;
	return (0);
}

int
ybuilder_from_json(const char *json, cbl_yarena *a,
    struct arcana_builder_builder *out)
{
	struct arcana_builder_builder_conf	*cf;
	struct arcana_builder_builder_jail	*jl;
	struct arcana_builder_builder_ports	*pt;
	struct arcana_builder_builder_make_conf	*mc;
	struct arcana_builder_builder_repo	*rp;
	struct arcana_builder_builder_build	*bd;
	const ucl_object_t			*e, *o;
	ucl_object_iter_t			 it;
	ucl_object_t				*top;
	int64_t					 n;
	size_t					 k;

	memset(out, 0, sizeof(*out));
	if ((top = yj_parse(json)) == NULL)
		return (EINVAL);
	out->installed = yj_yes(top, "installed", &out->has_installed);
	out->program = yj_str(a, top, "program");
	out->conf_file = yj_str(a, top, "conf_file");
	out->configured = yj_yes(top, "configured", &out->has_configured);
	/* poudriere.conf's assignments: an object. */
	o = ucl_object_lookup(top, "conf");
	k = 0;
	if (!ALLOC_N(a, cf, o != NULL && ucl_object_type(o) == UCL_OBJECT ?
	    (size_t)256 : 0))
		goto nomem;
	it = NULL;
	while (o != NULL && ucl_object_type(o) == UCL_OBJECT && k < 256 && (e =
	    ucl_object_iterate(o, &it, true)) != NULL) {
		if (ucl_object_key(e) == NULL)
			continue;
		cf[k].name = dup(a, ucl_object_key(e));
		cf[k].value = dup(a, ucl_object_tostring_forced(e));
		if (cf[k].name == NULL || cf[k].value == NULL)
			goto nomem;
		k++;
	}
	out->conf.n = k;
	out->conf.v = cf;
	out->basefs = yj_str(a, top, "basefs");
	out->data = yj_str(a, top, "data");
	/* The jails and trees, as jset and pset wrote them. */
	if (!ALLOC_N(a, jl, yj_count(ucl_object_lookup(top, "jails"))))
		goto nomem;
	k = 0;
	YJ_EACH(ucl_object_lookup(top, "jails"), it, e) {
		memset(&jl[k], 0, sizeof(jl[k]));
		if ((jl[k].name = yj_str(a, e, "name")) == NULL)
			continue;
		jl[k].version = yj_str(a, e, "version");
		jl[k].arch = yj_str(a, e, "arch");
		jl[k].method = yj_str(a, e, "method");
		jl[k].mnt = yj_str(a, e, "mnt");
		jl[k].fs = yj_str(a, e, "fs");
		if (yj_num(e, "timestamp", &n))
			jl[k].timestamp = datetime(a, n);
		k++;
	}
	out->jail.n = k;
	out->jail.v = jl;
	if (!ALLOC_N(a, pt, yj_count(ucl_object_lookup(top, "ports"))))
		goto nomem;
	k = 0;
	YJ_EACH(ucl_object_lookup(top, "ports"), it, e) {
		memset(&pt[k], 0, sizeof(pt[k]));
		if ((pt[k].name = yj_str(a, e, "name")) == NULL)
			continue;
		pt[k].method = yj_str(a, e, "method");
		pt[k].mnt = yj_str(a, e, "mnt");
		if (yj_num(e, "timestamp", &n))
			pt[k].timestamp = datetime(a, n);
		k++;
	}
	out->ports.n = k;
	out->ports.v = pt;
	if (!ALLOC_N(a, mc, yj_count(ucl_object_lookup(top, "makeconf"))))
		goto nomem;
	k = 0;
	YJ_EACH(ucl_object_lookup(top, "makeconf"), it, e) {
		memset(&mc[k], 0, sizeof(mc[k]));
		if ((mc[k].name = yj_str(a, e, "name")) == NULL)
			continue;
		mc[k].file = yj_str(a, e, "file");
		mc[k].text = yj_str(a, e, "text");
		k++;
	}
	out->make_conf.n = k;
	out->make_conf.v = mc;
	if (options_dirs(a, top, out) != 0)
		goto nomem;
	if (!ALLOC_N(a, rp, yj_count(ucl_object_lookup(top, "repos"))))
		goto nomem;
	k = 0;
	YJ_EACH(ucl_object_lookup(top, "repos"), it, e) {
		memset(&rp[k], 0, sizeof(rp[k]));
		if ((rp[k].name = yj_str(a, e, "name")) == NULL)
			continue;
		rp[k].path = yj_str(a, e, "path");
		YJ_NUM(e, "packages", &rp[k], packages);
		k++;
	}
	out->repo.n = k;
	out->repo.v = rp;
	/* The latest builds, keyed by jail, tree and set. */
	if (!ALLOC_N(a, bd, yj_count(ucl_object_lookup(top, "builds"))))
		goto nomem;
	k = 0;
	YJ_EACH(ucl_object_lookup(top, "builds"), it, e) {
		memset(&bd[k], 0, sizeof(bd[k]));
		if ((bd[k].jail = yj_str(a, e, "jail")) == NULL)
			continue;
		bd[k].ports = yj_str(a, e, "ports") != NULL ? yj_str(a, e,
		    "ports") : "";
		bd[k].set = yj_str(a, e, "set") != NULL ? yj_str(a, e, "set") :
		    "";
		bd[k].build = yj_str(a, e, "build");
		bd[k].status = yj_str(a, e, "status");
		YJ_NUM(e, "queued", &bd[k], queued);
		YJ_NUM(e, "inspected", &bd[k], inspected);
		YJ_NUM(e, "ignored", &bd[k], ignored);
		YJ_NUM(e, "built", &bd[k], built);
		YJ_NUM(e, "failed", &bd[k], failed);
		YJ_NUM(e, "skipped", &bd[k], skipped);
		YJ_NUM(e, "fetched", &bd[k], fetched);
		YJ_NUM(e, "remaining", &bd[k], remaining);
		bd[k].time = yj_str(a, e, "time");
		bd[k].logs = yj_str(a, e, "logs");
		if (build_ports(a, e, &bd[k]) != 0)
			goto nomem;
		k++;
	}
	out->build.n = k;
	out->build.v = bd;
	out->builds_error = yj_str(a, top, "builds_error");
	if (runs(a, top, out) != 0)
		goto nomem;
	ucl_object_unref(top);
	return (0);
nomem:
	ucl_object_unref(top);
	return (ENOMEM);
}

int
ybuilder_options_from_json(const char *json, cbl_yarena *a,
    struct arcana_builder_builder_port_options_output *out)
{
	struct arcana_builder_builder_port_options_output_section	 *sc;
	struct arcana_builder_builder_port_options_output_section_option *op;
	const ucl_object_t	*e, *o;
	ucl_object_iter_t	 it, oit;
	ucl_object_t		*top;
	size_t			 k, m;

	memset(out, 0, sizeof(*out));
	if ((top = yj_parse(json)) == NULL)
		return (EINVAL);
	out->pkgname = yj_str(a, top, "pkgname");
	out->options_dir = yj_str(a, top, "options_dir");
	out->options_dir_exists = yj_yes(top, "options_dir_exists",
	    &out->has_options_dir_exists);
	out->options_file = yj_str(a, top, "options_file");
	out->configured = yj_yes(top, "configured", &out->has_configured);
	if (!ALLOC_N(a, sc, yj_count(ucl_object_lookup(top, "sections"))))
		goto nomem;
	k = 0;
	YJ_EACH(ucl_object_lookup(top, "sections"), it, e) {
		memset(&sc[k], 0, sizeof(sc[k]));
		sc[k].index = (uint8_t)k;
		sc[k].title = yj_str(a, e, "title");
		if (!ALLOC_N(a, op, yj_count(ucl_object_lookup(e, "options"))))
			goto nomem;
		m = 0;
		YJ_EACH(ucl_object_lookup(e, "options"), oit, o) {
			memset(&op[m], 0, sizeof(op[m]));
			if ((op[m].name = yj_str(a, o, "name")) == NULL)
				continue;
			op[m].on = yj_yes(o, "on", &op[m].has_on);
			op[m].description = yj_str(a, o, "description");
			m++;
		}
		sc[k].option.n = m;
		sc[k].option.v = op;
		k++;
	}
	out->section.n = k;
	out->section.v = sc;
	ucl_object_unref(top);
	return (0);
nomem:
	ucl_object_unref(top);
	return (ENOMEM);
}
