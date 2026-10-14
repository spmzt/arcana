/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Gula: the processes as arcana-processes has them (PLAN-SDN-YANG
 * 3.1.7), OpenConfig's procmon shape with FreeBSD's besides, from the
 * processes operation's JSON (procs.c): the list, and one process's
 * files and threads put on it.
 */

#include <errno.h>
#include <string.h>

#include <arcana.h>

#include "collect.h"
#include "yjson.h"

typedef struct arcana_processes_processes_process yproc;

/* "a b c" split on blanks, the arena's. */
static int
words(cbl_yarena *a, const char *s, size_t *n, const char *const **v)
{
	const char **p;
	size_t k = 0, max = 1;
	char *c, *w, *save;

	*n = 0;
	*v = NULL;
	if (s == NULL || *s == '\0')
		return (0);
	for (const char *q = s; *q != '\0'; q++)
		max += *q == ' ';
	if ((c = cbl_yarena_alloc(a, strlen(s) + 1)) == NULL ||
	    (p = cbl_yarena_alloc(a, max * sizeof(*p))) == NULL)
		return (ENOMEM);
	memcpy(c, s, strlen(s) + 1);
	for (w = strtok_r(c, " ", &save); w != NULL && k < max;
	    w = strtok_r(NULL, " ", &save))
		p[k++] = w;
	*n = k;
	*v = p;
	return (0);
}

static int
state_of(const ucl_object_t *e, cbl_yarena *a,
    struct arcana_processes_processes_process_state *st)
{
	int64_t v;

	memset(st, 0, sizeof(*st));
	YJ_NUM(e, "pid", st, pid);
	st->name = yj_str(a, e, "comm");
	if (words(a, yj_str(a, e, "args"), &st->args.n, &st->args.v) != 0)
		return (ENOMEM);
	/* OpenConfig's timeticks64: nanoseconds since the Epoch. */
	if ((st->has_start_time = yj_num(e, "start", &v) && v >= 0))
		st->start_time = (uint64_t)v * 1000000000u;
	if (yj_hundredths(e, "cpu", &v)) {
		/* A percentage of one CPU, at most 100, as OpenConfig's. */
		st->has_cpu_utilization = true;
		st->cpu_utilization = v / 100 > 100 ? 100 : (uint8_t)
		    ((v + 50) / 100);
	}
	YJ_NUM(e, "rss", st, memory_usage);
	YJ_NUM(e, "ppid", st, ppid);
	st->user = yj_str(a, e, "user");
	YJ_NUM(e, "jid", st, jid);
	st->jail = yj_str(a, e, "jail");
	st->run_state = yj_str(a, e, "state");
	st->wait = yj_str(a, e, "wait");
	YJ_NUM(e, "nice", st, nice);
	YJ_NUM(e, "pri", st, priority);
	YJ_NUM(e, "threads", st, threads);
	YJ_NUM(e, "size", st, size);
	YJ_DEC2(e, "time", st, cpu_time);
	YJ_DEC2(e, "cpu", st, cpu);
	YJ_DEC2(e, "wcpu", st, wcpu);
	YJ_NUM(e, "in", st, blocks_in);
	YJ_NUM(e, "out", st, blocks_out);
	YJ_DEC2(e, "io", st, io);
	return (0);
}

/*
 * The processes operation's reply (all, or a jail's) put in out; then,
 * with detail (the reply for one pid: NULL none), that process's files
 * and threads on its entry.
 */
int
yprocs_from_json(const char *json, const char *detail, cbl_yarena *a,
    struct arcana_processes_processes *out)
{
	const ucl_object_t *arr, *e;
	ucl_object_t *top, *dt = NULL;
	ucl_object_iter_t it;
	yproc *v = NULL;
	int64_t dpid = -1;
	size_t i;
	int error = ENOMEM;

	memset(out, 0, sizeof(*out));
	if ((top = yj_parse(json)) == NULL)
		return (EINVAL);
	if (detail != NULL && ((dt = yj_parse(detail)) == NULL ||
	    !yj_num(dt, "pid", &dpid))) {
		error = EINVAL;
		goto out;
	}
	YJ_NUM(top, "ncpu", out, ncpu);
	YJ_DEC2(top, "elapsed", out, elapsed);
	arr = ucl_object_lookup(top, "processes");
	if (yj_count(arr) > 0 && (v = cbl_yarena_alloc(a, yj_count(arr) *
	    sizeof(*v))) == NULL)
		goto out;
	i = 0;
	YJ_EACH(arr, it, e) {
		struct arcana_processes_processes_process_state *st;
		int64_t pid = 0;

		memset(&v[i], 0, sizeof(v[i]));
		(void)yj_num(e, "pid", &pid);
		v[i].pid = (uint64_t)pid;
		if ((st = cbl_yarena_alloc(a, sizeof(*st))) == NULL ||
		    state_of(e, a, st) != 0)
			goto out;
		v[i].state = st;
		if (dt != NULL && pid == dpid) {
			const ucl_object_t *fa = ucl_object_lookup(dt, "files");
			const ucl_object_t *ta = ucl_object_lookup(dt,
			    "threads"), *f;
			struct arcana_processes_processes_process_file *fv =
			    NULL;
			struct arcana_processes_processes_process_thread *tv =
			    NULL;
			ucl_object_iter_t fit;
			size_t k = 0;

			if ((yj_count(fa) > 0 && (fv = cbl_yarena_alloc(a,
			    yj_count(fa) * sizeof(*fv))) == NULL) ||
			    (yj_count(ta) > 0 && (tv = cbl_yarena_alloc(a,
			    yj_count(ta) * sizeof(*tv))) == NULL))
				goto out;
			YJ_EACH(fa, fit, f) {
				memset(&fv[k], 0, sizeof(fv[k]));
				YJ_NUM(f, "fd", &fv[k], fd);
				fv[k].use = yj_str(a, f, "use");
				fv[k].type = yj_str(a, f, "type");
				fv[k].path = yj_str(a, f, "path");
				fv[k].proto = yj_str(a, f, "proto");
				fv[k].local = yj_str(a, f, "local");
				fv[k].remote = yj_str(a, f, "remote");
				fv[k++].mode = yj_str(a, f, "mode");
			}
			v[i].file.n = k;
			v[i].file.v = fv;
			k = 0;
			YJ_EACH(ta, fit, f) {
				int64_t tid = 0;

				memset(&tv[k], 0, sizeof(tv[k]));
				(void)yj_num(f, "tid", &tid);
				tv[k].tid = (uint64_t)tid;
				tv[k].name = yj_str(a, f, "name");
				tv[k].run_state = yj_str(a, f, "state");
				tv[k].wait = yj_str(a, f, "wait");
				YJ_NUM(f, "pri", &tv[k], priority);
				YJ_DEC2(f, "wcpu", &tv[k], wcpu);
				YJ_DEC2(f, "time", &tv[k], cpu_time);
				k++;
			}
			v[i].thread.n = k;
			v[i].thread.v = tv;
		}
		i++;
	}
	out->process.n = i;
	out->process.v = v;
	arr = ucl_object_lookup(top, "jails");
	if (yj_count(arr) > 0) {
		struct arcana_processes_processes_jail *jv;
		size_t k = 0;

		if ((jv = cbl_yarena_alloc(a, yj_count(arr) * sizeof(*jv))) ==
		    NULL)
			goto out;
		YJ_EACH(arr, it, e) {
			int64_t jid = 0;

			memset(&jv[k], 0, sizeof(jv[k]));
			(void)yj_num(e, "jid", &jid);
			jv[k].jid = (uint32_t)jid;
			jv[k].name = yj_str(a, e, "name");
			YJ_NUM(e, "procs", &jv[k], procs);
			YJ_NUM(e, "threads", &jv[k], threads);
			YJ_DEC2(e, "cpu", &jv[k], cpu);
			YJ_DEC2(e, "wcpu", &jv[k], wcpu);
			YJ_NUM(e, "rss", &jv[k], rss);
			k++;
		}
		out->jail.n = k;
		out->jail.v = jv;
	}
	error = 0;
out:
	ucl_object_unref(top);
	if (dt != NULL)
		ucl_object_unref(dt);
	return (error);
}
