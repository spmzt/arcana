/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

#ifndef _ARCANA_YQUEUE_H_
#define	_ARCANA_YQUEUE_H_

#include <stdbool.h>
#include <stdint.h>

#include <cblink.h>
#include <cbl_schema.h>

/*
 * An agent's jobs through arcana-jobs (yqueue.c), the console's and
 * arcanactl's, as arcana.yaml's job and job-spec have them: the
 * programs make jobs as they did, and read them so.  Each takes conn,
 * puts what it reads in a, and gives 0, or an errno and err (the
 * agent's words).
 *
 * yq_change(): a job-spec made the change submit takes (ychange.c,
 * jobs.awk's); EINVAL, a word none of its field's or a field its kind
 * has none of, refused rather than lost (*bad says which).
 * yq_submit(): the job-specs v (n of them) queued, in that order: the
 * jobs as the queue has them after, *jobs and *njobs.  yq_list(): the
 * queue, without the traces.  yq_job(): job id with its trace, by its
 * read action.  yq_cancel(), yq_confirm(): its cancel and confirm, the
 * job as it is after in *j where j is not NULL.  yq_lanes(): how many
 * jobs of pkg in jails run at once, arcana-jobs' lanes in the
 * candidate, committed.
 */
struct arc_job;
struct arc_job_spec;
struct arcana_jobs_submit_input_change;

struct yq_jobs {
	struct arc_job	*v;
	size_t		 n;
	const char	*activity;	/* what is under way, not a job */
	int64_t		 since;
	bool		 stopping;
	int		 lanes;		/* 0: not said */
};

int	yq_change(const struct arc_job_spec *sp, cbl_yarena *a,
	    struct arcana_jobs_submit_input_change *ch, const char **bad);
int	yq_submit(cbl_conn *conn, const struct arc_job_spec *v, size_t n,
	    cbl_yarena *a, struct arc_job **jobs, size_t *njobs, char *err,
	    size_t errlen);
int	yq_list(cbl_conn *conn, cbl_yarena *a, struct yq_jobs *out,
	    char *err, size_t errlen);
int	yq_job(cbl_conn *conn, uint64_t id, cbl_yarena *a, struct arc_job *j,
	    char *err, size_t errlen);
int	yq_cancel(cbl_conn *conn, uint64_t id, cbl_yarena *a,
	    struct arc_job *j, char *err, size_t errlen);
int	yq_confirm(cbl_conn *conn, uint64_t id, char *err, size_t errlen);
int	yq_lanes(cbl_conn *conn, int lanes, char *err, size_t errlen);

/*
 * The helpers, for ystore.c too: yq_top(), the top-level node name of
 * module mod; yq_child(), n's child name (NULL: none); yq_call(), rpc
 * act (list NULL), or action act of list's entry whose one key is *key,
 * or of container list (key NULL), in its input (NULL: none), out its
 * output (NULL: not read), in a.
 */
const struct cbl_ynode *yq_top(const char *mod, const char *name);
const struct cbl_ynode *yq_child(const struct cbl_ynode *n,
	    const char *name);
int	yq_call(cbl_conn *conn, const struct cbl_ynode *list, const void *key,
	    const struct cbl_ynode *act, const void *in, void *out,
	    cbl_yarena *a, char *err, size_t errlen);

#endif	/* !_ARCANA_YQUEUE_H_ */
