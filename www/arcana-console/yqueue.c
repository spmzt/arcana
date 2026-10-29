/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * An agent's jobs through arcana-jobs (PLAN-SDN-YANG 3.1.4), for the
 * console and arcanactl: submit, the queue's state, a job's read,
 * cancel and confirm actions, and lanes written by an EDIT of the
 * candidate and a commit; the jobs made the structs arcana.yaml's job
 * operations gave, so that the replies built from them keep their
 * shapes.
 */

#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include <cblink.h>
#include <cbl_schema.h>

#include <arcana.h>

#include "ymodel.h"
#include "yqueue.h"

typedef struct arcana_jobs_jobs_job yjob;

/* The top-level node name of module mod, NULL where it is not. */
const struct cbl_ynode *
yq_top(const char *mod, const char *name)
{
	const struct cbl_ymodule	*m;

	for (uint32_t i = 0; i < ymodel_schema.nmod; i++) {
		m = ymodel_schema.mod[i];
		if (strcmp(m->name, mod) != 0)
			continue;
		for (uint32_t k = 0; k < m->ntop; k++)
			if (strcmp(m->top[k]->name, name) == 0)
				return (m->top[k]);
	}
	return (NULL);
}

const struct cbl_ynode *
yq_child(const struct cbl_ynode *n, const char *name)
{

	for (uint32_t i = 0; n != NULL && i < n->nchild; i++)
		if (strcmp(n->child[i]->name, name) == 0)
			return (n->child[i]);
	return (NULL);
}

/* req asked, freed; *rep the answer, else err says why. */
static int
ask(cbl_conn *conn, cbl_msg *req, cbl_msg **rep, char *err, size_t errlen)
{
	int	error;

	*rep = NULL;
	if ((error = cbl_request(conn, req, rep, -1)) != 0) {
		snprintf(err, errlen, "%s", *rep != NULL &&
		    cbl_msg_err_str(*rep) != NULL ? cbl_msg_err_str(*rep) :
		    strerror(error));
		cbl_msg_free(*rep);
		*rep = NULL;
	}
	return (error);
}

int
yq_get(cbl_conn *conn, const struct cbl_ynode *n, int ds, void *data,
    cbl_yarena *a, char *err, size_t errlen)
{
	cbl_msg	*req, *rep;
	int	 error;

	if ((error = cbl_msg_new(cbl_conn_ctx(conn), CBL_YANG_FAMILY,
	    CBL_YCMD_GET, 0, &req)) != 0) {
		snprintf(err, errlen, "%s", strerror(error));
		return (error);
	}
	if ((error = cbl_msg_put_yget(req, &n->sid, 1)) != 0 || (ds >= 0 &&
	    (error = cbl_msg_set_datastore(req, (enum cbl_yds_name)ds)) !=
	    0)) {
		cbl_msg_free(req);
		snprintf(err, errlen, "%s", strerror(error));
		return (error);
	}
	if ((error = ask(conn, req, &rep, err, errlen)) != 0)
		return (error);
	error = cbl_msg_ydecode_member(rep, n, data, a, 0, err, errlen);
	cbl_msg_free(rep);
	return (error == ENOENT ? 0 : error);
}

int
yq_call(cbl_conn *conn, const struct cbl_ynode *list, const void *key,
    const struct cbl_ynode *act, const void *in, void *out, cbl_yarena *a,
    char *err, size_t errlen)
{
	const struct cbl_ynode	*inode, *onode;
	struct cbl_ybuf		 t = { NULL, 0, 0 };
	const void		*vals[1];
	cbl_msg			*req, *rep;
	int			 error;

	inode = onode = NULL;
	for (uint32_t i = 0; i < act->nchild; i++)
		if (act->child[i]->kind == CBL_YN_INPUT)
			inode = act->child[i];
		else if (act->child[i]->kind == CBL_YN_OUTPUT)
			onode = act->child[i];
	if (inode == NULL || onode == NULL) {
		snprintf(err, errlen, "%s: not in the tables", act->name);
		return (ENOENT);
	}
	if (in == NULL && (in = cbl_yarena_alloc(a, inode->size)) == NULL)
		return (ENOMEM);
	if ((error = cbl_msg_new(cbl_conn_ctx(conn), CBL_YANG_FAMILY,
	    CBL_YCMD_RPC, 0, &req)) != 0) {
		snprintf(err, errlen, "%s", strerror(error));
		return (error);
	}
	error = cbl_msg_put_ynode(req, inode, in);
	if (error == 0 && list != NULL) {
		vals[0] = key;
		if ((error = cbl_yiid_write(list, vals, key != NULL ? 1 : 0,
		    &t)) == 0)
			error = cbl_msg_put_yaction(req, t.p, t.len);
		cbl_ybuf_free(&t);
	}
	if (error != 0) {
		cbl_msg_free(req);
		snprintf(err, errlen, "%s", strerror(error));
		return (error);
	}
	if ((error = ask(conn, req, &rep, err, errlen)) != 0)
		return (error);
	error = out != NULL ? cbl_msg_ydecode(rep, onode, out, a, 0, err,
	    errlen) : 0;
	cbl_msg_free(rep);
	return (error == ENOENT ? 0 : error);
}

/* The job list, and the action named of its entries. */
static const struct cbl_ynode *
job_list(void)
{

	return (yq_child(yq_top("arcana-jobs", "jobs"), "job"));
}

static const struct cbl_ynode *
job_action(const char *name)
{

	return (yq_child(job_list(), name));
}

/* job-info's leaves, the module's, into j: the values the job's own. */
#define	JOB_INFO(j, y) do {						\
	if (((j)->has_kind = (y)->has_kind))				\
		(j)->kind = (uint8_t)(y)->kind;				\
	(j)->title = (y)->title;					\
	if (((j)->has_state = (y)->has_state))				\
		(j)->state = (uint8_t)(y)->state;			\
	if (((j)->has_ok = (y)->has_ok))				\
		(j)->ok = (y)->ok;					\
	(j)->error = (y)->error;					\
	if (((j)->has_created = (y)->has_created))			\
		(j)->created = (y)->created;				\
	if (((j)->has_started = (y)->has_started))			\
		(j)->started = (y)->started;				\
	if (((j)->has_finished = (y)->has_finished))			\
		(j)->finished = (y)->finished;				\
	(j)->peer = (y)->peer;						\
	if (((j)->has_confirm_by = (y)->has_confirm_by))		\
		(j)->confirm_by = (y)->confirm_by;			\
} while (0)

int
yq_list(cbl_conn *conn, cbl_yarena *a, struct yq_jobs *out, char *err,
    size_t errlen)
{
	const struct arcana_jobs_jobs	*js;
	const struct cbl_ynode		*n;
	struct arcana_jobs		 d;
	struct arc_job			*v = NULL;
	int				 error;

	memset(out, 0, sizeof(*out));
	if ((n = yq_top("arcana-jobs", "jobs")) == NULL) {
		snprintf(err, errlen, "arcana-jobs is not in the tables");
		return (ENOENT);
	}
	memset(&d, 0, sizeof(d));
	if ((error = yq_get(conn, n, -1, &d, a, err, errlen)) != 0)
		return (error);
	if ((js = d.jobs) == NULL)
		return (0);
	if (js->job.n > 0 && (v = cbl_yarena_alloc(a, js->job.n *
	    sizeof(*v))) == NULL)
		return (ENOMEM);
	for (size_t i = 0; i < js->job.n; i++) {
		const yjob *y = &js->job.v[i];

		memset(&v[i], 0, sizeof(v[i]));
		v[i].has_id = true;
		v[i].id = y->id;
		JOB_INFO(&v[i], y);
	}
	out->v = v;
	out->n = js->job.n;
	out->activity = js->activity;
	out->since = js->has_since ? js->since : 0;
	out->stopping = js->has_stopping && js->stopping;
	out->lanes = js->has_lanes ? js->lanes : 0;
	return (0);
}

int
yq_submit(cbl_conn *conn, const struct arc_job_spec *v, size_t n,
    cbl_yarena *a, struct arc_job **jobs, size_t *njobs, char *err,
    size_t errlen)
{
	struct arcana_jobs_submit_input		 in;
	struct arcana_jobs_submit_input_change	*ch;
	struct arcana_jobs_submit_output	 out;
	const struct cbl_ynode			*rpc;
	struct yq_jobs				 q;
	struct arc_job				*o;
	const char				*bad;
	size_t					 i, k;
	int					 error;

	*jobs = NULL;
	*njobs = 0;
	if ((rpc = yq_top("arcana-jobs", "submit")) == NULL) {
		snprintf(err, errlen, "arcana-jobs is not in the tables");
		return (ENOENT);
	}
	if (n == 0) {
		snprintf(err, errlen, "no change to make");
		return (EINVAL);
	}
	if ((ch = cbl_yarena_alloc(a, n * sizeof(*ch))) == NULL)
		return (ENOMEM);
	for (i = 0; i < n; i++)
		if ((error = yq_change(&v[i], a, &ch[i], &bad)) != 0) {
			if (error == EINVAL)
				snprintf(err, errlen, "job %zu: %s", i + 1,
				    bad);
			else
				snprintf(err, errlen, "%s", strerror(error));
			return (error);
		}
	memset(&in, 0, sizeof(in));
	in.change.n = n;
	in.change.v = ch;
	memset(&out, 0, sizeof(out));
	if ((error = yq_call(conn, NULL, NULL, rpc, &in, &out, a, err,
	    errlen)) != 0)
		return (error);
	if ((o = cbl_yarena_alloc(a, (out.id.n + 1) * sizeof(*o))) == NULL)
		return (ENOMEM);
	memset(o, 0, (out.id.n + 1) * sizeof(*o));
	/*
	 * Each as the queue has it, its title, who gave it; queued, as it
	 * was when it was given, though a runner may have taken it since.
	 */
	if (yq_list(conn, a, &q, err, errlen) != 0)
		memset(&q, 0, sizeof(q));
	for (i = 0; i < out.id.n; i++) {
		for (k = 0; k < q.n && q.v[k].id != out.id.v[i]; k++)
			;
		if (k < q.n)
			o[i] = q.v[k];
		o[i].has_id = true;
		o[i].id = out.id.v[i];
		o[i].has_state = true;
		o[i].state = ARC_JOB_STATE_QUEUED;
		o[i].has_ok = o[i].has_started = o[i].has_finished = false;
		o[i].error = NULL;
	}
	err[0] = '\0';
	*jobs = o;
	*njobs = out.id.n;
	return (0);
}

int
yq_job(cbl_conn *conn, uint64_t id, cbl_yarena *a, struct arc_job *j,
    char *err, size_t errlen)
{
	struct arcana_jobs_jobs_job_read_output	 out;
	const struct cbl_ynode			*act;
	struct arc_step				*s = NULL;
	int					 error;

	memset(j, 0, sizeof(*j));
	if ((act = job_action("read")) == NULL) {
		snprintf(err, errlen, "arcana-jobs has no read");
		return (ENOENT);
	}
	memset(&out, 0, sizeof(out));
	if ((error = yq_call(conn, job_list(), &id, act, NULL, &out, a, err,
	    errlen)) != 0)
		return (error);
	j->has_id = true;
	j->id = id;
	JOB_INFO(j, &out);
	if (out.step.n > 0 && (s = cbl_yarena_alloc(a, out.step.n *
	    sizeof(*s))) == NULL)
		return (ENOMEM);
	for (size_t i = 0; i < out.step.n; i++) {
		const struct arcana_jobs_step *t = &out.step.v[i];

		memset(&s[i], 0, sizeof(s[i]));
		s[i].has_id = true;
		s[i].id = t->id;
		if ((s[i].has_parent = t->has_parent))
			s[i].parent = t->parent;
		if ((s[i].has_kind = t->has_kind))
			s[i].kind = (uint8_t)t->kind;
		s[i].label = t->label;
		s[i].detail = t->detail;
		if ((s[i].has_status = t->has_status))
			s[i].status = (uint8_t)t->status;
		if ((s[i].has_duration_us = t->has_duration))
			s[i].duration_us = t->duration;
		s[i].argv.n = t->argv.n;
		s[i].argv.v = t->argv.v;
		if ((s[i].has_exit = t->has_exit))
			s[i].exit = t->exit;
		s[i].output = t->output;
		s[i].error_output = t->error_output;
	}
	j->trace.n = out.step.n;
	j->trace.v = s;
	return (0);
}

/* The job id as the queue has it, into j; ENOENT where it is not. */
static int
job_listed(cbl_conn *conn, uint64_t id, cbl_yarena *a, struct arc_job *j,
    char *err, size_t errlen)
{
	struct yq_jobs	q;
	int		error;

	if ((error = yq_list(conn, a, &q, err, errlen)) != 0)
		return (error);
	for (size_t i = 0; i < q.n; i++)
		if (q.v[i].id == id) {
			*j = q.v[i];
			return (0);
		}
	snprintf(err, errlen, "no such job");
	return (ENOENT);
}

int
yq_cancel(cbl_conn *conn, uint64_t id, cbl_yarena *a, struct arc_job *j,
    char *err, size_t errlen)
{
	struct arcana_jobs_jobs_job_cancel_output	out;
	const struct cbl_ynode				*act;
	int						error;

	if ((act = job_action("cancel")) == NULL) {
		snprintf(err, errlen, "arcana-jobs has no cancel");
		return (ENOENT);
	}
	memset(&out, 0, sizeof(out));
	if ((error = yq_call(conn, job_list(), &id, act, NULL, &out, a, err,
	    errlen)) != 0)
		return (error);
	return (j != NULL ? job_listed(conn, id, a, j, err, errlen) : 0);
}

int
yq_confirm(cbl_conn *conn, uint64_t id, char *err, size_t errlen)
{
	const struct cbl_ynode	*act;
	cbl_yarena		*a;
	int			 error;

	if ((act = job_action("confirm")) == NULL) {
		snprintf(err, errlen, "arcana-jobs has no confirm");
		return (ENOENT);
	}
	if ((a = cbl_yarena_new()) == NULL)
		return (ENOMEM);
	error = yq_call(conn, job_list(), &id, act, NULL, NULL, a, err, errlen);
	cbl_yarena_free(a);
	return (error);
}

/* ietf-netconf's rpc name, its input in. */
static int
netconf(cbl_conn *conn, const char *name, const void *in, cbl_yarena *a,
    char *err, size_t errlen)
{
	const struct cbl_ynode	*rpc;

	if ((rpc = yq_top("ietf-netconf", name)) == NULL) {
		snprintf(err, errlen, "%s: not in the tables", name);
		return (ENOENT);
	}
	return (yq_call(conn, NULL, NULL, rpc, in, NULL, a, err, errlen));
}

int
yq_lanes(cbl_conn *conn, int lanes, char *err, size_t errlen)
{
	struct arcana_jobs_jobs				 js;
	struct arcana_jobs				 d;
	const struct cbl_ynode				*n;

	if (lanes < 1 || lanes > 32) {
		snprintf(err, errlen, "lanes is 1 to 32");
		return (EINVAL);
	}
	if ((n = yq_top("arcana-jobs", "jobs")) == NULL) {
		snprintf(err, errlen, "arcana-jobs is not in the tables");
		return (ENOENT);
	}
	memset(&js, 0, sizeof(js));
	js.has_lanes = true;
	js.lanes = (uint8_t)lanes;
	memset(&d, 0, sizeof(d));
	d.jobs = &js;
	return (yq_commit(conn, n, &d, err, errlen));
}

int
yq_commit(cbl_conn *conn, const struct cbl_ynode *n, const void *d, char *err,
    size_t errlen)
{
	struct ietf_netconf_commit_input		 cin;
	struct ietf_netconf_discard_changes_input	 din;
	cbl_yarena					*a;
	cbl_msg						*req, *rep;
	char						 why[16];
	int						 error;

	if ((error = cbl_msg_new(cbl_conn_ctx(conn), CBL_YANG_FAMILY,
	    CBL_YCMD_EDIT, 0, &req)) != 0) {
		snprintf(err, errlen, "%s", strerror(error));
		return (error);
	}
	if ((error = cbl_msg_set_datastore(req, CBL_YDS_CANDIDATE)) != 0 ||
	    (error = cbl_msg_put_ymember(req, n, d)) != 0) {
		cbl_msg_free(req);
		snprintf(err, errlen, "%s", strerror(error));
		return (error);
	}
	if ((error = ask(conn, req, &rep, err, errlen)) != 0)
		return (error);
	cbl_msg_free(rep);
	if ((a = cbl_yarena_new()) == NULL)
		return (ENOMEM);
	memset(&cin, 0, sizeof(cin));
	if ((error = netconf(conn, "commit", &cin, a, err, errlen)) != 0) {
		/* The candidate back as running is. */
		memset(&din, 0, sizeof(din));
		(void)netconf(conn, "discard-changes", &din, a, why,
		    sizeof(why));
	}
	cbl_yarena_free(a);
	return (error);
}
