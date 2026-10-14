/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * yjobs: the jobs as arcana-jobs has them (yjobs.c), for agent_test.sh:
 * a done job with its trace and a queued one, a line each and a step a
 * line, through YANG-CBOR and back; then a submit's changes, five kinds,
 * made the job-specs the queue takes (yjobs_spec(), made from
 * jobs.yaml), a spec a line; and a change of no kind refused.
 */

#include <err.h>
#include <stdio.h>
#include <string.h>

#include <arcana.h>

#include "collect.h"

typedef struct arcana_jobs_submit_input_change ychange;

static const char *const argv1[] = { "jail", "-f", "/etc/jail.conf", "-rc",
    "web" };
static const struct arc_step steps[] = {
	{ .has_id = true, .id = 0, .has_parent = true, .parent = -1,
	    .has_kind = true, .kind = ARC_STEP_KIND_DAEMON,
	    .label = "arcana-agent", .detail = "restart web",
	    .has_status = true, .status = ARC_STEP_STATUS_OK,
	    .has_duration_us = true, .duration_us = 812345 },
	{ .has_id = true, .id = 1, .has_parent = true, .parent = 0,
	    .has_kind = true, .kind = ARC_STEP_KIND_EXEC, .label = "jail(8)",
	    .has_status = true, .status = ARC_STEP_STATUS_OK,
	    .argv = { 5, argv1 }, .has_exit = true, .exit = 0,
	    .output = { (const uint8_t *)"web: removed\n", 13 } },
};
static const struct arc_job jobs[] = {
	{ .has_id = true, .id = 41, .has_kind = true,
	    .kind = ARC_JOB_KIND_JAIL_ACTION, .title = "restart web",
	    .has_state = true, .state = ARC_JOB_STATE_DONE, .has_ok = true,
	    .ok = true, .has_created = true, .created = 1760400000,
	    .has_started = true, .started = 1760400001, .has_finished = true,
	    .finished = 1760400002, .peer = "console", .trace = { 2, steps } },
	{ .has_id = true, .id = 42, .has_kind = true,
	    .kind = ARC_JOB_KIND_PKG_UPGRADE, .title = "upgrade packages",
	    .has_state = true, .state = ARC_JOB_STATE_QUEUED,
	    .has_created = true, .created = 1760400003, .peer = "console" },
};

static const char *
str(const char *s)
{

	return (s != NULL ? s : "-");
}

static void
show(const struct arcana_jobs *d)
{
	const struct arcana_jobs_jobs *js = d->jobs;

	printf("activity=%s stopping=%d\n", str(js->activity), js->stopping);
	for (size_t i = 0; i < js->job.n; i++) {
		const struct arcana_jobs_jobs_job *j = &js->job.v[i];

		printf("job %ju kind=%d state=%d ok=%s title=%s created=%jd "
		    "started=%s finished=%s peer=%s\n", (uintmax_t)j->id,
		    (int)j->kind, (int)j->state, j->has_ok ? (j->ok ? "yes" :
		    "no") : "-", str(j->title), (intmax_t)j->created,
		    j->has_started ? "yes" : "-", j->has_finished ? "yes" :
		    "-", str(j->peer));
		for (size_t k = 0; k < j->step.n; k++) {
			const struct arcana_jobs_jobs_job_step *s =
			    &j->step.v[k];

			printf("  step %u parent=%d kind=%d status=%d "
			    "label=%s detail=%s duration=%s argv=%zu exit=%s "
			    "output=%zu\n", s->id, s->parent, (int)s->kind,
			    (int)s->status, str(s->label), str(s->detail),
			    s->has_duration ? "yes" : "-", s->argv.n,
			    s->has_exit ? "yes" : "-", s->output.len);
		}
	}
}

static void
spec(const struct arc_job_spec *sp)
{

	printf("spec kind=%u jail=%s action=%s service=%s service_action=%s "
	    "interface=%s verb=%s ipsec_mode=%s start_action=%s reqid=%s "
	    "persist=%d up=%s safe=%d names=%zu variables=%zu\n", sp->kind,
	    str(sp->jail), sp->has_action ? "yes" : "-", str(sp->service),
	    sp->has_service_action ? "yes" : "-", str(sp->interface),
	    str(sp->verb), str(sp->ipsec_mode), str(sp->start_action),
	    sp->has_reqid ? "yes" : "-", sp->persist, sp->has_up ?
	    (sp->up ? "yes" : "no") : "-", sp->safe, sp->names.n,
	    sp->variables.n);
	if (sp->has_action)
		printf("  action %u\n", sp->action);
	for (size_t i = 0; i < sp->names.n; i++)
		printf("  name %s\n", sp->names.v[i]);
	for (size_t i = 0; i < sp->variables.n; i++)
		printf("  variable %s%s%s\n", sp->variables.v[i].key,
		    sp->variables.v[i].remove ? " unset" : "=",
		    sp->variables.v[i].remove ? "" :
		    sp->variables.v[i].value);
}

int
main(void)
{
	struct arcana_jobs d, back;
	struct cbl_ybuf b1 = { 0 }, b2 = { 0 };
	struct arcana_jobs_submit_input in;
	struct arcana_jobs_submit_input_change_jail_action ja = {
		.jail = "web", .has_action = true, .action =
		ARCANA_JOBS_SUBMIT_INPUT_CHANGE_JAIL_ACTION_ACTION_RESTART };
	struct arcana_jobs_submit_input_change_service_config_set set[] = {
		{ "sshd_flags", "-o UseDNS=no" } };
	static const char *const unset[] = { "sshd_program" };
	struct arcana_jobs_submit_input_change_service_config sc = {
		.service = "sshd", .set = { 1, set }, .unset = { 1, unset } };
	struct arcana_jobs_submit_input_change_ipsec ip = {
		.has_verb = true,
		.verb = ARCANA_JOBS_SUBMIT_INPUT_CHANGE_IPSEC_VERB_CONN,
		.conn = "site-b", .has_ipsec_mode = true, .ipsec_mode =
		ARCANA_JOBS_SUBMIT_INPUT_CHANGE_IPSEC_IPSEC_MODE_TRANSPORT,
		.has_start_action = true, .start_action =
		ARCANA_JOBS_SUBMIT_INPUT_CHANGE_IPSEC_START_ACTION_TRAP,
		.has_reqid = true, .reqid = 5, .has_persist = true,
		.persist = true };
	static const char *const pkgs[] = { "curl", "git" };
	struct arcana_jobs_submit_input_change_pkg_install pi = {
		.jail = "web", .packages = { 2, pkgs } };
	struct arcana_jobs_submit_input_change_if_state is = {
		.interface = "epair0a", .has_up = true, .up = false,
		.has_safe = true, .safe = true };
	ychange ch[6];
	const struct arc_job_spec *specs;
	cbl_yarena *a;
	char why[256];
	size_t n, bad;
	int error;

	if ((a = cbl_yarena_new()) == NULL)
		err(1, "cbl_yarena_new");
	if ((error = yjobs_from(jobs, 2, NULL, 0, false, a, &d)) != 0)
		errc(1, error, "yjobs_from");
	show(&d);
	if (arcana_jobs_jobs_encode(d.jobs, &b1) != 0)
		errx(1, "encode");
	memset(&back, 0, sizeof(back));
	if ((back.jobs = cbl_yarena_alloc(a, sizeof(*back.jobs))) == NULL)
		err(1, "cbl_yarena_alloc");
	if (arcana_jobs_jobs_decode(b1.p, b1.len,
	    (struct arcana_jobs_jobs *)(uintptr_t)back.jobs, a, CBL_YD_STRICT,
	    why, sizeof(why)) != 0)
		errx(1, "decode: %s", why);
	if (arcana_jobs_jobs_encode(back.jobs, &b2) != 0)
		errx(1, "encode again");
	printf("yang-cbor %zu bytes, %s\n", b1.len, b1.len == b2.len &&
	    memcmp(b1.p, b2.p, b1.len) == 0 ? "the same back" : "not the same");

	memset(ch, 0, sizeof(ch));
	ch[0].kind = ARCANA_JOBS_SUBMIT_INPUT_CHANGE_KIND_JAIL_ACTION;
	ch[0].jail_action = &ja;
	ch[1].kind = ARCANA_JOBS_SUBMIT_INPUT_CHANGE_KIND_SERVICE_CONFIG;
	ch[1].service_config = &sc;
	ch[2].kind = ARCANA_JOBS_SUBMIT_INPUT_CHANGE_KIND_IPSEC;
	ch[2].ipsec = &ip;
	ch[3].kind = ARCANA_JOBS_SUBMIT_INPUT_CHANGE_KIND_PKG_INSTALL;
	ch[3].pkg_install = &pi;
	ch[4].kind = ARCANA_JOBS_SUBMIT_INPUT_CHANGE_KIND_IF_STATE;
	ch[4].if_state = &is;
	in.change.n = 5;
	in.change.v = ch;
	if ((error = yjobs_specs(&in, a, &specs, &n, &bad)) != 0)
		errc(1, error, "yjobs_specs");
	printf("kinds jail-action=%d service-config=%d ipsec=%d "
	    "pkg-install=%d if-state=%d\n", ARC_JOB_KIND_JAIL_ACTION,
	    ARC_JOB_KIND_SERVICE_CONFIG, ARC_JOB_KIND_IPSEC,
	    ARC_JOB_KIND_PKG_INSTALL, ARC_JOB_KIND_IF_STATE);
	printf("restart is %d\n", ARC_ACTION_RESTART);
	for (size_t i = 0; i < n; i++)
		spec(&specs[i]);
	/* A change of no kind. */
	in.change.n = 6;
	error = yjobs_specs(&in, a, &specs, &n, &bad);
	printf("no kind: %s, change %zu\n", strerror(error), bad);
	cbl_ybuf_free(&b1);
	cbl_ybuf_free(&b2);
	cbl_yarena_free(a);
	return (0);
}
