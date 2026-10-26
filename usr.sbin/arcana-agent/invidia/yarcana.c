/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Invidia: Arcana's own modules served by cblink's YANG family
 * (docs/PLAN-SDN-YANG.md Y-3), beside the standard models (yserve.c):
 * a GET runs the operation that reads the same, as its job would
 * (do_sysctl(), do_list(), ...), and the module's collector makes its
 * reply the module's structs (y*.c).  The troubleshooting module has
 * actions alone.  Edits,
 * actions and rpcs go by the agent's own operations still: here they
 * are not supported (cblink says operation-not-supported).
 *
 * Each runs on a thread of its own (cbl_yserver_threads(), yserve.c),
 * as the agent's own slow reads do, so a slow one (the storage's ZFS,
 * BIRD) holds no other request.  What
 * a plugin's program reads (BIRD, WireGuard, netgraph) is left out where
 * the program is not there or will not answer, logged: a GET of every
 * module is not lost for one host's lack of BIRD.
 */

#include <sys/param.h>

#include <errno.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>

#include <cblink.h>

#include "agent.h"
#include "collect.h"

static void
ywork_free(void *p)
{

	work_free(p);
	free(p);
}

/*
 * The work of a read, its replies' strings in its pool: the module's
 * structs may point into them (a jail's name, a service's), and cblink
 * encodes them after the handler returns, so it goes with the answer's
 * arena (cbl_yarena_atfree()).  NULL: out of memory.
 */
static struct work *
ywork(cbl_yarena *a)
{
	struct work	*w;

	if ((w = malloc(sizeof(*w))) == NULL)
		return (NULL);
	work_init(w);
	w->nice = true;
	if (cbl_yarena_atfree(a, ywork_free, w) != 0) {
		ywork_free(w);
		return (NULL);
	}
	return (w);
}

/* An operation that failed: said in the log, cblink tells EIO. */
static int
failed(const char *what, const char *why)
{

	logmsg(LOG_INFO, "a read of %s for a model failed: %s", what,
	    why != NULL ? why : "no reason given");
	return (EIO);
}

int
arcana_agent_agent_build_action(cbl_req *req, const struct cbl_bytes *target,
    const struct arcana_agent_agent_build_input *in,
    struct arcana_agent_agent_build_output *out, cbl_yarena *a)
{

	(void)req;
	(void)target;
	(void)in;
	(void)out;
	(void)a;
	return (EOPNOTSUPP);
}

int
arcana_agent_agent_config_apply_action(cbl_req *req,
    const struct cbl_bytes *target,
    const struct arcana_agent_agent_config_apply_input *in,
    struct arcana_agent_agent_config_apply_output *out, cbl_yarena *a)
{

	(void)req;
	(void)target;
	(void)in;
	(void)out;
	(void)a;
	return (EOPNOTSUPP);
}

int
arcana_agent_agent_config_export_action(cbl_req *req,
    const struct cbl_bytes *target,
    const struct arcana_agent_agent_config_export_input *in,
    struct arcana_agent_agent_config_export_output *out, cbl_yarena *a)
{

	(void)req;
	(void)target;
	(void)in;
	(void)out;
	(void)a;
	return (EOPNOTSUPP);
}

int
arcana_agent_agent_console_update_action(cbl_req *req,
    const struct cbl_bytes *target,
    const struct arcana_agent_agent_console_update_input *in,
    struct arcana_agent_agent_console_update_output *out, cbl_yarena *a)
{

	(void)req;
	(void)target;
	(void)in;
	(void)out;
	(void)a;
	return (EOPNOTSUPP);
}

int
arcana_agent_agent_edit(cbl_req *req, const struct arcana_agent *before,
    const struct arcana_agent *after)
{

	(void)req;
	(void)before;
	(void)after;
	return (EOPNOTSUPP);
}

int
arcana_agent_agent_get(cbl_req *req, struct arcana_agent *data, cbl_yarena *a)
{
	struct arc_transport_rsp	 tr;
	struct arc_tls_rsp		 lr;
	struct arcana_agent_agent	*o;
	struct arcana_agent_agent_transport *t;
	struct arcana_agent_agent_tls	*l;
	struct work			*w;
	int				 error;

	if (yang_refused(req))
		return (EACCES);
	if ((w = ywork(a)) == NULL)
		return (ENOMEM);
	if ((o = cbl_yarena_alloc(a, sizeof(*o))) == NULL ||
	    (t = cbl_yarena_alloc(a, sizeof(*t))) == NULL ||
	    (l = cbl_yarena_alloc(a, sizeof(*l))) == NULL)
		return (ENOMEM);
	memset(o, 0, sizeof(*o));
	memset(&tr, 0, sizeof(tr));
	(void)do_transport(w, false, NULL, NULL, false, NULL, &tr);
	if (!tr.ok)
		return (failed("transport", tr.error));
	if ((error = yagent_transport_from_json(tr.json, a, t)) != 0)
		return (error);
	o->transport = t;
	memset(&lr, 0, sizeof(lr));
	do_tls(w, "status", NULL, NULL, NULL, NULL, &lr);
	/* No TLS files, an agent on a local socket alone: no tls. */
	if (lr.ok) {
		if ((error = yagent_tls_from_json(lr.json, a, l)) != 0)
			return (error);
		o->tls = l;
	}
	data->agent = o;
	return (0);
}

int
arcana_agent_agent_source_head_action(cbl_req *req,
    const struct cbl_bytes *target,
    const struct arcana_agent_agent_source_head_input *in,
    struct arcana_agent_agent_source_head_output *out, cbl_yarena *a)
{

	(void)req;
	(void)target;
	(void)in;
	(void)out;
	(void)a;
	return (EOPNOTSUPP);
}

int
arcana_agent_agent_source_log_action(cbl_req *req,
    const struct cbl_bytes *target,
    const struct arcana_agent_agent_source_log_input *in,
    struct arcana_agent_agent_source_log_output *out, cbl_yarena *a)
{

	(void)req;
	(void)target;
	(void)in;
	(void)out;
	(void)a;
	return (EOPNOTSUPP);
}

int
arcana_agent_agent_tls_csr_action(cbl_req *req, const struct cbl_bytes *target,
    const struct arcana_agent_agent_tls_csr_input *in,
    struct arcana_agent_agent_tls_csr_output *out, cbl_yarena *a)
{

	(void)req;
	(void)target;
	(void)in;
	(void)out;
	(void)a;
	return (EOPNOTSUPP);
}

int
arcana_agent_agent_tls_install_action(cbl_req *req,
    const struct cbl_bytes *target,
    const struct arcana_agent_agent_tls_install_input *in,
    struct arcana_agent_agent_tls_install_output *out, cbl_yarena *a)
{

	(void)req;
	(void)target;
	(void)in;
	(void)out;
	(void)a;
	return (EOPNOTSUPP);
}

int
arcana_agent_agent_transport_retry_action(cbl_req *req,
    const struct cbl_bytes *target,
    const struct arcana_agent_agent_transport_retry_input *in,
    struct arcana_agent_agent_transport_retry_output *out, cbl_yarena *a)
{

	(void)req;
	(void)target;
	(void)in;
	(void)out;
	(void)a;
	return (EOPNOTSUPP);
}

int
arcana_agent_agent_update_action(cbl_req *req, const struct cbl_bytes *target,
    const struct arcana_agent_agent_update_input *in,
    struct arcana_agent_agent_update_output *out, cbl_yarena *a)
{

	(void)req;
	(void)target;
	(void)in;
	(void)out;
	(void)a;
	return (EOPNOTSUPP);
}

int
arcana_bird_bird_edit(cbl_req *req, const struct arcana_bird *before,
    const struct arcana_bird *after)
{

	(void)req;
	(void)before;
	(void)after;
	return (EOPNOTSUPP);
}

int
arcana_bird_bird_get(cbl_req *req, struct arcana_bird *data, cbl_yarena *a)
{
	struct arc_network_rsp		 r;
	struct arcana_bird_bird		*o;
	struct arcana_bird_bird_state	*st;
	struct work			*w;
	int				 error;

	if (yang_refused(req))
		return (EACCES);
	if ((w = ywork(a)) == NULL)
		return (ENOMEM);
	memset(&r, 0, sizeof(r));
	(void)do_network(w, ARC_NET_KIND_BIRD, ARC_NET_FAMILY_ALL, NULL, 0, 0,
	    &r);
	/* No BIRD running (birdc not answering): no bird, not a failure. */
	if (!r.ok) {
		(void)failed("bird", r.error);
		return (0);
	}
	if ((o = cbl_yarena_alloc(a, sizeof(*o))) == NULL ||
	    (st = cbl_yarena_alloc(a, sizeof(*st))) == NULL)
		return (ENOMEM);
	memset(o, 0, sizeof(*o));
	if ((error = ybird_from_json(r.json, a, st)) != 0)
		return (error);
	o->state = st;
	data->bird = o;
	return (0);
}

int
arcana_bird_bird_routes_action(cbl_req *req, const struct cbl_bytes *target,
    const struct arcana_bird_bird_routes_input *in,
    struct arcana_bird_bird_routes_output *out, cbl_yarena *a)
{

	(void)req;
	(void)target;
	(void)in;
	(void)out;
	(void)a;
	return (EOPNOTSUPP);
}

int
arcana_builder_builder_get(cbl_req *req, struct arcana_builder *data,
    cbl_yarena *a)
{
	struct arc_builder_rsp		 r;
	struct arcana_builder_builder	*o;
	struct work			*w;
	int				 error;

	if (yang_refused(req))
		return (EACCES);
	if ((w = ywork(a)) == NULL)
		return (ENOMEM);
	memset(&r, 0, sizeof(r));
	(void)do_builder(w, &r);
	if (!r.ok)
		return (failed("builder", r.error));
	if ((o = cbl_yarena_alloc(a, sizeof(*o))) == NULL)
		return (ENOMEM);
	if ((error = ybuilder_from_json(r.json, a, o)) != 0)
		return (error);
	data->builder = o;
	return (0);
}

int
arcana_events_events_get(cbl_req *req, struct arcana_events *data,
    cbl_yarena *a)
{
	struct arc_events_rsp		 r;
	struct arcana_events_events	*o;
	struct work			*w;
	int				 error;

	if (yang_refused(req))
		return (EACCES);
	if ((w = ywork(a)) == NULL)
		return (ENOMEM);
	memset(&r, 0, sizeof(r));
	(void)do_events(w, 0, &r);
	if (!r.ok)
		return (failed("events", r.error));
	if ((o = cbl_yarena_alloc(a, sizeof(*o))) == NULL)
		return (ENOMEM);
	if ((error = yev_from_json(r.json, a, o)) != 0)
		return (error);
	data->events = o;
	return (0);
}

int
arcana_events_events_read_action(cbl_req *req, const struct cbl_bytes *target,
    const struct arcana_events_events_read_input *in,
    struct arcana_events_events_read_output *out, cbl_yarena *a)
{

	(void)req;
	(void)target;
	(void)in;
	(void)out;
	(void)a;
	return (EOPNOTSUPP);
}

int
arcana_firewall_firewall_edit(cbl_req *req,
    const struct arcana_firewall *before, const struct arcana_firewall *after)
{

	(void)req;
	(void)before;
	(void)after;
	return (EOPNOTSUPP);
}

int
arcana_firewall_firewall_get(cbl_req *req, struct arcana_firewall *data,
    cbl_yarena *a)
{
	struct arc_network_rsp			 r;
	struct arc_ipfw_rules_req		 kq;
	struct arc_ipfw_rules_rsp		 kr;
	struct arcana_firewall_firewall		*o;
	struct arcana_firewall_firewall_kept	*k;
	struct work				*w;
	int					 error;

	if (yang_refused(req))
		return (EACCES);
	if ((w = ywork(a)) == NULL)
		return (ENOMEM);
	memset(&r, 0, sizeof(r));
	(void)do_network(w, ARC_NET_KIND_IPFW, ARC_NET_FAMILY_ALL, NULL, 0, 0,
	    &r);
	if (!r.ok)
		return (failed("ipfw", r.error));
	if ((o = cbl_yarena_alloc(a, sizeof(*o))) == NULL ||
	    (k = cbl_yarena_alloc(a, sizeof(*k))) == NULL)
		return (ENOMEM);
	if ((error = yfw_from_json(r.json, a, o)) != 0)
		return (error);
	/* The rules kept for the next boot, as the ipfw-rules read. */
	memset(&kq, 0, sizeof(kq));
	memset(&kr, 0, sizeof(kr));
	(void)do_ipfw_rules(w, &kq, &kr);
	if (kr.ok && (error = yfw_kept_from_text(kr.conf_text, kr.sha256, a,
	    k)) == 0)
		o->kept = k;
	else if (error != 0)
		return (error);
	data->firewall = o;
	return (0);
}

int
arcana_firewall_firewall_trace_action(cbl_req *req,
    const struct cbl_bytes *target,
    const struct arcana_firewall_firewall_trace_input *in,
    struct arcana_firewall_firewall_trace_output *out, cbl_yarena *a)
{

	(void)req;
	(void)target;
	(void)in;
	(void)out;
	(void)a;
	return (EOPNOTSUPP);
}

int
arcana_history_history_edit(cbl_req *req, const struct arcana_history *before,
    const struct arcana_history *after)
{

	(void)req;
	(void)before;
	(void)after;
	return (EOPNOTSUPP);
}

int
arcana_history_history_get(cbl_req *req, struct arcana_history *data,
    cbl_yarena *a)
{
	struct arc_history_rsp		 r;
	struct arcana_history_history	*o;
	struct work			*w;
	int				 error;

	if (yang_refused(req))
		return (EACCES);
	if ((w = ywork(a)) == NULL)
		return (ENOMEM);
	memset(&r, 0, sizeof(r));
	(void)do_history(w, 0, false, 0, 0, NULL, NULL, &r);
	if (!r.ok)
		return (failed("history", r.error));
	if ((o = cbl_yarena_alloc(a, sizeof(*o))) == NULL)
		return (ENOMEM);
	if ((error = yhist_from_json(r.json, a, o)) != 0)
		return (error);
	data->history = o;
	return (0);
}

int
arcana_history_history_read_action(cbl_req *req, const struct cbl_bytes *target,
    const struct arcana_history_history_read_input *in,
    struct arcana_history_history_read_output *out, cbl_yarena *a)
{

	(void)req;
	(void)target;
	(void)in;
	(void)out;
	(void)a;
	return (EOPNOTSUPP);
}

int
arcana_jails_jails_get(cbl_req *req, struct arcana_jails *data, cbl_yarena *a)
{
	struct arc_list_rsp	 r;
	struct work		*w;

	if (yang_refused(req))
		return (EACCES);
	if ((w = ywork(a)) == NULL)
		return (ENOMEM);
	memset(&r, 0, sizeof(r));
	(void)do_list(w, false, &r);
	if (!r.ok)
		return (failed("list", r.error));
	return (yjails_from_list(&r, a, data));
}

int
arcana_jails_jails_jail_arcbird_bird_routes_action(cbl_req *req,
    const struct cbl_bytes *target,
    const struct arcana_jails_jails_jail_arcbird_bird_routes_input *in,
    struct arcana_jails_jails_jail_arcbird_bird_routes_output *out,
    cbl_yarena *a)
{

	(void)req;
	(void)target;
	(void)in;
	(void)out;
	(void)a;
	return (EOPNOTSUPP);
}

int
arcana_jails_jails_jail_arcfw_firewall_trace_action(cbl_req *req,
    const struct cbl_bytes *target,
    const struct arcana_jails_jails_jail_arcfw_firewall_trace_input *in,
    struct arcana_jails_jails_jail_arcfw_firewall_trace_output *out,
    cbl_yarena *a)
{

	(void)req;
	(void)target;
	(void)in;
	(void)out;
	(void)a;
	return (EOPNOTSUPP);
}

int
arcana_jails_jails_jail_arcpkg_packages_refresh_action(cbl_req *req,
    const struct cbl_bytes *target,
    const struct arcana_jails_jails_jail_arcpkg_packages_refresh_input *in,
    struct arcana_jails_jails_jail_arcpkg_packages_refresh_output *out,
    cbl_yarena *a)
{

	(void)req;
	(void)target;
	(void)in;
	(void)out;
	(void)a;
	return (EOPNOTSUPP);
}

int
arcana_jails_jails_jail_arcpkg_packages_upgrade_action(cbl_req *req,
    const struct cbl_bytes *target,
    const struct arcana_jails_jails_jail_arcpkg_packages_upgrade_input *in,
    struct arcana_jails_jails_jail_arcpkg_packages_upgrade_output *out,
    cbl_yarena *a)
{

	(void)req;
	(void)target;
	(void)in;
	(void)out;
	(void)a;
	return (EOPNOTSUPP);
}

int
arcana_jails_jails_jail_kill_action(cbl_req *req,
    const struct cbl_bytes *target,
    const struct arcana_jails_jails_jail_kill_input *in,
    struct arcana_jails_jails_jail_kill_output *out, cbl_yarena *a)
{

	(void)req;
	(void)target;
	(void)in;
	(void)out;
	(void)a;
	return (EOPNOTSUPP);
}

int
arcana_jails_jails_jail_restart_action(cbl_req *req,
    const struct cbl_bytes *target,
    const struct arcana_jails_jails_jail_restart_input *in,
    struct arcana_jails_jails_jail_restart_output *out, cbl_yarena *a)
{

	(void)req;
	(void)target;
	(void)in;
	(void)out;
	(void)a;
	return (EOPNOTSUPP);
}

int
arcana_jails_jails_jail_start_action(cbl_req *req,
    const struct cbl_bytes *target,
    const struct arcana_jails_jails_jail_start_input *in,
    struct arcana_jails_jails_jail_start_output *out, cbl_yarena *a)
{

	(void)req;
	(void)target;
	(void)in;
	(void)out;
	(void)a;
	return (EOPNOTSUPP);
}

int
arcana_jails_jails_jail_stop_action(cbl_req *req,
    const struct cbl_bytes *target,
    const struct arcana_jails_jails_jail_stop_input *in,
    struct arcana_jails_jails_jail_stop_output *out, cbl_yarena *a)
{

	(void)req;
	(void)target;
	(void)in;
	(void)out;
	(void)a;
	return (EOPNOTSUPP);
}

int
arcana_jobs_jobs_get(cbl_req *req, struct arcana_jobs *data, cbl_yarena *a)
{
	const struct arc_job	*v;
	struct work		*w;
	const char		*activity;
	time_t			 since;
	size_t			 n;

	if (yang_refused(req))
		return (EACCES);
	if ((w = ywork(a)) == NULL)
		return (ENOMEM);
	jobs_list(w, &v, &n);
	since = 0;
	activity = changes_current(w, &since);
	return (yjobs_from(v, n, activity, (int64_t)since, changes_stopping(),
	    a, data));
}

int
arcana_jobs_jobs_job_cancel_action(cbl_req *req, const struct cbl_bytes *target,
    const struct arcana_jobs_jobs_job_cancel_input *in,
    struct arcana_jobs_jobs_job_cancel_output *out, cbl_yarena *a)
{

	(void)req;
	(void)target;
	(void)in;
	(void)out;
	(void)a;
	return (EOPNOTSUPP);
}

int
arcana_jobs_jobs_job_confirm_action(cbl_req *req,
    const struct cbl_bytes *target,
    const struct arcana_jobs_jobs_job_confirm_input *in,
    struct arcana_jobs_jobs_job_confirm_output *out, cbl_yarena *a)
{

	(void)req;
	(void)target;
	(void)in;
	(void)out;
	(void)a;
	return (EOPNOTSUPP);
}

int
arcana_jobs_submit_rpc(cbl_req *req, const struct arcana_jobs_submit_input *in,
    struct arcana_jobs_submit_output *out, cbl_yarena *a)
{

	(void)req;
	(void)in;
	(void)out;
	(void)a;
	return (EOPNOTSUPP);
}

int
arcana_kernel_kernel_edit(cbl_req *req, const struct arcana_kernel *before,
    const struct arcana_kernel *after)
{

	(void)req;
	(void)before;
	(void)after;
	return (EOPNOTSUPP);
}

int
arcana_kernel_kernel_file_unload_action(cbl_req *req,
    const struct cbl_bytes *target,
    const struct arcana_kernel_kernel_file_unload_input *in,
    struct arcana_kernel_kernel_file_unload_output *out, cbl_yarena *a)
{

	(void)req;
	(void)target;
	(void)in;
	(void)out;
	(void)a;
	return (EOPNOTSUPP);
}

int
arcana_kernel_kernel_get(cbl_req *req, struct arcana_kernel *data,
    cbl_yarena *a)
{
	struct arc_kernel_rsp		 r;
	struct arcana_kernel_kernel	*o;
	struct work			*w;
	int				 error;

	if (yang_refused(req))
		return (EACCES);
	if ((w = ywork(a)) == NULL)
		return (ENOMEM);
	memset(&r, 0, sizeof(r));
	(void)do_kernel(w, &r);
	if (!r.ok)
		return (failed("kernel", r.error));
	if ((o = cbl_yarena_alloc(a, sizeof(*o))) == NULL)
		return (ENOMEM);
	if ((error = ykernel_from_json(r.json, a, o)) != 0)
		return (error);
	data->kernel = o;
	return (0);
}

int
arcana_kernel_load_rpc(cbl_req *req, const struct arcana_kernel_load_input *in,
    struct arcana_kernel_load_output *out, cbl_yarena *a)
{

	(void)req;
	(void)in;
	(void)out;
	(void)a;
	return (EOPNOTSUPP);
}

int
arcana_log_logs_get(cbl_req *req, struct arcana_log *data, cbl_yarena *a)
{
	struct arc_log_rsp		 r;
	struct arcana_log_logs	*o;
	struct work			*w;
	int				 error;

	if (yang_refused(req))
		return (EACCES);
	if ((w = ywork(a)) == NULL)
		return (ENOMEM);
	memset(&r, 0, sizeof(r));
	(void)do_log(w, NULL, NULL, false, 0, 0, &r);
	if (!r.ok)
		return (failed("log", r.error));
	if ((o = cbl_yarena_alloc(a, sizeof(*o))) == NULL)
		return (ENOMEM);
	if ((error = ylog_files_from_json(r.json, "/var/log", a, o)) != 0)
		return (error);
	data->logs = o;
	return (0);
}

int
arcana_log_logs_read_action(cbl_req *req, const struct cbl_bytes *target,
    const struct arcana_log_logs_read_input *in,
    struct arcana_log_logs_read_output *out, cbl_yarena *a)
{

	(void)req;
	(void)target;
	(void)in;
	(void)out;
	(void)a;
	return (EOPNOTSUPP);
}

int
arcana_netgraph_netgraph_get(cbl_req *req, struct arcana_netgraph *data,
    cbl_yarena *a)
{
	struct arc_network_rsp		 r;
	struct arcana_netgraph_netgraph	*o;
	struct work			*w;
	int				 error;

	if (yang_refused(req))
		return (EACCES);
	if ((w = ywork(a)) == NULL)
		return (ENOMEM);
	memset(&r, 0, sizeof(r));
	(void)do_network(w, ARC_NET_KIND_NETGRAPH, ARC_NET_FAMILY_ALL, NULL, 0,
	    0, &r);
	/* ngctl(8) refused (an agent not root) or no netgraph(4): none,
	 * so that a read of every module is not lost for it. */
	if (!r.ok) {
		(void)failed("netgraph", r.error);
		return (0);
	}
	if ((o = cbl_yarena_alloc(a, sizeof(*o))) == NULL)
		return (ENOMEM);
	if ((error = yng_from_json(r.json, a, o)) != 0)
		return (error);
	data->netgraph = o;
	return (0);
}

int
arcana_notify_notify_rpc(cbl_req *req,
    const struct arcana_notify_notify_input *in,
    struct arcana_notify_notify_output *out, cbl_yarena *a)
{

	(void)req;
	(void)in;
	(void)out;
	(void)a;
	return (EOPNOTSUPP);
}

int
arcana_packages_packages_get(cbl_req *req, struct arcana_packages *data,
    cbl_yarena *a)
{
	struct arc_packages_rsp		 r;
	struct arcana_packages_packages	*o;
	struct work			*w;
	int				 error;

	if (yang_refused(req))
		return (EACCES);
	if ((w = ywork(a)) == NULL)
		return (ENOMEM);
	memset(&r, 0, sizeof(r));
	/* Those installed; which are outdated asks the repository, not a
	 * read's to do (the refresh action). */
	(void)do_packages(w, NULL, false, true, 0, false, &r);
	if (!r.ok)
		return (failed("packages", r.error));
	if ((o = cbl_yarena_alloc(a, sizeof(*o))) == NULL)
		return (ENOMEM);
	if ((error = ypackages_from(&r, NULL, a, o)) != 0)
		return (error);
	data->packages = o;
	return (0);
}

int
arcana_packages_packages_refresh_action(cbl_req *req,
    const struct cbl_bytes *target,
    const struct arcana_packages_packages_refresh_input *in,
    struct arcana_packages_packages_refresh_output *out, cbl_yarena *a)
{

	(void)req;
	(void)target;
	(void)in;
	(void)out;
	(void)a;
	return (EOPNOTSUPP);
}

int
arcana_packages_packages_upgrade_action(cbl_req *req,
    const struct cbl_bytes *target,
    const struct arcana_packages_packages_upgrade_input *in,
    struct arcana_packages_packages_upgrade_output *out, cbl_yarena *a)
{

	(void)req;
	(void)target;
	(void)in;
	(void)out;
	(void)a;
	return (EOPNOTSUPP);
}

int
arcana_probe_probes_edit(cbl_req *req, const struct arcana_probe *before,
    const struct arcana_probe *after)
{

	(void)req;
	(void)before;
	(void)after;
	return (EOPNOTSUPP);
}

int
arcana_probe_probes_get(cbl_req *req, struct arcana_probe *data, cbl_yarena *a)
{
	struct arc_sdwan_rsp		 r;
	struct arcana_probe_probes	*o;
	struct arcana_probe_probes_state *st;
	struct work			*w;
	int				 error;

	if (yang_refused(req))
		return (EACCES);
	if ((w = ywork(a)) == NULL)
		return (ENOMEM);
	memset(&r, 0, sizeof(r));
	(void)do_sdwan(w, 0, &r);
	if (!r.ok)
		return (failed("sdwan", r.error));
	if ((o = cbl_yarena_alloc(a, sizeof(*o))) == NULL ||
	    (st = cbl_yarena_alloc(a, sizeof(*st))) == NULL)
		return (ENOMEM);
	memset(o, 0, sizeof(*o));
	if ((error = yprobe_state_from_json(r.json, a, st)) != 0)
		return (error);
	o->state = st;
	data->probes = o;
	return (0);
}

int
arcana_probe_probes_read_action(cbl_req *req, const struct cbl_bytes *target,
    const struct arcana_probe_probes_read_input *in,
    struct arcana_probe_probes_read_output *out, cbl_yarena *a)
{

	(void)req;
	(void)target;
	(void)in;
	(void)out;
	(void)a;
	return (EOPNOTSUPP);
}

int
arcana_processes_processes_edit(cbl_req *req,
    const struct arcana_processes *before, const struct arcana_processes *after)
{

	(void)req;
	(void)before;
	(void)after;
	return (EOPNOTSUPP);
}

int
arcana_processes_processes_get(cbl_req *req, struct arcana_processes *data,
    cbl_yarena *a)
{
	struct arc_processes_rsp		 r;
	struct arcana_processes_processes	*o;
	struct work			*w;
	int				 error;

	if (yang_refused(req))
		return (EACCES);
	if ((w = ywork(a)) == NULL)
		return (ENOMEM);
	memset(&r, 0, sizeof(r));
	(void)do_processes(w, NULL, &r);
	if (!r.ok)
		return (failed("processes", r.error));
	if ((o = cbl_yarena_alloc(a, sizeof(*o))) == NULL)
		return (ENOMEM);
	if ((error = yprocs_from_json(r.json, NULL, a, o)) != 0)
		return (error);
	data->processes = o;
	return (0);
}

int
arcana_processes_processes_process_renice_action(cbl_req *req,
    const struct cbl_bytes *target,
    const struct arcana_processes_processes_process_renice_input *in,
    struct arcana_processes_processes_process_renice_output *out, cbl_yarena *a)
{

	(void)req;
	(void)target;
	(void)in;
	(void)out;
	(void)a;
	return (EOPNOTSUPP);
}

int
arcana_processes_processes_process_signal_action(cbl_req *req,
    const struct cbl_bytes *target,
    const struct arcana_processes_processes_process_signal_input *in,
    struct arcana_processes_processes_process_signal_output *out, cbl_yarena *a)
{

	(void)req;
	(void)target;
	(void)in;
	(void)out;
	(void)a;
	return (EOPNOTSUPP);
}

int
arcana_sdwan_sdwan_edit(cbl_req *req, const struct arcana_sdwan *before,
    const struct arcana_sdwan *after)
{

	(void)req;
	(void)before;
	(void)after;
	return (EOPNOTSUPP);
}

int
arcana_sdwan_sdwan_get(cbl_req *req, struct arcana_sdwan *data, cbl_yarena *a)
{
	struct arc_sdwan_rsp		 r;
	struct arcana_sdwan_sdwan	*o;
	struct arcana_sdwan_sdwan_state	*st;
	struct work			*w;
	int				 error;

	if (yang_refused(req))
		return (EACCES);
	if ((w = ywork(a)) == NULL)
		return (ENOMEM);
	memset(&r, 0, sizeof(r));
	(void)do_sdwan(w, 0, &r);
	if (!r.ok)
		return (failed("sdwan", r.error));
	if ((o = cbl_yarena_alloc(a, sizeof(*o))) == NULL ||
	    (st = cbl_yarena_alloc(a, sizeof(*st))) == NULL)
		return (ENOMEM);
	memset(o, 0, sizeof(*o));
	if ((error = ysd_state_from_json(r.json, a, st)) != 0)
		return (error);
	o->state = st;
	data->sdwan = o;
	return (0);
}

int
arcana_services_services_edit(cbl_req *req,
    const struct arcana_services *before, const struct arcana_services *after)
{

	(void)req;
	(void)before;
	(void)after;
	return (EOPNOTSUPP);
}

int
arcana_services_services_get(cbl_req *req, struct arcana_services *data,
    cbl_yarena *a)
{
	struct arc_services_rsp	 r;
	struct work		*w;

	if (yang_refused(req))
		return (EACCES);
	if ((w = ywork(a)) == NULL)
		return (ENOMEM);
	memset(&r, 0, sizeof(r));
	(void)do_services(w, &r);
	if (!r.ok)
		return (failed("services", r.error));
	return (yservices_from(&r, NULL, 0, a, data));
}

int
arcana_services_services_service_reload_action(cbl_req *req,
    const struct cbl_bytes *target,
    const struct arcana_services_services_service_reload_input *in,
    struct arcana_services_services_service_reload_output *out, cbl_yarena *a)
{

	(void)req;
	(void)target;
	(void)in;
	(void)out;
	(void)a;
	return (EOPNOTSUPP);
}

int
arcana_services_services_service_restart_action(cbl_req *req,
    const struct cbl_bytes *target,
    const struct arcana_services_services_service_restart_input *in,
    struct arcana_services_services_service_restart_output *out, cbl_yarena *a)
{

	(void)req;
	(void)target;
	(void)in;
	(void)out;
	(void)a;
	return (EOPNOTSUPP);
}

int
arcana_services_services_service_start_action(cbl_req *req,
    const struct cbl_bytes *target,
    const struct arcana_services_services_service_start_input *in,
    struct arcana_services_services_service_start_output *out, cbl_yarena *a)
{

	(void)req;
	(void)target;
	(void)in;
	(void)out;
	(void)a;
	return (EOPNOTSUPP);
}

int
arcana_services_services_service_stop_action(cbl_req *req,
    const struct cbl_bytes *target,
    const struct arcana_services_services_service_stop_input *in,
    struct arcana_services_services_service_stop_output *out, cbl_yarena *a)
{

	(void)req;
	(void)target;
	(void)in;
	(void)out;
	(void)a;
	return (EOPNOTSUPP);
}

int
arcana_sshd_sshd_get(cbl_req *req, struct arcana_sshd *data, cbl_yarena *a)
{
	struct arc_ssh_rsp		 r;
	struct arcana_sshd_sshd	*o;
	struct work			*w;
	int				 error;

	if (yang_refused(req))
		return (EACCES);
	if ((w = ywork(a)) == NULL)
		return (ENOMEM);
	memset(&r, 0, sizeof(r));
	(void)do_ssh(w, &r);
	if (!r.ok)
		return (failed("ssh", r.error));
	if ((o = cbl_yarena_alloc(a, sizeof(*o))) == NULL)
		return (ENOMEM);
	if ((error = ysshd_from_json(r.json, a, o)) != 0)
		return (error);
	data->sshd = o;
	return (0);
}

int
arcana_storage_receive_rpc(cbl_req *req,
    const struct arcana_storage_receive_input *in,
    struct arcana_storage_receive_output *out, cbl_yarena *a)
{

	(void)req;
	(void)in;
	(void)out;
	(void)a;
	return (EOPNOTSUPP);
}

int
arcana_storage_storage_dataset_change_key_action(cbl_req *req,
    const struct cbl_bytes *target,
    const struct arcana_storage_storage_dataset_change_key_input *in,
    struct arcana_storage_storage_dataset_change_key_output *out, cbl_yarena *a)
{

	(void)req;
	(void)target;
	(void)in;
	(void)out;
	(void)a;
	return (EOPNOTSUPP);
}

int
arcana_storage_storage_dataset_load_key_action(cbl_req *req,
    const struct cbl_bytes *target,
    const struct arcana_storage_storage_dataset_load_key_input *in,
    struct arcana_storage_storage_dataset_load_key_output *out, cbl_yarena *a)
{

	(void)req;
	(void)target;
	(void)in;
	(void)out;
	(void)a;
	return (EOPNOTSUPP);
}

int
arcana_storage_storage_dataset_unload_key_action(cbl_req *req,
    const struct cbl_bytes *target,
    const struct arcana_storage_storage_dataset_unload_key_input *in,
    struct arcana_storage_storage_dataset_unload_key_output *out, cbl_yarena *a)
{

	(void)req;
	(void)target;
	(void)in;
	(void)out;
	(void)a;
	return (EOPNOTSUPP);
}

int
arcana_storage_storage_fstab_replace_action(cbl_req *req,
    const struct cbl_bytes *target,
    const struct arcana_storage_storage_fstab_replace_input *in,
    struct arcana_storage_storage_fstab_replace_output *out, cbl_yarena *a)
{

	(void)req;
	(void)target;
	(void)in;
	(void)out;
	(void)a;
	return (EOPNOTSUPP);
}

int
arcana_storage_storage_get(cbl_req *req, struct arcana_storage *data,
    cbl_yarena *a)
{
	static const uint8_t kinds[] = { ARC_STORAGE_KIND_DISKS,
	    ARC_STORAGE_KIND_POOLS, ARC_STORAGE_KIND_DATASETS,
	    ARC_STORAGE_KIND_SNAPSHOTS, ARC_STORAGE_KIND_MOUNTS,
	    ARC_STORAGE_KIND_HEALTH };
	struct arc_storage_rsp		 r;
	struct arcana_storage_storage	*o;
	struct work			*w;
	size_t				 i;
	int				 error;

	if (yang_refused(req))
		return (EACCES);
	if ((w = ywork(a)) == NULL)
		return (ENOMEM);
	if ((o = cbl_yarena_alloc(a, sizeof(*o))) == NULL)
		return (ENOMEM);
	memset(o, 0, sizeof(*o));
	/* Each kind the storage operation reads, but the pools a scan
	 * finds to import (zpool import, slow): one struct of them all. */
	for (i = 0; i < nitems(kinds); i++) {
		memset(&r, 0, sizeof(r));
		(void)do_storage(w, kinds[i], NULL, &r);
		if (!r.ok)
			return (failed("storage", r.error));
		if ((error = ystorage_from_json(kinds[i], r.json, r.total,
		    r.truncated, a, o)) != 0)
			return (error);
	}
	data->storage = o;
	return (0);
}

int
arcana_storage_storage_snapshot_send_action(cbl_req *req,
    const struct cbl_bytes *target,
    const struct arcana_storage_storage_snapshot_send_input *in,
    struct arcana_storage_storage_snapshot_send_output *out, cbl_yarena *a)
{

	(void)req;
	(void)target;
	(void)in;
	(void)out;
	(void)a;
	return (EOPNOTSUPP);
}

int
arcana_sysctl_sysctl_edit(cbl_req *req, const struct arcana_sysctl *before,
    const struct arcana_sysctl *after)
{

	(void)req;
	(void)before;
	(void)after;
	return (EOPNOTSUPP);
}

int
arcana_sysctl_sysctl_get(cbl_req *req, struct arcana_sysctl *data,
    cbl_yarena *a)
{
	struct arc_sysctl_rsp		 r;
	struct arcana_sysctl_sysctl	*o;
	struct work			*w;
	int				 error;

	if (yang_refused(req))
		return (EACCES);
	if ((w = ywork(a)) == NULL)
		return (ENOMEM);
	memset(&r, 0, sizeof(r));
	(void)do_sysctl(w, NULL, &r);
	if (!r.ok)
		return (failed("sysctl", r.error));
	if ((o = cbl_yarena_alloc(a, sizeof(*o))) == NULL)
		return (ENOMEM);
	if ((error = ysysctl_from_json(r.json, r.total, r.truncated, a, o)) !=
	    0)
		return (error);
	data->sysctl = o;
	return (0);
}

int
arcana_troubleshoot_troubleshoot_capture_action(cbl_req *req,
    const struct cbl_bytes *target,
    const struct arcana_troubleshoot_troubleshoot_capture_input *in,
    struct arcana_troubleshoot_troubleshoot_capture_output *out, cbl_yarena *a)
{

	(void)req;
	(void)target;
	(void)in;
	(void)out;
	(void)a;
	return (EOPNOTSUPP);
}

int
arcana_troubleshoot_troubleshoot_edit(cbl_req *req,
    const struct arcana_troubleshoot *before,
    const struct arcana_troubleshoot *after)
{

	(void)req;
	(void)before;
	(void)after;
	return (EOPNOTSUPP);
}

int
arcana_troubleshoot_troubleshoot_get(cbl_req *req,
    struct arcana_troubleshoot *data, cbl_yarena *a)
{
	(void)data;
	(void)a;
	/* Its actions alone: nothing to read. */
	return (yang_refused(req) ? EACCES : 0);
}

int
arcana_troubleshoot_troubleshoot_path_check_action(cbl_req *req,
    const struct cbl_bytes *target,
    const struct arcana_troubleshoot_troubleshoot_path_check_input *in,
    struct arcana_troubleshoot_troubleshoot_path_check_output *out,
    cbl_yarena *a)
{

	(void)req;
	(void)target;
	(void)in;
	(void)out;
	(void)a;
	return (EOPNOTSUPP);
}

int
arcana_troubleshoot_troubleshoot_traceroute_action(cbl_req *req,
    const struct cbl_bytes *target,
    const struct arcana_troubleshoot_troubleshoot_traceroute_input *in,
    struct arcana_troubleshoot_troubleshoot_traceroute_output *out,
    cbl_yarena *a)
{

	(void)req;
	(void)target;
	(void)in;
	(void)out;
	(void)a;
	return (EOPNOTSUPP);
}

int
arcana_wireguard_wireguard_get(cbl_req *req, struct arcana_wireguard *data,
    cbl_yarena *a)
{
	struct arc_network_rsp		 r;
	struct arcana_wireguard_wireguard	*o;
	struct work			*w;
	int				 error;

	if (yang_refused(req))
		return (EACCES);
	if ((w = ywork(a)) == NULL)
		return (ENOMEM);
	memset(&r, 0, sizeof(r));
	(void)do_network(w, ARC_NET_KIND_WIREGUARD, ARC_NET_FAMILY_ALL, NULL,
	    0, 0, &r);
	/* No wg(8) (wireguard-tools not installed): none. */
	if (!r.ok) {
		(void)failed("wireguard", r.error);
		return (0);
	}
	if ((o = cbl_yarena_alloc(a, sizeof(*o))) == NULL)
		return (ENOMEM);
	if ((error = ywg_from_json(r.json, a, o)) != 0)
		return (error);
	data->wireguard = o;
	return (0);
}

int
ietf_syslog_syslog_edit(cbl_req *req, const struct ietf_syslog *before,
    const struct ietf_syslog *after)
{

	(void)req;
	(void)before;
	(void)after;
	return (EOPNOTSUPP);
}

int
ietf_syslog_syslog_get(cbl_req *req, struct ietf_syslog *data, cbl_yarena *a)
{
	struct yunread	*u;
	size_t		 nu, i;
	int		 error;

	if (yang_refused(req))
		return (EACCES);
	if ((error = ysyslog_read("/etc/syslog.conf", "/etc/newsyslog.conf", a,
	    data, &u, &nu)) != 0)
		return (error);
	for (i = 0; i < nu; i++)
		logmsg(LOG_INFO, "syslog.conf: %s: %s", u[i].var, u[i].why);
	return (0);
}

/* The host: hello's facts, the stats, the certificates. */
int
arcana_host_host_get(cbl_req *req, struct arcana_host *data, cbl_yarena *a)
{
	struct arc_host				 h;
	struct arc_stats_rsp			 sr;
	struct arc_certs_rsp			 cr;
	struct arcana_host_host			*o;
	struct arcana_host_host_certificates	*c;
	struct work				*w;
	int					 error;

	if (yang_refused(req))
		return (EACCES);
	if ((w = ywork(a)) == NULL)
		return (ENOMEM);
	memset(&h, 0, sizeof(h));
	host_info(w, &h);
	memset(&sr, 0, sizeof(sr));
	(void)do_stats(w, &sr);
	memset(&cr, 0, sizeof(cr));
	do_certs(w, &cr);
	if ((o = cbl_yarena_alloc(a, sizeof(*o))) == NULL ||
	    (c = cbl_yarena_alloc(a, sizeof(*c))) == NULL)
		return (ENOMEM);
	memset(c, 0, sizeof(*c));
	if (cr.ok && (error = yhost_certs_from_json(cr.json, a, c)) != 0)
		return (error);
	if ((error = yhost_from(&h, sr.ok ? sr.stats : NULL, cr.ok ? c : NULL,
	    a, o)) != 0)
		return (error);
	data->host = o;
	return (0);
}

int
arcana_builder_builder_port_options_action(cbl_req *req,
    const struct cbl_bytes *target,
    const struct arcana_builder_builder_port_options_input *in,
    struct arcana_builder_builder_port_options_output *out, cbl_yarena *a)
{

	(void)req;
	(void)target;
	(void)in;
	(void)out;
	(void)a;
	return (EOPNOTSUPP);
}
