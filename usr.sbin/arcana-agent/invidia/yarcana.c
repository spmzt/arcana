/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Invidia: Arcana's own modules served by cblink's YANG family,
 * beside the standard models (yserve.c):
 * a GET runs the operation that reads the same, as its job would
 * (do_list(), do_storage(), ...), and the module's collector makes its
 * reply the module's structs (y*.c).  An action is its operation too:
 * a jail's start, stop, restart and kill as the action operation's, a
 * service's start, stop, restart, reload and read by service(8)
 * (services.c), a process's signal and renice as the
 * proc job's, a job's cancel, confirm and read, the packages' refresh,
 * a log's read, BIRD's routes; arcana-jobs' submit queues jobs, its
 * changes the job-specs jobs.yaml makes them (yjobs_spec.c), and its
 * lanes are written to jobs.conf by an edit.  What
 * changes the host is one change at a time, as the agent's own
 * (change_lock).  The other edits, actions and rpcs answer
 * operation-not-supported.
 *
 * Each runs on a thread of its own (cbl_yserver_threads(), yserve.c),
 * as the agent's own slow reads do, so a slow one (the storage's ZFS,
 * BIRD) holds no other request.  What a plugin's program reads (BIRD,
 * WireGuard, netgraph) is left out where the program is not there or
 * will not answer, logged: a GET of every module is not lost for one
 * host's lack of BIRD.
 */

#include <sys/param.h>
#include <sys/linker.h>

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <jail.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>

#include <cblink.h>

#include "agent.h"
#include "collect.h"
#include "yjson.h"

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
struct work *
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

/*
 * The work of a request whose steps its requester hears (the steps
 * group, as an operation's): its root step, what, begun; *root its
 * index.  NULL: out of memory.
 */
struct work *
ywork_told(cbl_req *req, cbl_yarena *a, const char *what, int *root)
{
	struct work	*w;

	if ((w = ywork(a)) == NULL)
		return (NULL);
	trace_tell(w, req);
	*root = step_begin(w, ARC_STEP_KIND_DAEMON, "arcana-agent", "%s",
	    what);
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

/* What an action failed of, said for the request: cblink's error. */
static int
said(cbl_req *req, const char *why)
{

	(void)cbl_req_set_yerr(req, why != NULL ? why : "it failed", 0);
	return (EIO);
}

/* The keys of the list entry an action is on, want of them; NULL: not. */
static const void **
keys_of(const struct cbl_bytes *target, size_t want, cbl_yarena *a)
{
	const struct cbl_ynode	*n;
	const void		**vals;
	size_t			  nvals;

	if (cbl_yiid_read(&ymodel_schema, target, &n, &vals, &nvals, a) != 0 ||
	    nvals != want)
		return (NULL);
	return (vals);
}

/*
 * An action given a vnet jail by its input (NULL or "": the host): the
 * work in the jail's scope.  0, or the error said.
 */
static int
yjail_in(cbl_req *req, const char *jail, struct work *w)
{
	const char	*e;

	if (jail == NULL || jail[0] == '\0')
		return (0);
	if (!valid_jail(jail))
		return (said(req, "invalid jail name"));
	e = NULL;
	if (scope_enter(w, jail, &e) != 0)
		return (said(req, e));
	return (0);
}

/* yang:date-and-time into *t, to the second; false: it is none. */
static bool
ytime_parse(const char *s, time_t *t)
{
	struct tm	 tm;
	const char	*p;
	int		 oh, om;

	memset(&tm, 0, sizeof(tm));
	if ((p = strptime(s, "%Y-%m-%dT%H:%M:%S", &tm)) == NULL)
		return (false);
	if (*p == '.')
		for (p++; isdigit((unsigned char)*p); p++)
			;
	if ((*t = timegm(&tm)) == -1)
		return (false);
	if (*p == 'Z' || *p == 'z')
		return (p[1] == '\0');
	if ((*p == '+' || *p == '-') && sscanf(p + 1, "%2d:%2d", &oh, &om) ==
	    2 && strlen(p) == 6) {
		*t += (*p == '+' ? -1 : 1) * (oh * 3600 + om * 60);
		return (true);
	}
	return (false);
}

/*
 * A change, one at a time as the agent's own (change_lock), its note
 * the agent's current activity; false: the agent is stopping.
 */
static bool	change_begin(const char *) __trylocks_exclusive(true,
		    change_lock);
static void	change_end(void) __unlocks(change_lock);

static bool
change_begin(const char *what)
{

	pthread_mutex_lock(&change_lock);
	if (change_note("%s", what))
		return (true);
	(void)change_note(NULL);
	pthread_mutex_unlock(&change_lock);
	return (false);
}

static void
change_end(void)
{

	(void)change_note(NULL);
	pthread_mutex_unlock(&change_lock);
}

/* kldload or kldunload of a module, as the kmod job does it. */
static int
kmod(cbl_req *req, const char *verb, const char *name, cbl_yarena *a)
{
	const char	*e;
	struct work	*w;
	int		 rc;

	if (name == NULL || !kmod_name_ok(name))
		return (said(req, "not a module's name"));
	if ((w = ywork(a)) == NULL)
		return (ENOMEM);
	e = NULL;
	if (!change_begin(wfmt(w, "kld%s %s", verb, name)))
		return (said(req, "not done: arcana-agent is stopping"));
	rc = do_kmod(w, verb, name, false, &e);
	change_end();
	return (rc != 0 ? said(req, e) : 0);
}

/* A dataset's key loaded (key), or changed (new_key), as zfs-key does. */
static int
zfs_key(cbl_req *req, const struct cbl_bytes *target, const char *key,
    const char *new_key, cbl_yarena *a)
{
	struct zfskey_req	 q;
	struct zfskey_rsp	 r;
	const void		**k;
	struct work		*w;

	if ((k = keys_of(target, 1, a)) == NULL)
		return (EINVAL);
	if ((w = ywork(a)) == NULL)
		return (ENOMEM);
	memset(&q, 0, sizeof(q));
	q.zfs_dataset = *(const char *const *)k[0];
	q.zfs_key = key;
	q.zfs_new_key = new_key;
	memset(&r, 0, sizeof(r));
	r.has_ok = true;
	if (!change_begin(wfmt(w, "zfs key of %s", q.zfs_dataset)))
		return (said(req, "not done: arcana-agent is stopping"));
	do_zfs_key(w, &q, &r);
	change_end();
	/* The keys go as soon as they are used, as zfs-key's do. */
	if (key != NULL)
		explicit_bzero((void *)(uintptr_t)key, strlen(key));
	if (new_key != NULL)
		explicit_bzero((void *)(uintptr_t)new_key, strlen(new_key));
	return (r.ok ? 0 : said(req, r.error));
}

static void *
restart_thread(void *arg)
{

	restart_after((uintptr_t)arg != 0, true);
	return (NULL);
}

/* The agent restarted (and first the console, with console) once the
 * answer is on its way: service(8) runs a second after. */
static void
restart_later(bool console)
{
	pthread_t	t;

	if (pthread_create(&t, NULL, restart_thread, (void *)(uintptr_t)
	    console) == 0)
		(void)pthread_detach(t);
	else
		logmsg(LOG_ERR, "restart: no thread: restart the service by "
		    "hand");
}

/* A jail's action (ARC_ACTION_*): do_action()'s work, the jail after. */
static int
jail_action(cbl_req *req, const struct cbl_bytes *target, uint8_t action,
    bool *has_state, int *state, bool *has_jid, uint32_t *jid, cbl_yarena *a)
{
	static const char *const names[] = { "start", "stop", "restart",
	    "kill" };
	struct jail_done	 r;
	const void		**k;
	const char		*name, *what;
	struct work		*w;
	int			 root;

	if ((k = keys_of(target, 1, a)) == NULL)
		return (EINVAL);
	name = *(const char *const *)k[0];
	if ((w = ywork(a)) == NULL)
		return (ENOMEM);
	what = wfmt(w, "%s %s", action < nitems(names) ? names[action] :
	    "action", name);
	if ((w = ywork_told(req, a, what, &root)) == NULL)
		return (ENOMEM);
	if (!change_begin(what)) {
		step_end(w, root, false, NULL);
		return (said(req, "not done: arcana-agent is stopping"));
	}
	(void)do_action(w, name, action, &r);
	change_end();
	step_end(w, root, r.ok, NULL);
	if (!r.ok)
		return (said(req, r.error));
	/* jail-state's values are the operation's. */
	if ((*has_state = r.result != NULL && r.result->has_state))
		*state = r.result->state;
	if ((*has_jid = r.result != NULL && r.result->has_jid))
		*jid = r.result->jid;
	return (0);
}

/* A service's action (ARC_SERVICE_ACTION_*), as services.c does it. */
static int
service_action(cbl_req *req, const struct cbl_bytes *target, uint8_t action,
    bool *has_running, bool *running, bool *has_pid, uint32_t *pid,
    const char **status, cbl_yarena *a)
{
	static const char *const verbs[] = {
		[ARC_SERVICE_ACTION_START] = "start",
		[ARC_SERVICE_ACTION_STOP] = "stop",
		[ARC_SERVICE_ACTION_RESTART] = "restart",
		[ARC_SERVICE_ACTION_RELOAD] = "reload",
	};
	struct service_action_rsp	 r;
	const struct arc_service	*sv;
	const void			**k;
	const char			*name, *what;
	struct work			*w;
	int				 root;

	if ((k = keys_of(target, 1, a)) == NULL)
		return (EINVAL);
	name = *(const char *const *)k[0];
	if ((w = ywork(a)) == NULL)
		return (ENOMEM);
	what = wfmt(w, "service %s %s", name, action < nitems(verbs) ?
	    verbs[action] : "action");
	if ((w = ywork_told(req, a, what, &root)) == NULL)
		return (ENOMEM);
	memset(&r, 0, sizeof(r));
	if (!change_begin(what)) {
		step_end(w, root, false, NULL);
		return (said(req, "not done: arcana-agent is stopping"));
	}
	(void)do_service_action(w, name, action, &r);
	change_end();
	step_end(w, root, r.ok, NULL);
	if (!r.ok)
		return (said(req, r.error));
	if ((sv = r.service_result) != NULL) {
		*has_running = sv->has_running;
		*running = sv->has_running && sv->running;
		if ((*has_pid = sv->has_pid))
			*pid = sv->pid;
		*status = sv->status;
	}
	return (0);
}

/* A process's signal or renice as the proc job does it. */
static int
process_action(cbl_req *req, const struct cbl_bytes *target, const char *verb,
    const char *arg, bool has_start, uint64_t start, cbl_yarena *a)
{
	struct arc_job_spec	 sp;
	const char		*names[3], *e;
	const void		**k;
	struct work		*w;
	uint64_t		 pid;
	int			 rc;

	if ((k = keys_of(target, 1, a)) == NULL)
		return (EINVAL);
	pid = *(const uint64_t *)k[0];
	if (arg == NULL)
		return (said(req, verb[0] == 's' ? "which signal" :
		    "which nice value"));
	if ((w = ywork(a)) == NULL)
		return (ENOMEM);
	memset(&sp, 0, sizeof(sp));
	sp.verb = verb;
	names[0] = wfmt(w, "%ju", (uintmax_t)pid);
	names[1] = arg;
	/* The start-time it was read with, in nanoseconds, as seconds. */
	names[2] = wfmt(w, "%ju", (uintmax_t)(start / 1000000000u));
	sp.names.v = names;
	sp.names.n = has_start && start != 0 ? 3 : 2;
	e = NULL;
	if (!change_begin(wfmt(w, "%s %ju", verb, (uintmax_t)pid)))
		return (said(req, "not done: arcana-agent is stopping"));
	rc = do_proc_job(w, &sp, &e);
	change_end();
	return (rc != 0 ? said(req, e) : 0);
}

/* A job of the queue cancelled, or confirmed. */
static int
job_action(cbl_req *req, const struct cbl_bytes *target, bool confirm,
    bool *has_state, int *state, cbl_yarena *a)
{
	const struct arc_job	*j;
	const void		**k;
	const char		*e;
	struct work		*w;

	if ((k = keys_of(target, 1, a)) == NULL)
		return (EINVAL);
	if ((w = ywork(a)) == NULL)
		return (ENOMEM);
	e = NULL;
	j = confirm ? jobs_confirm(w, *(const uint64_t *)k[0], &e) :
	    jobs_cancel(w, *(const uint64_t *)k[0], &e);
	if (j == NULL)
		return (said(req, e));
	/* job-state's values are the operation's. */
	if ((*has_state = j->has_state))
		*state = j->state;
	return (0);
}


int
arcana_agent_agent_build_action(cbl_req *req, const struct cbl_bytes *target,
    const struct arcana_agent_agent_build_input *in,
    struct arcana_agent_agent_build_output *out, cbl_yarena *a)
{
	struct arc_agent_build_rsp	 r;
	struct work			*w;

	(void)target;
	if (in->source == NULL)
		return (said(req, "a repository is needed"));
	if ((w = ywork(a)) == NULL)
		return (ENOMEM);
	memset(&r, 0, sizeof(r));
	/* One build at a time: they share the directory. */
	pthread_mutex_lock(&build_lock);
	(void)do_agent_build(w, in->source, in->ref != NULL && in->ref[0] !=
	    '\0' ? in->ref : NULL, in->host_keys, in->ssh_key, false, &r);
	pthread_mutex_unlock(&build_lock);
	if (!r.ok)
		return (said(req, r.error));
	out->binary = r.binary;
	out->sha256 = r.sha256;
	out->version = r.agent_version;
	out->commit = r.commit;
	out->host_keys = r.host_keys;
	out->fingerprint.n = r.fingerprints.n;
	out->fingerprint.v = r.fingerprints.v;
	out->deploy_key = r.deploy_key;
	return (0);
}

int
arcana_agent_agent_config_apply_action(cbl_req *req,
    const struct cbl_bytes *target,
    const struct arcana_agent_agent_config_apply_input *in,
    struct arcana_agent_agent_config_apply_output *out, cbl_yarena *a)
{
	struct json_rsp			 r;
	struct work			*w;
	char				*json;
	bool				 dry;
	int				 root, error;

	(void)target;
	if (in->bundle == NULL)
		return (said(req, "a bundle is needed"));
	dry = in->has_dry_run && in->dry_run;
	if ((w = ywork_told(req, a, dry ? "config-apply, a dry run" :
	    "config-apply", &root)) == NULL)
		return (ENOMEM);
	/* What changes the host is no read: not niced. */
	w->nice = dry;
	if ((json = yagent_bundle_json(in->bundle)) == NULL) {
		step_end(w, root, false, NULL);
		return (ENOMEM);
	}
	memset(&r, 0, sizeof(r));
	if (!change_begin(dry ? "config-apply, a dry run" : "config-apply")) {
		free(json);
		step_end(w, root, false, NULL);
		return (said(req, "not done: arcana-agent is stopping"));
	}
	(void)do_config_apply(w, json, dry, in->has_anyway && in->anyway,
	    in->hostname, &r);
	change_end();
	free(json);
	step_end(w, root, r.ok, NULL);
	/* Refused with a report: the report, and why. */
	if (!r.ok && r.json == NULL)
		return (said(req, r.error));
	if ((error = yagent_apply_from_json(r.json, a, out)) != 0)
		return (error);
	if (!r.ok)
		out->refused = r.error != NULL ? r.error : "it failed";
	return (0);
}

int
arcana_agent_agent_config_export_action(cbl_req *req,
    const struct cbl_bytes *target,
    const struct arcana_agent_agent_config_export_input *in,
    struct arcana_agent_agent_config_export_output *out, cbl_yarena *a)
{
	struct json_rsp			 r;
	struct work			*w;
	int				 root;

	(void)target;
	if ((w = ywork_told(req, a, in->has_secrets && in->secrets ?
	    "config-export, secrets too" : "config-export", &root)) == NULL)
		return (ENOMEM);
	memset(&r, 0, sizeof(r));
	(void)do_config_export(w, in->has_secrets && in->secrets, &r);
	step_end(w, root, r.ok, NULL);
	if (!r.ok)
		return (said(req, r.error));
	return (yagent_bundle_from_json(r.json, a, out));
}

int
arcana_agent_agent_console_update_action(cbl_req *req,
    const struct cbl_bytes *target,
    const struct arcana_agent_agent_console_update_input *in,
    struct arcana_agent_agent_console_update_output *out, cbl_yarena *a)
{
	struct arc_console_update_rsp	 r;
	struct work			*w;

	(void)target;
	if (in->source == NULL)
		return (said(req, "a repository is needed"));
	if ((w = ywork(a)) == NULL)
		return (ENOMEM);
	memset(&r, 0, sizeof(r));
	pthread_mutex_lock(&build_lock);
	(void)do_console_update(w, in->source, in->ref != NULL &&
	    in->ref[0] != '\0' ? in->ref : NULL, in->host_keys, in->ssh_key,
	    &r);
	pthread_mutex_unlock(&build_lock);
	if (!r.ok)
		return (said(req, r.error));
	out->host_keys = r.host_keys;
	out->fingerprint.n = r.fingerprints.n;
	out->fingerprint.v = r.fingerprints.v;
	out->deploy_key = r.deploy_key;
	/* The tree installed has this daemon in it too: both restart. */
	restart_later(true);
	return (0);
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
	struct json_rsp			 tr;
	struct json_rsp			 lr;
	struct arcana_agent_agent	*o;
	struct arcana_agent_agent_transport *t;
	struct arcana_agent_agent_tls	*l;
	struct work			*w;
	int				 error;

	(void)req;
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
	struct arc_source_head_rsp	 r;
	struct work			*w;

	(void)target;
	if (in->source == NULL)
		return (said(req, "a repository is needed"));
	if ((w = ywork(a)) == NULL)
		return (ENOMEM);
	memset(&r, 0, sizeof(r));
	pthread_mutex_lock(&build_lock);
	(void)do_source_head(w, in->source, in->ref != NULL && in->ref[0] !=
	    '\0' ? in->ref : NULL, in->host_keys, in->ssh_key, &r);
	pthread_mutex_unlock(&build_lock);
	if (!r.ok)
		return (said(req, r.error));
	out->commit = r.commit;
	out->host_keys = r.host_keys;
	out->fingerprint.n = r.fingerprints.n;
	out->fingerprint.v = r.fingerprints.v;
	out->deploy_key = r.deploy_key;
	return (0);
}

int
arcana_agent_agent_source_log_action(cbl_req *req,
    const struct cbl_bytes *target,
    const struct arcana_agent_agent_source_log_input *in,
    struct arcana_agent_agent_source_log_output *out, cbl_yarena *a)
{
	struct source_log_rsp		 r;
	struct work			*w;
	int				 root;

	(void)target;
	if (in->source == NULL)
		return (said(req, "a repository is needed"));
	if ((w = ywork_told(req, a, "source log", &root)) == NULL)
		return (ENOMEM);
	memset(&r, 0, sizeof(r));
	pthread_mutex_lock(&build_lock);
	(void)do_source_log(w, in->source, in->ref != NULL && in->ref[0] !=
	    '\0' ? in->ref : NULL, in->host_keys, in->ssh_key,
	    in->has_count ? in->count : 0, &r);
	pthread_mutex_unlock(&build_lock);
	step_end(w, root, r.ok, NULL);
	if (!r.ok)
		return (said(req, r.error));
	return (yagent_log_from_json(r.commit, r.log, r.tags, a, out));
}

int
arcana_agent_agent_tls_csr_action(cbl_req *req, const struct cbl_bytes *target,
    const struct arcana_agent_agent_tls_csr_input *in,
    struct arcana_agent_agent_tls_csr_output *out, cbl_yarena *a)
{
	struct json_rsp	 r;
	struct work	*w;
	ucl_object_t	*top;
	int		 root;

	(void)target;
	(void)in;
	if ((w = ywork_told(req, a, "tls csr", &root)) == NULL)
		return (ENOMEM);
	w->nice = false;
	memset(&r, 0, sizeof(r));
	if (!change_begin("tls csr")) {
		step_end(w, root, false, NULL);
		return (said(req, "not done: arcana-agent is stopping"));
	}
	do_tls(w, "csr", NULL, NULL, NULL, NULL, &r);
	change_end();
	step_end(w, root, r.ok, NULL);
	if (!r.ok)
		return (said(req, r.error));
	if ((top = yj_parse(r.json)) == NULL)
		return (EINVAL);
	out->csr = yj_str(a, top, "csr");
	ucl_object_unref(top);
	return (0);
}

/*
 * A certificate for the waiting key, the CAs to trust, or both; the
 * peer asking kept trusted across the change.
 */
int
arcana_agent_agent_tls_install_action(cbl_req *req,
    const struct cbl_bytes *target,
    const struct arcana_agent_agent_tls_install_input *in,
    struct arcana_agent_agent_tls_install_output *out, cbl_yarena *a)
{
	struct json_rsp	 r;
	const cbl_peer	*pe;
	struct work	*w;
	uint8_t		 fp[64];
	size_t		 fplen;
	bool		 have;
	int		 root;

	(void)target;
	(void)out;
	if (in->certificate == NULL && in->ca == NULL)
		return (said(req, "a certificate or the CAs to trust are "
		    "needed"));
	if ((w = ywork_told(req, a, "tls install", &root)) == NULL)
		return (ENOMEM);
	w->nice = false;
	fplen = sizeof(fp);
	pe = cbl_req_peer(req);
	have = pe != NULL && (cbl_peer_flags(pe) & CBL_PEER_AUTHENTICATED) !=
	    0 && cbl_peer_fingerprint(pe, "sha256", fp, &fplen) == 0 &&
	    fplen == 32;
	memset(&r, 0, sizeof(r));
	if (!change_begin("tls install")) {
		step_end(w, root, false, NULL);
		return (said(req, "not done: arcana-agent is stopping"));
	}
	do_tls(w, "install", in->certificate, in->ca, in->peer, have ? fp :
	    NULL, &r);
	change_end();
	step_end(w, root, r.ok, NULL);
	return (r.ok ? 0 : said(req, r.error));
}

int
arcana_agent_agent_transport_retry_action(cbl_req *req,
    const struct cbl_bytes *target,
    const struct arcana_agent_agent_transport_retry_input *in,
    struct arcana_agent_agent_transport_retry_output *out, cbl_yarena *a)
{
	struct json_rsp	 r;
	struct work	*w;
	int		 root;

	(void)target;
	(void)in;
	(void)out;
	if ((w = ywork_told(req, a, "transport retry", &root)) == NULL)
		return (ENOMEM);
	w->nice = false;
	memset(&r, 0, sizeof(r));
	(void)do_transport(w, true, NULL, NULL, false, NULL, &r);
	step_end(w, root, r.ok, NULL);
	return (r.ok ? 0 : said(req, r.error));
}

/* The listeners changed, the SCTP ones' other addresses set anew. */
int
arcana_agent_agent_transport_listen_action(cbl_req *req,
    const struct cbl_bytes *target,
    const struct arcana_agent_agent_transport_listen_input *in,
    struct arcana_agent_agent_transport_listen_output *out, cbl_yarena *a)
{
	struct json_rsp	 r;
	struct work	*w;
	const char	*listen, *unlisten;
	int		 root;

	(void)target;
	(void)out;
	listen = in->listen != NULL && in->listen[0] != '\0' ? in->listen :
	    NULL;
	unlisten = in->unlisten != NULL && in->unlisten[0] != '\0' ?
	    in->unlisten : NULL;
	if (listen == NULL && unlisten == NULL && in->sctp_also == NULL)
		return (said(req, "listen, unlisten or sctp-also is needed"));
	if ((w = ywork_told(req, a, "transport listeners", &root)) == NULL)
		return (ENOMEM);
	w->nice = false;
	memset(&r, 0, sizeof(r));
	(void)do_transport(w, false, listen, unlisten, in->has_keep &&
	    in->keep, in->sctp_also, &r);
	step_end(w, root, r.ok, NULL);
	return (r.ok ? 0 : said(req, r.error));
}

int
arcana_agent_agent_update_action(cbl_req *req, const struct cbl_bytes *target,
    const struct arcana_agent_agent_update_input *in,
    struct arcana_agent_agent_update_output *out, cbl_yarena *a)
{
	struct arc_agent_update_rsp	 r;
	const cbl_peer			*pe;
	struct work			*w;
	bool				 local, restart;

	(void)target;
	if (in->binary.len == 0 || in->sha256 == NULL ||
	    strlen(in->sha256) != 64)
		return (said(req, "a program and its SHA-256 are needed"));
	if ((w = ywork(a)) == NULL)
		return (ENOMEM);
	/* The local socket's root is root already: its program is taken
	 * unsigned; any other peer's must be signed by the CA. */
	pe = cbl_req_peer(req);
	local = pe != NULL && cbl_peer_transport(pe) == CBL_TR_UNIX;
	restart = in->has_restart && in->restart;
	memset(&r, 0, sizeof(r));
	/* Not while a change runs: a restart would cut it short. */
	if (pthread_mutex_trylock(&change_lock) != 0)
		return (said(req, change_busy(w)));
	if (change_note("agent update"))
		(void)do_agent_update(w, in->binary.p, in->binary.len, 0,
		    in->sha256, in->signature.p, in->signature.len, local, &r);
	else
		r.error = "not done: arcana-agent is stopping";
	change_end();
	if (!r.ok)
		return (said(req, r.error));
	out->version = r.agent_version;
	out->has_restarting = true;
	out->restarting = restart;
	if (restart)
		restart_later(false);
	return (0);
}

/*
 * arcana-bird: BIRD's configuration, the host's and that of each
 * running vnet jail that has one, read from its files; what birdc says
 * in the operational datastore alone, a jail's by the read action.
 */

/* A copy of n bytes of s in a's, terminated; NULL: no memory. */
static char *
ycopy(cbl_yarena *a, const char *s, size_t n)
{
	char	*p;

	if ((p = cbl_yarena_alloc(a, n + 1)) != NULL) {
		memcpy(p, s, n);
		p[n] = '\0';
	}
	return (p);
}

/*
 * The configuration's files, w's (the host's or its jail's): each read
 * whole, with its SHA-256.  ENOENT where there is no main file.
 */
static int
ybird_conf(struct work *w, cbl_yarena *a,
    const struct arcana_bird_configuration **outp)
{
	struct arcana_bird_configuration	*out;
	struct arcana_bird_configuration_file	*f;
	const char				**v, *sha;
	char					*text;
	size_t					 n, len, k = 0;

	*outp = NULL;
	if (scope_slurp(w, opts.bird_conf, &len) == NULL)
		return (errno == ENOENT ? ENOENT : EIO);
	v = bird_conf_files(w, &n);
	if ((out = cbl_yarena_alloc(a, sizeof(*out))) == NULL ||
	    (f = cbl_yarena_alloc(a, (n + 1) * sizeof(*f))) == NULL)
		return (ENOMEM);
	memset(out, 0, sizeof(*out));
	for (size_t i = 0; i < n; i++) {
		if ((text = scope_slurp(w, v[i], &len)) == NULL)
			continue;
		sha = bird_sha(w, text, len);
		memset(&f[k], 0, sizeof(f[k]));
		if ((f[k].path = ycopy(a, v[i], strlen(v[i]))) == NULL ||
		    (f[k].text = ycopy(a, text, len)) == NULL ||
		    (f[k].sha256 = ycopy(a, sha, strlen(sha))) == NULL)
			return (ENOMEM);
		k++;
	}
	out->path = k > 0 ? f[0].path : NULL;
	out->file.n = k;
	out->file.v = f;
	*outp = out;
	return (0);
}

int
arcana_bird_bird_get(cbl_req *req, struct arcana_bird *data, cbl_yarena *a)
{
	struct arc_network_rsp		 r;
	struct arcana_bird_bird		*o;
	struct arcana_bird_bird_jail	*jv;
	struct arcana_bird_state	*st;
	struct work			*w, *jw;
	const char			*e;
	size_t				 k = 0;
	int				 error, jid, lastjid;

	if ((w = ywork(a)) == NULL || (o = cbl_yarena_alloc(a,
	    sizeof(*o))) == NULL)
		return (ENOMEM);
	memset(o, 0, sizeof(*o));
	if ((error = ybird_conf(w, a, &o->configuration)) != 0 && error !=
	    ENOENT)
		return (error);
	/* Each running vnet jail's that has one. */
	jv = NULL;
	for (lastjid = 0;; lastjid = jid) {
		struct arcana_bird_bird_jail	*nv;
		char				 last[16], name[MAXHOSTNAMELEN];
		char				 vnet[16];

		snprintf(last, sizeof(last), "%d", lastjid);
		name[0] = vnet[0] = '\0';
		if ((jid = jail_getv(0, "lastjid", last, "name", name, "vnet",
		    vnet, NULL)) == -1)
			break;
		if (strcmp(vnet, "new") != 0 && strcmp(vnet, "1") != 0)
			continue;
		if ((jw = ywork(a)) == NULL || (nv = cbl_yarena_alloc(a,
		    (k + 1) * sizeof(*nv))) == NULL)
			return (ENOMEM);
		if (k > 0)
			memcpy(nv, jv, k * sizeof(*nv));
		jv = nv;
		memset(&jv[k], 0, sizeof(jv[k]));
		e = NULL;
		if (scope_enter(jw, name, &e) != 0 || ybird_conf(jw, a,
		    &jv[k].configuration) != 0 || (jv[k].name = ycopy(a, name,
		    strlen(name))) == NULL)
			continue;
		k++;
	}
	o->jail.n = k;
	o->jail.v = jv;
	/* What birdc says: no BIRD running, none, not a failure. */
	if (cbl_req_ydatastore(req) == CBL_YDS_OPERATIONAL) {
		memset(&r, 0, sizeof(r));
		(void)do_network(w, ARC_NET_KIND_BIRD, ARC_NET_FAMILY_ALL, NULL,
		    0, 0, &r);
		if (!r.ok)
			(void)failed("bird", r.error);
		else {
			if ((st = cbl_yarena_alloc(a, sizeof(*st))) == NULL)
				return (ENOMEM);
			if ((error = ybird_from_json(r.json, a, st)) != 0)
				return (error);
			o->state = st;
		}
	}
	if (o->configuration != NULL || o->state != NULL || o->jail.n > 0)
		data->bird = o;
	return (0);
}

/*
 * The commit req is, its confirm-timeout (s) when it is a confirmed
 * one (RFC 6241's 600 where it says none); 0 for another, or an undo.
 */
static int
commit_timeout(cbl_req *req, cbl_yarena *a)
{
	struct ietf_netconf_commit_input	 in;
	const struct cbl_ymodule		*m;
	const struct cbl_ynode			*n = NULL, *inode = NULL;
	const cbl_msg				*msg;

	if (cbl_req_yundo(req) || (msg = cbl_req_msg(req)) == NULL)
		return (0);
	for (uint32_t i = 0; n == NULL && i < ymodel_schema.nmod; i++) {
		m = ymodel_schema.mod[i];
		if (strcmp(m->name, "ietf-netconf") != 0)
			continue;
		for (uint32_t k = 0; k < m->ntop; k++)
			if (strcmp(m->top[k]->name, "commit") == 0)
				n = m->top[k];
	}
	for (uint32_t i = 0; n != NULL && i < n->nchild; i++)
		if (n->child[i]->kind == CBL_YN_INPUT)
			inode = n->child[i];
	memset(&in, 0, sizeof(in));
	if (inode == NULL || cbl_msg_ydecode(msg, inode, &in, a, 0, NULL,
	    0) != 0 || !in.confirmed)
		return (0);
	return (in.has_confirm_timeout && in.confirm_timeout > 0 ?
	    (int)in.confirm_timeout : 600);
}

/* A file of a configuration, by its path; NULL where it is none. */
static const struct arcana_bird_configuration_file *
conf_file(const struct arcana_bird_configuration *c, const char *path)
{

	for (size_t i = 0; c != NULL && i < c->file.n; i++)
		if (strcmp(c->file.v[i].path, path) == 0)
			return (&c->file.v[i]);
	return (NULL);
}

/* A jail's configuration, by its name; NULL where it is none. */
static const struct arcana_bird_configuration *
conf_of_jail(const struct arcana_bird_bird *b, const char *jail)
{

	for (size_t i = 0; b != NULL && i < b->jail.n; i++)
		if (strcmp(b->jail.v[i].name, jail) == 0)
			return (b->jail.v[i].configuration);
	return (NULL);
}

struct bchange {
	const char	*jail;		/* NULL: the host's */
	const char	*path;
	const char	*was;		/* its text before; NULL: none */
	const char	*text;
};

/*
 * What after changes of before, a configuration's: each file whose
 * text is new, put in *ch (one at most, *nch it), -1 and why where
 * there is more or a file is taken out (undo takes back what its
 * commit made, a file made left).
 */
static int
conf_diff(const char *jail, const struct arcana_bird_configuration *before,
    const struct arcana_bird_configuration *after, bool undo,
    struct bchange *ch, size_t *nch, const char **why)
{
	const struct arcana_bird_configuration_file	*f, *g;

	for (size_t i = 0; before != NULL && i < before->file.n; i++)
		if (!undo && conf_file(after, before->file.v[i].path) ==
		    NULL) {
			*why = "a file of BIRD's configuration is not taken out "
			    "by a commit: take out what includes it";
			return (-1);
		}
	for (size_t i = 0; after != NULL && i < after->file.n; i++) {
		f = &after->file.v[i];
		g = conf_file(before, f->path);
		if (f->text == NULL || (g != NULL && g->text != NULL &&
		    strcmp(g->text, f->text) == 0))
			continue;
		if (*nch == 1) {
			*why = "one file of BIRD's configuration at a time";
			return (-1);
		}
		ch->jail = jail;
		ch->path = f->path;
		ch->was = g != NULL ? g->text : NULL;
		ch->text = f->text;
		(*nch)++;
	}
	return (0);
}

int
arcana_bird_bird_edit(cbl_req *req, const struct arcana_bird *before,
    const struct arcana_bird *after)
{
	const struct arcana_bird_bird	*b, *f;
	struct bchange			 ch;
	struct work			 w;
	cbl_yarena			*a;
	const char			*why, *warn;
	size_t				 nch = 0;
	bool				 undo;
	int				 rc, root;

	b = before != NULL ? before->bird : NULL;
	f = after != NULL ? after->bird : NULL;
	undo = cbl_req_yundo(req);
	why = NULL;
	memset(&ch, 0, sizeof(ch));
	if (conf_diff(NULL, b != NULL ? b->configuration : NULL, f != NULL ?
	    f->configuration : NULL, undo, &ch, &nch, &why) != 0)
		return (said(req, why));
	for (size_t i = 0; f != NULL && i < f->jail.n; i++) {
		if (!valid_jail(f->jail.v[i].name))
			return (said(req, "invalid jail name"));
		if (conf_diff(f->jail.v[i].name, conf_of_jail(b,
		    f->jail.v[i].name), f->jail.v[i].configuration, undo, &ch,
		    &nch, &why) != 0)
			return (said(req, why));
	}
	if (nch == 0)
		return (0);
	if ((a = cbl_yarena_new()) == NULL)
		return (ENOMEM);
	if (!change_begin("BIRD's configuration")) {
		cbl_yarena_free(a);
		return (said(req, "not done: arcana-agent is stopping"));
	}
	work_init(&w);
	trace_tell(&w, req);
	root = step_begin(&w, ARC_STEP_KIND_DAEMON, "arcana-agent", "BIRD's "
	    "configuration: %s%s%s", ch.path, ch.jail != NULL ? " in " : "",
	    ch.jail != NULL ? ch.jail : "");
	why = warn = NULL;
	rc = 0;
	if (!undo)
		bird_conf_settle();
	if (ch.jail != NULL && scope_enter(&w, ch.jail, &why) != 0)
		rc = -1;
	else if (undo)
		rc = bird_conf_undo(&w, ch.path, ch.text, &why);
	else
		rc = bird_conf_put(&w, ch.path, ch.text, bird_sha(&w, ch.was !=
		    NULL ? ch.was : "", ch.was != NULL ? strlen(ch.was) : 0),
		    commit_timeout(req, a), cbl_req_ctx(req), &why, &warn);
	change_end();
	step_end(&w, root, rc == 0, NULL);
	if (rc == 0 && warn != NULL)
		(void)cbl_req_ywarn(req, 0, "bird-not-told", warn);
	rc = rc == 0 ? 0 : said(req, why);
	work_free(&w);
	cbl_yarena_free(a);
	return (rc);
}

/* What birdc says now, the host's or the jail's the target is. */
static int
bird_read(cbl_req *req, const char *jail, struct arcana_bird_state *out,
    cbl_yarena *a)
{
	struct arc_network_rsp	 r;
	struct work		*w;
	int			 error, root;

	if ((w = ywork_told(req, a, "BIRD", &root)) == NULL)
		return (ENOMEM);
	if ((error = yjail_in(req, jail, w)) != 0) {
		step_end(w, root, false, NULL);
		return (error);
	}
	memset(&r, 0, sizeof(r));
	(void)do_network(w, ARC_NET_KIND_BIRD, ARC_NET_FAMILY_ALL, NULL, 0, 0,
	    &r);
	step_end(w, root, r.ok, NULL);
	if (!r.ok)
		return (said(req, r.error));
	return (ybird_from_json(r.json, a, out));
}

int
arcana_bird_bird_read_action(cbl_req *req, const struct cbl_bytes *target,
    const struct arcana_bird_bird_read_input *in, struct arcana_bird_state *out,
    cbl_yarena *a)
{

	(void)target;
	return (bird_read(req, in->jail, out, a));
}

/* Routes of BIRD's tables, in birdc's words. */
static int
bird_routes(cbl_req *req, const char *jail, const char *filter,
    struct arcana_bird_routes *out, cbl_yarena *a)
{
	struct arc_network_rsp	 r;
	struct work		*w;
	int			 error, root;

	if ((w = ywork_told(req, a, "BIRD's routes", &root)) == NULL)
		return (ENOMEM);
	if ((error = yjail_in(req, jail, w)) != 0) {
		step_end(w, root, false, NULL);
		return (error);
	}
	memset(&r, 0, sizeof(r));
	(void)do_bird_routes(w, filter != NULL ? filter : "all", &r);
	step_end(w, root, r.ok, NULL);
	if (!r.ok)
		return (said(req, r.error));
	return (ybird_routes_from_json(r.json, a, out));
}

int
arcana_bird_bird_routes_action(cbl_req *req, const struct cbl_bytes *target,
    const struct arcana_bird_bird_routes_input *in,
    struct arcana_bird_routes *out, cbl_yarena *a)
{

	(void)target;
	return (bird_routes(req, in->jail, in->filter, out, a));
}

/* BIRD's OSPF protocols, their areas, with topology their topology. */
static int
bird_ospf(cbl_req *req, const char *jail, bool topology, const char *protocol,
    struct arcana_bird_ospf *out, cbl_yarena *a)
{
	struct arc_network_rsp		 r;
	struct arcana_bird_ospf_protocol	*v;
	struct work			*w;
	size_t				 n = 0;
	int				 error, root;

	if ((w = ywork_told(req, a, "BIRD's OSPF", &root)) == NULL)
		return (ENOMEM);
	if ((error = yjail_in(req, jail, w)) != 0) {
		step_end(w, root, false, NULL);
		return (error);
	}
	memset(&r, 0, sizeof(r));
	(void)do_bird_ospf(w, !topology ? NULL : protocol != NULL ? wfmt(w,
	    "topology %s", protocol) : "topology", &r);
	step_end(w, root, r.ok, NULL);
	if (!r.ok)
		return (said(req, r.error));
	if ((error = ybird_ospf_from_json(r.json, a, out)) != 0 ||
	    protocol == NULL || topology)
		return (error);
	/* The one protocol, without its topology. */
	v = (struct arcana_bird_ospf_protocol *)(uintptr_t)out->protocol.v;
	for (size_t i = 0; i < out->protocol.n; i++)
		if (strcmp(v[i].name, protocol) == 0)
			v[n++] = v[i];
	out->protocol.n = n;
	return (0);
}

int
arcana_bird_bird_ospf_action(cbl_req *req, const struct cbl_bytes *target,
    const struct arcana_bird_bird_ospf_input *in, struct arcana_bird_ospf *out,
    cbl_yarena *a)
{

	(void)target;
	return (bird_ospf(req, in->jail, in->has_topology && in->topology,
	    in->protocol, out, a));
}

/* Whether bird(8) takes text in path's place; the file left. */
static int
bird_check_text(cbl_req *req, const char *jail, const char *path,
    const char *text, cbl_yarena *a)
{
	struct work	*w;
	const char	*why;
	int		 error, root, rc;

	if ((w = ywork_told(req, a, "BIRD's configuration checked",
	    &root)) == NULL)
		return (ENOMEM);
	if ((error = yjail_in(req, jail, w)) != 0) {
		step_end(w, root, false, NULL);
		return (error);
	}
	if (!change_begin("BIRD's configuration checked")) {
		step_end(w, root, false, NULL);
		return (said(req, "not done: arcana-agent is stopping"));
	}
	why = NULL;
	rc = bird_conf_check(w, path, text, &why);
	change_end();
	step_end(w, root, rc == 0, NULL);
	return (rc == 0 ? 0 : said(req, why));
}

int
arcana_bird_bird_check_action(cbl_req *req, const struct cbl_bytes *target,
    const struct arcana_bird_bird_check_input *in,
    struct arcana_bird_bird_check_output *out, cbl_yarena *a)
{

	(void)target;
	(void)out;
	return (bird_check_text(req, in->jail, in->path, in->text, a));
}

int
arcana_builder_builder_get(cbl_req *req, struct arcana_builder *data,
    cbl_yarena *a)
{
	struct arc_builder_rsp		 r;
	struct arcana_builder_builder	*o;
	struct work			*w;
	int				 error;

	(void)req;
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
	struct json_rsp			 r;
	struct arcana_events_events	*o;
	struct work			*w;
	int				 error;

	(void)req;
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
	struct json_rsp			 r;
	struct arcana_events_events	 o;
	struct work			*w;
	int				 error;

	(void)req;
	(void)target;
	if ((w = ywork(a)) == NULL)
		return (ENOMEM);
	memset(&r, 0, sizeof(r));
	(void)do_events(w, in->has_after ? in->after : 0, &r);
	if (!r.ok)
		return (failed("events", r.error));
	memset(&o, 0, sizeof(o));
	if ((error = yev_from_json(r.json, a, &o)) != 0)
		return (error);
	out->has_last = o.has_last;
	out->last = o.last;
	out->has_first = o.has_first;
	out->first = o.first;
	out->has_kept = o.has_kept;
	out->kept = o.kept;
	out->event.n = o.event.n;
	out->event.v = o.event.v;
	return (0);
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

	(void)req;
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
	struct json_rsp		 r;
	const char		*addr, *e;
	const void		**k;
	struct work		*w;

	addr = in->has_address ? in->address.v.m0 : NULL;
	if (addr == NULL || strlen(addr) > 64)
		return (said(req, "the address to follow is an IPv4 or IPv6 "
		    "address"));
	if ((w = ywork(a)) == NULL)
		return (ENOMEM);
	memset(&r, 0, sizeof(r));
	/* A jail's firewall: the jail's own network, a vnet. */
	if ((k = keys_of(target, 1, a)) != NULL) {
		if (!valid_jail(*(const char *const *)k[0]))
			return (said(req, "invalid jail name"));
		e = NULL;
		if (scope_enter_jail(w, *(const char *const *)k[0], &e,
		    true) != 0)
			return (said(req, e));
	}
	(void)do_fw_trace(w, addr, in->has_seconds ? in->seconds : 0,
	    in->has_packets ? in->packets : 0, &r);
	if (!r.ok)
		return (said(req, r.error));
	return (yfw_trace_from_json(r.json, a, out));
}

/*
 * How the agent samples and its limits, as committed: the whole of it
 * (an EDIT replaces the container), each rule kind:name=limit as
 * history.c takes them; none, the defaults.
 */
int
arcana_history_history_edit(cbl_req *req, const struct arcana_history *before,
    const struct arcana_history *after)
{
	static const char *const kinds[] = { "net", "disk", "jail-cpu",
	    "jail-mem" };
	const struct arcana_history_history	*h;
	struct json_rsp				 r;
	struct work				 w;
	uint32_t				 lim[4];
	uint32_t				 step, keep;
	char					*rl;
	size_t					 len;
	int					 rc;

	(void)before;
	h = after != NULL ? after->history : NULL;
	step = h != NULL && h->sampling != NULL && h->sampling->has_step ?
	    h->sampling->step : 5;
	keep = h != NULL && h->sampling != NULL && h->sampling->has_keep ?
	    h->sampling->keep : 720;
	memset(lim, 0, sizeof(lim));
	if (h != NULL && h->limits != NULL) {
		lim[0] = h->limits->has_cpu ? h->limits->cpu : 0;
		lim[1] = h->limits->has_memory ? h->limits->memory : 0;
		lim[2] = h->limits->has_swap ? h->limits->swap : 0;
		lim[3] = h->limits->has_storage ? h->limits->storage : 0;
	}
	len = 1;
	for (size_t i = 0; h != NULL && i < h->rule.n; i++)
		len += strlen(h->rule.v[i].name) + 32;
	if ((rl = calloc(1, len)) == NULL)
		return (ENOMEM);
	for (size_t i = 0; h != NULL && i < h->rule.n; i++) {
		const struct arcana_history_history_rule *ru = &h->rule.v[i];

		if ((size_t)ru->kind >= nitems(kinds)) {
			free(rl);
			return (said(req, "a rule's kind is net, disk, jail-cpu "
			    "or jail-mem"));
		}
		snprintf(rl + strlen(rl), len - strlen(rl), "%s%s:%s=%ju",
		    i > 0 ? "," : "", kinds[ru->kind], ru->name, (uintmax_t)
		    (ru->has_limit ? ru->limit : 0));
	}
	work_init(&w);
	memset(&r, 0, sizeof(r));
	(void)do_history(&w, UINT64_MAX, true, step, keep, lim, rl, &r);
	rc = r.ok ? 0 : said(req, r.error);
	work_free(&w);
	free(rl);
	return (rc);
}

int
arcana_history_history_get(cbl_req *req, struct arcana_history *data,
    cbl_yarena *a)
{
	struct json_rsp			 r;
	struct arcana_history_history	*o;
	struct work			*w;
	int				 error;

	(void)req;
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
	struct json_rsp			 r;
	struct arcana_history_history	 o;
	struct work			*w;
	time_t				 after = 0;
	int				 error;

	(void)target;
	if (in->after != NULL && !ytime_parse(in->after, &after))
		return (said(req, "after is no date-and-time"));
	if ((w = ywork(a)) == NULL)
		return (ENOMEM);
	memset(&r, 0, sizeof(r));
	(void)do_history(w, (uint64_t)after, false, 0, 0, NULL, NULL, &r);
	if (!r.ok)
		return (failed("history", r.error));
	memset(&o, 0, sizeof(o));
	if ((error = yhist_from_json(r.json, a, &o)) != 0)
		return (error);
	/* With how it samples and the sampler as it is: the output's
	 * containers and list have the module's layouts. */
	out->sampling = (const void *)o.sampling;
	out->limits = (const void *)o.limits;
	out->rule.n = o.rule.n;
	out->rule.v = (const void *)o.rule.v;
	if (o.state != NULL) {
		const struct arcana_history_history_state *st = o.state;

		out->has_bytes = st->has_bytes;
		out->bytes = st->bytes;
		out->has_ncpu = st->has_ncpu;
		out->ncpu = st->ncpu;
		out->has_memory_total = st->has_memory_total;
		out->memory_total = st->memory_total;
		out->has_swap_total = st->has_swap_total;
		out->swap_total = st->swap_total;
		out->has_racct = st->has_racct;
		out->racct = st->racct;
		out->interface.n = st->interface.n;
		out->interface.v = st->interface.v;
		out->disk.n = st->disk.n;
		out->disk.v = st->disk.v;
		out->jail.n = st->jail.n;
		out->jail.v = st->jail.v;
		out->relay.n = st->relay.n;
		out->relay.v = st->relay.v;
		out->sample.n = st->sample.n;
		out->sample.v = st->sample.v;
	}
	return (0);
}

int
arcana_jails_jails_jail_kill_action(cbl_req *req,
    const struct cbl_bytes *target,
    const struct arcana_jails_jails_jail_kill_input *in,
    struct arcana_jails_jails_jail_kill_output *out, cbl_yarena *a)
{
	bool	hs, hj;
	int	st, error;

	(void)in;
	if ((error = jail_action(req, target, ARC_ACTION_KILL, &hs, &st, &hj,
	    &out->jid, a)) != 0)
		return (error);
	if ((out->has_state = hs))
		out->state = st;
	out->has_jid = hj;
	return (0);
}

/* The jails' files: jail.conf, jail.conf.d's (jailmake.c). */
int
arcana_jails_jails_arcjf_read_files_action(cbl_req *req,
    const struct cbl_bytes *target,
    const struct arcana_jails_jails_arcjf_read_files_input *in,
    struct arcana_jails_jails_arcjf_read_files_output *out, cbl_yarena *a)
{
	struct json_rsp	 r;
	struct work	*w;
	int		 root;

	(void)target;
	(void)in;
	if ((w = ywork_told(req, a, "jail files", &root)) == NULL)
		return (ENOMEM);
	memset(&r, 0, sizeof(r));
	do_jail_files(w, &r);
	step_end(w, root, r.ok, NULL);
	if (!r.ok)
		return (said(req, r.error));
	return (yjf_from_json(r.json, a, out));
}

int
arcana_jails_jails_jail_restart_action(cbl_req *req,
    const struct cbl_bytes *target,
    const struct arcana_jails_jails_jail_restart_input *in,
    struct arcana_jails_jails_jail_restart_output *out, cbl_yarena *a)
{
	bool	hs, hj;
	int	st, error;

	(void)in;
	if ((error = jail_action(req, target, ARC_ACTION_RESTART, &hs, &st, &hj,
	    &out->jid, a)) != 0)
		return (error);
	if ((out->has_state = hs))
		out->state = st;
	out->has_jid = hj;
	return (0);
}

int
arcana_jails_jails_jail_start_action(cbl_req *req,
    const struct cbl_bytes *target,
    const struct arcana_jails_jails_jail_start_input *in,
    struct arcana_jails_jails_jail_start_output *out, cbl_yarena *a)
{
	bool	hs, hj;
	int	st, error;

	(void)in;
	if ((error = jail_action(req, target, ARC_ACTION_START, &hs, &st, &hj,
	    &out->jid, a)) != 0)
		return (error);
	if ((out->has_state = hs))
		out->state = st;
	out->has_jid = hj;
	return (0);
}

int
arcana_jails_jails_jail_stop_action(cbl_req *req,
    const struct cbl_bytes *target,
    const struct arcana_jails_jails_jail_stop_input *in,
    struct arcana_jails_jails_jail_stop_output *out, cbl_yarena *a)
{
	bool	hs, hj;
	int	st, error;

	(void)in;
	if ((error = jail_action(req, target, ARC_ACTION_STOP, &hs, &st, &hj,
	    &out->jid, a)) != 0)
		return (error);
	if ((out->has_state = hs))
		out->state = st;
	out->has_jid = hj;
	return (0);
}

int
arcana_jobs_jobs_get(cbl_req *req, struct arcana_jobs *data, cbl_yarena *a)
{
	const struct arc_job	*v;
	struct work		*w;
	const char		*activity;
	time_t			 since;
	size_t			 n;

	(void)req;
	if ((w = ywork(a)) == NULL)
		return (ENOMEM);
	jobs_list(w, &v, &n);
	since = 0;
	activity = changes_current(w, &since);
	return (yjobs_from(v, n, activity, (int64_t)since, changes_stopping(),
	    jobs_lanes(), a, data));
}

/* lanes, kept in jobs.conf; the default where it is taken out. */
int
arcana_jobs_jobs_edit(cbl_req *req, const struct arcana_jobs *before,
    const struct arcana_jobs *after)
{
	const char	*e;
	int		 n;

	(void)before;
	n = after != NULL && after->jobs != NULL && after->jobs->has_lanes ?
	    after->jobs->lanes : PKG_LANES;
	if (n == jobs_lanes())
		return (0);
	return ((e = jobs_set_lanes(n)) != NULL ? said(req, e) : 0);
}

int
arcana_jobs_jobs_job_read_action(cbl_req *req, const struct cbl_bytes *target,
    const struct arcana_jobs_jobs_job_read_input *in,
    struct arcana_jobs_jobs_job_read_output *out, cbl_yarena *a)
{
	const struct arc_job	*j;
	const void		**k;
	struct work		*w;

	(void)in;
	if ((k = keys_of(target, 1, a)) == NULL)
		return (EINVAL);
	if ((w = ywork(a)) == NULL)
		return (ENOMEM);
	if ((j = jobs_get(w, *(const uint64_t *)k[0])) == NULL)
		return (said(req, "no such job; the agent keeps the last "
		    "finished ones and forgets all when it restarts"));
	return (yjobs_read(j, a, out));
}

int
arcana_jobs_jobs_job_cancel_action(cbl_req *req, const struct cbl_bytes *target,
    const struct arcana_jobs_jobs_job_cancel_input *in,
    struct arcana_jobs_jobs_job_cancel_output *out, cbl_yarena *a)
{
	bool	hs;
	int	st;
	int	error;

	(void)in;
	if ((error = job_action(req, target, false, &hs, &st, a)) != 0)
		return (error);
	if ((out->has_state = hs))
		out->state = st;
	return (0);
}

int
arcana_jobs_jobs_job_confirm_action(cbl_req *req,
    const struct cbl_bytes *target,
    const struct arcana_jobs_jobs_job_confirm_input *in,
    struct arcana_jobs_jobs_job_confirm_output *out, cbl_yarena *a)
{
	bool	hs;
	int	st;
	int	error;

	(void)in;
	if ((error = job_action(req, target, true, &hs, &st, a)) != 0)
		return (error);
	if ((out->has_state = hs))
		out->state = st;
	return (0);
}

int
arcana_jobs_submit_rpc(cbl_req *req, const struct arcana_jobs_submit_input *in,
    struct arcana_jobs_submit_output *out, cbl_yarena *a)
{
	const struct arc_job_spec	*specs;
	const struct arc_job		*v;
	struct work			*w;
	const char			*e;
	uint64_t			*ids;
	size_t				 n, nv, bad, i;
	int				 error;

	bad = 0;
	if ((error = yjobs_specs(in, a, &specs, &n, &bad)) != 0)
		return (said(req, error == ENOMEM ? "out of memory" :
		    in->change.n == 0 ? "no change to make" : "a change is "
		    "no kind of job, or not the one it names"));
	if ((w = ywork(a)) == NULL)
		return (ENOMEM);
	/* Each change checked, the queue's room. */
	if (jobs_submit_checked(req, specs, n, w, &v, &nv, &e) != 0)
		return (said(req, e));
	if ((ids = cbl_yarena_alloc(a, (nv > 0 ? nv : 1) * sizeof(*ids))) ==
	    NULL)
		return (ENOMEM);
	for (i = 0; i < nv; i++)
		ids[i] = v[i].id;
	out->id.n = nv;
	out->id.v = ids;
	return (0);
}

int
arcana_kernel_kernel_file_unload_action(cbl_req *req,
    const struct cbl_bytes *target,
    const struct arcana_kernel_kernel_file_unload_input *in,
    struct arcana_kernel_kernel_file_unload_output *out, cbl_yarena *a)
{
	struct kld_file_stat	 st;
	const void		**k;

	(void)in;
	(void)out;
	if ((k = keys_of(target, 1, a)) == NULL)
		return (EINVAL);
	/* The file's name, as kldunload(8) takes it. */
	memset(&st, 0, sizeof(st));
	st.version = sizeof(st);
	if (kldstat((int)*(const uint32_t *)k[0], &st) == -1)
		return (said(req, "no such file in the kernel"));
	return (kmod(req, "unload", st.name, a));
}

int
arcana_kernel_load_rpc(cbl_req *req, const struct arcana_kernel_load_input *in,
    struct arcana_kernel_load_output *out, cbl_yarena *a)
{

	(void)out;
	return (kmod(req, "load", in->name, a));
}

int
arcana_log_logs_get(cbl_req *req, struct arcana_log *data, cbl_yarena *a)
{
	struct json_rsp			 r;
	struct arcana_log_logs	*o;
	struct work			*w;
	int				 error;

	(void)req;
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
	struct json_rsp		 r;
	const char		*e;
	struct work		*w;
	int			 error;

	(void)target;
	if (in->name == NULL || (in->name[0] != '@' && !log_name_ok(in->name)))
		return (said(req, "a log is named with letters, digits and "
		    ". _ -"));
	if (in->jail != NULL && !valid_jail(in->jail))
		return (said(req, "invalid jail name"));
	if ((w = ywork(a)) == NULL)
		return (ENOMEM);
	/* A jail's own log directory, under its root. */
	e = NULL;
	if (scope_enter_jail(w, in->jail, &e, false) != 0)
		return (said(req, e));
	memset(&r, 0, sizeof(r));
	(void)do_log(w, in->name, in->filter, in->has_position,
	    in->position, in->has_lines ? in->lines : 0, &r);
	if (!r.ok)
		return (said(req, r.error));
	if ((error = ylog_read_from_json(r.json, a, out)) != 0)
		return (error);
	return (0);
}

int
arcana_netgraph_netgraph_get(cbl_req *req, struct arcana_netgraph *data,
    cbl_yarena *a)
{
	struct arc_network_rsp		 r;
	struct arcana_netgraph_netgraph	*o;
	struct work			*w;
	int				 error;

	(void)req;
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
	if ((error = yng_from_json(r.json, a, &o->node.n, &o->node.v)) != 0)
		return (error);
	data->netgraph = o;
	return (0);
}

/* The graph now, the host's or a vnet jail's, what ngctl said if not. */
int
arcana_netgraph_netgraph_read_action(cbl_req *req,
    const struct cbl_bytes *target,
    const struct arcana_netgraph_netgraph_read_input *in,
    struct arcana_netgraph_netgraph_read_output *out, cbl_yarena *a)
{
	struct arc_network_rsp	 r;
	struct work		*w;
	int			 error, root;

	(void)target;
	if ((w = ywork_told(req, a, "the netgraph graph", &root)) == NULL)
		return (ENOMEM);
	if ((error = yjail_in(req, in->jail, w)) != 0) {
		step_end(w, root, false, NULL);
		return (error);
	}
	memset(&r, 0, sizeof(r));
	(void)do_network(w, ARC_NET_KIND_NETGRAPH, ARC_NET_FAMILY_ALL, NULL, 0,
	    0, &r);
	step_end(w, root, r.ok, NULL);
	if (!r.ok)
		return (said(req, r.error));
	return (yng_from_json(r.json, a, &out->node.n, &out->node.v));
}

int
arcana_notify_notify_rpc(cbl_req *req,
    const struct arcana_notify_notify_input *in,
    struct arcana_notify_notify_output *out, cbl_yarena *a)
{
	const char	*e;
	struct work	*w;
	int		 rc;

	(void)out;
	if (in->token == NULL || in->chat == NULL || in->text == NULL)
		return (said(req, "a token, a chat and a text are needed"));
	if ((w = ywork(a)) == NULL)
		return (ENOMEM);
	e = NULL;
	rc = do_notify(w, in->token, in->chat, in->text, &e);
	/* The token goes as soon as it is used. */
	explicit_bzero((void *)(uintptr_t)in->token, strlen(in->token));
	return (rc != 0 ? said(req, e) : 0);
}

int
arcana_packages_packages_get(cbl_req *req, struct arcana_packages *data,
    cbl_yarena *a)
{
	struct pkg_read			 r;
	struct arcana_packages_packages	*o;
	struct work			*w;
	int				 error;

	(void)req;
	if ((w = ywork(a)) == NULL)
		return (ENOMEM);
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

/* The host's packages, or a jail's (the target's key, the jail). */
static int
pkg_target(cbl_req *req, const struct cbl_bytes *target, const char **jail,
    cbl_yarena *a)
{
	const void	**k;

	*jail = NULL;
	if ((k = keys_of(target, 1, a)) != NULL &&
	    !valid_jail(*jail = *(const char *const *)k[0]))
		return (said(req, "invalid jail name"));
	return (0);
}

int
arcana_packages_packages_read_action(cbl_req *req,
    const struct cbl_bytes *target,
    const struct arcana_packages_packages_read_input *in,
    struct arcana_packages_packages_read_output *out, cbl_yarena *a)
{
	struct pkg_read	 r;
	const char	*jail;
	struct work	*w;
	int		 root, error;

	(void)in;
	if ((error = pkg_target(req, target, &jail, a)) != 0)
		return (error);
	if ((w = ywork_told(req, a, jail != NULL ? "packages installed of "
	    "a jail" : "packages installed", &root)) == NULL)
		return (ENOMEM);
	(void)do_packages(w, jail, false, true, 0, false, &r);
	step_end(w, root, r.ok, NULL);
	if (!r.ok)
		return (said(req, r.error));
	return (ypackages_listed(&r, NULL, a, &out->package.v,
	    &out->package.n, &out->repository.v, &out->repository.n,
	    &out->has_pkgbase, &out->pkgbase));
}

int
arcana_packages_packages_refresh_action(cbl_req *req,
    const struct cbl_bytes *target,
    const struct arcana_packages_packages_refresh_input *in,
    struct arcana_packages_packages_refresh_output *out, cbl_yarena *a)
{
	struct pkg_read	 r;
	const char	*jail;
	struct work	*w;
	bool		 update;
	int		 root, error;

	if ((error = pkg_target(req, target, &jail, a)) != 0)
		return (error);
	update = in->has_update && in->update;
	if ((w = ywork_told(req, a, update ? "packages (refresh)" :
	    "packages", &root)) == NULL)
		return (ENOMEM);
	/* Only pkg update writes (the catalogue): a read without it
	 * waits for no change, and none waits for it.  ip-version's
	 * values are pkg's: 0, 4, 6. */
	if (!update)
		(void)do_packages(w, jail, false, false, in->has_ip_version ?
		    (uint8_t)in->ip_version : 0, in->has_ignore_osversion &&
		    in->ignore_osversion, &r);
	else if (!change_begin(jail != NULL ? wfmt(w, "packages of %s "
	    "(refresh)", jail) : "packages (refresh)")) {
		step_end(w, root, false, NULL);
		return (said(req, "not done: arcana-agent is stopping"));
	} else {
		(void)do_packages(w, jail, true, false, in->has_ip_version ?
		    (uint8_t)in->ip_version : 0, in->has_ignore_osversion &&
		    in->ignore_osversion, &r);
		change_end();
	}
	step_end(w, root, r.ok, NULL);
	if (!r.ok)
		return (said(req, r.error));
	return (ypackages_listed(&r, NULL, a, &out->package.v,
	    &out->package.n, &out->repository.v, &out->repository.n,
	    &out->has_pkgbase, &out->pkgbase));
}

int
arcana_packages_packages_upgrade_action(cbl_req *req,
    const struct cbl_bytes *target,
    const struct arcana_packages_packages_upgrade_input *in,
    struct arcana_packages_packages_upgrade_output *out, cbl_yarena *a)
{
	struct pkg_upgrade	 q;
	struct pkg_upgraded	 r;
	const char		*jail, *what;
	struct work		*w;
	int			 root, error;

	if ((error = pkg_target(req, target, &jail, a)) != 0)
		return (error);
	for (size_t i = 0; i < in->name.n; i++)
		if (in->name.v[i] == NULL || in->name.v[i][0] == '\0')
			return (said(req, "a package without a name"));
	if ((w = ywork(a)) == NULL)
		return (ENOMEM);
	memset(&q, 0, sizeof(q));
	/* Of the host's: in every running jail instead. */
	if (in->has_every_jail && in->every_jail) {
		if (jail != NULL)
			return (said(req, "every-jail is the host's packages' "
			    "alone"));
		jail = "*";
	}
	q.jail = jail;
	q.names.v = in->name.v;
	q.names.n = in->name.n;
	q.dry_run = in->has_dry_run && in->dry_run;
	q.ignore_osversion = in->has_ignore_osversion && in->ignore_osversion;
	/* ip-version's values are pkg's: 0, 4, 6. */
	q.pkg_ip = in->has_ip_version ? (uint8_t)in->ip_version : 0;
	q.pkg_repo = in->repository != NULL && in->repository[0] != '\0' ?
	    in->repository : NULL;
	what = jail == NULL ? "pkg upgrade" : strcmp(jail, "*") == 0 ?
	    "pkg upgrade in every jail" : wfmt(w, "pkg upgrade in jail %s",
	    jail);
	if ((w = ywork_told(req, a, what, &root)) == NULL)
		return (ENOMEM);
	if (!change_begin(what)) {
		step_end(w, root, false, NULL);
		return (said(req, "not done: arcana-agent is stopping"));
	}
	(void)do_pkg_upgrade(w, &q, &r);
	change_end();
	step_end(w, root, r.ok, NULL);
	if (!r.ok)
		return (said(req, r.error));
	return (ypackages_upgraded(&r, a, out));
}

/* An edge of probes' (jail NULL: the host's), as a jail entry has it. */
static void
probe_edge(const struct arcana_probe_probes *p, const char *jail,
    struct arcana_probe_probes_jail *out)
{

	memset(out, 0, sizeof(*out));
	out->name = jail;
	if (p == NULL)
		return;
	if (jail == NULL) {
		out->target.n = p->target.n;
		out->target.v = p->target.v;
		out->link.n = p->link.n;
		out->link.v = p->link.v;
		out->monitor.n = p->monitor.n;
		out->monitor.v = p->monitor.v;
		return;
	}
	for (size_t i = 0; i < p->jail.n; i++)
		if (strcmp(p->jail.v[i].name, jail) == 0) {
			*out = p->jail.v[i];
			return;
		}
}

/*
 * An edge's lists as they were and are to be: each set anew that
 * differs, the SD-WAN targets with the links, the monitors apart.
 */
static int
probe_edge_set(struct work *w, const char *jail,
    const struct arcana_probe_probes_jail *was,
    const struct arcana_probe_probes_jail *now, const char **errp)
{
	char	*a, *b;
	int	 rc = 0;

	a = yprobe_edge_json(jail, was->target.n, was->target.v, was->link.n,
	    was->link.v);
	b = yprobe_edge_json(jail, now->target.n, now->target.v, now->link.n,
	    now->link.v);
	if (a == NULL || b == NULL) {
		*errp = "no memory";
		rc = -1;
	} else if (strcmp(a, b) != 0)
		rc = do_probes_set(w, b, errp);
	free(a);
	free(b);
	if (rc != 0)
		return (rc);
	a = yprobe_monitors_json(jail, was->monitor.n, was->monitor.v);
	b = yprobe_monitors_json(jail, now->monitor.n, now->monitor.v);
	if (a == NULL || b == NULL) {
		*errp = "no memory";
		rc = -1;
	} else if (strcmp(a, b) != 0)
		rc = do_monitors_set(w, b, errp);
	free(a);
	free(b);
	return (rc);
}

int
arcana_probe_probes_edit(cbl_req *req, const struct arcana_probe *before,
    const struct arcana_probe *after)
{
	const struct arcana_probe_probes	*b, *f;
	struct arcana_probe_probes_jail		 was, now;
	struct work				 w;
	const char				*why, *jail;
	int					 rc, root;

	b = before != NULL ? before->probes : NULL;
	f = after != NULL ? after->probes : NULL;
	for (size_t i = 0; f != NULL && i < f->jail.n; i++)
		if (!valid_jail(f->jail.v[i].name))
			return (said(req, "invalid jail name"));
	if (!change_begin("the probes"))
		return (said(req, "not done: arcana-agent is stopping"));
	work_init(&w);
	trace_tell(&w, req);
	root = step_begin(&w, ARC_STEP_KIND_DAEMON, "arcana-agent",
	    "the probes' targets, links and monitors");
	why = NULL;
	/* The host's, then each jail's that is or was. */
	probe_edge(b, NULL, &was);
	probe_edge(f, NULL, &now);
	rc = probe_edge_set(&w, NULL, &was, &now, &why);
	for (size_t k = 0; rc == 0 && f != NULL && k < f->jail.n; k++) {
		jail = f->jail.v[k].name;
		probe_edge(b, jail, &was);
		probe_edge(f, jail, &now);
		rc = probe_edge_set(&w, jail, &was, &now, &why);
	}
	/* A jail no longer there: its lists emptied. */
	for (size_t k = 0; rc == 0 && b != NULL && k < b->jail.n; k++) {
		size_t	m;

		jail = b->jail.v[k].name;
		for (m = 0; f != NULL && m < f->jail.n && strcmp(
		    f->jail.v[m].name, jail) != 0; m++)
			;
		if (f != NULL && m < f->jail.n)
			continue;
		probe_edge(b, jail, &was);
		probe_edge(NULL, jail, &now);
		rc = probe_edge_set(&w, jail, &was, &now, &why);
	}
	change_end();
	step_end(&w, root, rc == 0, NULL);
	work_free(&w);
	return (rc == 0 ? 0 : said(req, why));
}

int
arcana_probe_probes_get(cbl_req *req, struct arcana_probe *data, cbl_yarena *a)
{
	struct json_rsp			 r;
	struct arcana_probe_probes	*o;
	struct arcana_probe_probes_state *st;
	struct work			*w;
	char				*json;
	int				 error;

	if ((w = ywork(a)) == NULL || (o = cbl_yarena_alloc(a,
	    sizeof(*o))) == NULL)
		return (ENOMEM);
	memset(o, 0, sizeof(*o));
	/* Each edge's lists, as the prober has them. */
	if ((json = probe_conf_json()) == NULL)
		return (ENOMEM);
	error = yprobe_conf_from_json(json, a, o);
	free(json);
	if (error != 0)
		return (error);
	data->probes = o;
	if (cbl_req_ydatastore(req) != CBL_YDS_OPERATIONAL)
		return (0);
	memset(&r, 0, sizeof(r));
	(void)do_probes_read(w, 0, &r);
	if (!r.ok)
		return (failed("probes", r.error));
	if ((st = cbl_yarena_alloc(a, sizeof(*st))) == NULL)
		return (ENOMEM);
	if ((error = yprobe_state_from_json(r.json, a, st)) != 0)
		return (error);
	o->state = st;
	return (0);
}

int
arcana_probe_probes_read_action(cbl_req *req, const struct cbl_bytes *target,
    const struct arcana_probe_probes_read_input *in,
    struct arcana_probe_probes_read_output *out, cbl_yarena *a)
{
	struct arcana_probe_probes_state		 st;
	struct json_rsp					 r;
	struct work					*w;
	time_t						 after = 0;
	int						 error;

	(void)target;
	if (in->after != NULL && !ytime_parse(in->after, &after))
		return (said(req, "after is no date-and-time"));
	if ((w = ywork(a)) == NULL)
		return (ENOMEM);
	memset(&r, 0, sizeof(r));
	(void)do_probes_read(w, (uint64_t)after, &r);
	if (!r.ok)
		return (failed("probes", r.error));
	memset(&st, 0, sizeof(st));
	if ((error = yprobe_state_from_json(r.json, a, &st)) != 0)
		return (error);
	/* Each target as the state has it, its samples after the time. */
	out->has_probing = st.has_probing;
	out->probing = st.probing;
	out->time = st.time;
	out->target.n = st.target.n;
	out->target.v = st.target.v;
	return (0);
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
	struct json_rsp				 r;
	struct arcana_processes_processes	*o;
	struct work			*w;
	int				 error;

	(void)req;
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
	struct work	*w;

	(void)out;
	if ((w = ywork(a)) == NULL)
		return (ENOMEM);
	return (process_action(req, target, "renice", in->has_nice ?
	    wfmt(w, "%d", in->nice) : NULL, in->has_start_time,
	    in->start_time, a));
}

int
arcana_processes_processes_process_read_action(cbl_req *req,
    const struct cbl_bytes *target,
    const struct arcana_processes_processes_process_read_input *in,
    struct arcana_processes_processes_process_read_output *out, cbl_yarena *a)
{
	struct json_rsp	 r;
	const void	**k;
	struct work	*w;
	uint64_t	 pid;

	(void)in;
	if ((k = keys_of(target, 1, a)) == NULL)
		return (EINVAL);
	if ((pid = *(const uint64_t *)k[0]) == 0 || pid > INT32_MAX)
		return (said(req, "no such process"));
	if ((w = ywork(a)) == NULL)
		return (ENOMEM);
	memset(&r, 0, sizeof(r));
	(void)do_process(w, (uint32_t)pid, &r);
	if (!r.ok)
		return (said(req, r.error));
	return (yprocs_read_from_json(r.json, a, out));
}

int
arcana_processes_processes_process_signal_action(cbl_req *req,
    const struct cbl_bytes *target,
    const struct arcana_processes_processes_process_signal_input *in,
    struct arcana_processes_processes_process_signal_output *out, cbl_yarena *a)
{
	(void)out;
	return (process_action(req, target, "signal", in->signal,
	    in->has_start_time, in->start_time, a));
}

/*
 * arcana-sdwan: its configuration is what the setters keep (sdwan.c's,
 * the luxuria instances'), read from their files; an edit makes each
 * edge's part that changed the JSON its setter takes and has it set,
 * as the operations did.
 */
enum { SD_RULES, SD_STEER, SD_BIRD, SD_DHCP, SD_DNS, SD_PROXY, SD_IDS };
static const char *const sd_kinds[] = { "rules", "steer", "bird", "dhcp",
    "dns", "proxy", "ids" };
#define	SD_JAILS	64	/* edges that are jails, as sdwan.c has */

/* A kept file of the host's (jail NULL), or of a jail's (base@jail). */
static const char *
sd_file(struct work *w, const char *base, const char *jail)
{

	if (jail == NULL)
		return (wfmt(w, "%s.json", base));
	return (wfmt(w, "%s@%s.json", base, jail));
}

static char *
sd_kept(struct work *w, const char *base, const char *jail)
{

	return (sdwan_kept_read(sd_file(w, base, jail)));
}

/* The jails with an edge kept: sdwan-{rules,steer,bird}@jail.json. */
static size_t
sd_jails(struct work *w, const char **v, size_t max)
{
	static const char *const bases[] = { "sdwan-rules@", "sdwan-steer@",
	    "sdwan-bird@" };
	struct dirent	*de;
	DIR		*d;
	char		 dir[MAXPATHLEN], *slash, *name;
	size_t		 n = 0, len, b, k;

	sdwan_conf_path("sdwan-rules.json", dir, sizeof(dir));
	if ((slash = strrchr(dir, '/')) == NULL)
		snprintf(dir, sizeof(dir), ".");
	else
		*slash = '\0';
	if ((d = opendir(dir)) == NULL)
		return (0);
	while (n < max && (de = readdir(d)) != NULL) {
		len = strlen(de->d_name);
		for (b = 0; b < nitems(bases); b++)
			if (strncmp(de->d_name, bases[b], strlen(bases[b])) == 0)
				break;
		if (b == nitems(bases) || len <= strlen(bases[b]) + 5 ||
		    strcmp(de->d_name + len - 5, ".json") != 0)
			continue;
		name = wfmt(w, "%.*s", (int)(len - strlen(bases[b]) - 5),
		    de->d_name + strlen(bases[b]));
		if (!valid_jail(name))
			continue;
		for (k = 0; k < n && strcmp(v[k], name) != 0; k++)
			;
		if (k == n)
			v[n++] = name;
	}
	closedir(d);
	return (n);
}

/* An edge's rules, steer and BIRD instances, as their files keep them. */
static int
sd_edge_conf(struct work *w, const char *jail, cbl_yarena *a,
    struct arcana_sdwan_sdwan_jail *e)
{
	struct arcana_sdwan_rules_config	*r;
	struct arcana_sdwan_steer_config	*s;
	const void				*v;
	char					*json;
	int					 error = 0;

	memset(e, 0, sizeof(*e));
	e->name = jail;
	if ((json = sd_kept(w, "sdwan-rules", jail)) != NULL) {
		if ((r = cbl_yarena_alloc(a, sizeof(*r))) == NULL)
			error = ENOMEM;
		else if ((error = ysd_rules_from_json(json, a, r)) == 0)
			e->rules = r;
		free(json);
	}
	if (error == 0 && (json = sd_kept(w, "sdwan-steer", jail)) != NULL) {
		if ((s = cbl_yarena_alloc(a, sizeof(*s))) == NULL)
			error = ENOMEM;
		else if ((error = ysd_steer_from_json(json, a, s)) == 0)
			e->steer = s;
		free(json);
	}
	if (error == 0 && (json = sd_kept(w, "sdwan-bird", jail)) != NULL) {
		if ((error = ysd_instances_from_json(json, YSD_PLAIN, a,
		    &e->bird_instance.n, &v)) == 0)
			e->bird_instance.v = v;
		free(json);
	}
	return (error == EINVAL ? 0 : error);
}

/* The instances of a kind, its files' together (SD-WAN's, then the
 * Security section's). */
static int
sd_instances(struct work *w, int kind, const char *const *files,
    cbl_yarena *a, size_t elem, size_t *np, const void **vp)
{
	const void	*v[2];
	size_t		 n[2] = { 0, 0 }, k;
	char		*json, *all;
	int		 error;

	*np = 0;
	*vp = NULL;
	for (k = 0; k < 2 && files[k] != NULL; k++) {
		v[k] = NULL;
		if ((json = sdwan_kept_read(files[k])) == NULL)
			continue;
		error = ysd_instances_from_json(json, kind, a, &n[k], &v[k]);
		free(json);
		if (error == ENOMEM)
			return (error);
	}
	if (n[1] == 0) {
		*np = n[0];
		*vp = v[0];
		return (0);
	}
	if (n[0] == 0) {
		*np = n[1];
		*vp = v[1];
		return (0);
	}
	if ((all = cbl_yarena_alloc(a, (n[0] + n[1]) * elem)) == NULL)
		return (ENOMEM);
	memcpy(all, v[0], n[0] * elem);
	memcpy(all + n[0] * elem, v[1], n[1] * elem);
	*np = n[0] + n[1];
	*vp = all;
	(void)w;
	return (0);
}

/* The whole configuration, the host's edge and each jail's. */
static int
sd_conf(struct work *w, cbl_yarena *a, struct arcana_sdwan_sdwan *o)
{
	static const char *const dhcp[] = { "sdwan-dhcp.json", NULL };
	static const char *const dns[] = { "sdwan-dns.json", NULL };
	static const char *const proxy[] = { "sdwan-proxy.json",
	    "security-proxy.json" };
	static const char *const ids[] = { "sdwan-ids.json",
	    "security-ids.json" };
	struct arcana_sdwan_sdwan_jail	 host, *jv;
	const char			*names[SD_JAILS];
	const void			*v;
	size_t				 n, k;
	int				 error;

	memset(o, 0, sizeof(*o));
	if ((error = sd_edge_conf(w, NULL, a, &host)) != 0)
		return (error);
	o->rules = host.rules;
	o->steer = host.steer;
	o->bird_instance.n = host.bird_instance.n;
	o->bird_instance.v = host.bird_instance.v;
	if ((error = sd_instances(w, YSD_PLAIN, dhcp, a,
	    sizeof(struct arcana_sdwan_sdwan_dhcp_instance), &o->dhcp_instance.n,
	    &v)) != 0)
		return (error);
	o->dhcp_instance.v = v;
	if ((error = sd_instances(w, YSD_PLAIN, dns, a,
	    sizeof(struct arcana_sdwan_sdwan_dns_instance), &o->dns_instance.n,
	    &v)) != 0)
		return (error);
	o->dns_instance.v = v;
	if ((error = sd_instances(w, YSD_PROXY, proxy, a,
	    sizeof(struct arcana_sdwan_sdwan_proxy_instance),
	    &o->proxy_instance.n, &v)) != 0)
		return (error);
	o->proxy_instance.v = v;
	if ((error = sd_instances(w, YSD_IDS, ids, a,
	    sizeof(struct arcana_sdwan_sdwan_ids_instance), &o->ids_instance.n,
	    &v)) != 0)
		return (error);
	o->ids_instance.v = v;
	n = sd_jails(w, names, nitems(names));
	if (n == 0)
		return (0);
	if ((jv = cbl_yarena_alloc(a, n * sizeof(*jv))) == NULL)
		return (ENOMEM);
	for (k = 0; k < n; k++)
		if ((error = sd_edge_conf(w, wstrdup(w, names[k]), a, &jv[k])) !=
		    0)
			return (error);
	/* The names the arena's: w's go with it. */
	for (k = 0; k < n; k++) {
		char	*p;

		if ((p = cbl_yarena_alloc(a, strlen(names[k]) + 1)) == NULL)
			return (ENOMEM);
		memcpy(p, names[k], strlen(names[k]) + 1);
		jv[k].name = p;
	}
	o->jail.n = n;
	o->jail.v = jv;
	return (0);
}

/* A rendered file of an instance's, the arena's; NULL: none. */
static const char *
sd_rendered(struct work *w, cbl_yarena *a, const char *kind,
    const char *name, const char *ext)
{
	char	*text, *p;

	if (name == NULL || (text = sdwan_kept_read(wfmt(w, "sdwan-%s-%s.%s",
	    kind, name, ext))) == NULL)
		return (NULL);
	if ((p = cbl_yarena_alloc(a, strlen(text) + 1)) != NULL)
		memcpy(p, text, strlen(text) + 1);
	free(text);
	return (p);
}

/*
 * The host's instances' files as the agent rendered them from their
 * forms, the conf leaves (config false); a jail's BIRD files are the
 * jail's own.
 */
#define	SD_RENDERED(w, a, o, list, type, kind) do {			\
	for (size_t i_ = 0; i_ < (o)->list.n; i_++) {			\
		struct type *in_ = (void *)(uintptr_t)&(o)->list.v[i_];	\
									\
		in_->conf = sd_rendered((w), (a), (kind), in_->name,	\
		    "conf");						\
	}								\
} while (0)

static void
sd_conf_rendered(struct work *w, cbl_yarena *a, struct arcana_sdwan_sdwan *o)
{

	SD_RENDERED(w, a, o, bird_instance, arcana_sdwan_bird_instance, "bird");
	SD_RENDERED(w, a, o, dhcp_instance, arcana_sdwan_sdwan_dhcp_instance,
	    "dhcp");
	SD_RENDERED(w, a, o, dns_instance, arcana_sdwan_sdwan_dns_instance,
	    "dns");
	SD_RENDERED(w, a, o, proxy_instance, arcana_sdwan_sdwan_proxy_instance,
	    "proxy");
}

int
arcana_sdwan_sdwan_get(cbl_req *req, struct arcana_sdwan *data, cbl_yarena *a)
{
	struct json_rsp			 r;
	struct arcana_sdwan_sdwan	*o;
	struct arcana_sdwan_sdwan_state	*st;
	struct work			 w;
	int				 error;

	if ((o = cbl_yarena_alloc(a, sizeof(*o))) == NULL)
		return (ENOMEM);
	work_init(&w);
	error = sd_conf(&w, a, o);
	if (error == 0 && cbl_req_ydatastore(req) == CBL_YDS_OPERATIONAL) {
		/* What runs, and the files rendered, read only for the
		 * state. */
		sd_conf_rendered(&w, a, o);
		memset(&r, 0, sizeof(r));
		(void)do_sdwan_state(&w, &r);
		if (!r.ok)
			error = failed("sdwan", r.error);
		else if ((st = cbl_yarena_alloc(a, sizeof(*st))) == NULL)
			error = ENOMEM;
		else if ((error = ysd_state_from_json(r.json, a, st)) == 0)
			o->state = st;
	}
	work_free(&w);
	if (error == 0)
		data->sdwan = o;
	return (error);
}

/* An edge of s's (jail NULL: the host's), as a jail entry has it. */
static void
sd_edge(const struct arcana_sdwan_sdwan *s, const char *jail,
    struct arcana_sdwan_sdwan_jail *out)
{

	memset(out, 0, sizeof(*out));
	out->name = jail;
	if (s == NULL)
		return;
	if (jail == NULL) {
		out->rules = s->rules;
		out->steer = s->steer;
		out->bird_instance.n = s->bird_instance.n;
		out->bird_instance.v = s->bird_instance.v;
		return;
	}
	for (size_t i = 0; i < s->jail.n; i++)
		if (strcmp(s->jail.v[i].name, jail) == 0) {
			*out = s->jail.v[i];
			return;
		}
}

/* A part to set: its kind, edge, and the JSON it was and is to be. */
struct sd_step {
	int		 kind;
	const char	*jail;
	char		*was, *now;
	bool		 done;
};

struct sd_plan {
	struct sd_step	 v[3 * (SD_JAILS + 1) + 6];
	size_t		 n;
	const char	*why;
};

/* A part that changed, planned; was and now taken (NULL: no memory). */
static bool
sd_plan(struct sd_plan *p, int kind, const char *jail, char *was, char *now)
{

	if (was == NULL || now == NULL || p->n == nitems(p->v)) {
		free(was);
		free(now);
		if (p->why == NULL)
			p->why = p->n == nitems(p->v) ? "too many edges" :
			    "no memory, or a spec that is no JSON object";
		return (false);
	}
	if (strcmp(was, now) == 0) {
		free(was);
		free(now);
		return (true);
	}
	p->v[p->n].kind = kind;
	p->v[p->n].jail = jail;
	p->v[p->n].was = was;
	p->v[p->n].now = now;
	p->v[p->n].done = false;
	p->n++;
	return (true);
}

/* An edge's rules, steering and BIRD as they were and are to be. */
static bool
sd_plan_edge(struct sd_plan *p, const char *jail,
    const struct arcana_sdwan_sdwan_jail *b,
    const struct arcana_sdwan_sdwan_jail *f)
{
	unsigned	set;
	const char	*e;

	/* The set they are emptied in: the other side's. */
	if (b->rules != NULL || f->rules != NULL) {
		set = f->rules != NULL && f->rules->has_set ? f->rules->set :
		    b->rules != NULL && b->rules->has_set ? b->rules->set : 0;
		if (!sd_plan(p, SD_RULES, jail, ysd_rules_json(jail, b->rules,
		    set), ysd_rules_json(jail, f->rules, set)))
			return (false);
	}
	if ((b->steer != NULL || f->steer != NULL) && !sd_plan(p, SD_STEER,
	    jail, ysd_steer_json(jail, b->steer), ysd_steer_json(jail,
	    f->steer)))
		return (false);
	e = NULL;
	if ((b->bird_instance.n > 0 || f->bird_instance.n > 0) && !sd_plan(p,
	    SD_BIRD, jail, ysd_instances_json(YSD_PLAIN, jail, -1,
	    b->bird_instance.n, b->bird_instance.v, &e), ysd_instances_json(
	    YSD_PLAIN, jail, -1, f->bird_instance.n, f->bird_instance.v, &e)))
		return (false);
	return (true);
}

/* The host's instances of a kind, of a group, as they were and are. */
static bool
sd_plan_kind(struct sd_plan *p, int kind, int ykind, int group,
    size_t bn, const void *bv, size_t fn, const void *fv)
{
	const char	*e = NULL;

	if (bn == 0 && fn == 0)
		return (true);
	return (sd_plan(p, kind, NULL, ysd_instances_json(ykind, NULL, group,
	    bn, bv, &e), ysd_instances_json(ykind, NULL, group, fn, fv, &e)));
}

static int
sd_set(struct work *w, int kind, const char *json, const char **errp)
{

	switch (kind) {
	case SD_RULES:
		return (do_sdwan_rules(w, json, errp));
	case SD_STEER:
		return (do_sdwan_steer(w, json, errp));
	case SD_BIRD:
		return (do_sdwan_bird(w, json, errp));
	case SD_DHCP:
		return (do_sdwan_dhcp(w, json, errp));
	case SD_DNS:
		return (do_sdwan_dns(w, json, errp));
	case SD_PROXY:
		return (do_sdwan_proxy(w, json, errp));
	default:
		return (do_sdwan_ids(w, json, errp));
	}
}

int
arcana_sdwan_sdwan_edit(cbl_req *req, const struct arcana_sdwan *before,
    const struct arcana_sdwan *after)
{
	static const struct arcana_sdwan_sdwan	 none;
	const struct arcana_sdwan_sdwan		*b, *f;
	struct arcana_sdwan_sdwan_jail		 was, now;
	struct sd_plan				*p;
	struct work				 w;
	const char				*why, *jail;
	int					 root, step, rc;
	size_t					 k, m;

	b = before != NULL && before->sdwan != NULL ? before->sdwan : &none;
	f = after != NULL && after->sdwan != NULL ? after->sdwan : &none;
	if (f->jail.n > SD_JAILS)
		return (said(req, "too many edges that are jails"));
	for (k = 0; k < f->jail.n; k++)
		if (!valid_jail(f->jail.v[k].name))
			return (said(req, "invalid jail name"));
	if ((p = calloc(1, sizeof(*p))) == NULL)
		return (ENOMEM);
	/* Every part's JSON made before any is set: a spec that is none
	 * refuses the edit whole. */
	sd_edge(b, NULL, &was);
	sd_edge(f, NULL, &now);
	rc = sd_plan_edge(p, NULL, &was, &now) ? 0 : -1;
	for (k = 0; rc == 0 && k < f->jail.n; k++) {
		jail = f->jail.v[k].name;
		sd_edge(b, jail, &was);
		sd_edge(f, jail, &now);
		rc = sd_plan_edge(p, jail, &was, &now) ? 0 : -1;
	}
	/* A jail no longer there: its parts emptied. */
	for (k = 0; rc == 0 && k < b->jail.n; k++) {
		jail = b->jail.v[k].name;
		for (m = 0; m < f->jail.n && strcmp(f->jail.v[m].name, jail) !=
		    0; m++)
			;
		if (m < f->jail.n)
			continue;
		sd_edge(b, jail, &was);
		sd_edge(NULL, jail, &now);
		rc = sd_plan_edge(p, jail, &was, &now) ? 0 : -1;
	}
	if (rc == 0 && (!sd_plan_kind(p, SD_DHCP, YSD_PLAIN, -1,
	    b->dhcp_instance.n, b->dhcp_instance.v, f->dhcp_instance.n,
	    f->dhcp_instance.v) || !sd_plan_kind(p, SD_DNS, YSD_PLAIN, -1,
	    b->dns_instance.n, b->dns_instance.v, f->dns_instance.n,
	    f->dns_instance.v)))
		rc = -1;
	/* The proxies and the IDS, SD-WAN's and the Security section's
	 * apart, as their setters keep them. */
	for (int g = 0; rc == 0 && g < 2; g++)
		if (!sd_plan_kind(p, SD_PROXY, YSD_PROXY, g, b->proxy_instance.n,
		    b->proxy_instance.v, f->proxy_instance.n,
		    f->proxy_instance.v) || !sd_plan_kind(p, SD_IDS, YSD_IDS, g,
		    b->ids_instance.n, b->ids_instance.v, f->ids_instance.n,
		    f->ids_instance.v))
			rc = -1;
	if (rc != 0) {
		why = p->why;
		for (k = 0; k < p->n; k++) {
			free(p->v[k].was);
			free(p->v[k].now);
		}
		free(p);
		return (said(req, why));
	}
	if (p->n == 0) {
		free(p);
		return (0);
	}
	if (!change_begin("the SD-WAN edge")) {
		for (k = 0; k < p->n; k++) {
			free(p->v[k].was);
			free(p->v[k].now);
		}
		free(p);
		return (said(req, "not done: arcana-agent is stopping"));
	}
	work_init(&w);
	trace_tell(&w, req);
	root = step_begin(&w, ARC_STEP_KIND_DAEMON, "arcana-agent",
	    "the SD-WAN edge: %zu part%s", p->n, p->n == 1 ? "" : "s");
	why = NULL;
	for (k = 0; rc == 0 && k < p->n; k++) {
		step = step_begin(&w, ARC_STEP_KIND_DAEMON, "arcana-agent",
		    "sdwan %s%s%s", sd_kinds[p->v[k].kind], p->v[k].jail != NULL ?
		    " of " : "", p->v[k].jail != NULL ? p->v[k].jail : "");
		rc = sd_set(&w, p->v[k].kind, p->v[k].now, &why);
		step_end(&w, step, rc == 0, rc == 0 ? NULL : "%s", why);
		p->v[k].done = true;
	}
	/* One failed: those set before it, and it, as they were, the last
	 * first; the edit refused. */
	for (m = k; rc != 0 && m-- > 0;) {
		const char	*e = NULL;

		step = step_begin(&w, ARC_STEP_KIND_DAEMON, "arcana-agent",
		    "sdwan %s%s%s as it was", sd_kinds[p->v[m].kind],
		    p->v[m].jail != NULL ? " of " : "", p->v[m].jail != NULL ?
		    p->v[m].jail : "");
		if (sd_set(&w, p->v[m].kind, p->v[m].was, &e) != 0) {
			step_end(&w, step, false, "%s", e);
			logmsg(LOG_WARNING, "sdwan %s: not as it was: %s",
			    sd_kinds[p->v[m].kind], e != NULL ? e : "failed");
		} else
			step_end(&w, step, true, NULL);
	}
	change_end();
	step_end(&w, root, rc == 0, NULL);
	why = rc == 0 ? NULL : wstrdup(&w, why != NULL ? why : "failed");
	rc = rc == 0 ? 0 : said(req, why);
	for (k = 0; k < p->n; k++) {
		free(p->v[k].was);
		free(p->v[k].now);
	}
	free(p);
	work_free(&w);
	return (rc);
}

int
arcana_sdwan_sdwan_apply_action(cbl_req *req, const struct cbl_bytes *target,
    const struct arcana_sdwan_sdwan_apply_input *in,
    struct arcana_sdwan_sdwan_apply_output *out, cbl_yarena *a)
{
	static const int kinds[] = { SD_RULES, SD_STEER, SD_BIRD, SD_DHCP,
	    SD_DNS, SD_PROXY, SD_IDS };
	struct arcana_sdwan_sdwan	 conf;
	struct arcana_sdwan_sdwan_jail	 e;
	struct work			 w;
	const char			*jail, *why;
	char				*json;
	int				 kind, root, rc, group;

	(void)target;
	(void)out;
	if (!in->has_part || in->part >= nitems(kinds))
		return (said(req, "which part: rules, steer, bird, dhcp, dns, "
		    "proxy or ids"));
	kind = kinds[in->part];
	jail = in->jail != NULL && in->jail[0] != '\0' ? in->jail : NULL;
	if (jail != NULL && !valid_jail(jail))
		return (said(req, "invalid jail name"));
	if (jail != NULL && kind > SD_BIRD)
		return (said(req, "an edge that is a vnet jail has its rules, "
		    "steering and BIRD alone"));
	group = kind < SD_PROXY ? -1 : in->has_security && in->security ?
	    1 : 0;
	work_init(&w);
	/* The part as running has it, the JSON its setter takes. */
	why = NULL;
	if ((rc = sd_conf(&w, a, &conf)) != 0) {
		work_free(&w);
		return (rc);
	}
	sd_edge(&conf, jail, &e);
	switch (kind) {
	case SD_RULES:
		json = e.rules != NULL ? ysd_rules_json(jail, e.rules, 0) :
		    NULL;
		why = "no rules are kept";
		break;
	case SD_STEER:
		json = ysd_steer_json(jail, e.steer);
		break;
	case SD_BIRD:
		json = ysd_instances_json(YSD_PLAIN, jail, -1,
		    e.bird_instance.n, e.bird_instance.v, &why);
		break;
	case SD_DHCP:
		json = ysd_instances_json(YSD_PLAIN, NULL, -1,
		    conf.dhcp_instance.n, conf.dhcp_instance.v, &why);
		break;
	case SD_DNS:
		json = ysd_instances_json(YSD_PLAIN, NULL, -1,
		    conf.dns_instance.n, conf.dns_instance.v, &why);
		break;
	case SD_PROXY:
		json = ysd_instances_json(YSD_PROXY, NULL, group,
		    conf.proxy_instance.n, conf.proxy_instance.v, &why);
		break;
	default:
		json = ysd_instances_json(YSD_IDS, NULL, group,
		    conf.ids_instance.n, conf.ids_instance.v, &why);
		break;
	}
	if (json == NULL) {
		work_free(&w);
		return (said(req, why != NULL ? why : "no memory"));
	}
	if (!change_begin("the SD-WAN edge")) {
		free(json);
		work_free(&w);
		return (said(req, "not done: arcana-agent is stopping"));
	}
	trace_tell(&w, req);
	root = step_begin(&w, ARC_STEP_KIND_DAEMON, "arcana-agent",
	    "sdwan %s%s%s set again", sd_kinds[kind], jail != NULL ? " of " :
	    "", jail != NULL ? jail : "");
	why = NULL;
	rc = sd_set(&w, kind, json, &why);
	change_end();
	step_end(&w, root, rc == 0, rc == 0 ? NULL : "%s", why);
	free(json);
	rc = rc == 0 ? 0 : said(req, why != NULL ? why : "failed");
	work_free(&w);
	return (rc);
}

int
arcana_services_services_service_reload_action(cbl_req *req,
    const struct cbl_bytes *target,
    const struct arcana_services_services_service_reload_input *in,
    struct arcana_services_services_service_reload_output *out, cbl_yarena *a)
{

	(void)in;
	return (service_action(req, target, ARC_SERVICE_ACTION_RELOAD,
	    &out->has_running, &out->running, &out->has_pid, &out->pid,
	    &out->status, a));
}

int
arcana_services_services_service_restart_action(cbl_req *req,
    const struct cbl_bytes *target,
    const struct arcana_services_services_service_restart_input *in,
    struct arcana_services_services_service_restart_output *out, cbl_yarena *a)
{

	(void)in;
	return (service_action(req, target, ARC_SERVICE_ACTION_RESTART,
	    &out->has_running, &out->running, &out->has_pid, &out->pid,
	    &out->status, a));
}

int
arcana_services_services_service_start_action(cbl_req *req,
    const struct cbl_bytes *target,
    const struct arcana_services_services_service_start_input *in,
    struct arcana_services_services_service_start_output *out, cbl_yarena *a)
{

	(void)in;
	return (service_action(req, target, ARC_SERVICE_ACTION_START,
	    &out->has_running, &out->running, &out->has_pid, &out->pid,
	    &out->status, a));
}

int
arcana_services_services_service_stop_action(cbl_req *req,
    const struct cbl_bytes *target,
    const struct arcana_services_services_service_stop_input *in,
    struct arcana_services_services_service_stop_output *out, cbl_yarena *a)
{

	(void)in;
	return (service_action(req, target, ARC_SERVICE_ACTION_STOP,
	    &out->has_running, &out->running, &out->has_pid, &out->pid,
	    &out->status, a));
}

/* A service as it is now: a read, no change. */
int
arcana_services_services_service_read_action(cbl_req *req,
    const struct cbl_bytes *target,
    const struct arcana_services_services_service_read_input *in,
    struct arcana_services_services_service_read_output *out, cbl_yarena *a)
{
	struct service_config_rsp	 r;
	const void			**k;
	const char			*name;
	struct work			*w;
	int				 root;

	(void)in;
	if ((k = keys_of(target, 1, a)) == NULL)
		return (EINVAL);
	name = *(const char *const *)k[0];
	if ((w = ywork(a)) == NULL)
		return (ENOMEM);
	if ((w = ywork_told(req, a, wfmt(w, "service %s", name), &root)) ==
	    NULL)
		return (ENOMEM);
	memset(&r, 0, sizeof(r));
	(void)service_read(w, name, &r);
	step_end(w, root, r.ok, NULL);
	if (!r.ok)
		return (said(req, r.error));
	yservices_read(&r, out);
	return (0);
}

/* The services' rc.conf configuration moved under Arcana: a change of
 * the agent's own, as a commit's writes are (ira/ysvcedit.c). */
int
arcana_services_services_convert_action(cbl_req *req,
    const struct cbl_bytes *target,
    const struct arcana_services_services_convert_input *in,
    struct arcana_services_services_convert_output *out, cbl_yarena *a)
{
	bool	dry = in->has_dry_run && in->dry_run;
	int	error;

	(void)target;
	if (dry)
		return (yservices_convert(req, in->service.v, in->service.n,
		    true, a, out));
	if (!change_begin("services convert"))
		return (said(req, "not done: arcana-agent is stopping"));
	error = yservices_convert(req, in->service.v, in->service.n, false, a,
	    out);
	change_end();
	return (error);
}

int
arcana_sshd_sshd_get(cbl_req *req, struct arcana_sshd *data, cbl_yarena *a)
{
	struct arc_ssh_rsp		 r;
	struct arcana_sshd_sshd	*o;
	struct work			*w;
	int				 error;

	(void)req;
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

	(void)out;
	if (in->new_key == NULL)
		return (said(req, "a new key is needed"));
	return (zfs_key(req, target, in->key, in->new_key, a));
}

/* A dataset made encrypted, as zfs-key's zfs-create made one. */
int
arcana_storage_storage_create_encrypted_action(cbl_req *req,
    const struct cbl_bytes *target,
    const struct arcana_storage_storage_create_encrypted_input *in,
    struct arcana_storage_storage_create_encrypted_output *out,
    cbl_yarena *a)
{
	static const char *const ciphers[] = { "on", "aes-128-ccm",
	    "aes-192-ccm", "aes-256-ccm", "aes-128-gcm", "aes-192-gcm",
	    "aes-256-gcm" };
	struct zfskey_req	 q;
	struct zfskey_rsp	 r;
	struct work		*w;

	(void)target;
	(void)out;
	if (in->dataset == NULL || in->key == NULL)
		return (said(req, "the dataset and its key are needed"));
	if (in->has_encryption && (size_t)in->encryption >= nitems(ciphers))
		return (EINVAL);
	if ((w = ywork(a)) == NULL)
		return (ENOMEM);
	memset(&q, 0, sizeof(q));
	q.zfs_dataset = in->dataset;
	q.zfs_new_key = in->key;
	q.zfs_create = ciphers[in->has_encryption ? in->encryption : 0];
	memset(&r, 0, sizeof(r));
	r.has_ok = true;
	if (!change_begin(wfmt(w, "zfs key of %s", q.zfs_dataset)))
		return (said(req, "not done: arcana-agent is stopping"));
	do_zfs_key(w, &q, &r);
	change_end();
	explicit_bzero((void *)(uintptr_t)in->key, strlen(in->key));
	return (r.ok ? 0 : said(req, r.error));
}

int
arcana_storage_storage_dataset_load_key_action(cbl_req *req,
    const struct cbl_bytes *target,
    const struct arcana_storage_storage_dataset_load_key_input *in,
    struct arcana_storage_storage_dataset_load_key_output *out, cbl_yarena *a)
{

	(void)out;
	if (in->key == NULL)
		return (said(req, "a key is needed"));
	return (zfs_key(req, target, in->key, NULL, a));
}

int
arcana_storage_storage_dataset_unload_key_action(cbl_req *req,
    const struct cbl_bytes *target,
    const struct arcana_storage_storage_dataset_unload_key_input *in,
    struct arcana_storage_storage_dataset_unload_key_output *out, cbl_yarena *a)
{
	struct arc_job_spec	 sp;
	const char		*names[1], *e;
	const void		**k;
	struct work		*w;
	int			 rc;

	(void)in;
	(void)out;
	if ((k = keys_of(target, 1, a)) == NULL)
		return (EINVAL);
	if ((w = ywork(a)) == NULL)
		return (ENOMEM);
	/* As the zfs job's unload-key. */
	memset(&sp, 0, sizeof(sp));
	sp.kind = ARC_JOB_KIND_ZFS;
	sp.verb = "unload-key";
	names[0] = *(const char *const *)k[0];
	sp.names.v = names;
	sp.names.n = 1;
	e = NULL;
	if (!change_begin(wfmt(w, "zfs unload-key %s", names[0])))
		return (said(req, "not done: arcana-agent is stopping"));
	rc = do_storage_job(w, &sp, &e);
	change_end();
	return (rc != 0 ? said(req, e) : 0);
}

int
arcana_storage_storage_fstab_replace_action(cbl_req *req,
    const struct cbl_bytes *target,
    const struct arcana_storage_storage_fstab_replace_input *in,
    struct arcana_storage_storage_fstab_replace_output *out, cbl_yarena *a)
{
	struct fstab_req	 q;
	struct fstab_rsp	 r;
	struct work		*w;
	bool			 dry;

	(void)target;
	if (in->text == NULL || in->sha256 == NULL)
		return (said(req, "the text and the SHA-256 of the one it was "
		    "made from are needed"));
	if ((w = ywork(a)) == NULL)
		return (ENOMEM);
	dry = in->has_dry_run && in->dry_run;
	memset(&q, 0, sizeof(q));
	q.conf_text = in->text;
	q.sha256 = in->sha256;
	q.dry_run = dry;
	memset(&r, 0, sizeof(r));
	if (dry)
		(void)do_fstab(w, &q, &r);
	else {
		if (!change_begin("fstab write"))
			return (said(req, "not done: arcana-agent is stopping"));
		(void)do_fstab(w, &q, &r);
		change_end();
	}
	if (!r.ok)
		return (said(req, r.error));
	out->sha256 = r.sha256;
	return (0);
}

int
arcana_storage_storage_get(cbl_req *req, struct arcana_storage *data,
    cbl_yarena *a)
{
	static const uint8_t kinds[] = { ARC_STORAGE_KIND_DISKS,
	    ARC_STORAGE_KIND_POOLS, ARC_STORAGE_KIND_DATASETS,
	    ARC_STORAGE_KIND_SNAPSHOTS, ARC_STORAGE_KIND_MOUNTS,
	    ARC_STORAGE_KIND_HEALTH };
	struct storage_rsp		 r;
	struct arcana_storage_storage	*o;
	struct work			*w;
	size_t				 i;
	int				 error;

	(void)req;
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

/*
 * One part of the storage, as the storage operation read it for a page:
 * datasets and snapshots under filter's dataset, those jail's zfs sees.
 * read's kind is the operation's storage-kind.
 */
int
arcana_storage_storage_read_action(cbl_req *req, const struct cbl_bytes *target,
    const struct arcana_storage_storage_read_input *in,
    struct arcana_storage_storage_read_output *out, cbl_yarena *a)
{
	struct storage_rsp		 r;
	struct arcana_storage_storage	 st;
	struct work			*w;
	const char			*e;
	uint8_t				 kind;
	int				 error;

	(void)target;
	if (!in->has_kind)
		return (said(req, "which part of the storage"));
	kind = (uint8_t)in->kind;
	if (in->jail != NULL && in->jail[0] != '\0') {
		if (!valid_jail(in->jail))
			return (said(req, "invalid jail name"));
		if (kind != ARC_STORAGE_KIND_DATASETS &&
		    kind != ARC_STORAGE_KIND_SNAPSHOTS)
			return (said(req, "of a jail, its datasets and "
			    "snapshots only"));
	}
	if ((w = ywork(a)) == NULL)
		return (ENOMEM);
	e = NULL;
	if (scope_enter_jail(w, in->jail != NULL && in->jail[0] != '\0' ?
	    in->jail : NULL, &e, false) != 0)
		return (said(req, e));
	memset(&r, 0, sizeof(r));
	(void)do_storage(w, kind, in->filter != NULL && in->filter[0] !=
	    '\0' ? in->filter : NULL, &r);
	if (!r.ok)
		return (said(req, r.error != NULL ? r.error : "not read"));
	memset(&st, 0, sizeof(st));
	if ((error = ystorage_from_json(kind, r.json, r.total, r.truncated, a,
	    &st)) != 0)
		return (error);
	/* With what is mounted, fstab(5)'s text and its SHA-256, which
	 * fstab's replace is given back. */
	if (kind == ARC_STORAGE_KIND_MOUNTS) {
		struct fstab_req	fq;
		struct fstab_rsp	fr;

		memset(&fq, 0, sizeof(fq));
		memset(&fr, 0, sizeof(fr));
		(void)do_fstab(w, &fq, &fr);
		if (fr.ok && (error = ystorage_fstab(fr.conf_text, fr.sha256,
		    a, &st)) != 0)
			return (error);
	}
	out->disk.n = st.disk.n;
	out->disk.v = st.disk.v;
	out->pool.n = st.pool.n;
	out->pool.v = st.pool.v;
	out->importable.n = st.importable.n;
	out->importable.v = st.importable.v;
	/*
	 * The dataset, snapshot and fstab of the state carry actions, the
	 * output's do not: a struct each, of the same members (actions are
	 * none), which the state's are read as.
	 */
	_Static_assert(sizeof(*out->dataset.v) == sizeof(*st.dataset.v) &&
	    sizeof(*out->snapshot.v) == sizeof(*st.snapshot.v) &&
	    sizeof(*out->fstab) == sizeof(*st.fstab), "read's own structs");
	out->has_datasets_total = st.has_datasets_total;
	out->datasets_total = st.datasets_total;
	out->dataset.n = st.dataset.n;
	out->dataset.v = (const void *)st.dataset.v;
	out->has_snapshots_total = st.has_snapshots_total;
	out->snapshots_total = st.snapshots_total;
	out->snapshot.n = st.snapshot.n;
	out->snapshot.v = (const void *)st.snapshot.v;
	out->mount.n = st.mount.n;
	out->mount.v = st.mount.v;
	out->fstab = (const void *)st.fstab;
	out->swap.n = st.swap.n;
	out->swap.v = st.swap.v;
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
arcana_troubleshoot_troubleshoot_capture_action(cbl_req *req,
    const struct cbl_bytes *target,
    const struct arcana_troubleshoot_troubleshoot_capture_input *in,
    struct arcana_troubleshoot_troubleshoot_capture_output *out,
    cbl_yarena *a)
{
	struct capture_req	 q;
	struct json_rsp		 r;
	const char		*e;
	struct work		*w;

	(void)target;
	if (in->jail != NULL && in->jail[0] != '\0' && !valid_jail(in->jail))
		return (said(req, "invalid jail name"));
	if ((w = ywork(a)) == NULL)
		return (ENOMEM);
	memset(&q, 0, sizeof(q));
	q.interface = in->interface;
	q.filter = in->filter;
	q.seconds = in->has_seconds ? in->seconds : 0;
	q.packets = in->has_packets ? in->packets : 0;
	memset(&r, 0, sizeof(r));
	r.has_ok = true;
	e = NULL;
	if (scope_enter(w, in->jail != NULL && in->jail[0] != '\0' ?
	    in->jail : NULL, &e) != 0)
		return (said(req, e));
	do_capture(w, &q, &r);
	if (!r.ok)
		return (said(req, r.error));
	return (yts_capture_from_json(r.json, a, out));
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
	(void)req;
	return (0);
}

int
arcana_troubleshoot_troubleshoot_path_check_action(cbl_req *req,
    const struct cbl_bytes *target,
    const struct arcana_troubleshoot_troubleshoot_path_check_input *in,
    struct arcana_troubleshoot_troubleshoot_path_check_output *out,
    cbl_yarena *a)
{
	static const char *const protos[] = { "tcp", "udp", "icmp", "ip",
	    "sctp" };
	struct json_rsp			 r;
	const char			*e;
	struct work			*w;

	(void)target;
	if (!in->has_source || !in->has_destination)
		return (said(req, "a source and a destination are needed"));
	if (in->jail != NULL && in->jail[0] != '\0' && !valid_jail(in->jail))
		return (said(req, "invalid jail name"));
	if ((w = ywork(a)) == NULL)
		return (ENOMEM);
	memset(&r, 0, sizeof(r));
	r.has_ok = true;
	e = NULL;
	if (scope_enter(w, in->jail != NULL && in->jail[0] != '\0' ?
	    in->jail : NULL, &e) != 0)
		return (said(req, e));
	do_path_check(w, in->source.v.m0, in->destination.v.m0,
	    in->has_protocol && (size_t)in->protocol < nitems(protos) ?
	    protos[in->protocol] : NULL, in->has_port ? in->port : 0,
	    in->interface, in->has_fib, in->has_fib ? in->fib : 0,
	    in->has_reply && in->reply, &r);
	if (!r.ok)
		return (said(req, r.error));
	return (yts_path_from_json(r.json, a, out));
}

int
arcana_troubleshoot_troubleshoot_traceroute_action(cbl_req *req,
    const struct cbl_bytes *target,
    const struct arcana_troubleshoot_troubleshoot_traceroute_input *in,
    struct arcana_troubleshoot_troubleshoot_traceroute_output *out,
    cbl_yarena *a)
{
	struct json_rsp			 r;
	const char			*addr;
	struct work			*w;

	(void)target;
	addr = in->has_address ? in->address.v.m0 : NULL;
	if (addr == NULL || addr[0] == '-' || addr[strspn(addr,
	    "0123456789abcdefABCDEF.:")] != '\0')
		return (said(req, "an address to trace the route to is "
		    "needed"));
	if ((w = ywork(a)) == NULL)
		return (ENOMEM);
	memset(&r, 0, sizeof(r));
	(void)do_traceroute(w, addr, &r);
	if (!r.ok)
		return (said(req, r.error));
	return (yts_traceroute_from_json(r.json, a, out));
}

int
arcana_wireguard_wireguard_get(cbl_req *req, struct arcana_wireguard *data,
    cbl_yarena *a)
{
	struct arc_network_rsp		 r;
	struct arcana_wireguard_wireguard	*o;
	struct work			*w;
	int				 error;

	(void)req;
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
	if ((error = ywg_from_json(r.json, a, &o->now, &o->interface.n,
	    &o->interface.v)) != 0)
		return (error);
	data->wireguard = o;
	return (0);
}

/* The interfaces now, the host's or a vnet jail's, what wg said if not. */
int
arcana_wireguard_wireguard_read_action(cbl_req *req,
    const struct cbl_bytes *target,
    const struct arcana_wireguard_wireguard_read_input *in,
    struct arcana_wireguard_wireguard_read_output *out, cbl_yarena *a)
{
	struct arc_network_rsp	 r;
	struct work		*w;
	int			 error, root;

	(void)target;
	if ((w = ywork_told(req, a, "the WireGuard interfaces", &root)) == NULL)
		return (ENOMEM);
	if ((error = yjail_in(req, in->jail, w)) != 0) {
		step_end(w, root, false, NULL);
		return (error);
	}
	memset(&r, 0, sizeof(r));
	(void)do_network(w, ARC_NET_KIND_WIREGUARD, ARC_NET_FAMILY_ALL, NULL,
	    0, 0, &r);
	step_end(w, root, r.ok, NULL);
	if (!r.ok)
		return (said(req, r.error));
	return (ywg_from_json(r.json, a, &out->now, &out->interface.n,
	    &out->interface.v));
}

/*
 * The host: hello's facts and the stats, what the console polls; the
 * certificates are the read-certificates action's, read when asked.
 */
int
arcana_host_host_get(cbl_req *req, struct arcana_host *data, cbl_yarena *a)
{
	struct arc_host			 h;
	struct host_stats		 st;
	struct arcana_host_host		*o;
	struct work			*w;
	int				 error;

	(void)req;
	if ((w = ywork(a)) == NULL)
		return (ENOMEM);
	memset(&h, 0, sizeof(h));
	host_info(w, &h);
	do_stats(w, &st);
	if ((o = cbl_yarena_alloc(a, sizeof(*o))) == NULL)
		return (ENOMEM);
	if ((error = yhost_from(&h, &st, a, o)) != 0)
		return (error);
	data->host = o;
	return (0);
}

/* What OpenSSL trusts, the host's or a jail's (certs.c). */
int
arcana_host_host_read_certificates_action(cbl_req *req,
    const struct cbl_bytes *target,
    const struct arcana_host_host_read_certificates_input *in,
    struct arcana_host_host_read_certificates_output *out, cbl_yarena *a)
{
	struct json_rsp	 r;
	struct work	*w;
	const char	*jail;
	int		 root;

	(void)target;
	jail = in->jail != NULL && in->jail[0] != '\0' ? in->jail : NULL;
	if (jail != NULL && !valid_jail(jail))
		return (said(req, "invalid jail name"));
	if ((w = ywork_told(req, a, "certificates", &root)) == NULL)
		return (ENOMEM);
	memset(&r, 0, sizeof(r));
	if (scope_enter_jail(w, jail, &r.error, false) == 0)
		do_certs(w, &r);
	step_end(w, root, r.ok, NULL);
	if (!r.ok)
		return (said(req, r.error));
	return (yhost_certs_from_json(r.json, a, out));
}

int
arcana_builder_builder_port_options_action(cbl_req *req,
    const struct cbl_bytes *target,
    const struct arcana_builder_builder_port_options_input *in,
    struct arcana_builder_builder_port_options_output *out, cbl_yarena *a)
{
	struct arc_builder_options_rsp	 r;
	struct arc_job_spec		 sp;
	const char			*names[8];
	struct work			*w;
	size_t				 n = 0;

	(void)target;
	/* As the builder-options operation takes them: jail=, ports=,
	 * set=, origin=. */
	if ((w = ywork(a)) == NULL)
		return (ENOMEM);
	if (in->jail != NULL)
		names[n++] = wfmt(w, "jail=%s", in->jail);
	if (in->ports != NULL)
		names[n++] = wfmt(w, "ports=%s", in->ports);
	if (in->set != NULL)
		names[n++] = wfmt(w, "set=%s", in->set);
	if (in->origin != NULL)
		names[n++] = wfmt(w, "origin=%s", in->origin);
	memset(&sp, 0, sizeof(sp));
	sp.names.v = names;
	sp.names.n = n;
	memset(&r, 0, sizeof(r));
	r.has_ok = true;
	do_builder_options(w, &sp, &r);
	if (!r.ok)
		return (said(req, r.error));
	return (ybuilder_options_from_json(r.json, a, out));
}
