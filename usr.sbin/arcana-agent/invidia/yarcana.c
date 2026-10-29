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
#include <errno.h>
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
 * An action of a jail's (its target a jail's entry, the key its name):
 * the work in the jail's scope.  0, or the error said.
 */
static int
yjail_scope(cbl_req *req, const struct cbl_bytes *target, struct work *w,
    cbl_yarena *a)
{
	const void	**k;
	const char	*e;

	if ((k = keys_of(target, 1, a)) == NULL)
		return (0);
	if (!valid_jail(*(const char *const *)k[0]))
		return (said(req, "invalid jail name"));
	e = NULL;
	if (scope_enter(w, *(const char *const *)k[0], &e) != 0)
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
	    '\0' ? in->ref : NULL, in->host_keys, in->ssh_key, &r);
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
	struct arc_config_apply_rsp	 r;
	struct work			*w;
	char				*json;
	bool				 dry;

	(void)target;
	if (in->bundle == NULL)
		return (said(req, "a bundle is needed"));
	if ((w = ywork(a)) == NULL)
		return (ENOMEM);
	if ((json = yagent_bundle_json(in->bundle)) == NULL)
		return (ENOMEM);
	dry = in->has_dry_run && in->dry_run;
	memset(&r, 0, sizeof(r));
	if (!change_begin(dry ? "config-apply, a dry run" : "config-apply")) {
		free(json);
		return (said(req, "not done: arcana-agent is stopping"));
	}
	(void)do_config_apply(w, json, dry, in->has_anyway && in->anyway,
	    in->hostname, &r);
	change_end();
	free(json);
	if (!r.ok)
		return (said(req, r.error));
	return (yagent_apply_from_json(r.json, a, out));
}

int
arcana_agent_agent_config_export_action(cbl_req *req,
    const struct cbl_bytes *target,
    const struct arcana_agent_agent_config_export_input *in,
    struct arcana_agent_agent_config_export_output *out, cbl_yarena *a)
{
	struct arc_config_export_rsp	 r;
	struct work			*w;

	(void)target;
	if ((w = ywork(a)) == NULL)
		return (ENOMEM);
	memset(&r, 0, sizeof(r));
	(void)do_config_export(w, in->has_secrets && in->secrets, &r);
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
	struct arc_transport_rsp	 tr;
	struct arc_tls_rsp		 lr;
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
	struct arc_source_log_rsp	 r;
	struct work			*w;

	(void)target;
	if (in->source == NULL)
		return (said(req, "a repository is needed"));
	if ((w = ywork(a)) == NULL)
		return (ENOMEM);
	memset(&r, 0, sizeof(r));
	pthread_mutex_lock(&build_lock);
	(void)do_source_log(w, in->source, in->ref != NULL && in->ref[0] !=
	    '\0' ? in->ref : NULL, in->host_keys, in->ssh_key,
	    in->has_count ? in->count : 0, &r);
	pthread_mutex_unlock(&build_lock);
	if (!r.ok)
		return (said(req, r.error));
	return (yagent_log_from_json(r.commit, r.log, r.tags, a, out));
}

int
arcana_agent_agent_tls_csr_action(cbl_req *req, const struct cbl_bytes *target,
    const struct arcana_agent_agent_tls_csr_input *in,
    struct arcana_agent_agent_tls_csr_output *out, cbl_yarena *a)
{
	struct arc_tls_rsp	 r;
	struct work		*w;
	ucl_object_t		*top;

	(void)target;
	(void)in;
	if ((w = ywork(a)) == NULL)
		return (ENOMEM);
	memset(&r, 0, sizeof(r));
	if (!change_begin("tls csr"))
		return (said(req, "not done: arcana-agent is stopping"));
	do_tls(w, "csr", NULL, NULL, NULL, NULL, &r);
	change_end();
	if (!r.ok)
		return (said(req, r.error));
	if ((top = yj_parse(r.json)) == NULL)
		return (EINVAL);
	out->csr = yj_str(a, top, "csr");
	ucl_object_unref(top);
	return (0);
}

int
arcana_agent_agent_tls_install_action(cbl_req *req,
    const struct cbl_bytes *target,
    const struct arcana_agent_agent_tls_install_input *in,
    struct arcana_agent_agent_tls_install_output *out, cbl_yarena *a)
{
	struct arc_tls_rsp	 r;
	const cbl_peer		*pe;
	struct work		*w;
	uint8_t			 fp[64];
	size_t			 fplen;
	bool			 have;

	(void)target;
	(void)out;
	if (in->certificate == NULL)
		return (said(req, "a certificate is needed"));
	if ((w = ywork(a)) == NULL)
		return (ENOMEM);
	/* The peer asking, kept trusted across the change. */
	fplen = sizeof(fp);
	pe = cbl_req_peer(req);
	have = pe != NULL && (cbl_peer_flags(pe) & CBL_PEER_AUTHENTICATED) !=
	    0 && cbl_peer_fingerprint(pe, "sha256", fp, &fplen) == 0 &&
	    fplen == 32;
	memset(&r, 0, sizeof(r));
	if (!change_begin("tls install"))
		return (said(req, "not done: arcana-agent is stopping"));
	do_tls(w, "install", in->certificate, in->ca, in->peer, have ? fp :
	    NULL, &r);
	change_end();
	return (r.ok ? 0 : said(req, r.error));
}

int
arcana_agent_agent_transport_retry_action(cbl_req *req,
    const struct cbl_bytes *target,
    const struct arcana_agent_agent_transport_retry_input *in,
    struct arcana_agent_agent_transport_retry_output *out, cbl_yarena *a)
{
	struct arc_transport_rsp	 r;
	struct work			*w;

	(void)target;
	(void)in;
	(void)out;
	if ((w = ywork(a)) == NULL)
		return (ENOMEM);
	memset(&r, 0, sizeof(r));
	(void)do_transport(w, true, NULL, NULL, false, NULL, &r);
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
		(void)do_agent_update(w, in->binary.p, in->binary.len,
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

	(void)req;
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
	struct arc_network_rsp	 r;
	struct work		*w;
	int			 error;

	if ((w = ywork(a)) == NULL)
		return (ENOMEM);
	if ((error = yjail_scope(req, target, w, a)) != 0)
		return (error);
	memset(&r, 0, sizeof(r));
	(void)do_bird_routes(w, in->filter != NULL ? in->filter : "all", &r);
	if (!r.ok)
		return (said(req, r.error));
	return (ybird_routes_from_json(r.json, a, out));
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
	struct arc_events_rsp		 r;
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
	struct arc_events_rsp		 r;
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
	struct arc_fw_trace_rsp	 r;
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
	struct arc_history_rsp		 r;
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
	if (o.state != NULL) {
		out->sample.n = o.state->sample.n;
		out->sample.v = o.state->sample.v;
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
	struct arc_log_rsp		 r;
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
	struct arc_log_rsp	 r;
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
	w->jail = in->jail;
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

	(void)req;
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
	struct arcana_probe_probes_read_output_target	*v;
	struct arcana_probe_probes_state		 st;
	struct arc_sdwan_rsp				 r;
	struct work					*w;
	time_t						 after = 0;
	int						 error;

	(void)target;
	if (in->after != NULL && !ytime_parse(in->after, &after))
		return (said(req, "after is no date-and-time"));
	if ((w = ywork(a)) == NULL)
		return (ENOMEM);
	memset(&r, 0, sizeof(r));
	(void)do_sdwan(w, (uint64_t)after, &r);
	if (!r.ok)
		return (failed("sdwan", r.error));
	memset(&st, 0, sizeof(st));
	if ((error = yprobe_state_from_json(r.json, a, &st)) != 0)
		return (error);
	if (st.target.n == 0)
		return (0);
	if ((v = cbl_yarena_alloc(a, st.target.n * sizeof(*v))) == NULL)
		return (ENOMEM);
	for (size_t i = 0; i < st.target.n; i++) {
		v[i].id = st.target.v[i].id;
		v[i].sample.n = st.target.v[i].sample.n;
		v[i].sample.v = st.target.v[i].sample.v;
		v[i].jail = st.target.v[i].jail;
	}
	out->target.n = st.target.n;
	out->target.v = v;
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
	struct arc_processes_rsp		 r;
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
arcana_processes_processes_process_signal_action(cbl_req *req,
    const struct cbl_bytes *target,
    const struct arcana_processes_processes_process_signal_input *in,
    struct arcana_processes_processes_process_signal_output *out, cbl_yarena *a)
{
	(void)out;
	return (process_action(req, target, "signal", in->signal,
	    in->has_start_time, in->start_time, a));
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

	(void)req;
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
	struct arc_capture_req	 q;
	struct arc_capture_rsp	 r;
	const char		*e;
	struct work		*w;

	(void)target;
	if (in->jail != NULL && in->jail[0] != '\0' && !valid_jail(in->jail))
		return (said(req, "invalid jail name"));
	if ((w = ywork(a)) == NULL)
		return (ENOMEM);
	memset(&q, 0, sizeof(q));
	q.interface = in->interface;
	q.net_filter = in->filter;
	q.has_seconds = in->has_seconds;
	q.seconds = in->seconds;
	q.has_packets = in->has_packets;
	q.packets = in->packets;
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
	static const char *const protos[] = { "tcp", "udp", "icmp", "ip" };
	struct arc_path_check_rsp	 r;
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
	struct arc_traceroute_rsp	 r;
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
	if ((error = ywg_from_json(r.json, a, o)) != 0)
		return (error);
	data->wireguard = o;
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

	(void)req;
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
