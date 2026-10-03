/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Requests to arcana-agent.  Each one runs in a Kore task thread, which
 * makes a synchronous cblink call (mutual TLS over TCP, or the local
 * socket) so the event loop never waits on a jail(8) that takes minutes.
 * The reply's typed structures become JSON here, and the console's own
 * steps are put on top of the daemon's trace.
 */

#include <sys/types.h>
#include <sys/stat.h>

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <vis.h>

#include <openssl/evp.h>

#include "console.h"

enum op {
	OP_HELLO,
	OP_LIST,
	OP_ACTION,
	OP_ADDRESS,
	OP_SERVICES,
	OP_SERVICE_ACTION,
	OP_SERVICE_CONFIG,
	OP_NETWORK,
	OP_STATS,
	OP_PACKAGES,
	OP_PKG_UPGRADE,
	OP_JOB_SUBMIT,
	OP_JOBS,
	OP_JOB,
	OP_JOB_CANCEL,
	OP_AGENT_UPDATE,
};

struct call {
	struct kore_task	 task;		/* first: Kore frees the call */
	enum op			 op;
	char			 sid[9];
	char			*sname;
	char			*uri;
	char			*peer;
	char			 route[128];
	uint64_t		 t0;		/* µs, request arrived */
	uint64_t		 auth_us;	/* the session check */
	bool			 config_only;
	char			 jail[256];
	uint8_t			 action;
	struct arc_address_req	 addr;
	char			 address[65];
	char			 ifname[16];
	uint8_t			 family;	/* network */
	bool			 refresh;	/* packages */
	bool			 dry_run;	/* pkg-upgrade */
	char			**names;	/* pkg-upgrade: packages */
	size_t			 nnames;
	struct arc_job_spec	*specs;		/* job-submit: the batch */
	size_t			 nspecs;
	uint64_t		 jobid;		/* job, job-cancel */
	bool			 restart;	/* agent-update */
	struct arc_variable	*vars;		/* service-config: to set */
	size_t			 nvars;
	char			*json;		/* the reply, from the thread */
	int			 status;
};

static cbl_ctx	*ctx;

static const char *state_names[] = {
	[ARC_JAIL_STATE_RUNNING] = "running",
	[ARC_JAIL_STATE_STOPPED] = "stopped",
	[ARC_JAIL_STATE_DYING] = "dying",
	[ARC_JAIL_STATE_ABSENT] = "absent",
};

static const char *kind_names[] = {
	[ARC_STEP_KIND_DAEMON] = "daemon",
	[ARC_STEP_KIND_LIB] = "lib",
	[ARC_STEP_KIND_SYSCALL] = "syscall",
	[ARC_STEP_KIND_FILE] = "file",
	[ARC_STEP_KIND_EXEC] = "exec",
};

static const char *status_names[] = {
	[ARC_STEP_STATUS_OK] = "ok",
	[ARC_STEP_STATUS_FAILED] = "failed",
	[ARC_STEP_STATUS_INCOMPLETE] = "incomplete",
};

static const char *action_names[] = {
	[ARC_ACTION_START] = "start",
	[ARC_ACTION_STOP] = "stop",
	[ARC_ACTION_RESTART] = "restart",
	[ARC_ACTION_KILL] = "kill",
};

static const char *net_kind_names[] = {
	[ARC_NET_KIND_ROUTES] = "routes",
	[ARC_NET_KIND_NEXTHOPS] = "nexthops",
	[ARC_NET_KIND_CONNECTIONS] = "connections",
	[ARC_NET_KIND_SOCKETS] = "sockets",
};

static const char *service_action_names[] = {
	[ARC_SERVICE_ACTION_START] = "start",
	[ARC_SERVICE_ACTION_STOP] = "stop",
	[ARC_SERVICE_ACTION_RESTART] = "restart",
	[ARC_SERVICE_ACTION_RELOAD] = "reload",
	[ARC_SERVICE_ACTION_ENABLE] = "enable",
	[ARC_SERVICE_ACTION_DISABLE] = "disable",
};

static uint64_t	 now_us(void);
static void	 put(ucl_object_t *, const char *, ucl_object_t *);
static void	 put_str(ucl_object_t *, const char *, const char *);
static ucl_object_t *strs(const char *const *, size_t);
static ucl_object_t *output(const struct cbl_bytes *);
static ucl_object_t *host_object(const struct arc_host *);
static ucl_object_t *jail_object(const struct arc_jail *);
static ucl_object_t *service_object(const struct arc_service *);
static void	 call_free_vars(struct call *);
static ucl_object_t *job_object(struct call *, const struct arc_job *, bool,
		    uint64_t);
static const char *spec_from_json(const ucl_object_t *, struct arc_job_spec *);
static void	 spec_free(struct arc_job_spec *);
static char	*jdup(const ucl_object_t *, const char *);
static ucl_object_t *step_object(int, int, const char *, const char *,
		    const char *, bool, uint64_t);
static ucl_object_t *trace_object(struct call *, const struct arc_step *,
		    size_t, const char *, bool, uint64_t);
static int	 call_run(struct kore_task *);
static int	 call_start(struct http_request *, struct call *);
static int	 call_finish(struct http_request *);
static struct call *call_new(struct http_request *, enum op);

static uint64_t
now_us(void)
{
	struct timespec	ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ((uint64_t)ts.tv_sec * 1000000 + (uint64_t)ts.tv_nsec / 1000);
}

static void
put(ucl_object_t *o, const char *key, ucl_object_t *v)
{

	ucl_object_insert_key(o, v, key, 0, true);
}

static void
put_str(ucl_object_t *o, const char *key, const char *v)
{

	put(o, key, v != NULL ? ucl_object_fromstring(v) :
	    ucl_object_typed_new(UCL_NULL));
}

static ucl_object_t *
strs(const char *const *v, size_t n)
{
	ucl_object_t	*a;
	size_t		 i;

	a = ucl_object_typed_new(UCL_ARRAY);
	for (i = 0; i < n; i++)
		ucl_array_append(a, ucl_object_fromstring(v[i]));
	return (a);
}

/*
 * What a program printed, as text: control characters other than
 * newlines and tabs, and bytes that are not UTF-8, as vis(3) escapes
 * ("\037"), the way arcanactl(8) shows them.
 */
static ucl_object_t *
output(const struct cbl_bytes *b)
{
	ucl_object_t	*o;
	char		*v;

	/* ucl_object_fromlstring() takes length 0 to mean strlen(). */
	if (b->len == 0)
		return (ucl_object_fromstring(""));
	if ((v = malloc(b->len * 4 + 1)) == NULL)
		return (ucl_object_fromstring(""));
	strvisx(v, b->p, b->len, VIS_SAFE | VIS_OCTAL | VIS_CSTYLE);
	o = ucl_object_fromstring(v);
	free(v);
	return (o);
}

int
hosts_init(void)
{
	int	error;

	if ((error = cbl_ctx_new(&ctx)) != 0) {
		kore_log(LOG_ERR, "cbl_ctx_new: %s", strerror(error));
		return (-1);
	}
	(void)cbl_ctx_set_limit(ctx, CBL_LIM_MAX_FRAME, CBLINK_MAX_FRAME);
	(void)cbl_ctx_set_limit(ctx, CBL_LIM_MAX_ATTRS, CBLINK_MAX_ATTRS);
	(void)cbl_ctx_set_limit(ctx, CBL_LIM_REQUEST_MS, CBLINK_TIMEOUT_MS);
	return (0);
}

static ucl_object_t *
host_object(const struct arc_host *h)
{
	ucl_object_t	*o;

	o = ucl_object_typed_new(UCL_OBJECT);
	if (h == NULL)
		return (o);
	put_str(o, "hostname", h->hostname);
	put_str(o, "sysname", h->sysname);
	put_str(o, "release", h->release);
	put_str(o, "machine", h->machine);
	put(o, "ncpu", ucl_object_fromint(h->ncpu));
	put(o, "physmem", ucl_object_fromint((int64_t)h->physmem));
	put(o, "boottime", ucl_object_fromint(h->boottime));
	put(o, "time", ucl_object_fromint(h->time));
	put(o, "securelevel", ucl_object_fromint(h->securelevel));
	put(o, "privileged", ucl_object_frombool(h->privileged));
	put_str(o, "version", h->version);
	put_str(o, "build", h->build);
	return (o);
}

static ucl_object_t *
jail_object(const struct arc_jail *j)
{
	ucl_object_t	*o, *ps, *p;
	size_t		 i;

	o = ucl_object_typed_new(UCL_OBJECT);
	put_str(o, "name", j->name);
	put_str(o, "state", j->has_state && j->state < nitems(state_names) ?
	    state_names[j->state] : "unknown");
	put(o, "jid", j->has_jid ? ucl_object_fromint(j->jid) :
	    ucl_object_typed_new(UCL_NULL));
	put(o, "configured", ucl_object_frombool(j->configured));
	put_str(o, "scope", j->scope);
	put_str(o, "hostname", j->hostname);
	put_str(o, "path", j->path);
	put(o, "ip4", strs(j->ip4.v, j->ip4.n));
	put(o, "ip6", strs(j->ip6.v, j->ip6.n));
	put(o, "vnet", ucl_object_frombool(j->vnet));
	put_str(o, "osrelease", j->osrelease);
	put(o, "persist", ucl_object_frombool(j->persist));
	put_str(o, "interface", j->interface);
	if (j->has_nproc) {
		put(o, "nproc", ucl_object_fromint(j->nproc));
		put(o, "rss_kb", ucl_object_fromint((int64_t)j->rss_kb));
		put(o, "cpu_pct", ucl_object_fromdouble(j->cpu_pct));
		put(o, "securelevel", ucl_object_fromint(j->securelevel));
		put(o, "children", ucl_object_fromint(j->children));
	}
	ps = ucl_object_typed_new(UCL_ARRAY);
	for (i = 0; i < j->params.n; i++) {
		p = ucl_object_typed_new(UCL_OBJECT);
		put_str(p, "key", j->params.v[i].key);
		put(p, "values", strs(j->params.v[i].values.v,
		    j->params.v[i].values.n));
		ucl_array_append(ps, p);
	}
	put(o, "params", ps);
	return (o);
}

static ucl_object_t *
service_object(const struct arc_service *s)
{
	ucl_object_t	*o;

	o = ucl_object_typed_new(UCL_OBJECT);
	put_str(o, "name", s->name);
	put_str(o, "path", s->path);
	put_str(o, "rcvar", s->rcvar);
	put(o, "enabled", s->has_enabled ? ucl_object_frombool(s->enabled) :
	    ucl_object_typed_new(UCL_NULL));
	put(o, "running", s->has_running ? ucl_object_frombool(s->running) :
	    ucl_object_typed_new(UCL_NULL));
	put(o, "pid", s->has_pid ? ucl_object_fromint(s->pid) :
	    ucl_object_typed_new(UCL_NULL));
	put_str(o, "status", s->status);
	return (o);
}

static void
call_free_vars(struct call *c)
{
	size_t	i;

	for (i = 0; i < c->nvars; i++) {
		kore_free((char *)(uintptr_t)c->vars[i].key);
		kore_free((char *)(uintptr_t)c->vars[i].value);
	}
	kore_free(c->vars);
	c->vars = NULL;
	c->nvars = 0;
}

static ucl_object_t *
step_object(int id, int parent, const char *kind, const char *label,
    const char *detail, bool ok, uint64_t us)
{
	ucl_object_t	*o;

	o = ucl_object_typed_new(UCL_OBJECT);
	put(o, "id", ucl_object_fromint(id));
	put(o, "parent", ucl_object_fromint(parent));
	put_str(o, "kind", kind);
	put_str(o, "label", label);
	put_str(o, "detail", detail);
	put_str(o, "status", ok ? "ok" : "failed");
	put(o, "duration_us", ucl_object_fromint((int64_t)us));
	return (o);
}

/*
 * The console's steps (the API call, the session check, the cblink
 * request) with the daemon's trace under the request.
 */
static ucl_object_t *
trace_object(struct call *c, const struct arc_step *v, size_t n,
    const char *calldetail, bool callok, uint64_t callus)
{
	ucl_object_t	*a, *o;
	const char	*fn;
	char		 label[64];
	size_t		 i;
	bool		 ok;

	fn = c->op == OP_HELLO ? "arc_hello" : c->op == OP_LIST ? "arc_list" :
	    c->op == OP_ACTION ? "arc_action" : c->op == OP_ADDRESS ?
	    "arc_address" : c->op == OP_SERVICES ? "arc_services" :
	    c->op == OP_SERVICE_ACTION ? "arc_service_action" :
	    c->op == OP_NETWORK ? "arc_network" : c->op == OP_STATS ?
	    "arc_stats" : c->op == OP_PACKAGES ? "arc_packages" :
	    c->op == OP_PKG_UPGRADE ? "arc_pkg_upgrade" :
	    c->op == OP_JOB_SUBMIT ? "arc_job_submit" : c->op == OP_JOBS ?
	    "arc_jobs" : c->op == OP_JOB ? "arc_job" : c->op == OP_JOB_CANCEL ?
	    "arc_job_cancel" : c->op == OP_AGENT_UPDATE ? "arc_agent_update" :
	    "arc_service_config";
	snprintf(label, sizeof(label), "libcblink %s()", fn);
	ok = callok;
	for (i = 0; i < n; i++)
		if (v[i].parent < 0 && v[i].status != ARC_STEP_STATUS_OK)
			ok = false;
	a = ucl_object_typed_new(UCL_ARRAY);
	ucl_array_append(a, step_object(0, -1, "api", c->route, c->sname, ok,
	    now_us() - c->t0));
	ucl_array_append(a, step_object(1, 0, "auth", "session check",
	    "WebAuthn session cookie", true, c->auth_us));
	ucl_array_append(a, step_object(2, 0, "lib", label, calldetail,
	    callok, callus));
	for (i = 0; i < n; i++) {
		o = step_object((int)i + 3, v[i].parent < 0 ? 2 :
		    v[i].parent + 3, v[i].kind < nitems(kind_names) ?
		    kind_names[v[i].kind] : "lib", v[i].label, v[i].detail,
		    true, v[i].duration_us);
		put_str(o, "status", v[i].status < nitems(status_names) ?
		    status_names[v[i].status] : "incomplete");
		if (v[i].argv.n > 0) {
			put(o, "argv", strs(v[i].argv.v, v[i].argv.n));
			put(o, "exit", ucl_object_fromint(v[i].exit));
			put(o, "output", output(&v[i].output));
			put(o, "error_output", output(&v[i].error_output));
		}
		ucl_array_append(a, o);
	}
	return (a);
}

/* In a task thread: one cblink request, its reply as JSON. */
/*
 * The arcana-agent this console hands to hosts: the one installed with
 * it.  Returns what is wrong, or NULL with the program, to be freed,
 * and its SHA-256 in hex.
 */
static const char *
agent_binary(uint8_t **binp, size_t *lenp, char sha[65])
{
	struct stat	 sb;
	unsigned char	 md[EVP_MAX_MD_SIZE];
	uint8_t		*bin;
	ssize_t		 n;
	size_t		 off;
	unsigned int	 i, mdlen;
	int		 fd;

	if ((fd = open(cfg.agent_binary, O_RDONLY | O_CLOEXEC)) == -1)
		return (errno == ENOENT ? "the console has no arcana-agent to "
		    "send: agent_binary in web.conf names none" :
		    "the console cannot read its arcana-agent");
	if (fstat(fd, &sb) == -1 || !S_ISREG(sb.st_mode) || sb.st_size == 0 ||
	    sb.st_size > ARC_MAX_BINARY || (bin = malloc((size_t)sb.st_size)) ==
	    NULL) {
		close(fd);
		return ("the console's arcana-agent is not a program an "
		    "update can carry");
	}
	for (off = 0; off < (size_t)sb.st_size; off += (size_t)n)
		if ((n = read(fd, bin + off, (size_t)sb.st_size - off)) <= 0)
			break;
	close(fd);
	if (off < (size_t)sb.st_size || EVP_Digest(bin, off, md, &mdlen,
	    EVP_sha256(), NULL) != 1) {
		free(bin);
		return ("the console cannot read its arcana-agent");
	}
	for (i = 0; i < mdlen; i++)
		snprintf(sha + 2 * i, 3, "%02x", md[i]);
	*binp = bin;
	*lenp = off;
	return (NULL);
}

/*
 * The SHA-256 of the arcana-agent the console would send, for the page
 * to tell which hosts run another build; NULL when there is none.  Kept
 * until the file changes.
 */
const char *
agent_build(void)
{
	static char		 sha[65];
	static struct timespec	 mtime;
	static off_t		 size;
	struct stat		 sb;
	uint8_t			*bin;
	size_t			 len;

	if (stat(cfg.agent_binary, &sb) == -1)
		return (NULL);
	if (sha[0] != '\0' && sb.st_size == size && sb.st_mtim.tv_sec ==
	    mtime.tv_sec && sb.st_mtim.tv_nsec == mtime.tv_nsec)
		return (sha);
	if (agent_binary(&bin, &len, sha) != NULL) {
		sha[0] = '\0';
		return (NULL);
	}
	free(bin);
	size = sb.st_size;
	mtime = sb.st_mtim;
	return (sha);
}

static int
call_run(struct kore_task *t)
{
	struct call		*c;
	struct arc_client	 cl;
	struct arc_hello_rsp	*hr;
	struct arc_list_req	 lq;
	struct arc_list_rsp	*lr;
	struct arc_action_req	 aq;
	struct arc_action_rsp	*ar;
	struct arc_address_rsp	*dr;
	struct arc_services_rsp	*sr;
	struct arc_service_action_req saq;
	struct arc_service_action_rsp *sar;
	struct arc_service_config_req scq;
	struct arc_service_config_rsp *scr;
	struct arc_network_req	 nq;
	struct arc_network_rsp	*nr;
	struct arc_stats_rsp	*str;
	struct arc_packages_req	 pq;
	struct arc_packages_rsp	*pr;
	struct arc_pkg_upgrade_req uq;
	struct arc_pkg_upgrade_rsp *ur;
	struct arc_job_submit_req jsq;
	struct arc_job_submit_rsp *jsr;
	struct arc_jobs_rsp	*jlr;
	struct arc_job_req	 jq;
	struct arc_job_rsp	*jr;
	struct arc_job_cancel_req jcq;
	struct arc_job_cancel_rsp *jcr;
	struct arc_agent_update_req auq;
	struct arc_agent_update_rsp *aur;
	uint8_t			*bin;
	size_t			 binlen;
	char			 sha[65];
	const struct arc_step	*steps;
	ucl_object_t		*top, *srv, *a, *e;
	cbl_conn		*conn;
	cbl_tls			*tls;
	const char		*msg;
	char			 detail[512];
	uint64_t		 t1, us;
	size_t			 nsteps, i;
	bool			 local, ok;
	int			 error;

	c = (struct call *)t;
	top = ucl_object_typed_new(UCL_OBJECT);
	srv = ucl_object_typed_new(UCL_OBJECT);
	put_str(srv, "id", c->sid);
	put_str(srv, "name", c->sname);
	put(top, "server", srv);
	put(top, "fetched_at", ucl_object_fromint(time(NULL)));

	conn = NULL;
	tls = NULL;
	steps = NULL;
	nsteps = 0;
	hr = NULL;
	lr = NULL;
	ar = NULL;
	dr = NULL;
	sr = NULL;
	sar = NULL;
	scr = NULL;
	nr = NULL;
	str = NULL;
	pr = NULL;
	ur = NULL;
	jsr = NULL;
	jlr = NULL;
	jr = NULL;
	jcr = NULL;
	aur = NULL;
	bin = NULL;
	msg = NULL;
	local = strncmp(c->uri, "unix:", 5) == 0;
	snprintf(detail, sizeof(detail), "%s, %s", c->uri, local ?
	    "local socket" : "mutual TLS 1.3");
	t1 = now_us();
	memset(&cl, 0, sizeof(cl));

	if ((error = cbl_conn_new(ctx, c->uri, 0, &conn)) != 0) {
		msg = strerror(error);
		goto fail;
	}
	if (!local) {
		if (cfg.tls_ca == NULL || cfg.tls_cert == NULL ||
		    cfg.tls_key == NULL) {
			msg = "no tls { ca cert key } in web.conf";
			goto fail;
		}
		if (cbl_tls_new(&tls) != 0 ||
		    cbl_tls_set_cert(tls, cfg.tls_cert, cfg.tls_key) != 0 ||
		    cbl_tls_set_ca(tls, cfg.tls_ca, NULL) != 0 ||
		    (c->peer != NULL &&
		    cbl_tls_set_peer_name(tls, c->peer) != 0)) {
			msg = tls != NULL ? cbl_tls_errstr(tls) :
			    "cbl_tls_new failed";
			goto fail;
		}
		(void)cbl_conn_set_tls(conn, tls);
	}
	if ((error = cbl_conn_connect(conn)) != 0) {
		msg = cbl_conn_errstr(conn);
		goto fail;
	}
	if ((error = arc_client_init(&cl, conn)) != 0) {
		msg = "no arcana family there";
		goto fail;
	}

	switch (c->op) {
	case OP_HELLO:
		if ((error = arc_hello(&cl, &hr)) != 0)
			goto rpcfail;
		put(top, "host", host_object(hr->host));
		ok = true;
		break;
	case OP_LIST:
		memset(&lq, 0, sizeof(lq));
		lq.config_only = c->config_only;
		if ((error = arc_list(&cl, &lq, &lr)) != 0)
			goto rpcfail;
		ok = lr->ok;
		put_str(top, "error", lr->error);
		put(top, "host", host_object(lr->host));
		a = ucl_object_typed_new(UCL_ARRAY);
		for (i = 0; i < lr->jails.n; i++)
			ucl_array_append(a, jail_object(&lr->jails.v[i]));
		put(top, "jails", a);
		put(top, "scopes", strs(lr->scopes.v, lr->scopes.n));
		a = ucl_object_typed_new(UCL_ARRAY);
		for (i = 0; i < lr->conf_errors.n; i++) {
			e = ucl_object_typed_new(UCL_OBJECT);
			put_str(e, "scope", lr->conf_errors.v[i].scope);
			put_str(e, "message", lr->conf_errors.v[i].message);
			ucl_array_append(a, e);
		}
		put(top, "conf_errors", a);
		steps = lr->trace.v;
		nsteps = lr->trace.n;
		break;
	case OP_ACTION:
		memset(&aq, 0, sizeof(aq));
		aq.jail = c->jail;
		aq.has_action = true;
		aq.action = c->action;
		if ((error = arc_action(&cl, &aq, &ar)) != 0)
			goto rpcfail;
		ok = ar->ok;
		put_str(top, "error", ar->error);
		if (ar->result != NULL)
			put(top, "jail", jail_object(ar->result));
		steps = ar->trace.v;
		nsteps = ar->trace.n;
		break;
	case OP_ADDRESS:
		if ((error = arc_address(&cl, &c->addr, &dr)) != 0)
			goto rpcfail;
		ok = dr->ok;
		put_str(top, "error", dr->error);
		put_str(top, "diff", dr->diff);
		if (dr->result != NULL)
			put(top, "jail", jail_object(dr->result));
		steps = dr->trace.v;
		nsteps = dr->trace.n;
		break;
	case OP_SERVICES:
		if ((error = arc_services(&cl, &sr)) != 0)
			goto rpcfail;
		ok = sr->ok;
		put_str(top, "error", sr->error);
		a = ucl_object_typed_new(UCL_ARRAY);
		for (i = 0; i < sr->services.n; i++)
			ucl_array_append(a, service_object(&sr->services.v[i]));
		put(top, "services", a);
		steps = sr->trace.v;
		nsteps = sr->trace.n;
		break;
	case OP_SERVICE_ACTION:
		memset(&saq, 0, sizeof(saq));
		saq.service = c->jail;
		saq.has_service_action = true;
		saq.service_action = c->action;
		if ((error = arc_service_action(&cl, &saq, &sar)) != 0)
			goto rpcfail;
		ok = sar->ok;
		put_str(top, "error", sar->error);
		if (sar->service_result != NULL)
			put(top, "service", service_object(sar->service_result));
		steps = sar->trace.v;
		nsteps = sar->trace.n;
		break;
	case OP_PACKAGES:
		memset(&pq, 0, sizeof(pq));
		pq.jail = c->jail[0] != '\0' ? c->jail : NULL;
		pq.refresh = c->refresh;
		if ((error = arc_packages(&cl, &pq, &pr)) != 0)
			goto rpcfail;
		ok = pr->ok;
		put_str(top, "error", pr->error);
		a = ucl_object_typed_new(UCL_ARRAY);
		for (i = 0; i < pr->packages.n; i++) {
			e = ucl_object_typed_new(UCL_OBJECT);
			put_str(e, "name", pr->packages.v[i].name);
			put_str(e, "installed", pr->packages.v[i].installed);
			put_str(e, "available", pr->packages.v[i].available);
			ucl_array_append(a, e);
		}
		put(top, "packages", a);
		steps = pr->trace.v;
		nsteps = pr->trace.n;
		break;
	case OP_PKG_UPGRADE:
		memset(&uq, 0, sizeof(uq));
		uq.jail = c->jail[0] != '\0' ? c->jail : NULL;
		uq.dry_run = c->dry_run;
		uq.names.v = (const char *const *)c->names;
		uq.names.n = c->nnames;
		if ((error = arc_pkg_upgrade(&cl, &uq, &ur)) != 0)
			goto rpcfail;
		ok = ur->ok;
		put_str(top, "error", ur->error);
		put(top, "upgraded", ur->has_upgraded ?
		    ucl_object_fromint(ur->upgraded) :
		    ucl_object_typed_new(UCL_NULL));
		a = ucl_object_typed_new(UCL_ARRAY);
		for (i = 0; i < ur->packages.n; i++) {
			e = ucl_object_typed_new(UCL_OBJECT);
			put_str(e, "name", ur->packages.v[i].name);
			put_str(e, "installed", ur->packages.v[i].installed);
			put_str(e, "available", ur->packages.v[i].available);
			ucl_array_append(a, e);
		}
		put(top, "packages", a);
		steps = ur->trace.v;
		nsteps = ur->trace.n;
		break;
	case OP_JOB_SUBMIT:
		memset(&jsq, 0, sizeof(jsq));
		jsq.batch.v = c->specs;
		jsq.batch.n = c->nspecs;
		if ((error = arc_job_submit(&cl, &jsq, &jsr)) != 0)
			goto rpcfail;
		ok = jsr->ok;
		put_str(top, "error", jsr->error);
		a = ucl_object_typed_new(UCL_ARRAY);
		for (i = 0; i < jsr->jobs.n; i++)
			ucl_array_append(a, job_object(c, &jsr->jobs.v[i], false,
			    0));
		put(top, "jobs", a);
		break;
	case OP_JOBS:
		if ((error = arc_jobs(&cl, &jlr)) != 0)
			goto rpcfail;
		ok = jlr->ok;
		a = ucl_object_typed_new(UCL_ARRAY);
		for (i = 0; i < jlr->jobs.n; i++)
			ucl_array_append(a, job_object(c, &jlr->jobs.v[i], false,
			    0));
		put(top, "jobs", a);
		break;
	case OP_JOB:
		memset(&jq, 0, sizeof(jq));
		jq.has_id = true;
		jq.id = c->jobid;
		if ((error = arc_job(&cl, &jq, &jr)) != 0)
			goto rpcfail;
		ok = jr->ok;
		put_str(top, "error", jr->error);
		if (jr->job != NULL) {
			put(top, "job", job_object(c, jr->job, true,
			    now_us() - t1));
			/* The job's own trace is the reply's. */
			put(top, "ok", ucl_object_frombool(ok));
			c->status = 200;
			goto done;
		}
		break;
	case OP_JOB_CANCEL:
		memset(&jcq, 0, sizeof(jcq));
		jcq.has_id = true;
		jcq.id = c->jobid;
		if ((error = arc_job_cancel(&cl, &jcq, &jcr)) != 0)
			goto rpcfail;
		ok = jcr->ok;
		put_str(top, "error", jcr->error);
		if (jcr->job != NULL)
			put(top, "job", job_object(c, jcr->job, false, 0));
		break;
	case OP_STATS:
		if ((error = arc_stats(&cl, &str)) != 0)
			goto rpcfail;
		ok = str->ok;
		put_str(top, "error", str->error);
		e = ucl_object_typed_new(UCL_OBJECT);
		if (str->stats != NULL) {
			const struct arc_stats *st = str->stats;
			ucl_object_t *pl, *po;

			put(e, "cpu_pct", ucl_object_fromdouble(st->cpu_pct));
			put(e, "load1", ucl_object_fromdouble(st->load1));
			put(e, "load5", ucl_object_fromdouble(st->load5));
			put(e, "load15", ucl_object_fromdouble(st->load15));
			put(e, "mem_total", ucl_object_fromint((int64_t)
			    st->mem_total));
			put(e, "mem_used", ucl_object_fromint((int64_t)
			    st->mem_used));
			put(e, "mem_inactive", ucl_object_fromint((int64_t)
			    st->mem_inactive));
			put(e, "mem_free", ucl_object_fromint((int64_t)
			    st->mem_free));
			put(e, "swap_total", ucl_object_fromint((int64_t)
			    st->swap_total));
			put(e, "swap_used", ucl_object_fromint((int64_t)
			    st->swap_used));
			pl = ucl_object_typed_new(UCL_ARRAY);
			for (i = 0; i < st->pools.n; i++) {
				po = ucl_object_typed_new(UCL_OBJECT);
				put_str(po, "name", st->pools.v[i].name);
				put(po, "size", ucl_object_fromint((int64_t)
				    st->pools.v[i].size));
				put(po, "alloc", ucl_object_fromint((int64_t)
				    st->pools.v[i].alloc));
				put(po, "free", ucl_object_fromint((int64_t)
				    st->pools.v[i].free));
				put_str(po, "health", st->pools.v[i].health);
				ucl_array_append(pl, po);
			}
			put(e, "pools", pl);
		}
		put(top, "stats", e);
		steps = str->trace.v;
		nsteps = str->trace.n;
		break;
	case OP_NETWORK:
		memset(&nq, 0, sizeof(nq));
		nq.has_net_kind = true;
		nq.net_kind = c->action;
		nq.has_net_family = true;
		nq.net_family = c->family;
		if ((error = arc_network(&cl, &nq, &nr)) != 0)
			goto rpcfail;
		ok = nr->ok;
		put_str(top, "error", nr->error);
		/* The program's JSON becomes part of ours. */
		e = NULL;
		if (nr->json != NULL) {
			struct ucl_parser *p;

			p = ucl_parser_new(UCL_PARSER_NO_IMPLICIT_ARRAYS |
			    UCL_PARSER_DISABLE_MACRO | UCL_PARSER_NO_TIME);
			if (ucl_parser_add_string(p, nr->json, 0))
				e = ucl_parser_get_object(p);
			ucl_parser_free(p);
		}
		put(top, "data", e != NULL ? e : ucl_object_typed_new(UCL_NULL));
		steps = nr->trace.v;
		nsteps = nr->trace.n;
		break;
	case OP_AGENT_UPDATE:
		if ((msg = agent_binary(&bin, &binlen, sha)) != NULL) {
			ok = false;
			put_str(top, "error", msg);
			break;
		}
		memset(&auq, 0, sizeof(auq));
		auq.binary.p = bin;
		auq.binary.len = binlen;
		auq.sha256 = sha;
		auq.restart = c->restart;
		if ((error = arc_agent_update(&cl, &auq, &aur)) != 0)
			goto rpcfail;
		ok = aur->ok;
		put_str(top, "error", aur->error);
		put_str(top, "version", aur->agent_version);
		put(top, "restarting", ucl_object_frombool(aur->restarting));
		steps = aur->trace.v;
		nsteps = aur->trace.n;
		break;
	default:
		memset(&scq, 0, sizeof(scq));
		scq.service = c->jail;
		scq.variables.v = c->vars;
		scq.variables.n = c->nvars;
		if ((error = arc_service_config(&cl, &scq, &scr)) != 0)
			goto rpcfail;
		ok = scr->ok;
		put_str(top, "error", scr->error);
		if (scr->service_result != NULL)
			put(top, "service", service_object(scr->service_result));
		e = ucl_object_typed_new(UCL_OBJECT);
		for (i = 0; i < scr->variables.n; i++)
			put_str(e, scr->variables.v[i].key,
			    scr->variables.v[i].value);
		put(top, "variables", e);
		put_str(top, "description", scr->description);
		put(top, "commands", strs(scr->commands.v, scr->commands.n));
		steps = scr->trace.v;
		nsteps = scr->trace.n;
		break;
	}
	us = now_us() - t1;
	put(top, "ok", ucl_object_frombool(ok));
	put(top, "trace", trace_object(c, steps, nsteps, detail, true, us));
	c->status = 200;
	goto done;

rpcfail:
	msg = cl.err != NULL && cbl_msg_err_str(cl.err) != NULL ?
	    cbl_msg_err_str(cl.err) : strerror(error);
	c->status = 502;
	e = ucl_object_typed_new(UCL_OBJECT);
	put_str(e, "code", "rejected");
	put_str(e, "message", msg);
	put(top, "error", e);
	put(top, "trace", trace_object(c, NULL, 0, msg, false,
	    now_us() - t1));
	goto done;
fail:
	c->status = 502;
	e = ucl_object_typed_new(UCL_OBJECT);
	put_str(e, "code", "unreachable");
	put_str(e, "message", msg != NULL ? msg : "cannot connect");
	put(top, "error", e);
	put(top, "trace", trace_object(c, NULL, 0, msg, false,
	    now_us() - t1));
done:
	c->json = (char *)ucl_object_emit(top, UCL_EMIT_JSON_COMPACT);
	ucl_object_unref(top);
	if (hr != NULL)
		arc_hello_rsp_free(hr);
	if (lr != NULL)
		arc_list_rsp_free(lr);
	if (ar != NULL)
		arc_action_rsp_free(ar);
	if (dr != NULL)
		arc_address_rsp_free(dr);
	if (sr != NULL)
		arc_services_rsp_free(sr);
	if (sar != NULL)
		arc_service_action_rsp_free(sar);
	if (scr != NULL)
		arc_service_config_rsp_free(scr);
	if (nr != NULL)
		arc_network_rsp_free(nr);
	if (str != NULL)
		arc_stats_rsp_free(str);
	if (pr != NULL)
		arc_packages_rsp_free(pr);
	if (ur != NULL)
		arc_pkg_upgrade_rsp_free(ur);
	if (jsr != NULL)
		arc_job_submit_rsp_free(jsr);
	if (jlr != NULL)
		arc_jobs_rsp_free(jlr);
	if (jr != NULL)
		arc_job_rsp_free(jr);
	if (jcr != NULL)
		arc_job_cancel_rsp_free(jcr);
	if (aur != NULL)
		arc_agent_update_rsp_free(aur);
	free(bin);
	if (cl.conn != NULL)
		arc_client_fini(&cl);
	cbl_conn_free(conn);
	cbl_tls_free(tls);
	return (KORE_RESULT_OK);
}

/*
 * Common start of the host routes: session, server id from the path.
 * Returns NULL with the reply sent when the request goes no further.
 */
static struct call *
call_new(struct http_request *req, enum op op)
{
	const struct server	*s;
	struct call		*c;
	uint64_t		 t0, t1;
	char			 sid[16];

	t0 = now_us();
	if (!guard(req, op == OP_ACTION || op == OP_ADDRESS ||
	    op == OP_SERVICE_ACTION || op == OP_PKG_UPGRADE ||
	    op == OP_JOB_SUBMIT || op == OP_JOB_CANCEL ||
	    op == OP_AGENT_UPDATE ||
	    (op == OP_SERVICE_CONFIG && req->method == HTTP_METHOD_POST)))
		return (NULL);
	t1 = now_us();
	if (!capture(req, 3, sid, sizeof(sid)) || (s = server_find(sid)) ==
	    NULL) {
		reply_error(req, 404, "not_found", "no such server");
		return (NULL);
	}
	c = kore_calloc(1, sizeof(*c));
	c->op = op;
	c->t0 = t0;
	c->auth_us = t1 - t0;
	strlcpy(c->sid, s->id, sizeof(c->sid));
	c->sname = kore_strdup(s->name);
	c->uri = kore_strdup(s->uri);
	c->peer = s->peer_name != NULL ? kore_strdup(s->peer_name) : NULL;
	snprintf(c->route, sizeof(c->route), "%s %s",
	    req->method == HTTP_METHOD_GET ? "GET" :
	    req->method == HTTP_METHOD_DELETE ? "DELETE" : "POST", req->path);
	return (c);
}

static int
call_start(struct http_request *req, struct call *c)
{

	req->hdlr_extra = c;
	kore_task_create(&c->task, call_run);
	kore_task_bind_request(&c->task, req);
	kore_task_run(&c->task);
	return (KORE_RESULT_RETRY);
}

/* Called again by Kore until the task is done, then replies. */
static int
call_finish(struct http_request *req)
{
	struct call	*c;

	c = req->hdlr_extra;
	if (kore_task_state(&c->task) != KORE_TASK_STATE_FINISHED) {
		http_request_sleep(req);
		return (KORE_RESULT_RETRY);
	}
	http_response_header(req, "content-type",
	    "application/json; charset=utf-8");
	http_response_header(req, "cache-control", "no-store");
	http_response_header(req, "x-content-type-options", "nosniff");
	if (c->json != NULL)
		http_response(req, c->status, c->json, strlen(c->json));
	else
		http_response(req, HTTP_STATUS_INTERNAL_ERROR, NULL, 0);
	return (KORE_RESULT_OK);
}

/*
 * on_free of the host routes: what the call holds goes with the request,
 * whether it was answered or the browser went away first.  Kore asks
 * every time it tries to free the request, also while the task still
 * runs; it destroys the finished task and frees the call itself.
 */
void
api_call_free(struct http_request *req)
{
	struct call	*c;
	size_t		 i;

	if ((c = req->hdlr_extra) == NULL || !kore_task_finished(&c->task))
		return;
	free(c->json);
	c->json = NULL;
	kore_free(c->sname);
	kore_free(c->uri);
	kore_free(c->peer);
	c->sname = c->uri = c->peer = NULL;
	call_free_vars(c);
	for (i = 0; i < c->nnames; i++)
		kore_free(c->names[i]);
	kore_free(c->names);
	c->names = NULL;
	c->nnames = 0;
	for (i = 0; i < c->nspecs; i++)
		spec_free(&c->specs[i]);
	kore_free(c->specs);
	c->specs = NULL;
	c->nspecs = 0;
}

/* GET /api/servers/<id>/services */
int
api_services(struct http_request *req)
{
	struct call	*c;

	if (req->hdlr_extra != NULL)
		return (call_finish(req));
	if ((c = call_new(req, OP_SERVICES)) == NULL)
		return (KORE_RESULT_OK);
	return (call_start(req, c));
}

/* POST /api/servers/<id>/services/<name>/action {"action": "restart"} */
int
api_service_action(struct http_request *req)
{
	ucl_object_t	*body;
	struct call	*c;
	const char	*a;
	size_t		 i;

	if (req->hdlr_extra != NULL)
		return (call_finish(req));
	if ((c = call_new(req, OP_SERVICE_ACTION)) == NULL)
		return (KORE_RESULT_OK);
	body = read_json(req);
	a = body != NULL ? ucl_str(body, "action") : NULL;
	for (i = 0; a != NULL && i < nitems(service_action_names); i++)
		if (strcmp(a, service_action_names[i]) == 0)
			break;
	ucl_object_unref(body);
	if (a == NULL || i == nitems(service_action_names) ||
	    !capture(req, 5, c->jail, sizeof(c->jail))) {
		kore_free(c->sname);
		kore_free(c->uri);
		kore_free(c->peer);
		kore_free(c);
		return (reply_error(req, 400, "invalid", "action is one of "
		    "start, stop, restart, reload, enable, disable"));
	}
	c->action = (uint8_t)i;
	return (call_start(req, c));
}

/*
 * POST /api/servers/<id>/agent-update, {"restart": true}: send the host
 * the console's arcana-agent; with restart, have it restart its service.
 */
int
api_agent_update(struct http_request *req)
{
	ucl_object_t	*body;
	struct call	*c;

	if (req->hdlr_extra != NULL)
		return (call_finish(req));
	if ((c = call_new(req, OP_AGENT_UPDATE)) == NULL)
		return (KORE_RESULT_OK);
	if ((body = read_json(req)) != NULL) {
		c->restart = ucl_object_toboolean(ucl_object_lookup(body,
		    "restart"));
		ucl_object_unref(body);
	}
	return (call_start(req, c));
}

/*
 * GET /api/servers/<id>/services/<name>/config: the variables.
 * POST, {"set": {"sshd_flags": "-4"}, "unset": ["sshd_x"]}: change them
 * first.
 */
int
api_service_config(struct http_request *req)
{
	ucl_object_t		*body;
	const ucl_object_t	*set, *unset, *v;
	ucl_object_iter_t	 it;
	struct call		*c;
	size_t			 n;

	if (req->hdlr_extra != NULL)
		return (call_finish(req));
	if ((c = call_new(req, OP_SERVICE_CONFIG)) == NULL)
		return (KORE_RESULT_OK);
	if (!capture(req, 5, c->jail, sizeof(c->jail))) {
		kore_free(c->sname);
		kore_free(c->uri);
		kore_free(c->peer);
		kore_free(c);
		return (reply_error(req, 400, "invalid", "bad service name"));
	}
	if (req->method == HTTP_METHOD_POST && (body = read_json(req)) != NULL) {
		set = ucl_object_lookup(body, "set");
		unset = ucl_object_lookup(body, "unset");
		n = ucl_array_size(unset);
		it = NULL;
		while (set != NULL && ucl_object_type(set) == UCL_OBJECT &&
		    ucl_object_iterate(set, &it, true) != NULL)
			n++;
		if (n > 0 && n <= 64) {
			c->vars = kore_calloc(n, sizeof(*c->vars));
			it = NULL;
			while (set != NULL && ucl_object_type(set) == UCL_OBJECT &&
			    (v = ucl_object_iterate(set, &it, true)) != NULL) {
				c->vars[c->nvars].key =
				    kore_strdup(ucl_object_key(v));
				c->vars[c->nvars].value = kore_strdup(
				    ucl_object_tostring_forced(v));
				c->nvars++;
			}
			it = NULL;
			while ((v = ucl_object_iterate(unset, &it, true)) != NULL &&
			    c->nvars < n) {
				if (ucl_object_type(v) != UCL_STRING)
					continue;
				c->vars[c->nvars].key =
				    kore_strdup(ucl_object_tostring(v));
				c->vars[c->nvars].remove = true;
				c->nvars++;
			}
		}
		ucl_object_unref(body);
	}
	return (call_start(req, c));
}

/* GET /api/servers/<id>/hello */
int
api_hello(struct http_request *req)
{
	struct call	*c;

	if (req->hdlr_extra != NULL)
		return (call_finish(req));
	if ((c = call_new(req, OP_HELLO)) == NULL)
		return (KORE_RESULT_OK);
	return (call_start(req, c));
}

/* GET /api/servers/<id>/jails[?config_only=1] */
int
api_jails(struct http_request *req)
{
	struct call	*c;

	if (req->hdlr_extra != NULL)
		return (call_finish(req));
	if ((c = call_new(req, OP_LIST)) == NULL)
		return (KORE_RESULT_OK);
	c->config_only = req->query_string != NULL &&
	    strstr(req->query_string, "config_only=1") != NULL;
	return (call_start(req, c));
}

/* POST /api/servers/<id>/jails/<jail>/action {"action": "start"} */
int
api_action(struct http_request *req)
{
	ucl_object_t	*body;
	struct call	*c;
	const char	*a;
	size_t		 i;

	if (req->hdlr_extra != NULL)
		return (call_finish(req));
	if ((c = call_new(req, OP_ACTION)) == NULL)
		return (KORE_RESULT_OK);
	body = read_json(req);
	a = body != NULL ? ucl_str(body, "action") : NULL;
	for (i = 0; a != NULL && i < nitems(action_names); i++)
		if (strcmp(a, action_names[i]) == 0)
			break;
	ucl_object_unref(body);
	if (a == NULL || i == nitems(action_names) ||
	    !capture(req, 5, c->jail, sizeof(c->jail))) {
		kore_free(c->sname);
		kore_free(c->uri);
		kore_free(c->peer);
		kore_free(c);
		return (reply_error(req, 400, "invalid",
		    "action is one of start, stop, restart, kill"));
	}
	c->action = (uint8_t)i;
	return (call_start(req, c));
}

/*
 * POST /api/servers/<id>/jails/<jail>/address
 * {"address": "10.0.0.5/24", "interface": "em0", "remove": false,
 *  "live": true, "persist": false, "dry_run": false}
 */
int
api_address(struct http_request *req)
{
	ucl_object_t	*body;
	struct call	*c;
	const char	*addr, *ifname;

	if (req->hdlr_extra != NULL)
		return (call_finish(req));
	if ((c = call_new(req, OP_ADDRESS)) == NULL)
		return (KORE_RESULT_OK);
	body = read_json(req);
	addr = body != NULL ? ucl_str(body, "address") : NULL;
	ifname = body != NULL ? ucl_str(body, "interface") : NULL;
	if (addr == NULL || strlcpy(c->address, addr, sizeof(c->address)) >=
	    sizeof(c->address) || (ifname != NULL && *ifname != '\0' &&
	    strlcpy(c->ifname, ifname, sizeof(c->ifname)) >=
	    sizeof(c->ifname)) || !capture(req, 5, c->jail,
	    sizeof(c->jail))) {
		ucl_object_unref(body);
		kore_free(c->sname);
		kore_free(c->uri);
		kore_free(c->peer);
		kore_free(c);
		return (reply_error(req, 400, "invalid", "an address is "
		    "needed, an interface name is at most 15 characters"));
	}
	c->addr.jail = c->jail;
	c->addr.address = c->address;
	c->addr.interface = c->ifname[0] != '\0' ? c->ifname : NULL;
	c->addr.remove = ucl_flag(body, "remove");
	c->addr.live = ucl_flag(body, "live");
	c->addr.persist = ucl_flag(body, "persist");
	c->addr.dry_run = ucl_flag(body, "dry_run");
	ucl_object_unref(body);
	return (call_start(req, c));
}

/* GET /api/servers/<id>/net/<kind>[?family=inet|inet6] */
int
api_network(struct http_request *req)
{
	struct call	*c;
	char		 kind[16];
	size_t		 i;

	if (req->hdlr_extra != NULL)
		return (call_finish(req));
	if ((c = call_new(req, OP_NETWORK)) == NULL)
		return (KORE_RESULT_OK);
	for (i = 0; i < nitems(net_kind_names); i++)
		if (capture(req, 5, kind, sizeof(kind)) &&
		    strcmp(kind, net_kind_names[i]) == 0)
			break;
	if (i == nitems(net_kind_names)) {
		kore_free(c->sname);
		kore_free(c->uri);
		kore_free(c->peer);
		kore_free(c);
		return (reply_error(req, 400, "invalid", "kind is one of "
		    "routes, nexthops, connections, sockets"));
	}
	c->action = (uint8_t)i;
	c->family = ARC_NET_FAMILY_ALL;
	if (req->query_string != NULL) {
		if (strstr(req->query_string, "family=inet6") != NULL)
			c->family = ARC_NET_FAMILY_INET6;
		else if (strstr(req->query_string, "family=inet") != NULL)
			c->family = ARC_NET_FAMILY_INET;
	}
	return (call_start(req, c));
}

/* GET /api/servers/<id>/stats */
int
api_stats(struct http_request *req)
{
	struct call	*c;

	if (req->hdlr_extra != NULL)
		return (call_finish(req));
	if ((c = call_new(req, OP_STATS)) == NULL)
		return (KORE_RESULT_OK);
	return (call_start(req, c));
}

/* A query string parameter's value, raw (no %-decoding needed here). */
static bool
query_param(struct http_request *req, const char *name, char *buf, size_t len)
{
	const char	*q, *e;
	size_t		 nl;

	buf[0] = '\0';
	nl = strlen(name);
	for (q = req->query_string; q != NULL && *q != '\0'; q = e != NULL ?
	    e + 1 : NULL) {
		e = strchr(q, '&');
		if (strncmp(q, name, nl) == 0 && q[nl] == '=') {
			snprintf(buf, len, "%.*s", (int)(e != NULL ?
			    (size_t)(e - q) - nl - 1 : strlen(q + nl + 1)),
			    q + nl + 1);
			return (true);
		}
	}
	return (false);
}

/* The jail named by ?jail=<name> or by the body, into the call. */
static bool
pick_jail(struct call *c, const char *name)
{
	const char	*p;

	if (name == NULL || *name == '\0')
		return (true);
	for (p = name; *p != '\0'; p++)
		if (!isalnum((unsigned char)*p) && strchr("_.-", *p) == NULL)
			return (false);
	return (strlcpy(c->jail, name, sizeof(c->jail)) < sizeof(c->jail));
}

/* GET /api/servers/<id>/packages[?jail=<name>&refresh=1] */
int
api_packages(struct http_request *req)
{
	struct call	*c;
	char		 jail[256], v[8];

	if (req->hdlr_extra != NULL)
		return (call_finish(req));
	if ((c = call_new(req, OP_PACKAGES)) == NULL)
		return (KORE_RESULT_OK);
	query_param(req, "jail", jail, sizeof(jail));
	c->refresh = query_param(req, "refresh", v, sizeof(v)) &&
	    strcmp(v, "1") == 0;
	if (!pick_jail(c, jail)) {
		kore_free(c->sname);
		kore_free(c->uri);
		kore_free(c->peer);
		kore_free(c);
		return (reply_error(req, 400, "invalid", "bad jail name"));
	}
	return (call_start(req, c));
}

/*
 * POST /api/servers/<id>/packages/upgrade
 * {"jail": "web", "packages": ["pimd"], "dry_run": false}
 */
int
api_pkg_upgrade(struct http_request *req)
{
	ucl_object_t		*body;
	const ucl_object_t	*a, *v;
	ucl_object_iter_t	 it;
	struct call		*c;
	size_t			 n;

	if (req->hdlr_extra != NULL)
		return (call_finish(req));
	if ((c = call_new(req, OP_PKG_UPGRADE)) == NULL)
		return (KORE_RESULT_OK);
	body = read_json(req);
	if (body == NULL || !pick_jail(c, ucl_str(body, "jail"))) {
		ucl_object_unref(body);
		kore_free(c->sname);
		kore_free(c->uri);
		kore_free(c->peer);
		kore_free(c);
		return (reply_error(req, 400, "invalid", "a JSON object with "
		    "an optional jail and packages"));
	}
	c->dry_run = ucl_flag(body, "dry_run");
	a = ucl_object_lookup(body, "packages");
	if ((n = ucl_array_size(a)) > 0) {
		c->names = kore_calloc(n, sizeof(*c->names));
		it = NULL;
		while ((v = ucl_object_iterate(a, &it, true)) != NULL &&
		    c->nnames < n)
			if (ucl_object_type(v) == UCL_STRING)
				c->names[c->nnames++] =
				    kore_strdup(ucl_object_tostring(v));
	}
	ucl_object_unref(body);
	return (call_start(req, c));
}

static const char *job_kind_names[] = {
	[ARC_JOB_KIND_JAIL_ACTION] = "jail-action",
	[ARC_JOB_KIND_ADDRESS] = "address",
	[ARC_JOB_KIND_SERVICE_ACTION] = "service-action",
	[ARC_JOB_KIND_SERVICE_CONFIG] = "service-config",
	[ARC_JOB_KIND_PKG_UPGRADE] = "pkg-upgrade",
};

static const char *job_state_names[] = {
	[ARC_JOB_STATE_QUEUED] = "queued",
	[ARC_JOB_STATE_RUNNING] = "running",
	[ARC_JOB_STATE_DONE] = "done",
	[ARC_JOB_STATE_CANCELLED] = "cancelled",
};

/* A job; with its trace, under the console's own steps. */
static ucl_object_t *
job_object(struct call *c, const struct arc_job *j, bool trace, uint64_t us)
{
	ucl_object_t	*o;

	o = ucl_object_typed_new(UCL_OBJECT);
	put(o, "id", ucl_object_fromint((int64_t)j->id));
	put_str(o, "kind", j->has_kind && j->kind < nitems(job_kind_names) ?
	    job_kind_names[j->kind] : NULL);
	put_str(o, "title", j->title);
	put_str(o, "state", j->has_state && j->state <
	    nitems(job_state_names) ? job_state_names[j->state] : "unknown");
	put(o, "ok", j->has_ok ? ucl_object_frombool(j->ok) :
	    ucl_object_typed_new(UCL_NULL));
	put_str(o, "error", j->error);
	put_str(o, "peer", j->peer);
	put(o, "created", ucl_object_fromint(j->created));
	put(o, "started", j->has_started ? ucl_object_fromint(j->started) :
	    ucl_object_typed_new(UCL_NULL));
	put(o, "finished", j->has_finished ? ucl_object_fromint(j->finished) :
	    ucl_object_typed_new(UCL_NULL));
	if (trace)
		put(o, "trace", trace_object(c, j->trace.v, j->trace.n, c->uri,
		    true, us));
	return (o);
}

static void
spec_free(struct arc_job_spec *sp)
{
	size_t	i;

	kore_free((char *)(uintptr_t)sp->jail);
	kore_free((char *)(uintptr_t)sp->address);
	kore_free((char *)(uintptr_t)sp->interface);
	kore_free((char *)(uintptr_t)sp->service);
	for (i = 0; i < sp->variables.n; i++) {
		kore_free((char *)(uintptr_t)sp->variables.v[i].key);
		kore_free((char *)(uintptr_t)sp->variables.v[i].value);
	}
	kore_free((void *)(uintptr_t)sp->variables.v);
	for (i = 0; i < sp->names.n; i++)
		kore_free((char *)(uintptr_t)sp->names.v[i]);
	kore_free((void *)(uintptr_t)sp->names.v);
	memset(sp, 0, sizeof(*sp));
}

static char *
jdup(const ucl_object_t *o, const char *key)
{
	const char	*s;

	return ((s = ucl_str(o, key)) != NULL && *s != '\0' ? kore_strdup(s) :
	    NULL);
}

/*
 * {"kind": "jail-action", "jail": "web", "action": "restart"} and its
 * siblings into a spec; NULL, or what is wrong.  The daemon checks the
 * names again.
 */
static const char *
spec_from_json(const ucl_object_t *o, struct arc_job_spec *sp)
{
	const ucl_object_t	*set, *unset, *names, *v;
	ucl_object_iter_t	 it;
	struct arc_variable	*vars;
	const char		**nv, *kind, *a;
	size_t			 i, n;

	memset(sp, 0, sizeof(*sp));
	if (ucl_object_type(o) != UCL_OBJECT || (kind = ucl_str(o, "kind")) ==
	    NULL)
		return ("every job is an object with a kind");
	for (i = 0; i < nitems(job_kind_names); i++)
		if (strcmp(kind, job_kind_names[i]) == 0)
			break;
	if (i == nitems(job_kind_names))
		return ("unknown kind of job");
	sp->has_kind = true;
	sp->kind = (uint8_t)i;
	sp->jail = jdup(o, "jail");
	sp->address = jdup(o, "address");
	sp->interface = jdup(o, "interface");
	sp->service = jdup(o, "service");
	sp->remove = ucl_flag(o, "remove");
	sp->live = ucl_flag(o, "live");
	sp->persist = ucl_flag(o, "persist");
	a = ucl_str(o, "action");
	switch (sp->kind) {
	case ARC_JOB_KIND_JAIL_ACTION:
		for (i = 0; a != NULL && i < nitems(action_names); i++)
			if (strcmp(a, action_names[i]) == 0)
				break;
		if (a == NULL || i == nitems(action_names) || sp->jail == NULL)
			return ("a jail-action needs a jail and an action");
		sp->has_action = true;
		sp->action = (uint8_t)i;
		break;
	case ARC_JOB_KIND_ADDRESS:
		if (sp->jail == NULL || sp->address == NULL)
			return ("an address job needs a jail and an address");
		break;
	case ARC_JOB_KIND_SERVICE_ACTION:
		for (i = 0; a != NULL && i < nitems(service_action_names); i++)
			if (strcmp(a, service_action_names[i]) == 0)
				break;
		if (a == NULL || i == nitems(service_action_names) ||
		    sp->service == NULL)
			return ("a service-action needs a service and an "
			    "action");
		sp->has_service_action = true;
		sp->service_action = (uint8_t)i;
		break;
	case ARC_JOB_KIND_SERVICE_CONFIG:
		if (sp->service == NULL)
			return ("a service-config needs a service");
		set = ucl_object_lookup(o, "set");
		unset = ucl_object_lookup(o, "unset");
		n = ucl_array_size(unset);
		it = NULL;
		while (set != NULL && ucl_object_type(set) == UCL_OBJECT &&
		    ucl_object_iterate(set, &it, true) != NULL)
			n++;
		if (n == 0 || n > 64)
			return ("a service-config needs variables to set");
		vars = kore_calloc(n, sizeof(*vars));
		sp->variables.v = vars;
		it = NULL;
		while (set != NULL && ucl_object_type(set) == UCL_OBJECT &&
		    (v = ucl_object_iterate(set, &it, true)) != NULL) {
			vars[sp->variables.n].key = kore_strdup(ucl_object_key(v));
			vars[sp->variables.n].value =
			    kore_strdup(ucl_object_tostring_forced(v));
			sp->variables.n++;
		}
		it = NULL;
		while ((v = ucl_object_iterate(unset, &it, true)) != NULL &&
		    sp->variables.n < n) {
			if (ucl_object_type(v) != UCL_STRING)
				continue;
			vars[sp->variables.n].key =
			    kore_strdup(ucl_object_tostring(v));
			vars[sp->variables.n].remove = true;
			sp->variables.n++;
		}
		break;
	default:
		names = ucl_object_lookup(o, "packages");
		if ((n = ucl_array_size(names)) > 0) {
			nv = kore_calloc(n, sizeof(*nv));
			sp->names.v = nv;
			it = NULL;
			while ((v = ucl_object_iterate(names, &it, true)) !=
			    NULL && sp->names.n < n)
				if (ucl_object_type(v) == UCL_STRING)
					nv[sp->names.n++] =
					    kore_strdup(ucl_object_tostring(v));
		}
		break;
	}
	return (NULL);
}

/*
 * GET /api/servers/<id>/jobs: the host's jobs.
 * POST, {"jobs": [{"kind": ...}, ...]}: queue them, in that order.
 */
int
api_jobs(struct http_request *req)
{
	ucl_object_t		*body;
	const ucl_object_t	*a, *v;
	ucl_object_iter_t	 it;
	struct call		*c;
	const char		*e;
	size_t			 n;

	if (req->hdlr_extra != NULL)
		return (call_finish(req));
	if ((c = call_new(req, req->method == HTTP_METHOD_POST ?
	    OP_JOB_SUBMIT : OP_JOBS)) == NULL)
		return (KORE_RESULT_OK);
	if (req->method != HTTP_METHOD_POST)
		return (call_start(req, c));
	e = NULL;
	body = read_json(req);
	a = body != NULL ? ucl_object_lookup(body, "jobs") : NULL;
	if ((n = ucl_array_size(a)) == 0 || n > ARC_MAX_BATCH)
		e = "jobs is a list of 1 to 64 jobs";
	else {
		c->specs = kore_calloc(n, sizeof(*c->specs));
		it = NULL;
		while (e == NULL && (v = ucl_object_iterate(a, &it, true)) !=
		    NULL)
			e = spec_from_json(v, &c->specs[c->nspecs++]);
	}
	ucl_object_unref(body);
	if (e != NULL) {
		for (n = 0; n < c->nspecs; n++)
			spec_free(&c->specs[n]);
		kore_free(c->specs);
		kore_free(c->sname);
		kore_free(c->uri);
		kore_free(c->peer);
		kore_free(c);
		return (reply_error(req, 400, "invalid", "%s", e));
	}
	return (call_start(req, c));
}

/* GET /api/servers/<id>/jobs/<n>: a job with its trace; DELETE: cancel. */
int
api_job(struct http_request *req)
{
	struct call	*c;
	char		 id[24];

	if (req->hdlr_extra != NULL)
		return (call_finish(req));
	if ((c = call_new(req, req->method == HTTP_METHOD_DELETE ?
	    OP_JOB_CANCEL : OP_JOB)) == NULL)
		return (KORE_RESULT_OK);
	if (!capture(req, 5, id, sizeof(id))) {
		kore_free(c->sname);
		kore_free(c->uri);
		kore_free(c->peer);
		kore_free(c);
		return (reply_error(req, 400, "invalid", "bad job number"));
	}
	c->jobid = strtoull(id, NULL, 10);
	return (call_start(req, c));
}
