/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * arcanactl: talk to a arcana-agent(8) from the command line.
 */

#include <sys/param.h>
#include <sys/stat.h>

#include <err.h>
#include <fcntl.h>
#include <libxo/xo.h>
#include <sha256.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <vis.h>

/* Generated into the object directory; <> so that a stale copy next
 * to the sources is never picked up. */
#include <arcana.h>

#define	PATH_SOCKET	"unix:/var/run/arcana-agent.sock"
#define	MAX_FRAME	(8 * 1024 * 1024)
#define	MAX_ATTRS	(1024 * 1024)
#define	TIMEOUT_MS	(15 * 60 * 1000)

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

static bool	show_trace;
static bool	queue;		/* -q: submit as a job */

static const char *job_states[] = {
	[ARC_JOB_STATE_QUEUED] = "queued",
	[ARC_JOB_STATE_RUNNING] = "running",
	[ARC_JOB_STATE_DONE] = "done",
	[ARC_JOB_STATE_CANCELLED] = "cancelled",
};

static void	usage(void) __dead2;
static void	fail(struct arc_client *, int, const char *) __dead2;
static const char *join(const char *const *, size_t);
static void	emit_jail(const struct arc_jail *, bool);
static void	emit_trace(const struct arc_step *, size_t);
static void	emit_lines(const char *, const struct cbl_bytes *);
static int	cmd_hello(struct arc_client *);
static int	cmd_list(struct arc_client *, int, char **);
static int	cmd_action(struct arc_client *, uint8_t, int, char **);
static int	cmd_address(struct arc_client *, int, char **);
static int	cmd_services(struct arc_client *);
static int	cmd_net(struct arc_client *, int, char **);
static int	cmd_stats(struct arc_client *);
static int	cmd_packages(struct arc_client *, int, char **);
static int	cmd_pkg_upgrade(struct arc_client *, int, char **);
static void	emit_packages(const struct arc_package *, size_t);
static int	submit(struct arc_client *, struct arc_job_spec *);
static void	emit_job(const struct arc_job *);
static int	cmd_jobs(struct arc_client *);
static int	cmd_job(struct arc_client *, int, char **);
static int	cmd_job_cancel(struct arc_client *, int, char **);
static int	cmd_service(struct arc_client *, int, char **);
static void	emit_service(const struct arc_service *, bool);

static void
usage(void)
{

	xo_error("usage: arcanactl [-qt] [-c uri] [-A cafile -C certfile "
	    "-K keyfile] [-N name] command\n"
	    "commands:\n"
	    "    hello\n"
	    "    list [-c]\n"
	    "    start | stop | restart | kill jail\n"
	    "    address add | remove [-lnp] [-i interface] jail address\n"
	    "    services\n"
	    "    service name start | stop | restart | reload | enable | "
	    "disable\n"
	    "    service name config [-x key ...] [key=value ...]\n"
	    "    net routes | nexthops | connections | sockets [-4 | -6]\n"
	    "    stats\n"
	    "    packages [-r] [jail]\n"
	    "    pkg-upgrade [-n] [-j jail] [package ...]\n"
	    "    jobs\n"
	    "    job [-w] id\n"
	    "    job-cancel id\n"
	    "    agent-update [-r] program\n"
	    "    agent-build [-y] [-i key] [-o file] repository [ref]\n"
	    "    console-update [-y] [-i key] repository [ref]\n"
	    "with -q, start, stop, restart, kill, address, service (but "
	    "config without\nvalues) and pkg-upgrade are queued as a job "
	    "instead of waited for.\n");
	exit(2);
}

/* A request failed in transport or validation: say why and exit. */
static void
fail(struct arc_client *cl, int error, const char *what)
{
	const char	*msg;

	msg = cl->err != NULL ? cbl_msg_err_str(cl->err) : NULL;
	xo_errx(1, "%s: %s", what, msg != NULL ? msg : strerror(error));
}

/* An array of strings as "a,b,c" (static buffer). */
static const char *
join(const char *const *v, size_t n)
{
	static char	buf[1024];
	size_t		i;

	buf[0] = '\0';
	for (i = 0; i < n; i++) {
		if (i > 0)
			strlcat(buf, ",", sizeof(buf));
		strlcat(buf, v[i], sizeof(buf));
	}
	return (buf);
}

static void
emit_jail(const struct arc_jail *j, bool table)
{
	size_t	i, k;

	if (table) {
		xo_open_instance("jail");
		xo_emit("{k:name/%-16s/%s} {:state/%-8s/%s} ", j->name,
		    j->has_state && j->state < nitems(state_names) ?
		    state_names[j->state] : "?");
		if (j->has_jid)
			xo_emit("{:jid/%4u/%u} ", j->jid);
		else
			xo_emit("{P:/%4s} ", "-");
		xo_emit("{d:addresses/%-31s} {:hostname/%s}\n",
		    j->ip4.n + j->ip6.n == 0 ? "-" :
		    join(j->ip4.n > 0 ? j->ip4.v : j->ip6.v,
		    j->ip4.n > 0 ? j->ip4.n : j->ip6.n),
		    j->hostname != NULL ? j->hostname : "-");
		/* libxo ends a leaf list at the next other field. */
		for (i = 0; i < j->ip4.n; i++)
			xo_emit("{el:ip4/%s}", j->ip4.v[i]);
		xo_emit("{en:configured/%s}", j->configured ? "true" :
		    "false");
		for (i = 0; i < j->ip6.n; i++)
			xo_emit("{el:ip6/%s}", j->ip6.v[i]);
		xo_emit("{e:path/%s}{e:scope/%s}",
		    j->path != NULL ? j->path : "",
		    j->scope != NULL ? j->scope : "");
		if (j->has_nproc)
			xo_emit("{e:nproc/%u}{e:rss-kb/%ju}{e:cpu-pct/%.1f}",
			    j->nproc, (uintmax_t)j->rss_kb, j->cpu_pct);
		xo_close_instance("jail");
		return;
	}

	/* One jail in detail. */
	xo_open_container("jail");
	xo_emit("{Lwc:Name}{:name/%s}\n", j->name);
	xo_emit("{Lwc:State}{:state/%s}", j->has_state &&
	    j->state < nitems(state_names) ? state_names[j->state] : "?");
	if (j->has_jid)
		xo_emit(" ({Lw:jid}{:jid/%u})", j->jid);
	xo_emit("\n");
	if (j->hostname != NULL)
		xo_emit("{Lwc:Hostname}{:hostname/%s}\n", j->hostname);
	if (j->path != NULL)
		xo_emit("{Lwc:Path}{:path/%s}\n", j->path);
	if (j->ip4.n > 0)
		xo_emit("{Lwc:IPv4}{d:/%s}\n", join(j->ip4.v, j->ip4.n));
	if (j->ip6.n > 0)
		xo_emit("{Lwc:IPv6}{d:/%s}\n", join(j->ip6.v, j->ip6.n));
	for (i = 0; i < j->ip4.n; i++)
		xo_emit("{el:ip4/%s}", j->ip4.v[i]);
	xo_emit("{en:configured/%s}", j->configured ? "true" : "false");
	for (i = 0; i < j->ip6.n; i++)
		xo_emit("{el:ip6/%s}", j->ip6.v[i]);
	if (j->scope != NULL)
		xo_emit("{Lwc:Configured in}{:scope/%s}\n", j->scope);
	if (j->has_nproc)
		xo_emit("{Lwc:Processes}{:nproc/%u}, {:rss-kb/%ju} KiB, "
		    "{:cpu-pct/%.1f}% CPU\n", j->nproc, (uintmax_t)j->rss_kb,
		    j->cpu_pct);
	if (j->params.n > 0) {
		xo_open_list("param");
		for (i = 0; i < j->params.n; i++) {
			xo_open_instance("param");
			xo_emit("{P:  }{:key/%s}", j->params.v[i].key);
			if (j->params.v[i].values.n > 0)
				xo_emit("{D: = }{d:/%s}", join(
				    j->params.v[i].values.v,
				    j->params.v[i].values.n));
			for (k = 0; k < j->params.v[i].values.n; k++)
				xo_emit("{el:value/%s}",
				    j->params.v[i].values.v[k]);
			xo_emit("\n");
			xo_close_instance("param");
		}
		xo_close_list("param");
	}
	xo_close_container("jail");
}

/*
 * Program output, each line indented under its step, unprintable
 * characters shown as C escapes (text output only).
 */
static void
emit_lines(const char *name, const struct cbl_bytes *b)
{
	const char	*p, *e, *end;
	char		*line;

	if (b->len == 0)
		return;
	end = (const char *)b->p + b->len;
	for (p = b->p; p < end; p = e + 1) {
		for (e = p; e < end && *e != '\n'; e++)
			;
		if ((line = malloc((size_t)(e - p) * 4 + 1)) == NULL)
			xo_err(1, "malloc");
		strvisx(line, p, (size_t)(e - p), VIS_CSTYLE | VIS_OCTAL |
		    VIS_SAFE);
		xo_emit("{P:          }{D:/%s}{D:/%s}\n", name, line);
		free(line);
		if (e == end)
			break;
	}
}

/* The trace as an indented tree. */
static void
emit_trace(const struct arc_step *v, size_t n)
{
	const struct arc_step	*s;
	size_t			 i, k;
	int			 depth, p;

	if (!show_trace || n == 0)
		return;
	xo_emit("{T:Trace}:\n");
	xo_open_list("step");
	for (i = 0; i < n; i++) {
		s = &v[i];
		for (depth = 0, p = s->parent; p >= 0 && (size_t)p < n &&
		    depth < 16; p = v[p].parent)
			depth++;
		xo_open_instance("step");
		xo_emit("{P:/%*s}[{:kind/%s}] {:label/%s}",
		    depth * 2 + 2, "", s->kind < nitems(kind_names) ?
		    kind_names[s->kind] : "?", s->label);
		if (s->detail != NULL)
			xo_emit(": {:detail/%s}", s->detail);
		xo_emit(" ({:duration-us/%ju}{U:us})",
		    (uintmax_t)s->duration_us);
		if (s->has_status && s->status != ARC_STEP_STATUS_OK)
			xo_emit(" {:status/%s}", s->status <
			    nitems(status_names) ? status_names[s->status] :
			    "?");
		else
			xo_emit("{e:status/ok}");
		xo_emit("\n");
		xo_emit("{e:id/%u}{e:parent/%d}", s->id, s->parent);
		if (s->argv.n > 0) {
			for (k = 0; k < s->argv.n; k++)
				xo_emit("{el:argv/%s}", s->argv.v[k]);
			xo_emit("{e:exit/%d}", s->exit);
			emit_lines("| ", &s->output);
			emit_lines("! ", &s->error_output);
			xo_emit("{e:output/%.*s}{e:error-output/%.*s}",
			    (int)s->output.len, (const char *)s->output.p,
			    (int)s->error_output.len,
			    (const char *)s->error_output.p);
		}
		xo_close_instance("step");
	}
	xo_close_list("step");
}

static int
cmd_hello(struct arc_client *cl)
{
	struct arc_hello_rsp	*rsp;
	const struct arc_host	*h;
	char			 boot[64];
	time_t			 t;
	int			 error;

	if ((error = arc_hello(cl, &rsp)) != 0)
		fail(cl, error, "hello");
	if ((h = rsp->host) == NULL)
		xo_errx(1, "hello: the reply has no host");
	xo_open_container("host");
	xo_emit("{Lwc:Host}{:hostname/%s}\n", h->hostname);
	xo_emit("{Lwc:System}{:sysname/%s} {:release/%s} {:machine/%s}\n",
	    h->sysname, h->release, h->machine);
	xo_emit("{Lwc:CPUs}{:ncpu/%u}\n", h->ncpu);
	xo_emit("{Lwc:Memory}{:physmem/%ju} {U:bytes}\n",
	    (uintmax_t)h->physmem);
	t = (time_t)h->boottime;
	strftime(boot, sizeof(boot), "%F %T", localtime(&t));
	xo_emit("{Lwc:Booted}{d:/%s}{e:boottime/%jd}\n", boot,
	    (intmax_t)h->boottime);
	xo_emit("{Lwc:Securelevel}{:securelevel/%d}\n", h->securelevel);
	xo_emit("{Lwc:Privileged}{n:privileged/%s}\n",
	    h->privileged ? "true" : "false");
	xo_emit("{Lwc:arcana-agent}{:version/%s}\n", h->version);
	xo_close_container("host");
	arc_hello_rsp_free(rsp);
	return (0);
}

static int
cmd_list(struct arc_client *cl, int argc, char **argv)
{
	struct arc_list_req	 req;
	struct arc_list_rsp	*rsp;
	size_t			 i;
	int			 ch, error;

	memset(&req, 0, sizeof(req));
	optind = 1;
	while ((ch = getopt(argc, argv, "c")) != -1) {
		switch (ch) {
		case 'c':
			req.config_only = true;
			break;
		default:
			usage();
		}
	}
	if (optind != argc)
		usage();
	if ((error = arc_list(cl, &req, &rsp)) != 0)
		fail(cl, error, "list");
	xo_emit("{T:/%-16s} {T:/%-8s} {T:/%4s} {T:/%-31s} {T:/%s}\n", "NAME",
	    "STATE", "JID", "ADDRESSES", "HOSTNAME");
	xo_open_list("jail");
	for (i = 0; i < rsp->jails.n; i++)
		emit_jail(&rsp->jails.v[i], true);
	xo_close_list("jail");
	for (i = 0; i < rsp->conf_errors.n; i++)
		xo_warnx("%s: %s", rsp->conf_errors.v[i].scope,
		    rsp->conf_errors.v[i].message);
	emit_trace(rsp->trace.v, rsp->trace.n);
	error = rsp->ok ? 0 : 1;
	if (!rsp->ok)
		xo_warnx("%s", rsp->error != NULL ? rsp->error : "failed");
	arc_list_rsp_free(rsp);
	return (error);
}

static int
cmd_action(struct arc_client *cl, uint8_t action, int argc, char **argv)
{
	struct arc_action_req	 req;
	struct arc_action_rsp	*rsp;
	int			 error;

	if (argc != 2)
		usage();
	if (queue) {
		struct arc_job_spec sp;

		memset(&sp, 0, sizeof(sp));
		sp.has_kind = true;
		sp.kind = ARC_JOB_KIND_JAIL_ACTION;
		sp.jail = argv[1];
		sp.has_action = true;
		sp.action = action;
		return (submit(cl, &sp));
	}
	memset(&req, 0, sizeof(req));
	req.jail = argv[1];
	req.has_action = true;
	req.action = action;
	if ((error = arc_action(cl, &req, &rsp)) != 0)
		fail(cl, error, argv[0]);
	if (rsp->result != NULL)
		emit_jail(rsp->result, false);
	emit_trace(rsp->trace.v, rsp->trace.n);
	error = rsp->ok ? 0 : 1;
	if (!rsp->ok)
		xo_warnx("%s %s: %s", argv[0], argv[1],
		    rsp->error != NULL ? rsp->error : "failed");
	arc_action_rsp_free(rsp);
	return (error);
}

static int
cmd_address(struct arc_client *cl, int argc, char **argv)
{
	struct arc_address_req	 req;
	struct arc_address_rsp	*rsp;
	int			 ch, error;

	if (argc < 2 || (strcmp(argv[1], "add") != 0 &&
	    strcmp(argv[1], "remove") != 0))
		usage();
	memset(&req, 0, sizeof(req));
	req.remove = strcmp(argv[1], "remove") == 0;
	argc--;
	argv++;
	optind = 1;
	while ((ch = getopt(argc, argv, "i:lnp")) != -1) {
		switch (ch) {
		case 'i':
			req.interface = optarg;
			break;
		case 'l':
			req.live = true;
			break;
		case 'n':
			req.dry_run = true;
			break;
		case 'p':
			req.persist = true;
			break;
		default:
			usage();
		}
	}
	if (argc - optind != 2)
		usage();
	if (!req.live && !req.persist)
		req.live = true;
	req.jail = argv[optind];
	req.address = argv[optind + 1];
	if (queue && !req.dry_run) {
		struct arc_job_spec sp;

		memset(&sp, 0, sizeof(sp));
		sp.has_kind = true;
		sp.kind = ARC_JOB_KIND_ADDRESS;
		sp.jail = req.jail;
		sp.address = req.address;
		sp.interface = req.interface;
		sp.remove = req.remove;
		sp.live = req.live;
		sp.persist = req.persist;
		return (submit(cl, &sp));
	}
	if ((error = arc_address(cl, &req, &rsp)) != 0)
		fail(cl, error, "address");
	if (rsp->diff != NULL)
		xo_emit("{:diff/%s}", rsp->diff);
	if (rsp->result != NULL && !req.dry_run)
		emit_jail(rsp->result, false);
	emit_trace(rsp->trace.v, rsp->trace.n);
	error = rsp->ok ? 0 : 1;
	if (!rsp->ok)
		xo_warnx("address %s: %s", req.address,
		    rsp->error != NULL ? rsp->error : "failed");
	arc_address_rsp_free(rsp);
	return (error);
}

static void
emit_service(const struct arc_service *s, bool table)
{

	if (table) {
		xo_open_instance("service");
		xo_emit("{k:name/%-24s/%s} {:enabled/%-8s/%s} ", s->name,
		    !s->has_enabled ? "?" : s->enabled ? "enabled" : "-");
		if (s->has_running)
			xo_emit("{:running/%-8s/%s} ", s->running ? "running" :
			    "stopped");
		else
			xo_emit("{P:/%-8s} ", "");
		if (s->has_pid)
			xo_emit("{:pid/%u}", s->pid);
		xo_emit("{e:path/%s}\n", s->path);
		xo_close_instance("service");
		return;
	}
	xo_open_container("service");
	xo_emit("{Lwc:Service}{:name/%s} ({:path/%s})\n", s->name, s->path);
	if (s->has_enabled)
		xo_emit("{Lwc:Enabled}{:enabled/%s}\n", s->enabled ? "yes" :
		    "no");
	if (s->has_running)
		xo_emit("{Lwc:Running}{:running/%s}", s->running ? "yes" : "no");
	if (s->has_pid)
		xo_emit(" ({Lw:pid}{:pid/%u})", s->pid);
	if (s->has_running)
		xo_emit("\n");
	if (s->status != NULL)
		xo_emit("{Lwc:Status}{:status/%s}\n", s->status);
	xo_close_container("service");
}

static int
cmd_services(struct arc_client *cl)
{
	struct arc_services_rsp	*rsp;
	size_t			 i;
	int			 error;

	if ((error = arc_services(cl, &rsp)) != 0)
		fail(cl, error, "services");
	xo_emit("{T:/%-24s} {T:/%-8s} {T:/%-8s} {T:/%s}\n", "NAME", "ENABLED",
	    "STATE", "PID");
	xo_open_list("service");
	for (i = 0; i < rsp->services.n; i++)
		emit_service(&rsp->services.v[i], true);
	xo_close_list("service");
	emit_trace(rsp->trace.v, rsp->trace.n);
	error = rsp->ok ? 0 : 1;
	if (!rsp->ok)
		xo_warnx("%s", rsp->error != NULL ? rsp->error : "failed");
	arc_services_rsp_free(rsp);
	return (error);
}

/* service name verb, or service name config [-x key] [key=value] */
static int
cmd_service(struct arc_client *cl, int argc, char **argv)
{
	static const char *verbs[] = { "start", "stop", "restart", "reload",
	    "enable", "disable" };
	struct arc_service_action_req	 areq;
	struct arc_service_action_rsp	*arsp;
	struct arc_service_config_req	 creq;
	struct arc_service_config_rsp	*crsp;
	struct arc_variable		*vars;
	size_t				 i, nv;
	char				*eq;
	int				 error;

	if (argc < 3)
		usage();
	for (i = 0; i < nitems(verbs); i++)
		if (strcmp(argv[2], verbs[i]) == 0)
			break;
	if (i < nitems(verbs)) {
		if (argc != 3)
			usage();
		if (queue) {
			struct arc_job_spec sp;

			memset(&sp, 0, sizeof(sp));
			sp.has_kind = true;
			sp.kind = ARC_JOB_KIND_SERVICE_ACTION;
			sp.service = argv[1];
			sp.has_service_action = true;
			sp.service_action = (uint8_t)i;
			return (submit(cl, &sp));
		}
		memset(&areq, 0, sizeof(areq));
		areq.service = argv[1];
		areq.has_service_action = true;
		areq.service_action = (uint8_t)i;
		if ((error = arc_service_action(cl, &areq, &arsp)) != 0)
			fail(cl, error, argv[2]);
		if (arsp->service_result != NULL)
			emit_service(arsp->service_result, false);
		emit_trace(arsp->trace.v, arsp->trace.n);
		error = arsp->ok ? 0 : 1;
		if (!arsp->ok)
			xo_warnx("service %s %s: %s", argv[1], argv[2],
			    arsp->error != NULL ? arsp->error : "failed");
		arc_service_action_rsp_free(arsp);
		return (error);
	}
	if (strcmp(argv[2], "config") != 0)
		usage();
	memset(&creq, 0, sizeof(creq));
	creq.service = argv[1];
	if ((vars = calloc((size_t)argc, sizeof(*vars))) == NULL)
		xo_err(1, "calloc");
	nv = 0;
	for (i = 3; i < (size_t)argc; i++) {
		if (strcmp(argv[i], "-x") == 0 && i + 1 < (size_t)argc) {
			vars[nv].key = argv[++i];
			vars[nv].remove = true;
		} else if ((eq = strchr(argv[i], '=')) != NULL) {
			*eq = '\0';
			vars[nv].key = argv[i];
			vars[nv].value = eq + 1;
		} else
			usage();
		nv++;
	}
	creq.variables.v = vars;
	creq.variables.n = nv;
	if (queue && nv > 0) {
		struct arc_job_spec sp;

		memset(&sp, 0, sizeof(sp));
		sp.has_kind = true;
		sp.kind = ARC_JOB_KIND_SERVICE_CONFIG;
		sp.service = argv[1];
		sp.variables.v = vars;
		sp.variables.n = nv;
		error = submit(cl, &sp);
		free(vars);
		return (error);
	}
	if ((error = arc_service_config(cl, &creq, &crsp)) != 0)
		fail(cl, error, "config");
	if (crsp->service_result != NULL)
		emit_service(crsp->service_result, false);
	if (crsp->description != NULL)
		xo_emit("{Lwc:Describe}{:description/%s}\n", crsp->description);
	if (crsp->commands.n > 0)
		xo_emit("{Lwc:Commands}{d:/%s}\n", join(crsp->commands.v,
		    crsp->commands.n));
	for (i = 0; i < crsp->commands.n; i++)
		xo_emit("{el:command/%s}", crsp->commands.v[i]);
	xo_open_list("variable");
	for (i = 0; i < crsp->variables.n; i++) {
		xo_open_instance("variable");
		xo_emit("{P:  }{k:key/%s}{D:=}{:value/%s}\n",
		    crsp->variables.v[i].key, crsp->variables.v[i].value !=
		    NULL ? crsp->variables.v[i].value : "");
		xo_close_instance("variable");
	}
	xo_close_list("variable");
	emit_trace(crsp->trace.v, crsp->trace.n);
	error = crsp->ok ? 0 : 1;
	if (!crsp->ok)
		xo_warnx("service %s config: %s", argv[1],
		    crsp->error != NULL ? crsp->error : "failed");
	arc_service_config_rsp_free(crsp);
	free(vars);
	return (error);
}

/*
 * agent-build [-o file] repository [ref]: have the host build
 * arcana-agent from a git repository, and keep what it sends back.
 */
static int
cmd_agent_build(struct arc_client *cl, int argc, char **argv)
{
	struct arc_agent_build_req	 req;
	struct arc_agent_build_rsp	*rsp;
	const char			*out;
	char				 hex[SHA256_DIGEST_STRING_LENGTH];
	char				*keys;
	size_t				 i;
	bool				 trust;
	int				 ch, error, fd;

	memset(&req, 0, sizeof(req));
	out = "arcana-agent";
	trust = false;
	keys = NULL;
	optreset = optind = 1;
	while ((ch = getopt(argc, argv, "i:o:y")) != -1) {
		switch (ch) {
		case 'i':
			req.ssh_key = optarg;
			break;
		case 'o':
			out = optarg;
			break;
		case 'y':
			trust = true;
			break;
		default:
			usage();
		}
	}
	if (argc - optind < 1 || argc - optind > 2)
		usage();
	req.source = argv[optind];
	req.ref = argv[optind + 1];
again:
	if ((error = arc_agent_build(cl, &req, &rsp)) != 0)
		fail(cl, error, "agent-build");
	emit_trace(rsp->trace.v, rsp->trace.n);
	/*
	 * The host does not know the server's SSH host key: show what it
	 * found, and with -y send it back as confirmed.
	 */
	if (!rsp->ok && rsp->host_keys != NULL) {
		for (i = 0; i < rsp->fingerprints.n; i++)
			xo_emit("{Lwc:Host key}{l:fingerprint/%s}\n",
			    rsp->fingerprints.v[i]);
		if (trust && keys == NULL) {
			if ((keys = strdup(rsp->host_keys)) == NULL)
				xo_err(1, "strdup");
			req.host_keys = keys;
			arc_agent_build_rsp_free(rsp);
			goto again;
		}
	}
	if (!rsp->ok && rsp->deploy_key != NULL)
		xo_emit("{Lwc:Deploy key}{:deploy-key/%s}\n", rsp->deploy_key);
	if (rsp->ok) {
		/* What arrived is what the host says it built. */
		if (rsp->sha256 == NULL || strcmp(SHA256_Data(rsp->binary.p,
		    rsp->binary.len, hex), rsp->sha256) != 0)
			xo_errx(1, "agent-build: the program does not match "
			    "its SHA-256");
		(void)unlink(out);
		if ((fd = open(out, O_WRONLY | O_CREAT | O_EXCL, 0755)) == -1 ||
		    write(fd, rsp->binary.p, rsp->binary.len) !=
		    (ssize_t)rsp->binary.len || close(fd) == -1)
			xo_err(1, "%s", out);
		xo_emit("{Lwc:Built}{:agent-version/%s}{P: }{:sha256/%s}"
		    "{P: }{:file/%s}\n", rsp->agent_version != NULL ?
		    rsp->agent_version : "?", hex, out);
	} else
		xo_warnx("agent-build: %s", rsp->error != NULL ? rsp->error :
		    "failed");
	error = rsp->ok ? 0 : 1;
	arc_agent_build_rsp_free(rsp);
	free(keys);
	return (error);
}

/*
 * console-update [-y] [-i key] repository [ref]: have the host build
 * the whole tree, install it and restart the console's service.
 */
static int
cmd_console_update(struct arc_client *cl, int argc, char **argv)
{
	struct arc_console_update_req	 req;
	struct arc_console_update_rsp	*rsp;
	char				*keys;
	size_t				 i;
	bool				 trust;
	int				 ch, error;

	memset(&req, 0, sizeof(req));
	trust = false;
	keys = NULL;
	optreset = optind = 1;
	while ((ch = getopt(argc, argv, "i:y")) != -1) {
		switch (ch) {
		case 'i':
			req.ssh_key = optarg;
			break;
		case 'y':
			trust = true;
			break;
		default:
			usage();
		}
	}
	if (argc - optind < 1 || argc - optind > 2)
		usage();
	req.source = argv[optind];
	req.ref = argv[optind + 1];
again:
	if ((error = arc_console_update(cl, &req, &rsp)) != 0)
		fail(cl, error, "console-update");
	emit_trace(rsp->trace.v, rsp->trace.n);
	if (!rsp->ok && rsp->host_keys != NULL) {
		for (i = 0; i < rsp->fingerprints.n; i++)
			xo_emit("{Lwc:Host key}{l:fingerprint/%s}\n",
			    rsp->fingerprints.v[i]);
		if (trust && keys == NULL) {
			if ((keys = strdup(rsp->host_keys)) == NULL)
				xo_err(1, "strdup");
			req.host_keys = keys;
			arc_console_update_rsp_free(rsp);
			goto again;
		}
	}
	if (!rsp->ok && rsp->deploy_key != NULL)
		xo_emit("{Lwc:Deploy key}{:deploy-key/%s}\n", rsp->deploy_key);
	if (rsp->ok)
		xo_emit("{Lwc:Console}{:console/installed}{d:restarting/%s}\n",
		    rsp->restarting ? ", restarting" : "");
	else
		xo_warnx("console-update: %s", rsp->error != NULL ?
		    rsp->error : "failed");
	error = rsp->ok ? 0 : 1;
	arc_console_update_rsp_free(rsp);
	free(keys);
	return (error);
}

/* agent-update [-r] program: put a new arcana-agent in place. */
static int
cmd_agent_update(struct arc_client *cl, int argc, char **argv)
{
	struct arc_agent_update_req	 req;
	struct arc_agent_update_rsp	*rsp;
	struct stat			 sb;
	char				 hex[SHA256_DIGEST_STRING_LENGTH];
	uint8_t				*data;
	ssize_t				 n;
	size_t				 off;
	int				 ch, error, fd;

	memset(&req, 0, sizeof(req));
	optreset = optind = 1;
	while ((ch = getopt(argc, argv, "r")) != -1) {
		if (ch != 'r')
			usage();
		req.restart = true;
	}
	if (argc - optind != 1)
		usage();
	if ((fd = open(argv[optind], O_RDONLY)) == -1 || fstat(fd, &sb) == -1)
		xo_err(1, "%s", argv[optind]);
	if (sb.st_size == 0 || sb.st_size > ARC_MAX_BINARY)
		xo_errx(1, "%s: not a program an update can carry",
		    argv[optind]);
	if ((data = malloc((size_t)sb.st_size)) == NULL)
		xo_err(1, "malloc");
	for (off = 0; off < (size_t)sb.st_size; off += (size_t)n)
		if ((n = read(fd, data + off, (size_t)sb.st_size - off)) <= 0)
			xo_err(1, "%s", argv[optind]);
	close(fd);
	req.binary.p = data;
	req.binary.len = off;
	req.sha256 = SHA256_Data(data, off, hex);
	if ((error = arc_agent_update(cl, &req, &rsp)) != 0)
		fail(cl, error, "agent-update");
	if (rsp->ok)
		xo_emit("{Lwc:Agent}{:agent-version/%s}{d:restarting/%s}\n",
		    rsp->agent_version != NULL ? rsp->agent_version : "?",
		    rsp->restarting ? ", restarting" :
		    " in place; it runs from the next start");
	xo_emit("{e:restarting/%s}", rsp->restarting ? "true" : "false");
	emit_trace(rsp->trace.v, rsp->trace.n);
	error = rsp->ok ? 0 : 1;
	if (!rsp->ok)
		xo_warnx("agent-update: %s", rsp->error != NULL ? rsp->error :
		    "failed");
	arc_agent_update_rsp_free(rsp);
	free(data);
	return (error);
}

/* The program's libxo JSON, printed as it came. */
static int
cmd_net(struct arc_client *cl, int argc, char **argv)
{
	static const char *kinds[] = { "routes", "nexthops", "connections",
	    "sockets" };
	struct arc_network_req	 req;
	struct arc_network_rsp	*rsp;
	size_t			 i;
	int			 ch, error;

	if (argc < 2)
		usage();
	for (i = 0; i < nitems(kinds); i++)
		if (strcmp(argv[1], kinds[i]) == 0)
			break;
	if (i == nitems(kinds))
		usage();
	memset(&req, 0, sizeof(req));
	req.has_net_kind = true;
	req.net_kind = (uint8_t)i;
	req.has_net_family = true;
	req.net_family = ARC_NET_FAMILY_ALL;
	argc--;
	argv++;
	optind = 1;
	while ((ch = getopt(argc, argv, "46")) != -1) {
		switch (ch) {
		case '4':
			req.net_family = ARC_NET_FAMILY_INET;
			break;
		case '6':
			req.net_family = ARC_NET_FAMILY_INET6;
			break;
		default:
			usage();
		}
	}
	if (optind != argc)
		usage();
	if ((error = arc_network(cl, &req, &rsp)) != 0)
		fail(cl, error, "net");
	if (rsp->json != NULL)
		xo_emit("{:json/%s}", rsp->json);
	emit_trace(rsp->trace.v, rsp->trace.n);
	error = rsp->ok ? 0 : 1;
	if (!rsp->ok)
		xo_warnx("net %s: %s", kinds[i], rsp->error != NULL ?
		    rsp->error : "failed");
	arc_network_rsp_free(rsp);
	return (error);
}

static int
cmd_stats(struct arc_client *cl)
{
	struct arc_stats_rsp	*rsp;
	const struct arc_stats	*st;
	size_t			 i;
	int			 error;

	if ((error = arc_stats(cl, &rsp)) != 0)
		fail(cl, error, "stats");
	if ((st = rsp->stats) != NULL) {
		xo_open_container("stats");
		xo_emit("{Lwc:CPU}{:cpu-pct/%.1f}%\n", st->cpu_pct);
		xo_emit("{Lwc:Load}{:load1/%.2f} {:load5/%.2f} {:load15/%.2f}\n",
		    st->load1, st->load5, st->load15);
		xo_emit("{Lwc:Memory}{:mem-used/%ju} used, {:mem-inactive/%ju} "
		    "inactive, {:mem-free/%ju} free of {:mem-total/%ju} MiB\n",
		    (uintmax_t)(st->mem_used >> 20),
		    (uintmax_t)(st->mem_inactive >> 20),
		    (uintmax_t)(st->mem_free >> 20),
		    (uintmax_t)(st->mem_total >> 20));
		xo_emit("{Lwc:Swap}{:swap-used/%ju} of {:swap-total/%ju} MiB\n",
		    (uintmax_t)(st->swap_used >> 20),
		    (uintmax_t)(st->swap_total >> 20));
		xo_open_list("pool");
		for (i = 0; i < st->pools.n; i++) {
			xo_open_instance("pool");
			xo_emit("{Lwc:Pool}{:name/%s} {:alloc/%ju} of {:size/%ju} "
			    "GiB, {:health/%s}\n", st->pools.v[i].name,
			    (uintmax_t)(st->pools.v[i].alloc >> 30),
			    (uintmax_t)(st->pools.v[i].size >> 30),
			    st->pools.v[i].health);
			xo_close_instance("pool");
		}
		xo_close_list("pool");
		xo_close_container("stats");
	}
	emit_trace(rsp->trace.v, rsp->trace.n);
	error = rsp->ok ? 0 : 1;
	if (!rsp->ok)
		xo_warnx("stats: %s", rsp->error != NULL ? rsp->error : "failed");
	arc_stats_rsp_free(rsp);
	return (error);
}

static void
emit_packages(const struct arc_package *v, size_t n)
{
	size_t	i;

	if (n == 0) {
		xo_emit("{P:nothing to upgrade}\n");
		return;
	}
	xo_emit("{T:/%-40s} {T:/%-20s} {T:/%s}\n", "PACKAGE", "INSTALLED",
	    "AVAILABLE");
	xo_open_list("package");
	for (i = 0; i < n; i++) {
		xo_open_instance("package");
		xo_emit("{k:name/%-40s/%s} {:installed/%-20s/%s} "
		    "{:available/%s}\n", v[i].name, v[i].installed,
		    v[i].available != NULL ? v[i].available : "");
		xo_close_instance("package");
	}
	xo_close_list("package");
}

/* packages [-r] [jail]: what has a newer version in the repository. */
static int
cmd_packages(struct arc_client *cl, int argc, char **argv)
{
	struct arc_packages_req	 req;
	struct arc_packages_rsp	*rsp;
	int			 ch, error;

	memset(&req, 0, sizeof(req));
	optind = 1;
	while ((ch = getopt(argc, argv, "r")) != -1) {
		switch (ch) {
		case 'r':
			req.refresh = true;
			break;
		default:
			usage();
		}
	}
	if (argc - optind > 1)
		usage();
	if (argc - optind == 1)
		req.jail = argv[optind];
	if ((error = arc_packages(cl, &req, &rsp)) != 0)
		fail(cl, error, "packages");
	if (rsp->ok)
		emit_packages(rsp->packages.v, rsp->packages.n);
	emit_trace(rsp->trace.v, rsp->trace.n);
	error = rsp->ok ? 0 : 1;
	if (!rsp->ok)
		xo_warnx("packages: %s", rsp->error != NULL ? rsp->error :
		    "failed");
	arc_packages_rsp_free(rsp);
	return (error);
}

/* pkg-upgrade [-n] [-j jail] [package ...] */
static int
cmd_pkg_upgrade(struct arc_client *cl, int argc, char **argv)
{
	struct arc_pkg_upgrade_req	 req;
	struct arc_pkg_upgrade_rsp	*rsp;
	int				 ch, error;

	memset(&req, 0, sizeof(req));
	optind = 1;
	while ((ch = getopt(argc, argv, "j:n")) != -1) {
		switch (ch) {
		case 'j':
			req.jail = optarg;
			break;
		case 'n':
			req.dry_run = true;
			break;
		default:
			usage();
		}
	}
	req.names.v = (const char *const *)(argv + optind);
	req.names.n = (size_t)(argc - optind);
	if (queue && !req.dry_run) {
		struct arc_job_spec sp;

		memset(&sp, 0, sizeof(sp));
		sp.has_kind = true;
		sp.kind = ARC_JOB_KIND_PKG_UPGRADE;
		sp.jail = req.jail;
		sp.names.v = req.names.v;
		sp.names.n = req.names.n;
		return (submit(cl, &sp));
	}
	if ((error = arc_pkg_upgrade(cl, &req, &rsp)) != 0)
		fail(cl, error, "pkg-upgrade");
	if (rsp->ok) {
		if (rsp->has_upgraded)
			xo_emit("{Lwc:Upgraded}{:upgraded/%u}\n", rsp->upgraded);
		xo_emit("{T:Still pending}:\n");
		emit_packages(rsp->packages.v, rsp->packages.n);
	}
	emit_trace(rsp->trace.v, rsp->trace.n);
	error = rsp->ok ? 0 : 1;
	if (!rsp->ok)
		xo_warnx("pkg-upgrade: %s", rsp->error != NULL ? rsp->error :
		    "failed");
	arc_pkg_upgrade_rsp_free(rsp);
	return (error);
}

static void
emit_job(const struct arc_job *j)
{
	const char	*st;

	st = j->has_state && j->state < nitems(job_states) ?
	    job_states[j->state] : "?";
	if (j->has_state && j->state == ARC_JOB_STATE_DONE && !j->ok)
		st = "failed";
	xo_open_instance("job");
	xo_emit("{k:id/%4ju} {:state/%-9s/%s} {:title/%s}", (uintmax_t)j->id,
	    st, j->title);
	if (j->error != NULL)
		xo_emit(": {:error/%s}", j->error);
	xo_emit("{e:peer/%s}{e:created/%jd}\n", j->peer != NULL ? j->peer : "",
	    (intmax_t)j->created);
	xo_close_instance("job");
}

/* Queue one job and say its number. */
static int
submit(struct arc_client *cl, struct arc_job_spec *sp)
{
	struct arc_job_submit_req	 req;
	struct arc_job_submit_rsp	*rsp;
	size_t				 i;
	int				 error;

	memset(&req, 0, sizeof(req));
	req.batch.v = sp;
	req.batch.n = 1;
	if ((error = arc_job_submit(cl, &req, &rsp)) != 0)
		fail(cl, error, "queue");
	xo_open_list("job");
	for (i = 0; i < rsp->jobs.n; i++)
		emit_job(&rsp->jobs.v[i]);
	xo_close_list("job");
	error = rsp->ok ? 0 : 1;
	arc_job_submit_rsp_free(rsp);
	return (error);
}

static int
cmd_jobs(struct arc_client *cl)
{
	struct arc_jobs_rsp	*rsp;
	size_t			 i;
	int			 error;

	if ((error = arc_jobs(cl, &rsp)) != 0)
		fail(cl, error, "jobs");
	xo_emit("{T:/%4s} {T:/%-9s} {T:/%s}\n", "ID", "STATE", "JOB");
	xo_open_list("job");
	for (i = 0; i < rsp->jobs.n; i++)
		emit_job(&rsp->jobs.v[i]);
	xo_close_list("job");
	arc_jobs_rsp_free(rsp);
	return (0);
}

/* job [-w] id: the job and its trace; -w waits for it to finish. */
static int
cmd_job(struct arc_client *cl, int argc, char **argv)
{
	struct arc_job_req	 req;
	struct arc_job_rsp	*rsp;
	bool			 wait, done, ok;
	int			 ch, error;

	wait = false;
	optind = 1;
	while ((ch = getopt(argc, argv, "w")) != -1) {
		switch (ch) {
		case 'w':
			wait = true;
			break;
		default:
			usage();
		}
	}
	if (argc - optind != 1)
		usage();
	memset(&req, 0, sizeof(req));
	req.has_id = true;
	req.id = strtoull(argv[optind], NULL, 10);
	for (;;) {
		if ((error = arc_job(cl, &req, &rsp)) != 0)
			fail(cl, error, "job");
		if (!rsp->ok || rsp->job == NULL) {
			xo_warnx("job %s: %s", argv[optind], rsp->error != NULL ?
			    rsp->error : "not found");
			arc_job_rsp_free(rsp);
			return (1);
		}
		done = rsp->job->state == ARC_JOB_STATE_DONE ||
		    rsp->job->state == ARC_JOB_STATE_CANCELLED;
		if (done || !wait)
			break;
		arc_job_rsp_free(rsp);
		usleep(300000);
	}
	xo_open_list("job");
	emit_job(rsp->job);
	xo_close_list("job");
	show_trace = true;
	emit_trace(rsp->job->trace.v, rsp->job->trace.n);
	ok = !done || (rsp->job->state == ARC_JOB_STATE_DONE && rsp->job->ok);
	arc_job_rsp_free(rsp);
	return (ok ? 0 : 1);
}

static int
cmd_job_cancel(struct arc_client *cl, int argc, char **argv)
{
	struct arc_job_cancel_req	 req;
	struct arc_job_cancel_rsp	*rsp;
	int				 error;

	if (argc != 2)
		usage();
	memset(&req, 0, sizeof(req));
	req.has_id = true;
	req.id = strtoull(argv[1], NULL, 10);
	if ((error = arc_job_cancel(cl, &req, &rsp)) != 0)
		fail(cl, error, "job-cancel");
	if (rsp->ok && rsp->job != NULL) {
		xo_open_list("job");
		emit_job(rsp->job);
		xo_close_list("job");
	} else
		xo_warnx("job %s: %s", argv[1], rsp->error != NULL ?
		    rsp->error : "failed");
	error = rsp->ok ? 0 : 1;
	arc_job_cancel_rsp_free(rsp);
	return (error);
}

int
main(int argc, char *argv[])
{
	struct arc_client	 cl;
	cbl_conn		*conn;
	cbl_ctx			*ctx;
	cbl_tls			*tls;
	const char		*uri, *cafile, *certfile, *keyfile, *name;
	int			 ch, error, rc;

	if ((argc = xo_parse_args(argc, argv)) < 0)
		exit(2);
	uri = PATH_SOCKET;
	cafile = certfile = keyfile = name = NULL;
	while ((ch = getopt(argc, argv, "+A:C:c:K:N:qt")) != -1) {
		switch (ch) {
		case 'A':
			cafile = optarg;
			break;
		case 'C':
			certfile = optarg;
			break;
		case 'c':
			uri = optarg;
			break;
		case 'K':
			keyfile = optarg;
			break;
		case 'N':
			name = optarg;
			break;
		case 'q':
			queue = true;
			break;
		case 't':
			show_trace = true;
			break;
		default:
			usage();
		}
	}
	argc -= optind;
	argv += optind;
	if (argc < 1)
		usage();

	if ((error = cbl_ctx_new(&ctx)) != 0)
		xo_errx(1, "cbl_ctx_new: %s", strerror(error));
	(void)cbl_ctx_set_limit(ctx, CBL_LIM_MAX_FRAME, MAX_FRAME);
	(void)cbl_ctx_set_limit(ctx, CBL_LIM_MAX_ATTRS, MAX_ATTRS);
	(void)cbl_ctx_set_limit(ctx, CBL_LIM_REQUEST_MS, TIMEOUT_MS);
	if ((error = cbl_conn_new(ctx, uri, 0, &conn)) != 0)
		xo_errx(1, "%s: %s", uri, strerror(error));
	tls = NULL;
	if (strncmp(uri, "unix:", 5) != 0) {
		if (cafile == NULL || certfile == NULL || keyfile == NULL)
			xo_errx(1, "%s: needs -A, -C and -K", uri);
		if (cbl_tls_new(&tls) != 0 ||
		    cbl_tls_set_cert(tls, certfile, keyfile) != 0 ||
		    cbl_tls_set_ca(tls, cafile, NULL) != 0 ||
		    (name != NULL && cbl_tls_set_peer_name(tls, name) != 0))
			xo_errx(1, "TLS: %s", tls != NULL ?
			    cbl_tls_errstr(tls) : "cbl_tls_new failed");
		(void)cbl_conn_set_tls(conn, tls);
	}
	if ((error = cbl_conn_connect(conn)) != 0)
		xo_errx(1, "%s: %s", uri, cbl_conn_errstr(conn));
	if ((error = arc_client_init(&cl, conn)) != 0)
		xo_errx(1, "%s: no %s family: %s", uri, ARC_FAMILY_NAME,
		    strerror(error));

	xo_open_container("arcana");
	if (strcmp(argv[0], "hello") == 0 && argc == 1)
		rc = cmd_hello(&cl);
	else if (strcmp(argv[0], "list") == 0)
		rc = cmd_list(&cl, argc, argv);
	else if (strcmp(argv[0], "start") == 0)
		rc = cmd_action(&cl, ARC_ACTION_START, argc, argv);
	else if (strcmp(argv[0], "stop") == 0)
		rc = cmd_action(&cl, ARC_ACTION_STOP, argc, argv);
	else if (strcmp(argv[0], "restart") == 0)
		rc = cmd_action(&cl, ARC_ACTION_RESTART, argc, argv);
	else if (strcmp(argv[0], "kill") == 0)
		rc = cmd_action(&cl, ARC_ACTION_KILL, argc, argv);
	else if (strcmp(argv[0], "address") == 0)
		rc = cmd_address(&cl, argc, argv);
	else if (strcmp(argv[0], "services") == 0 && argc == 1)
		rc = cmd_services(&cl);
	else if (strcmp(argv[0], "service") == 0)
		rc = cmd_service(&cl, argc, argv);
	else if (strcmp(argv[0], "net") == 0)
		rc = cmd_net(&cl, argc, argv);
	else if (strcmp(argv[0], "stats") == 0 && argc == 1)
		rc = cmd_stats(&cl);
	else if (strcmp(argv[0], "packages") == 0)
		rc = cmd_packages(&cl, argc, argv);
	else if (strcmp(argv[0], "jobs") == 0 && argc == 1)
		rc = cmd_jobs(&cl);
	else if (strcmp(argv[0], "job") == 0)
		rc = cmd_job(&cl, argc, argv);
	else if (strcmp(argv[0], "job-cancel") == 0)
		rc = cmd_job_cancel(&cl, argc, argv);
	else if (strcmp(argv[0], "pkg-upgrade") == 0)
		rc = cmd_pkg_upgrade(&cl, argc, argv);
	else if (strcmp(argv[0], "agent-update") == 0)
		rc = cmd_agent_update(&cl, argc, argv);
	else if (strcmp(argv[0], "agent-build") == 0)
		rc = cmd_agent_build(&cl, argc, argv);
	else if (strcmp(argv[0], "console-update") == 0)
		rc = cmd_console_update(&cl, argc, argv);
	else
		usage();
	xo_close_container("arcana");
	xo_finish();

	arc_client_fini(&cl);
	cbl_conn_free(conn);
	cbl_tls_free(tls);
	(void)cbl_ctx_free(ctx);
	return (rc);
}
