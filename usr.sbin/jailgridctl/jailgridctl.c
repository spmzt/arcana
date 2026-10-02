/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * jailgridctl: talk to a jailgridd(8) from the command line.
 */

#include <sys/param.h>

#include <err.h>
#include <libxo/xo.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <vis.h>

#include "jailgrid.h"

#define	PATH_SOCKET	"unix:/var/run/jailgridd.sock"
#define	MAX_FRAME	(8 * 1024 * 1024)
#define	TIMEOUT_MS	(15 * 60 * 1000)

static const char *state_names[] = {
	[JG_JAIL_STATE_RUNNING] = "running",
	[JG_JAIL_STATE_STOPPED] = "stopped",
	[JG_JAIL_STATE_DYING] = "dying",
	[JG_JAIL_STATE_ABSENT] = "absent",
};

static const char *kind_names[] = {
	[JG_STEP_KIND_DAEMON] = "daemon",
	[JG_STEP_KIND_LIB] = "lib",
	[JG_STEP_KIND_SYSCALL] = "syscall",
	[JG_STEP_KIND_FILE] = "file",
	[JG_STEP_KIND_EXEC] = "exec",
};

static const char *status_names[] = {
	[JG_STEP_STATUS_OK] = "ok",
	[JG_STEP_STATUS_FAILED] = "failed",
	[JG_STEP_STATUS_INCOMPLETE] = "incomplete",
};

static bool	show_trace;

static void	usage(void) __dead2;
static void	fail(struct jg_client *, int, const char *) __dead2;
static const char *join(const char *const *, size_t);
static void	emit_jail(const struct jg_jail *, bool);
static void	emit_trace(const struct jg_step *, size_t);
static void	emit_lines(const char *, const struct cbl_bytes *);
static int	cmd_hello(struct jg_client *);
static int	cmd_list(struct jg_client *, int, char **);
static int	cmd_action(struct jg_client *, uint8_t, int, char **);
static int	cmd_address(struct jg_client *, int, char **);
static int	cmd_services(struct jg_client *);
static int	cmd_net(struct jg_client *, int, char **);
static int	cmd_service(struct jg_client *, int, char **);
static void	emit_service(const struct jg_service *, bool);

static void
usage(void)
{

	xo_error("usage: jailgridctl [-t] [-c uri] [-A cafile -C certfile "
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
	    "    net routes | nexthops | connections | sockets [-4 | -6]\n");
	exit(2);
}

/* A request failed in transport or validation: say why and exit. */
static void
fail(struct jg_client *cl, int error, const char *what)
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
emit_jail(const struct jg_jail *j, bool table)
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
emit_trace(const struct jg_step *v, size_t n)
{
	const struct jg_step	*s;
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
		if (s->has_status && s->status != JG_STEP_STATUS_OK)
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
cmd_hello(struct jg_client *cl)
{
	struct jg_hello_rsp	*rsp;
	const struct jg_host	*h;
	char			 boot[64];
	time_t			 t;
	int			 error;

	if ((error = jg_hello(cl, &rsp)) != 0)
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
	xo_emit("{Lwc:jailgridd}{:version/%s}\n", h->version);
	xo_close_container("host");
	jg_hello_rsp_free(rsp);
	return (0);
}

static int
cmd_list(struct jg_client *cl, int argc, char **argv)
{
	struct jg_list_req	 req;
	struct jg_list_rsp	*rsp;
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
	if ((error = jg_list(cl, &req, &rsp)) != 0)
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
	jg_list_rsp_free(rsp);
	return (error);
}

static int
cmd_action(struct jg_client *cl, uint8_t action, int argc, char **argv)
{
	struct jg_action_req	 req;
	struct jg_action_rsp	*rsp;
	int			 error;

	if (argc != 2)
		usage();
	memset(&req, 0, sizeof(req));
	req.jail = argv[1];
	req.has_action = true;
	req.action = action;
	if ((error = jg_action(cl, &req, &rsp)) != 0)
		fail(cl, error, argv[0]);
	if (rsp->result != NULL)
		emit_jail(rsp->result, false);
	emit_trace(rsp->trace.v, rsp->trace.n);
	error = rsp->ok ? 0 : 1;
	if (!rsp->ok)
		xo_warnx("%s %s: %s", argv[0], argv[1],
		    rsp->error != NULL ? rsp->error : "failed");
	jg_action_rsp_free(rsp);
	return (error);
}

static int
cmd_address(struct jg_client *cl, int argc, char **argv)
{
	struct jg_address_req	 req;
	struct jg_address_rsp	*rsp;
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
	if ((error = jg_address(cl, &req, &rsp)) != 0)
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
	jg_address_rsp_free(rsp);
	return (error);
}

static void
emit_service(const struct jg_service *s, bool table)
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
cmd_services(struct jg_client *cl)
{
	struct jg_services_rsp	*rsp;
	size_t			 i;
	int			 error;

	if ((error = jg_services(cl, &rsp)) != 0)
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
	jg_services_rsp_free(rsp);
	return (error);
}

/* service name verb, or service name config [-x key] [key=value] */
static int
cmd_service(struct jg_client *cl, int argc, char **argv)
{
	static const char *verbs[] = { "start", "stop", "restart", "reload",
	    "enable", "disable" };
	struct jg_service_action_req	 areq;
	struct jg_service_action_rsp	*arsp;
	struct jg_service_config_req	 creq;
	struct jg_service_config_rsp	*crsp;
	struct jg_variable		*vars;
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
		memset(&areq, 0, sizeof(areq));
		areq.service = argv[1];
		areq.has_service_action = true;
		areq.service_action = (uint8_t)i;
		if ((error = jg_service_action(cl, &areq, &arsp)) != 0)
			fail(cl, error, argv[2]);
		if (arsp->service_result != NULL)
			emit_service(arsp->service_result, false);
		emit_trace(arsp->trace.v, arsp->trace.n);
		error = arsp->ok ? 0 : 1;
		if (!arsp->ok)
			xo_warnx("service %s %s: %s", argv[1], argv[2],
			    arsp->error != NULL ? arsp->error : "failed");
		jg_service_action_rsp_free(arsp);
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
	if ((error = jg_service_config(cl, &creq, &crsp)) != 0)
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
	jg_service_config_rsp_free(crsp);
	free(vars);
	return (error);
}

/* The program's libxo JSON, printed as it came. */
static int
cmd_net(struct jg_client *cl, int argc, char **argv)
{
	static const char *kinds[] = { "routes", "nexthops", "connections",
	    "sockets" };
	struct jg_network_req	 req;
	struct jg_network_rsp	*rsp;
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
	req.net_family = JG_NET_FAMILY_ALL;
	argc--;
	argv++;
	optind = 1;
	while ((ch = getopt(argc, argv, "46")) != -1) {
		switch (ch) {
		case '4':
			req.net_family = JG_NET_FAMILY_INET;
			break;
		case '6':
			req.net_family = JG_NET_FAMILY_INET6;
			break;
		default:
			usage();
		}
	}
	if (optind != argc)
		usage();
	if ((error = jg_network(cl, &req, &rsp)) != 0)
		fail(cl, error, "net");
	if (rsp->json != NULL)
		xo_emit("{:json/%s}", rsp->json);
	emit_trace(rsp->trace.v, rsp->trace.n);
	error = rsp->ok ? 0 : 1;
	if (!rsp->ok)
		xo_warnx("net %s: %s", kinds[i], rsp->error != NULL ?
		    rsp->error : "failed");
	jg_network_rsp_free(rsp);
	return (error);
}

int
main(int argc, char *argv[])
{
	struct jg_client	 cl;
	cbl_conn		*conn;
	cbl_ctx			*ctx;
	cbl_tls			*tls;
	const char		*uri, *cafile, *certfile, *keyfile, *name;
	int			 ch, error, rc;

	if ((argc = xo_parse_args(argc, argv)) < 0)
		exit(2);
	uri = PATH_SOCKET;
	cafile = certfile = keyfile = name = NULL;
	while ((ch = getopt(argc, argv, "+A:C:c:K:N:t")) != -1) {
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
	if ((error = jg_client_init(&cl, conn)) != 0)
		xo_errx(1, "%s: no %s family: %s", uri, JG_FAMILY_NAME,
		    strerror(error));

	xo_open_container("jailgrid");
	if (strcmp(argv[0], "hello") == 0 && argc == 1)
		rc = cmd_hello(&cl);
	else if (strcmp(argv[0], "list") == 0)
		rc = cmd_list(&cl, argc, argv);
	else if (strcmp(argv[0], "start") == 0)
		rc = cmd_action(&cl, JG_ACTION_START, argc, argv);
	else if (strcmp(argv[0], "stop") == 0)
		rc = cmd_action(&cl, JG_ACTION_STOP, argc, argv);
	else if (strcmp(argv[0], "restart") == 0)
		rc = cmd_action(&cl, JG_ACTION_RESTART, argc, argv);
	else if (strcmp(argv[0], "kill") == 0)
		rc = cmd_action(&cl, JG_ACTION_KILL, argc, argv);
	else if (strcmp(argv[0], "address") == 0)
		rc = cmd_address(&cl, argc, argv);
	else if (strcmp(argv[0], "services") == 0 && argc == 1)
		rc = cmd_services(&cl);
	else if (strcmp(argv[0], "service") == 0)
		rc = cmd_service(&cl, argc, argv);
	else if (strcmp(argv[0], "net") == 0)
		rc = cmd_net(&cl, argc, argv);
	else
		usage();
	xo_close_container("jailgrid");
	xo_finish();

	jg_client_fini(&cl);
	cbl_conn_free(conn);
	cbl_tls_free(tls);
	(void)cbl_ctx_free(ctx);
	return (rc);
}
