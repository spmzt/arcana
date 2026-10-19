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
#include <poll.h>
#include <sha256.h>
#include <stdbool.h>
#include <readpassphrase.h>
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
static bool	safe;		/* -s: undo the change unless confirmed */
static uint32_t	safe_wait;	/* -W: for how long, 0 the agent's own */
static bool	persist;	/* -p: keep the change in rc.conf too */
static uint32_t	fib;		/* -F: the routing table */
static const char *netjail;	/* -j: the vnet jail whose network it is */

static const char *job_states[] = {
	[ARC_JOB_STATE_QUEUED] = "queued",
	[ARC_JOB_STATE_RUNNING] = "running",
	[ARC_JOB_STATE_DONE] = "done",
	[ARC_JOB_STATE_CANCELLED] = "cancelled",
	[ARC_JOB_STATE_UNCONFIRMED] = "unconfirmed",
};

static void	usage(void) __dead2;
static void	fail(struct arc_client *, int, const char *) __dead2;
static char	*slurp(const char *);
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
static int	cmd_kmod(struct arc_client *, int, char **);
static int	cmd_sysctl(struct arc_client *, int, char **);
static int	cmd_gula(struct arc_client *, int, char **);
static int	cmd_ipfw(struct arc_client *, int, char **);
static int	cmd_l2(struct arc_client *, int, char **);
static int	cmd_transport(struct arc_client *, int, char **);
static int	cmd_config_export(struct arc_client *, int, char **);
static int	cmd_config_apply(struct arc_client *, int, char **);
static int	cmd_path_check(struct arc_client *, int, char **);
static int	cmd_notify(struct arc_client *, int, char **);
static int	cmd_storage(struct arc_client *, int, char **);
static int	cmd_storage_job(struct arc_client *, int, char **);
static int	cmd_fstab(struct arc_client *, int, char **);
static int	cmd_packages(struct arc_client *, int, char **);
static int	cmd_pkg_clean(struct arc_client *, int, char **);
static int	cmd_pkg_install(struct arc_client *, int, char **);
static int	cmd_ipsec(struct arc_client *, int, char **);
static int	cmd_pkg_upgrade(struct arc_client *, int, char **);
static void	emit_packages(const struct arc_package *, size_t);
static int	submit(struct arc_client *, struct arc_job_spec *);
static void	emit_job(const struct arc_job *);
static int	cmd_jobs(struct arc_client *);
static int	cmd_job(struct arc_client *, int, char **);
static int	cmd_interface(struct arc_client *, int, char **);
static int	cmd_job_cancel(struct arc_client *, int, char **);
static int	cmd_service(struct arc_client *, int, char **);
static void	emit_service(const struct arc_service *, bool);

static void
usage(void)
{

	xo_error("usage: arcanactl [-pqst] [-F fib] [-j jail] [-W seconds] "
	    "[-c uri] "
	    "[-A cafile -C certfile\n                 -K keyfile] [-N name] "
	    "command\n"
	    "commands:\n"
	    "    hello\n"
	    "    list [-c]\n"
	    "    start | stop | restart | kill jail\n"
	    "    address add | remove [-lnp] [-i interface] jail address\n"
	    "    services\n"
	    "    service name start | stop | restart | reload | enable | "
	    "disable\n"
	    "    service name config [-x key ...] [key=value ...]\n"
	    "    net routes | nexthops | connections | sockets | interfaces | "
	    "netgraph |\n        wireguard | bird [-4 | -6]\n"
	    "    net routes [-4 | -6] text\n"
	    "    net routes [-4 | -6] -o rows\n"
	    "    net routes | connections | sockets [-4 | -6] parts [text]\n"
	    "    net neighbours [-4 | -6] [text]\n"
	    "    interface name up | down | destroy\n"
	    "    interface name give | take jail\n"
	    "    interface epair give jail [bridge]\n"
	    "    interface name add | remove address\n"
	    "    interface name mtu number\n"
	    "    interface name description text\n"
	    "    interface name fib | tunnelfib number\n"
	    "    interface name addressing dhcp | slaac | static | was\n"
	    "    interface name create [tunnel local remote] [address "
	    "address [peer address]]\n        [mtu number] [description "
	    "text] [id number] [parent interface] [reqid number]\n"
	    "        [fib number] [tunnelfib number]\n"
	    "    route add destination gateway[@share][,gateway[@share]...] [metric n] [weight n] "
	    "[source address]\n"
	    "    route delete destination [gateway] [metric n]\n"
	    "    route get address\n"
	    "    traceroute address\n"
	    "    sdwan [probes | rules | steer | bird | dhcp | dns | proxy | ids json]\n"
	    "    ng mkpeer | connect | rmhook | shutdown | name argument "
	    "...\n"
	    "    wg interface init [port]\n"
	    "    wg interface peer key [endpoint address:port] [allowed-ips "
	    "list]\n        [keepalive seconds]\n"
	    "    wg interface unpeer key\n"
	    "    ipsec init | start\n"
	    "    ipsec conn name local remote [mode tunnel | transport] [pubkey key |\n"
	    "        remote-cert file | remote-ca file] [local-cert file] [reqid n]\n"
	    "        [local-ts list] [remote-ts list] [start start | trap | none]\n"
	    "        [local-id id] [remote-id id]\n"
	    "    ipsec child conn name tunnel | transport [reqid n] [local-ts list]\n"
	    "        [remote-ts list] [start start | trap | none]\n"
	    "    ipsec unchild conn name\n"
	    "    ipsec-sa set interface reqid local remote spi-in n spi-out n\n"
	    "        enc alg [auth alg] key-in hex key-out hex [akey-in hex\n"
	    "        akey-out hex] [encap] [esn]\n"
	    "    ipsec-sa key interface [next]\n"
	    "    ipsec-sa derive interface reqid local remote peer key enc alg\n"
	    "        [auth alg] [epoch n] [encap] [esn] [lifetime s] [next]\n"
	    "        [install both | in | out]\n"
	    "    ipsec-sa commit | clear interface reqid local remote\n"
	    "    ipsec unconn | up | down name\n"
	    "    bird enable | disable | restart | reload protocol\n"
	    "    bird configure\n"
	    "    bird config [file]\n"
	    "    bird config -w new-text [-n] [file]\n"
	    "    bird confirm\n"
	    "    bird routes [prefix | for address] [protocol | export name]\n"
	    "        [table name] [all]\n"
	    "    stats\n"
	    "    kmod [load | unload | keep | forget module]\n"
	    "    jailconf make jail file [dataset snapshot clone|send path] "
	    "[start]\n"
	    "    jailconf edit jail file | remove jail [dataset] |\n"
	    "        defaults file | template name file | untemplate name |\n"
	    "        files\n"
	    "    jailconf template name file | untemplate name\n"
	    "    neigh add address lladdr [temp] | delete address\n"
	    "    carp add interface address vhid=n [word=value ...] [key] |\n"
	    "        set interface vhid=n [word=value ...] [key] |\n"
	    "        remove interface address vhid=n\n"
	    "    cert [list] | add name file | remove name | trust file |\n"
	    "        untrust file | rehash\n"
	    "    poudriere [list] | show-options key=value ... |\n"
	    "        make-conf name|- file|- | verb [key=value ...]\n"
	    "    crashes [backtrace core [program]]\n"
	    "    clamav mirrors mirror ...\n"
	    "    netstore [nfs | iscsi | hast]\n"
	    "    system [file | host]\n"
	    "    sysfile file path | periodic name=YES|NO ... |\n"
	    "        rc kern_securelevel_enable=YES|NO kern_securelevel=N\n"	    "    geom class subcommand [word ...] [-P passfile]\n"
	    "    nfs exports file | server key=value ...\n"
	    "    iscsi conf file | enable yes|no\n"
	    "    hast conf file | enable yes|no | create resource |\n"
	    "        role init|primary|secondary resource\n"
	    "    suricata update | rules [q=text sid=N only=enabled|disabled|changed\n"
	    "        classtype=name offset=N limit=N | sources=1 |\n"
	    "        instance=name command=command [iface=interface]] |\n"
	    "        rule on=|off=|drop=|default=sid,... ... | sources |\n"
	    "        source-enable name=source [param=value ...] |\n"
	    "        source-disable|source-remove name=source |\n"
	    "        source-add name=source url=address |\n"
	    "        pcap instance=name file=path\n"
	    "    capture [source packets seconds [filter ...]]\n"
	    "    zfskey [-n] dataset\n"
	    "    tls [status] | csr | install certfile|- [cafile]\n"
	    "    sshd [list] | banner file | set Setting [value ...] |\n"
	    "        authorize user keyfile | unauthorize user fingerprint |\n"
	    "        options user fingerprint [options] |\n"
	    "        sign ca-key-file [principal ...] | user-cas file\n"
	    "    ntp server ... | remove\n"
	    "    rtadvd interface prefix [dns ...] | interface remove\n"
	    "    sysctl [name | start of a name]\n"
	    "    sysctl parts [name | start of a name]\n"
	    "    sysctl name=value\n"
	    "    transport [retry | listen uri | unlisten uri [for uri [keep]]]\n"
	    "    config-export [-s]\n"
	    "    config-apply [-an] [-H hostname] bundle.json\n"
	    "    path-check [-r] [-F fib] [-i interface] [-p proto] [-P port] src dst\n"
	    "    notify chat text   (the bot's token in ARCANA_TELEGRAM_TOKEN)\n"
	    "    ps [pid]\n"
	    "    signal pid [name | number]\n"
	    "    renice pid nice\n"
	    "    log [-o lines] [-f position] [name [text]]\n"
	    "    history [after]\n"
	    "    history set seconds samples [cpu%% mem%% swap%%] "
	    "[rules list]\n"
	    "    events [after | -f]\n"
	    "    net bridges | geneve | ipfw | nhgroups\n"
	    "    bridge name addm | deletem member\n"
	    "    bridge name access member vlan\n"
	    "    bridge name trunk member vlan-list [untagged-vlan]\n"
	    "    bridge name vlanfilter on | off\n"
	    "    bridge name flag member [-]flag\n"
	    "    bridge name deladdr address | static member address | flush\n"
	    "    bridge name set option value\n"
	    "    bridge name ifset member option value\n"
	    "    geneve name create | set option value ...\n"
	    "    geneve name flush [all]\n"
	    "    ipfw [keep] add number rule ...\n"
	    "    ipfw [keep] delete number\n"
	    "    ipfw [keep] replace number new-number rule ...\n"
	    "    ipfw alias name addr address ... | ports 80,443 | value word | delete\n"
	    "    ipfw apply | enable | disable | zero [number]\n"
	    "    ipfw table | nat | nat64lsn | nat64stl | nat64clat | nptv6 | "
	    "pipe |\n        queue | sched name word ...\n"
	    "    ipfw rules [-r | -w file [-n]]\n"
	    "    ipfw trace address [seconds [packets]]\n"
	    "    storage disks | pools | datasets | mounts | importable | health\n"
	    "    zfs load-key | unload-key [-r] dataset\n"
	    "    zfs jail | unjail dataset jail\n"
	    "    zfs replicate [-r] snapshot new-dataset [since-snapshot]\n"
	    "    gpart newfs [-f] partition [label]\n"
	    "    gpart newfs-msdos [-f] partition [label]\n"
	    "    gpart growfs partition\n"
	    "    swapon | swapoff device\n"
	    "    storage snapshots [dataset]\n"
	    "    zfs snapshot | destroy | rollback [-r] name\n"
	    "    zfs resnapshot [-r] snapshot\n"
	    "    zfs create dataset [property=value ...]\n"
	    "    zfs set dataset property=value ...\n"
	    "    zfs inherit dataset property\n"
	    "    zfs mount | unmount [-f] | promote dataset\n"
	    "    zfs clone snapshot dataset\n"
	    "    zfs rename name name\n"
	    "    zpool scrub | scrub-stop | trim pool\n"
	    "    zpool clear pool [device]\n"
	    "    zpool online | offline pool device\n"
	    "    zpool create [-f] pool [mirror | raidz1 ...] device ... "
	    "[mountpoint=path]\n"
	    "    zpool add [-f] pool [mirror | log | cache ...] device ...\n"
	    "    zpool destroy | export [-f] pool\n"
	    "    zpool import [-f] pool [altroot=path]\n"
	    "    zpool attach pool device new-device\n"
	    "    zpool detach | remove pool device\n"
	    "    zpool replace pool device [new-device]\n"
	    "    mount path\n"
	    "    umount [-f] path\n"
	    "    gpart create disk gpt | mbr | bsd\n"
	    "    gpart add disk type [size [label]]\n"
	    "    gpart delete disk index\n"
	    "    gpart resize disk index [size]\n"
	    "    gpart modify disk index label\n"
	    "    gpart destroy disk\n"
	    "    cam rescan\n"
	    "    fstab [-w new-text [-n]]\n"
	    "    packages [-i] [-r] [-4 | -6] [jail]\n"
	    "    pkg-upgrade [-n] [-O] [-4 | -6] [-r repo] [-j jail | -J] "
	    "[package ...]\n"
	    "    pkg-clean [-a] [-j jail | -J]\n"
	    "    pkg-install [-O] [-4 | -6] [-r repo] [-j jail] package ...\n"
	    "    jobs\n"
	    "    job [-w] id\n"
	    "    job-cancel id\n"
	    "    agent-update [-r] program\n"
	    "    agent-build [-y] [-i key] [-o file] repository [ref]\n"
	    "    console-update [-y] [-i key] repository [ref]\n"
	    "    source-head [-y] [-i key] repository [ref]\n"
	    "    source-log [-i key] [-n count] repository [ref]\n"
	    "with -q, start, stop, restart, kill, address, service (but "
	    "config without\nvalues) and pkg-upgrade are queued as a job "
	    "instead of waited for.\n-p keeps a change to an interface or a "
	    "route in rc.conf too, -s has it undone\nunless this program "
	    "reaches the host again, -F names a routing table,\n-j a running "
	    "jail with a network of its own (vnet), for net, route,\n"
	    "interface, ng, wg and bird to work in instead of the host.\n");
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
		/* For a program that reads this: its plugins, if it has. */
		for (i = 0; i < j->plugins.n; i++)
			xo_emit("{el:plugins/%s}", j->plugins.v[i]);
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
	if (j->plugins.n > 0) {
		xo_emit("{Lwc:Plugins}");
		xo_open_list("plugins");
		for (i = 0; i < j->plugins.n; i++)
			xo_emit("{P:/%s}{l:plugins/%s}", i > 0 ? " " : "",
			    j->plugins.v[i]);
		xo_close_list("plugins");
		xo_emit("\n");
	}
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
	if (h->build != NULL)
		xo_emit("{Lwc:Build}{:build/%s}\n", h->build);
	/* What is installed there that is not the base system's. */
	if (h->plugins.n > 0) {
		size_t	i;

		xo_emit("{Lwc:Plugins}");
		xo_open_list("plugins");
		for (i = 0; i < h->plugins.n; i++)
			xo_emit("{P:/%s}{l:plugins/%s}", i > 0 ? " " : "",
			    h->plugins.v[i]);
		xo_close_list("plugins");
		xo_emit("\n");
	}
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
	if ((queue || safe) && !req.dry_run) {
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
		if (queue || safe) {
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
	if ((queue || safe) && nv > 0) {
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
		if (rsp->commit != NULL)
			xo_emit("{Lwc:Commit}{:commit/%s}\n", rsp->commit);
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
	if (rsp->ok && rsp->commit != NULL)
		xo_emit("{Lwc:Commit}{:commit/%s}\n", rsp->commit);
	error = rsp->ok ? 0 : 1;
	arc_console_update_rsp_free(rsp);
	free(keys);
	return (error);
}

/*
 * source-head [-y] [-i key] repository [ref]: the commit at the head of
 * the repository's branch, as the host sees it: whether there is
 * anything new to build.
 */
static int
cmd_source_head(struct arc_client *cl, int argc, char **argv)
{
	struct arc_source_head_req	 req;
	struct arc_source_head_rsp	*rsp;
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
	if ((error = arc_source_head(cl, &req, &rsp)) != 0)
		fail(cl, error, "source-head");
	emit_trace(rsp->trace.v, rsp->trace.n);
	if (!rsp->ok && rsp->host_keys != NULL) {
		for (i = 0; i < rsp->fingerprints.n; i++)
			xo_emit("{Lwc:Host key}{l:fingerprint/%s}\n",
			    rsp->fingerprints.v[i]);
		if (trust && keys == NULL) {
			if ((keys = strdup(rsp->host_keys)) == NULL)
				xo_err(1, "strdup");
			req.host_keys = keys;
			arc_source_head_rsp_free(rsp);
			goto again;
		}
	}
	if (!rsp->ok && rsp->deploy_key != NULL)
		xo_emit("{Lwc:Deploy key}{:deploy-key/%s}\n", rsp->deploy_key);
	if (rsp->ok)
		xo_emit("{Lwc:Commit}{:commit/%s}\n", rsp->commit);
	else
		xo_warnx("source-head: %s", rsp->error != NULL ? rsp->error :
		    "failed");
	error = rsp->ok ? 0 : 1;
	arc_source_head_rsp_free(rsp);
	free(keys);
	return (error);
}

/*
 * source-log [-i key] [-n count] repository [ref]: the latest commits
 * of the repository's branch, newest first, and its tags: what is new.
 */
static int
cmd_source_log(struct arc_client *cl, int argc, char **argv)
{
	struct arc_source_log_req	 req;
	struct arc_source_log_rsp	*rsp;
	const char			*errstr;
	int				 ch, error;

	memset(&req, 0, sizeof(req));
	optreset = optind = 1;
	while ((ch = getopt(argc, argv, "i:n:")) != -1) {
		switch (ch) {
		case 'i':
			req.ssh_key = optarg;
			break;
		case 'n':
			req.has_count = true;
			req.count = (uint32_t)strtonum(optarg, 1, 10000, &errstr);
			if (errstr != NULL)
				xo_errx(2, "count %s: %s", optarg, errstr);
			break;
		default:
			usage();
		}
	}
	if (argc - optind < 1 || argc - optind > 2)
		usage();
	req.source = argv[optind];
	req.ref = argv[optind + 1];
	if ((error = arc_source_log(cl, &req, &rsp)) != 0)
		fail(cl, error, "source-log");
	emit_trace(rsp->trace.v, rsp->trace.n);
	if (!rsp->ok) {
		if (rsp->deploy_key != NULL)
			xo_emit("{Lwc:Deploy key}{:deploy-key/%s}\n",
			    rsp->deploy_key);
		xo_warnx("source-log: %s", rsp->error != NULL ? rsp->error :
		    "failed");
		arc_source_log_rsp_free(rsp);
		return (1);
	}
	xo_emit("{Lwc:Commit}{:commit/%s}\n", rsp->commit);
	/* The commits and the tags as the agent lists them, JSON each. */
	xo_emit("{Lwc:Commits}{:commits/%s}\n", rsp->log != NULL ? rsp->log :
	    "[]");
	xo_emit("{Lwc:Tags}{:tags/%s}\n", rsp->tags != NULL ? rsp->tags : "[]");
	arc_source_log_rsp_free(rsp);
	return (0);
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

/*
 * interface name up | down, interface name add | remove address: a job,
 * waited for unless it is only queued (-q).
 */
/*
 * bird config [file]: print a file of BIRD's configuration.
 * bird config -w new-text [-n] [file]: put the text of a local file in
 * its place, or with -n only have it parsed.
 */
static int
cmd_bird_config(struct arc_client *cl, int argc, char **argv)
{
	struct arc_bird_config_req	 req;
	struct arc_bird_config_rsp	*rsp, *cur;
	struct stat			 sb;
	const char			*from;
	char				*text;
	size_t				 i;
	int				 ch, error, fd;

	from = NULL;
	memset(&req, 0, sizeof(req));
	optind = 1;
	optreset = 1;
	while ((ch = getopt(argc, argv, "nw:")) != -1) {
		switch (ch) {
		case 'n':
			req.dry_run = true;
			break;
		case 'w':
			from = optarg;
			break;
		default:
			usage();
		}
	}
	if (argc - optind > 1 || (req.dry_run && from == NULL))
		usage();
	req.conf_path = argc - optind == 1 ? argv[optind] : NULL;
	req.jail = netjail;
	req.safe = safe && from != NULL && !req.dry_run;
	req.has_safe_wait = req.safe && safe_wait > 0;
	req.safe_wait = safe_wait;
	text = NULL;
	cur = NULL;
	if (from != NULL) {
		if ((fd = open(from, O_RDONLY)) == -1 || fstat(fd, &sb) == -1 ||
		    (text = malloc((size_t)sb.st_size + 1)) == NULL ||
		    read(fd, text, (size_t)sb.st_size) != sb.st_size)
			xo_err(1, "%s", from);
		close(fd);
		text[sb.st_size] = '\0';
		/* What is there now says what the new text replaces. */
		if ((error = arc_bird_config(cl, &req, &cur)) != 0)
			fail(cl, error, "bird config");
		req.sha256 = cur->sha256 != NULL ? cur->sha256 :
		    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b"
		    "7852b855";
		req.conf_text = text;
	}
	if ((error = arc_bird_config(cl, &req, &rsp)) != 0)
		fail(cl, error, "bird config");
	if (from == NULL && rsp->conf_text != NULL)
		xo_emit("{:text/%s}", rsp->conf_text);
	else if (rsp->ok)
		xo_emit("{:path/%s}: {:result/%s}\n", rsp->conf_path != NULL ?
		    rsp->conf_path : "", req.dry_run ? "parses; left as it "
		    "was" : req.safe ? "in place, and BIRD told; taken back "
		    "unless confirmed (bird confirm)" : "in place, and BIRD "
		    "told");
	if (rsp->ok && rsp->has_confirm_by)
		xo_emit("{e:confirm-by/%jd}", (intmax_t)rsp->confirm_by);
	if (from == NULL)
		for (i = 1; i < rsp->files.n; i++)
			xo_emit("{e:file/%s}", rsp->files.v[i]);
	emit_trace(rsp->trace.v, rsp->trace.n);
	error = rsp->ok ? 0 : 1;
	if (!rsp->ok)
		xo_warnx("bird config: %s", rsp->error != NULL ? rsp->error :
		    "failed");
	arc_bird_config_rsp_free(rsp);
	if (cur != NULL)
		arc_bird_config_rsp_free(cur);
	free(text);
	return (error);
}

/* bird confirm: the configuration changed in safe mode stays. */
static int
cmd_bird_confirm(struct arc_client *cl)
{
	struct arc_bird_config_req	 req;
	struct arc_bird_config_rsp	*rsp;
	int				 error;

	memset(&req, 0, sizeof(req));
	req.confirm = true;
	req.jail = netjail;
	if ((error = arc_bird_config(cl, &req, &rsp)) != 0)
		fail(cl, error, "bird confirm");
	if (rsp->ok)
		xo_emit("{:result/%s}\n", "confirmed: it stays");
	emit_trace(rsp->trace.v, rsp->trace.n);
	error = rsp->ok ? 0 : 1;
	if (!rsp->ok)
		xo_warnx("bird confirm: %s", rsp->error != NULL ? rsp->error :
		    "failed");
	arc_bird_config_rsp_free(rsp);
	return (error);
}

/* bird routes [words]: routes of BIRD's tables, said in birdc's words. */
static int
cmd_bird_routes(struct arc_client *cl, int argc, char **argv)
{
	struct arc_network_req	 req;
	struct arc_network_rsp	*rsp;
	char			 words[256];
	int			 i, error;

	words[0] = '\0';
	for (i = 0; i < argc; i++) {
		if (i > 0)
			strlcat(words, " ", sizeof(words));
		if (strlcat(words, argv[i], sizeof(words)) >= sizeof(words))
			usage();
	}
	memset(&req, 0, sizeof(req));
	req.has_net_kind = true;
	req.net_kind = ARC_NET_KIND_BIRD_ROUTES;
	req.net_filter = words[0] != '\0' ? words : NULL;
	req.jail = netjail;
	if ((error = arc_network(cl, &req, &rsp)) != 0)
		fail(cl, error, "bird routes");
	if (rsp->json != NULL)
		xo_emit("{:json/%s}\n", rsp->json);
	emit_trace(rsp->trace.v, rsp->trace.n);
	error = rsp->ok ? 0 : 1;
	if (!rsp->ok)
		xo_warnx("bird routes: %s", rsp->error != NULL ? rsp->error :
		    "failed");
	arc_network_rsp_free(rsp);
	return (error);
}

/* route get address: the route the host would take, and the others. */
static int
cmd_route_get(struct arc_client *cl, int argc, char **argv)
{
	struct arc_route_lookup_req	 req;
	struct arc_route_lookup_rsp	*rsp;
	int				 error;

	if (argc != 3)
		usage();
	memset(&req, 0, sizeof(req));
	req.lookup = argv[2];
	req.has_net_fib = fib != 0;
	req.net_fib = fib;
	req.jail = netjail;
	if ((error = arc_route_lookup(cl, &req, &rsp)) != 0)
		fail(cl, error, "route get");
	if (rsp->json != NULL)
		xo_emit("{:json/%s}\n", rsp->json);
	emit_trace(rsp->trace.v, rsp->trace.n);
	error = rsp->ok ? 0 : 1;
	if (!rsp->ok)
		xo_warnx("route get %s: %s", argv[2], rsp->error != NULL ?
		    rsp->error : "failed");
	arc_route_lookup_rsp_free(rsp);
	return (error);
}

static int	json_out(const char *, bool, const char *, const char *,
		    const struct arc_step *, size_t);

/* traceroute address: one round, a probe a hop, as JSON. */
/* sdwan: what the probes have seen; sdwan probes json: the targets. */
/* A JSON argument: as given, or the contents of a file after @. */
static const char *
json_arg(const char *arg)
{
	FILE	*fp;
	char	*text;
	size_t	len, n;

	if (arg == NULL || arg[0] != '@')
		return (arg);
	if ((fp = fopen(arg + 1, "r")) == NULL)
		xo_err(1, "%s", arg + 1);
	if ((text = malloc(8 * 1024 * 1024)) == NULL)
		xo_err(1, "malloc");
	for (len = 0; len < 8 * 1024 * 1024 - 1; len += n)
		if ((n = fread(text + len, 1, 8 * 1024 * 1024 - 1 - len, fp)) == 0)
			break;
	text[len] = '\0';
	fclose(fp);
	return (text);
}

static int
cmd_sdwan(struct arc_client *cl, int argc, char **argv)
{
	struct arc_sdwan_req		 req;
	struct arc_sdwan_rsp		*rsp;
	struct arc_sdwan_probes_req	 preq;
	struct arc_sdwan_probes_rsp	*prsp;
	int				 error;

	if (argc == 3 && strcmp(argv[1], "probes") == 0) {
		memset(&preq, 0, sizeof(preq));
		preq.json = argv[2];
		if ((error = arc_sdwan_probes(cl, &preq, &prsp)) != 0)
			fail(cl, error, "sdwan probes");
		error = json_out("sdwan-probes", prsp->ok, prsp->error, NULL,
		    prsp->trace.v, prsp->trace.n);
		arc_sdwan_probes_rsp_free(prsp);
		return (error);
	}
	if (argc == 3 && strcmp(argv[1], "rules") == 0) {
		struct arc_sdwan_rules_req	 rq;
		struct arc_sdwan_rules_rsp	*rs;

		memset(&rq, 0, sizeof(rq));
		rq.json = json_arg(argv[2]);
		if ((error = arc_sdwan_rules(cl, &rq, &rs)) != 0)
			fail(cl, error, "sdwan rules");
		error = json_out("sdwan-rules", rs->ok, rs->error, NULL,
		    rs->trace.v, rs->trace.n);
		arc_sdwan_rules_rsp_free(rs);
		return (error);
	}
	if (argc == 3 && strcmp(argv[1], "steer") == 0) {
		struct arc_sdwan_steer_req	 rq;
		struct arc_sdwan_steer_rsp	*rs;

		memset(&rq, 0, sizeof(rq));
		rq.json = json_arg(argv[2]);
		if ((error = arc_sdwan_steer(cl, &rq, &rs)) != 0)
			fail(cl, error, "sdwan steer");
		error = json_out("sdwan-steer", rs->ok, rs->error, NULL,
		    rs->trace.v, rs->trace.n);
		arc_sdwan_steer_rsp_free(rs);
		return (error);
	}
	if (argc == 3 && strcmp(argv[1], "bird") == 0) {
		struct arc_sdwan_bird_req	 rq;
		struct arc_sdwan_bird_rsp	*rs;

		memset(&rq, 0, sizeof(rq));
		rq.json = json_arg(argv[2]);
		if ((error = arc_sdwan_bird(cl, &rq, &rs)) != 0)
			fail(cl, error, "sdwan bird");
		error = json_out("sdwan-bird", rs->ok, rs->error, NULL,
		    rs->trace.v, rs->trace.n);
		arc_sdwan_bird_rsp_free(rs);
		return (error);
	}
	if (argc == 3 && strcmp(argv[1], "dhcp") == 0) {
		struct arc_sdwan_dhcp_req	 rq;
		struct arc_sdwan_dhcp_rsp	*rs;

		memset(&rq, 0, sizeof(rq));
		rq.json = json_arg(argv[2]);
		if ((error = arc_sdwan_dhcp(cl, &rq, &rs)) != 0)
			fail(cl, error, "sdwan dhcp");
		error = json_out("sdwan-dhcp", rs->ok, rs->error, NULL,
		    rs->trace.v, rs->trace.n);
		arc_sdwan_dhcp_rsp_free(rs);
		return (error);
	}
	if (argc == 3 && strcmp(argv[1], "ids") == 0) {
		struct arc_sdwan_ids_req	 rq;
		struct arc_sdwan_ids_rsp	*rs;

		memset(&rq, 0, sizeof(rq));
		rq.json = json_arg(argv[2]);
		if ((error = arc_sdwan_ids(cl, &rq, &rs)) != 0)
			fail(cl, error, "sdwan ids");
		error = json_out("sdwan-ids", rs->ok, rs->error, NULL,
		    rs->trace.v, rs->trace.n);
		arc_sdwan_ids_rsp_free(rs);
		return (error);
	}
	if (argc == 3 && strcmp(argv[1], "proxy") == 0) {
		struct arc_sdwan_proxy_req	 rq;
		struct arc_sdwan_proxy_rsp	*rs;

		memset(&rq, 0, sizeof(rq));
		rq.json = json_arg(argv[2]);
		if ((error = arc_sdwan_proxy(cl, &rq, &rs)) != 0)
			fail(cl, error, "sdwan proxy");
		error = json_out("sdwan-proxy", rs->ok, rs->error, NULL,
		    rs->trace.v, rs->trace.n);
		arc_sdwan_proxy_rsp_free(rs);
		return (error);
	}
	if (argc == 3 && strcmp(argv[1], "dns") == 0) {
		struct arc_sdwan_dns_req	 rq;
		struct arc_sdwan_dns_rsp	*rs;

		memset(&rq, 0, sizeof(rq));
		rq.json = json_arg(argv[2]);
		if ((error = arc_sdwan_dns(cl, &rq, &rs)) != 0)
			fail(cl, error, "sdwan dns");
		error = json_out("sdwan-dns", rs->ok, rs->error, NULL,
		    rs->trace.v, rs->trace.n);
		arc_sdwan_dns_rsp_free(rs);
		return (error);
	}
	if (argc != 1)
		usage();
	memset(&req, 0, sizeof(req));
	if ((error = arc_sdwan(cl, &req, &rsp)) != 0)
		fail(cl, error, "sdwan");
	error = json_out("sdwan", rsp->ok, rsp->error, rsp->json, rsp->trace.v,
	    rsp->trace.n);
	arc_sdwan_rsp_free(rsp);
	return (error);
}

static int
cmd_traceroute(struct arc_client *cl, int argc, char **argv)
{
	struct arc_traceroute_req	 req;
	struct arc_traceroute_rsp	*rsp;
	int				 error;

	if (argc != 2)
		usage();
	memset(&req, 0, sizeof(req));
	req.lookup = argv[1];
	if ((error = arc_traceroute(cl, &req, &rsp)) != 0)
		fail(cl, error, "traceroute");
	error = json_out("traceroute", rsp->ok, rsp->error, rsp->json,
	    rsp->trace.v, rsp->trace.n);
	arc_traceroute_rsp_free(rsp);
	return (error);
}

static int
cmd_interface(struct arc_client *cl, int argc, char **argv)
{
	struct arc_job_spec		 sp;
	const char			*errstr;
	uint32_t			 num;
	int				 i;

	if (argc < 3 && !(argc == 2 && strcmp(argv[0], "bird") == 0))
		usage();
	memset(&sp, 0, sizeof(sp));
	sp.has_kind = true;
	sp.persist = persist;
	sp.jail = netjail;
	if (strcmp(argv[0], "ng") == 0) {
		sp.kind = ARC_JOB_KIND_NETGRAPH;
		sp.verb = argv[1];
		sp.names.v = (const char **)(uintptr_t)&argv[2];
		sp.names.n = (size_t)argc - 2;
		sp.persist = false;
		goto send;
	}
	if (strcmp(argv[0], "bird") == 0 && strcmp(argv[1], "config") == 0)
		return (cmd_bird_config(cl, argc - 1, argv + 1));
	if (strcmp(argv[0], "bird") == 0 && strcmp(argv[1], "routes") == 0)
		return (cmd_bird_routes(cl, argc - 2, argv + 2));
	if (strcmp(argv[0], "bird") == 0 && strcmp(argv[1], "confirm") == 0 &&
	    argc == 2)
		return (cmd_bird_confirm(cl));
	if (strcmp(argv[0], "bird") == 0) {
		sp.kind = ARC_JOB_KIND_BIRD;
		sp.verb = argv[1];
		sp.names.v = (const char **)(uintptr_t)&argv[2];
		sp.names.n = (size_t)argc - 2;
		sp.persist = false;
		goto send;
	}
	if (strcmp(argv[0], "wg") == 0) {
		/* wg interface init [port] | peer key [...] | unpeer key */
		sp.kind = ARC_JOB_KIND_WIREGUARD;
		sp.interface = argv[1];
		sp.verb = argv[2];
		if (strcmp(argv[2], "init") == 0) {
			if (argc == 4) {
				sp.has_listen_port = true;
				sp.listen_port = (uint32_t)strtonum(argv[3], 1,
				    65535, &errstr);
				if (errstr != NULL)
					xo_errx(2, "port %s: %s", argv[3],
					    errstr);
			} else if (argc != 3)
				usage();
			goto send;
		}
		if (argc < 4)
			usage();
		sp.peer = argv[3];
		for (i = 4; i + 1 < argc; i += 2) {
			if (strcmp(argv[i], "endpoint") == 0)
				sp.endpoint = argv[i + 1];
			else if (strcmp(argv[i], "allowed-ips") == 0)
				sp.allowed_ips = argv[i + 1];
			else if (strcmp(argv[i], "preshared-key") == 0) {
				/* From a file, as wg(8) takes it: not
				 * on a command line. */
				char	*k = slurp(argv[i + 1]);

				k[strcspn(k, "\r\n")] = '\0';
				sp.preshared_key = k;
			}
			else if (strcmp(argv[i], "keepalive") == 0) {
				sp.has_keepalive = true;
				sp.keepalive = (uint32_t)strtonum(argv[i + 1],
				    0, 65535, &errstr);
				if (errstr != NULL)
					xo_errx(2, "keepalive %s: %s",
					    argv[i + 1], errstr);
			} else
				usage();
		}
		if (i != argc)
			usage();
		goto send;
	}
	if (strcmp(argv[0], "route") == 0 && strcmp(argv[1], "get") == 0)
		return (cmd_route_get(cl, argc, argv));
	if (strcmp(argv[0], "route") == 0) {
		/* route add destination gateway | delete destination [gw] */
		sp.kind = ARC_JOB_KIND_ROUTE;
		sp.has_fib = fib != 0;
		sp.fib = fib;
		sp.remove = strcmp(argv[1], "delete") == 0;
		if (!sp.remove && (strcmp(argv[1], "add") != 0 || argc < 4))
			usage();
		sp.destination = argv[2];
		/* Then the gateway, and words with what follows each. */
		i = 3;
		if (i < argc && strcmp(argv[i], "metric") != 0 && strcmp(
		    argv[i], "weight") != 0 && strcmp(argv[i], "source") != 0)
			sp.gateway = argv[i++];
		for (; i + 1 < argc; i += 2) {
			if (strcmp(argv[i], "source") == 0) {
				sp.source = argv[i + 1];
				continue;
			}
			num = (uint32_t)strtonum(argv[i + 1], 1, UINT32_MAX,
			    &errstr);
			if (errstr != NULL)
				xo_errx(2, "%s %s: %s", argv[i], argv[i + 1],
				    errstr);
			if (strcmp(argv[i], "metric") == 0) {
				sp.has_metric = true;
				sp.metric = num;
			} else if (strcmp(argv[i], "weight") == 0) {
				sp.has_weight = true;
				sp.weight = num;
			} else
				usage();
		}
		if (i != argc || (!sp.remove && sp.gateway == NULL))
			usage();
		goto send;
	}
	sp.interface = argv[1];
	if ((strcmp(argv[2], "up") == 0 || strcmp(argv[2], "down") == 0) &&
	    argc == 3) {
		sp.kind = ARC_JOB_KIND_IF_STATE;
		sp.has_up = true;
		sp.up = strcmp(argv[2], "up") == 0;
	} else if ((strcmp(argv[2], "add") == 0 || strcmp(argv[2],
	    "remove") == 0) && argc == 4) {
		sp.kind = ARC_JOB_KIND_IF_ADDRESS;
		sp.address = argv[3];
		sp.remove = strcmp(argv[2], "remove") == 0;
	} else if (strcmp(argv[2], "destroy") == 0 && argc == 3) {
		sp.kind = ARC_JOB_KIND_IF_DESTROY;
	} else if ((strcmp(argv[2], "give") == 0 || strcmp(argv[2],
	    "take") == 0) && (argc == 4 || (argc == 5 && argv[2][0] ==
	    'g'))) {
		/* The jail it goes to or comes from, not one worked in. */
		sp.kind = ARC_JOB_KIND_IF_VNET;
		sp.jail = argv[3];
		sp.remove = strcmp(argv[2], "take") == 0;
		/* And the bridge a new pair's end on the host goes in. */
		sp.parent = argc == 5 ? argv[4] : NULL;
	} else if (strcmp(argv[2], "mtu") == 0 && argc == 4) {
		sp.kind = ARC_JOB_KIND_IF_SET;
		sp.has_mtu = true;
		sp.mtu = (uint32_t)strtonum(argv[3], 68, 65535, &errstr);
		if (errstr != NULL)
			xo_errx(2, "mtu %s: %s", argv[3], errstr);
	} else if (strcmp(argv[2], "description") == 0 && argc == 4) {
		sp.kind = ARC_JOB_KIND_IF_SET;
		sp.description = argv[3];
	} else if (strcmp(argv[2], "addressing") == 0 && argc == 4) {
		sp.kind = ARC_JOB_KIND_IF_SET;
		sp.addressing = argv[3];
	} else if ((strcmp(argv[2], "fib") == 0 || strcmp(argv[2],
	    "tunnelfib") == 0) && argc == 4) {
		sp.kind = ARC_JOB_KIND_IF_SET;
		num = (uint32_t)strtonum(argv[3], 0, 65535, &errstr);
		if (errstr != NULL)
			xo_errx(2, "%s %s: %s", argv[2], argv[3], errstr);
		if (argv[2][0] == 'f') {
			sp.has_fib = true;
			sp.fib = num;
		} else {
			sp.has_tunnelfib = true;
			sp.tunnelfib = num;
		}
	} else if (strcmp(argv[2], "create") == 0) {
		/* Words and what follows each, in any order. */
		sp.kind = ARC_JOB_KIND_IF_CREATE;
		for (i = 3; i < argc; i++) {
			if (strcmp(argv[i], "tunnel") == 0 && i + 2 < argc) {
				sp.tunnel_local = argv[++i];
				sp.tunnel_remote = argv[++i];
			} else if (strcmp(argv[i], "address") == 0 &&
			    i + 1 < argc)
				sp.address = argv[++i];
			else if (strcmp(argv[i], "peer") == 0 && i + 1 < argc)
				sp.destination = argv[++i];
			else if (strcmp(argv[i], "description") == 0 &&
			    i + 1 < argc)
				sp.description = argv[++i];
			else if (strcmp(argv[i], "parent") == 0 && i + 1 < argc)
				sp.parent = argv[++i];
			else if (strcmp(argv[i], "reqid") == 0 && i + 1 < argc) {
				sp.has_reqid = true;
				sp.reqid = (uint32_t)strtonum(argv[++i], 1, 16383,
				    &errstr);
				if (errstr != NULL)
					xo_errx(2, "reqid %s: %s", argv[i], errstr);
			}
			else if ((strcmp(argv[i], "fib") == 0 || strcmp(argv[i],
			    "tunnelfib") == 0) && i + 1 < argc) {
				num = (uint32_t)strtonum(argv[i + 1], 0, 65535,
				    &errstr);
				if (errstr != NULL)
					xo_errx(2, "%s %s: %s", argv[i],
					    argv[i + 1], errstr);
				if (argv[i][0] == 'f') {
					sp.has_fib = true;
					sp.fib = num;
				} else {
					sp.has_tunnelfib = true;
					sp.tunnelfib = num;
				}
				i++;
			} else if ((strcmp(argv[i], "mtu") == 0 ||
			    strcmp(argv[i], "id") == 0) && i + 1 < argc) {
				num = (uint32_t)strtonum(argv[i + 1], 0,
				    16777215, &errstr);
				if (errstr != NULL)
					xo_errx(2, "%s %s: %s", argv[i],
					    argv[i + 1], errstr);
				if (argv[i][0] == 'm') {
					sp.has_mtu = true;
					sp.mtu = num;
				} else {
					sp.has_id = true;
					sp.id = num;
				}
				i++;
			} else
				usage();
		}
	} else
		usage();
send:
	return (submit(cl, &sp));
}

/* A text as a JSON string; what JSON would escape is left out. */
static void
route_str(FILE *fp, const char *key, const char *v, bool *first)
{

	if (v == NULL)
		return;
	fprintf(fp, "%s\"%s\":\"", *first ? "" : ",", key);
	for (; *v != '\0'; v++)
		if (*v != '"' && *v != '\\' && (unsigned char)*v >= 0x20)
			fputc(*v, fp);
	fputc('"', fp);
	*first = false;
}

static void
route_num(FILE *fp, const char *key, bool has, uint32_t v, bool *first)
{

	if (!has)
		return;
	fprintf(fp, "%s\"%s\":%u", *first ? "" : ",", key, v);
	*first = false;
}

/* The typed routes of a part, as the rows of a table: a JSON array. */
static char *
routes_json(const struct arc_route *v, size_t n)
{
	FILE	*fp;
	char	*json;
	size_t	 len, i;
	bool	 first;

	json = NULL;
	if ((fp = open_memstream(&json, &len)) == NULL)
		return (NULL);
	fputc('[', fp);
	for (i = 0; i < n; i++) {
		fprintf(fp, "%s{", i > 0 ? "," : "");
		first = true;
		route_str(fp, "family", v[i].family, &first);
		route_str(fp, "destination", v[i].destination, &first);
		route_str(fp, "gateway", v[i].gateway, &first);
		route_str(fp, "flags", v[i].flags, &first);
		route_num(fp, "nhop", v[i].has_nhop, v[i].nhop, &first);
		route_num(fp, "mtu", v[i].has_mtu, v[i].mtu, &first);
		route_str(fp, "interface-name", v[i].interface_name, &first);
		route_num(fp, "metric", v[i].has_metric, v[i].metric, &first);
		route_num(fp, "weight", v[i].has_weight, v[i].weight, &first);
		route_num(fp, "fib", v[i].has_fib, v[i].fib, &first);
		route_num(fp, "prefixlen", v[i].has_prefixlen, v[i].prefixlen,
		    &first);
		route_str(fp, "source", v[i].source, &first);
		route_num(fp, "path", v[i].has_path, v[i].path, &first);
		route_num(fp, "paths", v[i].has_paths, v[i].paths, &first);
		route_num(fp, "expire-time", v[i].has_expire_time,
		    v[i].expire_time, &first);
		fputc('}', fp);
	}
	fputc(']', fp);
	if (fclose(fp) != 0) {
		free(json);
		return (NULL);
	}
	return (json);
}

/* The program's libxo JSON, printed as it came. */
static int
cmd_net(struct arc_client *cl, int argc, char **argv)
{
	static const char *kinds[] = { "routes", "nexthops", "connections",
	    "sockets", "interfaces", "netgraph", "wireguard", "bird",
	    "bird-routes", "bridges", "geneve", "ipfw", "nhgroups",
	    "neighbours", "ipsec", "multicast" };
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
	req.has_net_fib = fib != 0;
	req.net_fib = fib;
	req.jail = netjail;
	argc--;
	argv++;
	optind = 1;
	while ((ch = getopt(argc, argv, "46o:")) != -1) {
		switch (ch) {
		case 'o':
			/* Read on, after this many rows. */
			req.has_offset = true;
			req.offset = (uint32_t)strtoul(optarg, NULL, 10);
			break;
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
	/* A text to search the routes for, on the host. */
	/* In parts, each printed as it comes: nothing left out for size. */
	if (optind < argc && strcmp(argv[optind], "parts") == 0) {
		struct arc_network_dump_req	 dq;
		struct arc_network_dump_rsp	*item;
		cbl_dump			*d;

		memset(&dq, 0, sizeof(dq));
		dq.has_net_kind = true;
		dq.net_kind = req.net_kind;
		dq.has_net_family = req.has_net_family;
		dq.net_family = req.net_family;
		dq.has_net_fib = req.has_net_fib;
		dq.net_fib = req.net_fib;
		dq.jail = req.jail;
		dq.net_filter = optind + 1 < argc ? argv[optind + 1] : NULL;
		if ((error = arc_network_dump(cl, &dq, &d)) != 0)
			fail(cl, error, "net");
		while ((error = arc_network_dump_next(d, &item)) == 0 && item !=
		    NULL) {
			char	*rows;

			if (item->json != NULL)
				xo_emit("{:json/%s}\n", item->json);
			/* The routes come typed: written as rows. */
			else if (item->routes.n > 0 && (rows = routes_json(
			    item->routes.v, item->routes.n)) != NULL) {
				xo_emit("{:json/%s}\n", rows);
				free(rows);
			}
		}
		cbl_dump_free(d);
		if (error != 0)
			fail(cl, error, "net");
		return (0);
	}
	if (argc - optind == 1 && (req.net_kind == ARC_NET_KIND_ROUTES ||
	    req.net_kind == ARC_NET_KIND_NEIGHBOURS))
		req.net_filter = argv[optind];
	else if (optind != argc)
		usage();
	if ((error = arc_network(cl, &req, &rsp)) != 0)
		fail(cl, error, "net");
	if (rsp->json != NULL)
		xo_emit("{:json/%s}", rsp->json);
	if (rsp->has_total)
		xo_emit("{e:total/%ju}{e:truncated/%s}", (uintmax_t)rsp->total,
		    rsp->truncated ? "true" : "false");
	if (rsp->truncated)
		xo_warnx("net %s: the table has %ju rows, more than a reply "
		    "carries: these are the first; give a text to search for",
		    kinds[i], (uintmax_t)rsp->total);
	emit_trace(rsp->trace.v, rsp->trace.n);
	error = rsp->ok ? 0 : 1;
	if (!rsp->ok)
		xo_warnx("net %s: %s", kinds[i], rsp->error != NULL ?
		    rsp->error : "failed");
	arc_network_rsp_free(rsp);
	return (error);
}

/*
 * kmod: the kernel's modules and its memory, as the host says them.
 * kmod load | unload module: a job; with -p also in rc.conf's kld_list.
 * kmod keep | forget module: rc.conf's kld_list alone, the kernel as is.
 */
/* ntp server...; ntp remove: the NTP servers of the host. */
static int
cmd_ntp(struct arc_client *cl, int argc, char **argv)
{
	struct arc_job_spec	sp;

	if (argc < 2)
		usage();
	memset(&sp, 0, sizeof(sp));
	sp.has_kind = true;
	sp.kind = ARC_JOB_KIND_NTP;
	sp.persist = persist;
	if (argc == 2 && strcmp(argv[1], "remove") == 0)
		sp.remove = true;
	else {
		sp.names.v = (const char **)(uintptr_t)&argv[1];
		sp.names.n = (size_t)argc - 1;
	}
	return (submit(cl, &sp));
}

/*
 * ipsec-sa set|clear interface reqid local remote [words]: manually
 * keyed SAs of an ipsec(4) interface; the words as the job takes them.
 */
static int
cmd_ipsec_sa(struct arc_client *cl, int argc, char **argv)
{
	struct arc_job_spec	 sp;
	const char		*errstr;

	if (argc < 3 || (strcmp(argv[1], "key") != 0 && argc < 6))
		usage();
	memset(&sp, 0, sizeof(sp));
	sp.has_kind = true;
	sp.kind = ARC_JOB_KIND_IPSEC_SA;
	sp.jail = netjail;
	sp.verb = argv[1];
	sp.interface = argv[2];
	if (strcmp(argv[1], "key") == 0) {
		sp.names.v = (const char **)(uintptr_t)&argv[3];
		sp.names.n = (size_t)argc - 3;
		return (submit(cl, &sp));
	}
	sp.has_reqid = true;
	sp.reqid = (uint32_t)strtonum(argv[3], 1, 16383, &errstr);
	if (errstr != NULL)
		xo_errx(2, "reqid %s: %s", argv[3], errstr);
	sp.tunnel_local = argv[4];
	sp.tunnel_remote = argv[5];
	sp.names.v = (const char **)(uintptr_t)&argv[6];
	sp.names.n = (size_t)argc - 6;
	return (submit(cl, &sp));
}

/*
 * rtadvd interface prefix [dns ...]; rtadvd interface remove: router
 * advertisements on an interface, for SLAAC.
 */
static int
cmd_rtadvd(struct arc_client *cl, int argc, char **argv)
{
	struct arc_job_spec	sp;

	if (argc < 3)
		usage();
	memset(&sp, 0, sizeof(sp));
	sp.has_kind = true;
	sp.kind = ARC_JOB_KIND_RTADVD;
	sp.persist = persist;
	sp.interface = argv[1];
	if (argc == 3 && strcmp(argv[2], "remove") == 0)
		sp.remove = true;
	else {
		sp.names.v = (const char **)(uintptr_t)&argv[2];
		sp.names.n = (size_t)argc - 2;
	}
	return (submit(cl, &sp));
}

/* A file's whole content, "-" standard input; exits on failure. */
static char *
slurp(const char *path)
{
	FILE	*fp;
	char	*buf;
	size_t	 len, cap, n;

	if ((fp = strcmp(path, "-") == 0 ? stdin : fopen(path, "r")) == NULL)
		xo_err(1, "%s", path);
	cap = 4096;
	len = 0;
	if ((buf = malloc(cap)) == NULL)
		xo_err(1, "malloc");
	while ((n = fread(buf + len, 1, cap - len - 1, fp)) > 0) {
		len += n;
		if (cap - len < 2 && (buf = realloc(buf, cap *= 2)) == NULL)
			xo_err(1, "realloc");
	}
	buf[len] = '\0';
	if (fp != stdin)
		fclose(fp);
	return (buf);
}

/*
 * neigh add address lladdr [temp] | delete address: an ARP or NDP
 * neighbour set by hand, now; with -p kept for a boot too.
 */
static int
cmd_neigh(struct arc_client *cl, int argc, char **argv)
{
	struct arc_job_spec	 sp;

	memset(&sp, 0, sizeof(sp));
	sp.has_kind = true;
	sp.kind = ARC_JOB_KIND_NEIGHBOUR;
	if (argc >= 4 && argc <= 5 && strcmp(argv[1], "add") == 0) {
		sp.lladdr = argv[3];
		if (argc == 5) {
			if (strcmp(argv[4], "temp") != 0)
				usage();
			sp.temporary = true;
		}
	} else if (argc != 3 || strcmp(argv[1], "delete") != 0)
		usage();
	sp.verb = argv[1];
	sp.address = argv[2];
	sp.live = true;
	sp.persist = persist;
	sp.safe = safe;
	sp.jail = netjail;
	return (submit(cl, &sp));
}

/* A key, at a prompt that does not show it, or a line of the input. */
static char *
key_read(const char *prompt, char *buf, size_t len)
{

	if (isatty(STDIN_FILENO))
		return (readpassphrase(prompt, buf, len, RPP_REQUIRE_TTY));
	if (fgets(buf, (int)len, stdin) == NULL)
		return (NULL);
	buf[strcspn(buf, "\r\n")] = '\0';
	return (buf);
}

/*
 * carp add interface address vhid=n [word=value ...] [key] | set
 * interface vhid=n [word=value ...] [key] | remove interface address
 * vhid=n: an address carp(4) shares, its vhid; key asks for the vhid's
 * key, which is never an argument.  With -p kept for a boot too.
 */
static int
cmd_carp(struct arc_client *cl, int argc, char **argv)
{
	struct arc_job_spec	 sp;
	char			 key[64];
	const char		**words;
	int			 i, first;

	memset(&sp, 0, sizeof(sp));
	sp.has_kind = true;
	sp.kind = ARC_JOB_KIND_CARP;
	if (argc < 4)
		usage();
	sp.verb = argv[1];
	sp.interface = argv[2];
	if (strcmp(argv[1], "add") == 0 || strcmp(argv[1], "remove") == 0) {
		if (argc < 5)
			usage();
		sp.address = argv[3];
		first = 4;
	} else if (strcmp(argv[1], "set") == 0)
		first = 3;
	else
		usage();
	if ((words = calloc((size_t)argc, sizeof(*words))) == NULL)
		err(1, "calloc");
	for (i = first; i < argc; i++) {
		if (strcmp(argv[i], "key") == 0) {
			if (key_read("The vhid's key: ", key, sizeof(key)) ==
			    NULL)
				errx(1, "no key");
			sp.preshared_key = key;
			continue;
		}
		words[sp.names.n++] = argv[i];
	}
	sp.names.v = words;
	sp.persist = persist;
	sp.safe = safe;
	sp.jail = netjail;
	i = submit(cl, &sp);
	explicit_bzero(key, sizeof(key));
	free(words);
	return (i);
}

/*
 * zfskey [-n] dataset: the key of an encrypted dataset asked for at a
 * prompt, typed: loaded; with -n changed, the key it has first (when it
 * is not loaded) and the new one.  At a terminal it is asked for; else
 * a line of the input each.
 */
static int
cmd_zfskey(struct arc_client *cl, int argc, char **argv)
{
	struct arc_zfs_key_req	 rq;
	struct arc_zfs_key_rsp	*rs;
	char			 key[513], nkey[513], again[513];
	bool			 change;
	int			 error;

	change = argc == 3 && strcmp(argv[1], "-n") == 0;
	if (argc != 2 && !change)
		usage();
	memset(&rq, 0, sizeof(rq));
	rq.zfs_dataset = argv[argc - 1];
	if (key_read(change ? "Key now (empty when it is loaded): " : "Key: ",
	    key, sizeof(key)) == NULL)
		errx(1, "no key");
	rq.zfs_key = key[0] != '\0' ? key : NULL;
	if (change) {
		if (key_read("New key: ", nkey, sizeof(nkey)) == NULL)
			errx(1, "no new key");
		if (isatty(STDIN_FILENO)) {
			if (key_read("New key, again: ", again, sizeof(again)) ==
			    NULL || strcmp(again, nkey) != 0)
				errx(1, "the new keys differ");
			explicit_bzero(again, sizeof(again));
		}
		rq.zfs_new_key = nkey;
	}
	error = arc_zfs_key(cl, &rq, &rs);
	explicit_bzero(key, sizeof(key));
	if (change)
		explicit_bzero(nkey, sizeof(nkey));
	if (error != 0)
		fail(cl, error, "zfs key");
	if (!rs->ok && rs->error != NULL)
		warnx("%s", rs->error);
	emit_trace(rs->trace.v, rs->trace.n);
	error = rs->ok ? 0 : 1;
	arc_zfs_key_rsp_free(rs);
	return (error);
}

/*
 * tls [status] | csr | install certfile|- [cafile]: the agent's own TLS
 * files: what they are, a new key and a request for it (the key stays
 * there), and a certificate for that key with the CAs to trust, or the
 * CAs alone.  Over TLS, -C is the certificate the agent checks it still
 * trusts afterwards.
 */
static int
cmd_tls(struct arc_client *cl, int argc, char **argv, const char *mine)
{
	struct arc_tls_req	 rq;
	struct arc_tls_rsp	*rs;
	int			 error;

	memset(&rq, 0, sizeof(rq));
	if (argc == 1 || (argc == 2 && strcmp(argv[1], "status") == 0))
		rq.tls_verb = "status";
	else if (argc == 2 && strcmp(argv[1], "csr") == 0)
		rq.tls_verb = "csr";
	else if ((argc == 3 || argc == 4) && strcmp(argv[1], "install") == 0) {
		rq.tls_verb = "install";
		rq.tls_cert = strcmp(argv[2], "-") == 0 ? NULL : slurp(argv[2]);
		rq.tls_ca = argc == 4 ? slurp(argv[3]) : NULL;
		rq.tls_peer = mine != NULL ? slurp(mine) : NULL;
	} else
		usage();
	if ((error = arc_tls(cl, &rq, &rs)) != 0)
		fail(cl, error, "tls");
	if (rs->json != NULL)
		xo_emit("{:json/%s}\n", rs->json);
	else if (rs->error != NULL)
		warnx("%s", rs->error);
	emit_trace(rs->trace.v, rs->trace.n);
	error = rs->ok ? 0 : 1;
	arc_tls_rsp_free(rs);
	return (error);
}

/*
 * capture [source packets seconds [filter ...]]: packets taken with
 * tcpdump off an interface or a tap, of the host or of -j's jail; with
 * nothing, the sources there are.
 */
static int
cmd_capture(struct arc_client *cl, int argc, char **argv)
{
	struct arc_capture_req	 rq;
	struct arc_capture_rsp	*rs;
	const char		*errstr;
	char			*f;
	size_t			 len;
	int			 i, error;

	memset(&rq, 0, sizeof(rq));
	rq.jail = netjail;
	f = NULL;
	if (argc != 1) {
		if (argc < 4)
			usage();
		rq.interface = argv[1];
		rq.has_packets = true;
		rq.packets = (uint32_t)strtonum(argv[2], 1, 500, &errstr);
		if (errstr != NULL)
			errx(2, "packets %s: %s", argv[2], errstr);
		rq.has_seconds = true;
		rq.seconds = (uint32_t)strtonum(argv[3], 1, 60, &errstr);
		if (errstr != NULL)
			errx(2, "seconds %s: %s", argv[3], errstr);
		for (len = 1, i = 4; i < argc; i++)
			len += strlen(argv[i]) + 1;
		if ((f = calloc(1, len)) == NULL)
			err(1, "calloc");
		for (i = 4; i < argc; i++) {
			if (i > 4)
				strlcat(f, " ", len);
			strlcat(f, argv[i], len);
		}
		rq.net_filter = f;
	}
	if ((error = arc_capture(cl, &rq, &rs)) != 0)
		fail(cl, error, "capture");
	if (rs->json != NULL)
		xo_emit("{:json/%s}\n", rs->json);
	else if (rs->error != NULL)
		warnx("%s", rs->error);
	emit_trace(rs->trace.v, rs->trace.n);
	error = rs->ok ? 0 : 1;
	arc_capture_rsp_free(rs);
	free(f);
	return (error);
}

/*
 * sshd [list] | banner file | set Setting [value ...] | authorize user
 * keyfile | unauthorize user fingerprint | options user fingerprint
 * [options] | sign ca-key-file [principal ...] | user-cas file: the base
 * system's sshd, of the host or of -j's jail; a change is a job, and
 * with -s undone unless confirmed.
 */
static int
cmd_sshd(struct arc_client *cl, int argc, char **argv)
{
	struct arc_job_spec	 sp;
	struct arc_ssh_req	 rq;
	struct arc_ssh_rsp	*rs;
	char			*t;
	int			 error;

	if (argc == 1 || (argc == 2 && strcmp(argv[1], "list") == 0)) {
		memset(&rq, 0, sizeof(rq));
		rq.jail = netjail;
		if ((error = arc_ssh(cl, &rq, &rs)) != 0)
			fail(cl, error, "sshd");
		if (rs->json != NULL)
			xo_emit("{:json/%s}\n", rs->json);
		else if (rs->error != NULL)
			warnx("%s", rs->error);
		emit_trace(rs->trace.v, rs->trace.n);
		error = rs->ok ? 0 : 1;
		arc_ssh_rsp_free(rs);
		return (error);
	}
	memset(&sp, 0, sizeof(sp));
	sp.has_kind = true;
	sp.kind = ARC_JOB_KIND_SSH;
	sp.verb = argv[1];
	if (argc == 3 && (strcmp(argv[1], "banner") == 0 || strcmp(argv[1],
	    "user-cas") == 0))
		sp.text = strcmp(argv[2], "-") == 0 ? "" : slurp(argv[2]);
	else if (argc >= 3 && strcmp(argv[1], "set") == 0) {
		sp.path = argv[2];
		sp.names.v = (const char **)(uintptr_t)&argv[3];
		sp.names.n = (size_t)argc - 3;
	} else if (argc == 4 && strcmp(argv[1], "authorize") == 0) {
		sp.user = argv[2];
		t = slurp(argv[3]);
		t[strcspn(t, "\n")] = '\0';
		sp.text = t;
	} else if (argc == 4 && strcmp(argv[1], "unauthorize") == 0) {
		sp.user = argv[2];
		sp.text = argv[3];
	} else if ((argc == 4 || argc == 5) && strcmp(argv[1], "options") ==
	    0) {
		/* A key's options, its fingerprint naming it: none when
		 * left out. */
		sp.user = argv[2];
		sp.names.v = (const char **)(uintptr_t)&argv[3];
		sp.names.n = 1;
		sp.text = argc == 5 ? argv[4] : "";
	} else if (argc >= 3 && strcmp(argv[1], "sign") == 0) {
		sp.text = slurp(argv[2]);
		sp.names.v = (const char **)(uintptr_t)&argv[3];
		sp.names.n = (size_t)argc - 3;
	} else
		usage();
	sp.safe = safe;
	sp.jail = netjail;
	return (submit(cl, &sp));
}

/*
 * poudriere [list] | show-options key=value ... | make-conf name|- file|- |
 * verb [key=value ...]: poudriere(8), the host's package builder;
 * show-options reads a port's (jail= ports= set= origin=); a verb is a
 * job, which for a build, a jail or a ports tree made or updated starts
 * a run and ends (see list's runs).
 */
static int
cmd_poudriere(struct arc_client *cl, int argc, char **argv)
{
	struct arc_job_spec		 sp;
	struct arc_builder_rsp		*rs;
	struct arc_builder_options_req	 oq;
	struct arc_builder_options_rsp	*ors;
	char				*nm;
	int				 error;

	if (argc == 1 || (argc == 2 && strcmp(argv[1], "list") == 0)) {
		if ((error = arc_builder(cl, &rs)) != 0)
			fail(cl, error, "builder");
		if (rs->json != NULL)
			xo_emit("{:json/%s}\n", rs->json);
		else if (rs->error != NULL)
			warnx("%s", rs->error);
		emit_trace(rs->trace.v, rs->trace.n);
		error = rs->ok ? 0 : 1;
		arc_builder_rsp_free(rs);
		return (error);
	}
	if (strcmp(argv[1], "show-options") == 0) {
		memset(&oq, 0, sizeof(oq));
		oq.names.v = (const char **)(uintptr_t)&argv[2];
		oq.names.n = (size_t)argc - 2;
		if ((error = arc_builder_options(cl, &oq, &ors)) != 0)
			fail(cl, error, "builder-options");
		if (ors->json != NULL)
			xo_emit("{:json/%s}\n", ors->json);
		else if (ors->error != NULL)
			warnx("%s", ors->error);
		emit_trace(ors->trace.v, ors->trace.n);
		error = ors->ok ? 0 : 1;
		arc_builder_options_rsp_free(ors);
		return (error);
	}
	memset(&sp, 0, sizeof(sp));
	sp.has_kind = true;
	sp.kind = ARC_JOB_KIND_POUDRIERE;
	sp.verb = argv[1];
	if (strcmp(argv[1], "make-conf") == 0) {
		/* name - for make.conf itself, file - to take it away. */
		if (argc != 4)
			usage();
		if (asprintf(&nm, "name=%s", strcmp(argv[2], "-") == 0 ? "" :
		    argv[2]) == -1)
			err(1, "asprintf");
		sp.names.v = (const char **)(uintptr_t)&nm;
		sp.names.n = 1;
		sp.text = strcmp(argv[3], "-") == 0 ? "" : slurp(argv[3]);
	} else {
		sp.names.v = (const char **)(uintptr_t)&argv[2];
		sp.names.n = (size_t)argc - 2;
	}
	/* The host's alone: -j is passed on to be refused, not dropped. */
	sp.jail = netjail;
	return (submit(cl, &sp));
}

/* crashes [backtrace core [program]]: the cores dumped, and one's
 * backtrace. */
static int
cmd_crashes(struct arc_client *cl, int argc, char **argv)
{
	struct arc_crashes_req	 rq;
	struct arc_crashes_rsp	*rs;
	int			 error;

	memset(&rq, 0, sizeof(rq));
	if (argc > 1) {
		if (strcmp(argv[1], "backtrace") != 0 || argc < 3 || argc > 4)
			usage();
		rq.names.v = (const char **)(uintptr_t)&argv[1];
		rq.names.n = (size_t)argc - 1;
	}
	if ((error = arc_crashes(cl, &rq, &rs)) != 0)
		fail(cl, error, "crashes");
	if (rs->json != NULL)
		xo_emit("{:json/%s}\n", rs->json);
	else if (rs->error != NULL)
		warnx("%s", rs->error);
	emit_trace(rs->trace.v, rs->trace.n);
	error = rs->ok ? 0 : 1;
	arc_crashes_rsp_free(rs);
	return (error);
}

/* system [file | host]: the system's own files, and settings beside. */
static int
cmd_system(struct arc_client *cl, int argc, char **argv)
{
	struct arc_system_req	 rq;
	struct arc_system_rsp	*rs;
	int			 error;

	if (argc > 2)
		usage();
	memset(&rq, 0, sizeof(rq));
	rq.names.v = (const char **)(uintptr_t)&argv[1];
	rq.names.n = (size_t)argc - 1;
	if ((error = arc_system(cl, &rq, &rs)) != 0)
		fail(cl, error, "system");
	if (rs->json != NULL)
		xo_emit("{:json/%s}\n", rs->json);
	else if (rs->error != NULL)
		warnx("%s", rs->error);
	emit_trace(rs->trace.v, rs->trace.n);
	error = rs->ok ? 0 : 1;
	arc_system_rsp_free(rs);
	return (error);
}

/* geom class subcommand [word ...] [-P passfile]: geom(8), a job; a
 * GELI passphrase read from passfile. */
static int
cmd_geom(struct arc_client *cl, int argc, char **argv)
{
	struct arc_job_spec	 sp;
	int			 n;

	if (argc < 3)
		usage();
	memset(&sp, 0, sizeof(sp));
	sp.has_kind = true;
	sp.kind = ARC_JOB_KIND_GEOM;
	sp.verb = argv[1];
	n = argc - 2;
	if (n >= 3 && strcmp(argv[argc - 2], "-P") == 0) {
		sp.text = slurp(argv[argc - 1]);
		n -= 2;
	}
	sp.names.v = (const char **)(uintptr_t)&argv[2];
	sp.names.n = (size_t)n;
	sp.jail = netjail;
	return (submit(cl, &sp));
}

/* sysfile file path | periodic name=YES|NO ...: a file of the system's
 * written from path, or periodic.conf's variables; a job. */
static int
cmd_sysfile(struct arc_client *cl, int argc, char **argv)
{
	struct arc_job_spec	 sp;

	if (argc < 3)
		usage();
	memset(&sp, 0, sizeof(sp));
	sp.has_kind = true;
	sp.kind = ARC_JOB_KIND_SYSFILE;
	sp.verb = argv[1];
	if (strcmp(argv[1], "periodic") == 0 || strcmp(argv[1], "rc") == 0) {
		sp.names.v = (const char **)(uintptr_t)&argv[2];
		sp.names.n = (size_t)argc - 2;
	} else {
		if (argc != 3)
			usage();
		sp.text = slurp(argv[2]);
	}
	sp.jail = netjail;
	return (submit(cl, &sp));
}

/* netstore [nfs | iscsi | hast]: the host's storage services. */
static int
cmd_netstore(struct arc_client *cl, int argc, char **argv)
{
	struct arc_netstore_req	 rq;
	struct arc_netstore_rsp	*rs;
	int			 error;

	if (argc > 2)
		usage();
	memset(&rq, 0, sizeof(rq));
	rq.names.v = (const char **)(uintptr_t)&argv[1];
	rq.names.n = (size_t)argc - 1;
	if ((error = arc_netstore(cl, &rq, &rs)) != 0)
		fail(cl, error, "netstore");
	if (rs->json != NULL)
		xo_emit("{:json/%s}\n", rs->json);
	else if (rs->error != NULL)
		warnx("%s", rs->error);
	emit_trace(rs->trace.v, rs->trace.n);
	error = rs->ok ? 0 : 1;
	arc_netstore_rsp_free(rs);
	return (error);
}

/*
 * nfs exports file | server key=value ...; iscsi conf file | enable
 * yes|no; hast conf file | enable yes|no | create resource | role role
 * resource: the storage services changed, a job each.
 */
static int
cmd_netstore_job(struct arc_client *cl, int argc, char **argv, int kind)
{
	struct arc_job_spec	 sp;
	char			*w[2];

	if (argc < 3)
		usage();
	memset(&sp, 0, sizeof(sp));
	sp.has_kind = true;
	sp.kind = (uint32_t)kind;
	sp.verb = argv[1];
	if (strcmp(argv[1], "exports") == 0 || strcmp(argv[1], "conf") == 0) {
		if (argc != 3)
			usage();
		sp.text = slurp(argv[2]);
	} else if (strcmp(argv[1], "enable") == 0) {
		if (argc != 3 || asprintf(&w[0], "enable=%s", argv[2]) == -1)
			usage();
		sp.names.v = (const char **)(uintptr_t)w;
		sp.names.n = 1;
	} else if (strcmp(argv[1], "create") == 0) {
		if (argc != 3 || asprintf(&w[0], "resource=%s", argv[2]) == -1)
			usage();
		sp.names.v = (const char **)(uintptr_t)w;
		sp.names.n = 1;
	} else if (strcmp(argv[1], "role") == 0) {
		if (argc != 4 || asprintf(&w[0], "role=%s", argv[2]) == -1 ||
		    asprintf(&w[1], "resource=%s", argv[3]) == -1)
			usage();
		sp.names.v = (const char **)(uintptr_t)w;
		sp.names.n = 2;
	} else {
		sp.names.v = (const char **)(uintptr_t)&argv[2];
		sp.names.n = (size_t)argc - 2;
	}
	sp.jail = netjail;
	return (submit(cl, &sp));
}

/*
 * clamav mirrors mirror ...: freshclam.conf's DatabaseMirror lines, in
 * place of those there were; a job.
 */
static int
cmd_clamav(struct arc_client *cl, int argc, char **argv)
{
	struct arc_job_spec	 sp;
	const char		**w;
	int			 i;

	if (argc < 3 || strcmp(argv[1], "mirrors") != 0)
		usage();
	if ((w = calloc((size_t)argc - 2, sizeof(*w))) == NULL)
		err(1, "calloc");
	for (i = 2; i < argc; i++)
		if (asprintf((char **)(uintptr_t)&w[i - 2], "mirror=%s",
		    argv[i]) == -1)
			err(1, "asprintf");
	memset(&sp, 0, sizeof(sp));
	sp.has_kind = true;
	sp.kind = ARC_JOB_KIND_CLAMAV;
	sp.verb = argv[1];
	sp.names.v = w;
	sp.names.n = (size_t)argc - 2;
	/* The host's alone: -j is passed on to be refused, not dropped. */
	sp.jail = netjail;
	return (submit(cl, &sp));
}

/*
 * suricata update | rules [key=value ...] | rule state=sids ... |
 * sources | source-verb name=source ...: suricata-update fetches the
 * ruleset, and the instances take it; the ruleset's rules, a page of
 * them (sources=1: the rule sources); rules set by sid; the index of
 * sources fetched; a source enabled, disabled, removed or added.  All
 * but rules are jobs.
 */
static int
cmd_suricata(struct arc_client *cl, int argc, char **argv)
{
	struct arc_job_spec		 sp;
	struct arc_suricata_rules_req	 rq;
	struct arc_suricata_rules_rsp	*rs;
	int				 error;

	if (argc >= 2 && strcmp(argv[1], "rules") == 0) {
		memset(&rq, 0, sizeof(rq));
		rq.names.v = (const char **)(uintptr_t)&argv[2];
		rq.names.n = (size_t)argc - 2;
		if ((error = arc_suricata_rules(cl, &rq, &rs)) != 0)
			fail(cl, error, "suricata rules");
		if (rs->json != NULL)
			xo_emit("{:json/%s}\n", rs->json);
		else if (rs->error != NULL)
			warnx("%s", rs->error);
		emit_trace(rs->trace.v, rs->trace.n);
		error = rs->ok ? 0 : 1;
		arc_suricata_rules_rsp_free(rs);
		return (error);
	}
	if (argc < 2 || ((strcmp(argv[1], "update") == 0 || strcmp(argv[1],
	    "sources") == 0) && argc != 2) || (strcmp(argv[1], "update") != 0 &&
	    strcmp(argv[1], "rule") != 0 && strcmp(argv[1], "sources") != 0 &&
	    strcmp(argv[1], "pcap") != 0 && strncmp(argv[1], "source-", 7) !=
	    0))
		usage();
	memset(&sp, 0, sizeof(sp));
	sp.has_kind = true;
	sp.kind = ARC_JOB_KIND_SURICATA;
	sp.verb = argv[1];
	sp.names.v = (const char **)(uintptr_t)&argv[2];
	sp.names.n = (size_t)argc - 2;
	sp.jail = netjail;
	return (submit(cl, &sp));
}

/*
 * cert [list] | add name file | remove name | trust file | untrust file |
 * rehash: the certificates OpenSSL trusts, of the host or of -j's jail;
 * a change is a job.
 */
static int
cmd_cert(struct arc_client *cl, int argc, char **argv)
{
	struct arc_job_spec	 sp;
	struct arc_certs_req	 rq;
	struct arc_certs_rsp	*rs;
	int			 error;

	if (argc == 1 || (argc == 2 && strcmp(argv[1], "list") == 0)) {
		memset(&rq, 0, sizeof(rq));
		rq.jail = netjail;
		if ((error = arc_certs(cl, &rq, &rs)) != 0)
			fail(cl, error, "certs");
		if (rs->json != NULL)
			xo_emit("{:json/%s}\n", rs->json);
		else if (rs->error != NULL)
			warnx("%s", rs->error);
		emit_trace(rs->trace.v, rs->trace.n);
		error = rs->ok ? 0 : 1;
		arc_certs_rsp_free(rs);
		return (error);
	}
	memset(&sp, 0, sizeof(sp));
	sp.has_kind = true;
	sp.kind = ARC_JOB_KIND_CERT;
	sp.verb = argv[1];
	if (argc == 4 && strcmp(argv[1], "add") == 0) {
		sp.path = argv[2];
		sp.text = slurp(argv[3]);
	} else if (argc == 3 && (strcmp(argv[1], "remove") == 0 ||
	    strcmp(argv[1], "trust") == 0 || strcmp(argv[1], "untrust") == 0))
		sp.path = argv[2];
	else if (argc != 2 || strcmp(argv[1], "rehash") != 0)
		usage();
	sp.safe = safe;
	sp.jail = netjail;
	return (submit(cl, &sp));
}

/*
 * jailconf make jail file [dataset snapshot clone|send path] [start]
 * jailconf edit jail file
 * jailconf remove jail [dataset]
 * jailconf defaults file
 * jailconf template name file | untemplate name
 * jailconf files
 * A jail made or taken away, the jails' defaults, a template: a job;
 * files reads what there is.
 */
static int
cmd_jailconf(struct arc_client *cl, int argc, char **argv)
{
	struct arc_job_spec	 sp;
	struct arc_jail_files_rsp *rs;
	const char		*name;
	int			 error;

	if (argc == 2 && strcmp(argv[1], "files") == 0) {
		if ((error = arc_jail_files(cl, &rs)) != 0)
			fail(cl, error, "jail files");
		if (rs->json != NULL)
			xo_emit("{:json/%s}\n", rs->json);
		emit_trace(rs->trace.v, rs->trace.n);
		error = rs->ok ? 0 : 1;
		arc_jail_files_rsp_free(rs);
		return (error);
	}
	if (argc < 3)
		usage();
	memset(&sp, 0, sizeof(sp));
	sp.has_kind = true;
	sp.kind = ARC_JOB_KIND_JAIL_CONF;
	sp.verb = argv[1];
	if (strcmp(argv[1], "make") == 0 && (argc == 4 || argc == 5 ||
	    argc == 8 || argc == 9)) {
		sp.jail = argv[2];
		sp.text = slurp(argv[3]);
		if (argc >= 8) {
			sp.dataset = argv[4];
			sp.snapshot = argv[5];
			sp.copy = argv[6];
			sp.path = argv[7];
		}
		if ((argc == 5 || argc == 9) && strcmp(argv[argc - 1], "start") ==
		    0)
			sp.start = true;
		else if (argc == 5 || argc == 9)
			usage();
	} else if (strcmp(argv[1], "edit") == 0 && argc == 4) {
		sp.jail = argv[2];
		sp.text = slurp(argv[3]);
	} else if (strcmp(argv[1], "remove") == 0 && (argc == 3 || argc ==
	    4)) {
		sp.jail = argv[2];
		if (argc == 4)
			sp.dataset = argv[3];
	} else if (strcmp(argv[1], "defaults") == 0 && argc == 3)
		sp.text = slurp(argv[2]);
	else if ((strcmp(argv[1], "template") == 0 && argc == 4) ||
	    (strcmp(argv[1], "untemplate") == 0 && argc == 3)) {
		name = argv[2];
		sp.names.v = &name;
		sp.names.n = 1;
		if (argc == 4)
			sp.text = slurp(argv[3]);
	} else
		usage();
	return (submit(cl, &sp));
}

static int
cmd_kmod(struct arc_client *cl, int argc, char **argv)
{
	struct arc_job_spec	 sp;
	struct arc_kernel_rsp	*rsp;
	const char		*name;
	int			 error;

	if (argc == 3 && (strcmp(argv[1], "load") == 0 || strcmp(argv[1],
	    "unload") == 0 || strcmp(argv[1], "keep") == 0 || strcmp(argv[1],
	    "forget") == 0)) {
		memset(&sp, 0, sizeof(sp));
		sp.has_kind = true;
		sp.kind = ARC_JOB_KIND_KMOD;
		sp.verb = argv[1];
		name = argv[2];
		sp.names.v = &name;
		sp.names.n = 1;
		sp.persist = persist;
		sp.safe = safe;
		sp.jail = netjail;
		return (submit(cl, &sp));
	}
	if (argc != 1)
		usage();
	if ((error = arc_kernel(cl, &rsp)) != 0)
		fail(cl, error, "kmod");
	if (rsp->json != NULL)
		xo_emit("{:json/%s}\n", rsp->json);
	emit_trace(rsp->trace.v, rsp->trace.n);
	error = rsp->ok ? 0 : 1;
	if (!rsp->ok)
		xo_warnx("kmod: %s", rsp->error != NULL ? rsp->error :
		    "failed");
	arc_kernel_rsp_free(rsp);
	return (error);
}

/*
 * sysctl [prefix]: the kernel's state, as the host says it.
 * sysctl name=value: a job; with -p also in sysctl.conf.
 */
static int
cmd_sysctl(struct arc_client *cl, int argc, char **argv)
{
	struct arc_job_spec	 sp;
	struct arc_sysctl_req	 req;
	struct arc_sysctl_rsp	*rsp;
	const char		*names[2];
	char			*eq;
	int			 error;

	if (argc == 2 && (eq = strchr(argv[1], '=')) != NULL) {
		*eq = '\0';
		memset(&sp, 0, sizeof(sp));
		sp.has_kind = true;
		sp.kind = ARC_JOB_KIND_SYSCTL;
		names[0] = argv[1];
		names[1] = eq + 1;
		sp.names.v = names;
		sp.names.n = 2;
		sp.persist = persist;
		sp.safe = safe;
		sp.jail = netjail;
		return (submit(cl, &sp));
	}
	/* In parts, each printed as it comes: nothing left out for size. */
	if (argc >= 2 && strcmp(argv[1], "parts") == 0) {
		struct arc_sysctl_dump_req	 dq;
		struct arc_sysctl_dump_rsp	*item;
		cbl_dump			*d;

		if (argc > 3)
			usage();
		memset(&dq, 0, sizeof(dq));
		dq.net_filter = argc == 3 ? argv[2] : NULL;
		if ((error = arc_sysctl_dump(cl, &dq, &d)) != 0)
			fail(cl, error, "sysctl");
		while ((error = arc_sysctl_dump_next(d, &item)) == 0 && item !=
		    NULL)
			if (item->json != NULL)
				xo_emit("{:json/%s}\n", item->json);
		cbl_dump_free(d);
		if (error != 0)
			fail(cl, error, "sysctl");
		return (0);
	}
	if (argc > 2)
		usage();
	memset(&req, 0, sizeof(req));
	req.net_filter = argc == 2 ? argv[1] : NULL;
	req.jail = netjail;
	if ((error = arc_sysctl(cl, &req, &rsp)) != 0)
		fail(cl, error, "sysctl");
	if (rsp->json != NULL)
		xo_emit("{:json/%s}\n", rsp->json);
	if (rsp->truncated)
		xo_warnx("sysctl: the first of %ju: name where to begin",
		    (uintmax_t)rsp->total);
	emit_trace(rsp->trace.v, rsp->trace.n);
	error = rsp->ok ? 0 : 1;
	if (!rsp->ok)
		xo_warnx("sysctl: %s", rsp->error != NULL ? rsp->error :
		    "failed");
	arc_sysctl_rsp_free(rsp);
	return (error);
}

/* What a reply of JSON says, and how it went. */
static int
json_out(const char *what, bool ok, const char *error, const char *json,
    const struct arc_step *steps, size_t nsteps)
{

	if (json != NULL)
		xo_emit("{:json/%s}\n", json);
	emit_trace(steps, nsteps);
	if (!ok)
		xo_warnx("%s: %s", what, error != NULL ? error : "failed");
	return (ok ? 0 : 1);
}

/*
 * ps: what runs on the host, or with -j in a jail, the busiest first.
 * signal pid [name]: send it a signal, TERM when none is named.
 * renice pid nice: give it another nice value.
 * log [name [text]]: the end of a log; -o how many lines, -f from where.
 * history [after]: how busy the host has been.
 * history set seconds samples: how often it is sampled, how many kept.
 * events [after]: what happened on the host, after an event's number.
 */
/* An event as it comes: a line of its own, at once. */
static void
event_line(const struct arc_event_ntf *ntf, void *arg)
{

	(void)arg;
	if (ntf->json != NULL) {
		printf("%s\n", ntf->json);
		fflush(stdout);
	}
}

/*
 * The host's events as they happen, until the host goes or we are
 * stopped: the connection is driven here, nothing asked of it after.
 */
static int
follow_events(struct arc_client *cl)
{
	static const struct arc_events_handlers h = { .event = event_line };
	struct pollfd	 pfd;
	cbl_sub		*sub;
	int		 error, ev, ms;

	if ((error = arc_events_subscribe(cl, &h, NULL, &sub)) != 0)
		fail(cl, error, "events");
	for (;;) {
		ev = 0;
		ms = -1;
		(void)cbl_conn_interest(cl->conn, &ev, &ms);
		pfd.fd = cbl_conn_fd(cl->conn);
		pfd.events = ((ev & CBL_EV_READ) != 0 ? POLLIN : 0) |
		    ((ev & CBL_EV_WRITE) != 0 ? POLLOUT : 0);
		pfd.revents = 0;
		if (poll(&pfd, 1, ms) == -1)
			continue;
		ev = ((pfd.revents & (POLLIN | POLLHUP | POLLERR)) != 0 ?
		    CBL_EV_READ : 0) | ((pfd.revents & POLLOUT) != 0 ?
		    CBL_EV_WRITE : 0);
		if ((error = cbl_conn_process(cl->conn, ev)) != 0)
			break;
	}
	xo_errx(1, "events: the host is gone: %s", strerror(error));
}

static int
cmd_gula(struct arc_client *cl, int argc, char **argv)
{
	struct arc_job_spec	 sp;
	struct arc_processes_req pq;
	struct arc_processes_rsp *pr;
	struct arc_log_req	 lq;
	struct arc_log_rsp	*lr;
	struct arc_history_req	 hq;
	struct arc_history_rsp	*hr;
	const char		*names[2], *e;
	int			 error, ch, rc;

	if (strcmp(argv[0], "ps") == 0) {
		if (argc > 2)
			usage();
		memset(&pq, 0, sizeof(pq));
		pq.jail = netjail;
		if (argc == 2) {
			pq.has_pid = true;
			pq.pid = (uint32_t)strtonum(argv[1], 1, 99999, &e);
			if (e != NULL)
				xo_errx(1, "ps: %s: %s", argv[1], e);
		}
		if ((error = arc_processes(cl, &pq, &pr)) != 0)
			fail(cl, error, "ps");
		rc = json_out("ps", pr->ok, pr->error, pr->json, pr->trace.v,
		    pr->trace.n);
		arc_processes_rsp_free(pr);
		return (rc);
	}
	if (strcmp(argv[0], "signal") == 0 || strcmp(argv[0], "renice") == 0) {
		if (argc < 2 || argc > 3 || (argc == 2 && argv[0][0] == 'r'))
			usage();
		memset(&sp, 0, sizeof(sp));
		sp.has_kind = true;
		sp.kind = ARC_JOB_KIND_PROCESS;
		sp.verb = argv[0];
		names[0] = argv[1];
		names[1] = argc == 3 ? argv[2] : "TERM";
		sp.names.v = names;
		sp.names.n = 2;
		sp.safe = safe;
		sp.jail = netjail;
		return (submit(cl, &sp));
	}
	if (strcmp(argv[0], "events") == 0 && argc == 2 && strcmp(argv[1],
	    "-f") == 0)
		return (follow_events(cl));
	if (strcmp(argv[0], "events") == 0) {
		struct arc_events_req	 eq;
		struct arc_events_rsp	*er;

		if (argc > 2)
			usage();
		memset(&eq, 0, sizeof(eq));
		if (argc == 2) {
			eq.has_after = true;
			eq.after = (uint64_t)strtonum(argv[1], 0, INT64_MAX,
			    &e);
			if (e != NULL)
				xo_errx(1, "events: after %s: %s", argv[1], e);
		}
		if ((error = arc_events(cl, &eq, &er)) != 0)
			fail(cl, error, "events");
		rc = json_out("events", er->ok, er->error, er->json,
		    er->trace.v, er->trace.n);
		arc_events_rsp_free(er);
		return (rc);
	}
	if (strcmp(argv[0], "history") == 0) {
		memset(&hq, 0, sizeof(hq));
		/* ... rules list: the limits of devices and jails, last. */
		if (argc >= 6 && strcmp(argv[1], "set") == 0 &&
		    strcmp(argv[argc - 2], "rules") == 0) {
			hq.limit_rules = argv[argc - 1];
			argc -= 2;
		}
		if ((argc == 4 || argc == 7 || argc == 8) && strcmp(argv[1],
		    "set") == 0) {
			/* ... cpu mem swap [storage] */
			if (argc == 8) {
				hq.has_limit_storage = true;
				hq.limit_storage = (uint32_t)strtonum(argv[7],
				    0, 100, &e);
				if (e != NULL)
					xo_errx(1, "history: a limit is 0 to "
					    "100");
			}
			if (argc >= 7) {
				hq.has_limit_cpu = hq.has_limit_mem =
				    hq.has_limit_swap = true;
				hq.limit_cpu = (uint32_t)strtonum(argv[4], 0,
				    100, &e);
				if (e == NULL)
					hq.limit_mem = (uint32_t)strtonum(
					    argv[5], 0, 100, &e);
				if (e == NULL)
					hq.limit_swap = (uint32_t)strtonum(
					    argv[6], 0, 100, &e);
				if (e != NULL)
					xo_errx(1, "history: a limit is 0 to "
					    "100");
			}
			hq.has_sample_step = hq.has_sample_keep = true;
			hq.sample_step = (uint32_t)strtonum(argv[2], 1, 3600,
			    &e);
			if (e != NULL)
				xo_errx(1, "history: seconds %s: %s", argv[2],
				    e);
			hq.sample_keep = (uint32_t)strtonum(argv[3], 0, 5000,
			    &e);
			if (e != NULL)
				xo_errx(1, "history: samples %s: %s", argv[3],
				    e);
		} else if (argc > 2)
			usage();
		else if (argc == 2) {
			hq.has_after = true;
			hq.after = (uint64_t)strtonum(argv[1], 0, INT64_MAX,
			    &e);
			if (e != NULL)
				xo_errx(1, "history: after %s: %s", argv[1], e);
		}
		if ((error = arc_history(cl, &hq, &hr)) != 0)
			fail(cl, error, "history");
		rc = json_out("history", hr->ok, hr->error, hr->json,
		    hr->trace.v, hr->trace.n);
		arc_history_rsp_free(hr);
		return (rc);
	}
	memset(&lq, 0, sizeof(lq));
	optreset = optind = 1;
	while ((ch = getopt(argc, argv, "f:o:")) != -1) {
		switch (ch) {
		case 'f':
			lq.has_position = true;
			lq.position = (uint64_t)strtonum(optarg, 0, INT64_MAX,
			    &e);
			if (e != NULL)
				xo_errx(1, "log: position %s: %s", optarg, e);
			break;
		case 'o':
			lq.has_lines = true;
			lq.lines = (uint32_t)strtonum(optarg, 1, 5000, &e);
			if (e != NULL)
				xo_errx(1, "log: lines %s: %s", optarg, e);
			break;
		default:
			usage();
		}
	}
	argc -= optind;
	argv += optind;
	if (argc > 2)
		usage();
	lq.log_name = argc > 0 ? argv[0] : NULL;
	lq.net_filter = argc > 1 ? argv[1] : NULL;
	lq.jail = netjail;
	if ((error = arc_log(cl, &lq, &lr)) != 0)
		fail(cl, error, "log");
	rc = json_out("log", lr->ok, lr->error, lr->json, lr->trace.v,
	    lr->trace.n);
	arc_log_rsp_free(lr);
	return (rc);
}

/*
 * config-export: the host as a bundle, JSON on stdout; -s with the
 * secrets.
 */
static int
cmd_config_export(struct arc_client *cl, int argc, char **argv)
{
	struct arc_config_export_req	 req;
	struct arc_config_export_rsp	*rsp;
	int				 error;

	if (argc > 2 || (argc == 2 && strcmp(argv[1], "-s") != 0))
		usage();
	memset(&req, 0, sizeof(req));
	req.secrets = argc == 2;
	if ((error = arc_config_export(cl, &req, &rsp)) != 0)
		fail(cl, error, "config-export");
	if (rsp->json != NULL)
		xo_emit("{:json/%s}\n", rsp->json);
	emit_trace(rsp->trace.v, rsp->trace.n);
	error = rsp->ok ? 0 : 1;
	if (!rsp->ok)
		xo_warnx("config-export: %s", rsp->error != NULL ? rsp->error :
		    "failed");
	arc_config_export_rsp_free(rsp);
	return (error);
}

/*
 * config-apply [-an] [-H hostname] bundle: a bundle made this host's
 * configuration; -n only the report, -a though the hardware differs,
 * -H another host name in rc.conf.  The report, JSON, on stdout.
 */
static int
cmd_config_apply(struct arc_client *cl, int argc, char **argv)
{
	struct arc_config_apply_req	 req;
	struct arc_config_apply_rsp	*rsp;
	char				*text;
	int				 ch, error;

	memset(&req, 0, sizeof(req));
	optind = 1;
	optreset = 1;
	while ((ch = getopt(argc, argv, "anH:")) != -1) {
		switch (ch) {
		case 'a':
			req.anyway = true;
			break;
		case 'n':
			req.dry_run = true;
			break;
		case 'H':
			req.new_hostname = optarg;
			break;
		default:
			usage();
		}
	}
	if (argc != optind + 1)
		usage();
	text = slurp(argv[optind]);
	req.bundle = text;
	if ((error = arc_config_apply(cl, &req, &rsp)) != 0)
		fail(cl, error, "config-apply");
	if (rsp->json != NULL)
		xo_emit("{:json/%s}\n", rsp->json);
	emit_trace(rsp->trace.v, rsp->trace.n);
	error = rsp->ok ? 0 : 1;
	if (!rsp->ok)
		xo_warnx("config-apply: %s", rsp->error != NULL ? rsp->error :
		    "failed");
	arc_config_apply_rsp_free(rsp);
	free(text);
	return (error);
}

/*
 * path-check: what this host does with a packet from src to dst, and
 * with its reply; -i the interface it comes in on, -F the FIB, -p tcp,
 * udp, icmp or ip, -P the port.  JSON on stdout.
 */
static int
cmd_path_check(struct arc_client *cl, int argc, char **argv)
{
	struct arc_path_check_req	 req;
	struct arc_path_check_rsp	*rsp;
	int				 ch, error;

	memset(&req, 0, sizeof(req));
	optind = 1;
	optreset = 1;
	while ((ch = getopt(argc, argv, "F:i:p:P:r")) != -1) {
		switch (ch) {
		case 'r':
			req.path_reply = true;
			break;
		case 'F':
			req.has_net_fib = true;
			req.net_fib = (uint32_t)strtoul(optarg, NULL, 10);
			break;
		case 'i':
			req.interface = optarg;
			break;
		case 'p':
			req.path_proto = optarg;
			break;
		case 'P':
			req.has_path_port = true;
			req.path_port = (uint32_t)strtoul(optarg, NULL, 10);
			break;
		default:
			usage();
		}
	}
	if (argc != optind + 2)
		usage();
	req.path_src = argv[optind];
	req.path_dst = argv[optind + 1];
	req.jail = netjail;
	if ((error = arc_path_check(cl, &req, &rsp)) != 0)
		fail(cl, error, "path-check");
	if (rsp->json != NULL)
		xo_emit("{:json/%s}\n", rsp->json);
	emit_trace(rsp->trace.v, rsp->trace.n);
	error = rsp->ok ? 0 : 1;
	if (!rsp->ok)
		xo_warnx("path-check: %s", rsp->error != NULL ? rsp->error :
		    "failed");
	arc_path_check_rsp_free(rsp);
	return (error);
}

/*
 * notify chat text: a Telegram message, sent by the agent through the
 * bot whose token ARCANA_TELEGRAM_TOKEN holds (not an argument: ps(1)
 * would show it).
 */
static int
cmd_notify(struct arc_client *cl, int argc, char **argv)
{
	struct arc_notify_req	 req;
	struct arc_notify_rsp	*rsp;
	const char		*token;
	int			 error;

	if (argc != 3)
		usage();
	if ((token = getenv("ARCANA_TELEGRAM_TOKEN")) == NULL ||
	    token[0] == '\0')
		xo_errx(2, "notify: the bot's token is in ARCANA_TELEGRAM_TOKEN");
	memset(&req, 0, sizeof(req));
	req.notify_token = token;
	req.notify_chat = argv[1];
	req.notify_text = argv[2];
	if ((error = arc_notify(cl, &req, &rsp)) != 0)
		fail(cl, error, "notify");
	emit_trace(rsp->trace.v, rsp->trace.n);
	error = rsp->ok ? 0 : 1;
	if (!rsp->ok)
		xo_warnx("notify: %s", rsp->error != NULL ? rsp->error :
		    "failed");
	arc_notify_rsp_free(rsp);
	return (error);
}

/*
 * transport: the agent's listeners and the connections open to it.
 * transport retry: start the SCTP listeners that are not up.
 * transport listen uri: listen there too.  transport unlisten uri
 * [for new [keep]]: close that one; with keep, new takes its place in
 * rc.conf.
 */
static int
cmd_transport(struct arc_client *cl, int argc, char **argv)
{
	struct arc_transport_req	 req;
	struct arc_transport_rsp	*rsp;
	int				 error;

	memset(&req, 0, sizeof(req));
	if (argc == 3 && strcmp(argv[1], "listen") == 0)
		req.listen = argv[2];
	else if ((argc == 3 || argc == 5 || argc == 6) && strcmp(argv[1],
	    "unlisten") == 0 && (argc == 3 || strcmp(argv[3], "for") == 0) &&
	    (argc != 6 || strcmp(argv[5], "keep") == 0)) {
		req.unlisten = argv[2];
		req.listen = argc >= 5 ? argv[4] : NULL;
		req.listen_keep = argc == 6;
	} else if (argc > 2 || (argc == 2 && strcmp(argv[1], "retry") != 0))
		usage();
	req.retry = argc == 2;
	if ((error = arc_transport(cl, &req, &rsp)) != 0)
		fail(cl, error, "transport");
	if (rsp->json != NULL)
		xo_emit("{:json/%s}\n", rsp->json);
	emit_trace(rsp->trace.v, rsp->trace.n);
	error = rsp->ok ? 0 : 1;
	if (!rsp->ok)
		xo_warnx("transport: %s", rsp->error != NULL ? rsp->error :
		    "failed");
	arc_transport_rsp_free(rsp);
	return (error);
}

/*
 * ipfw add | delete: a rule, now; with -p kept too, and after "keep"
 * kept only.  ipfw apply: the kept rules as the whole ruleset, through
 * set 1; with -s taken back unless confirmed.  ipfw rules: the kept
 * file read, or with -w put in place, with -n only checked; with -r the
 * file rc.conf's firewall_type names, as kept rules, nothing written.
 */
static int
cmd_ipfw(struct arc_client *cl, int argc, char **argv)
{
	struct arc_job_spec		 sp;
	struct arc_ipfw_rules_req	 req;
	struct arc_ipfw_rules_rsp	*rsp, *cur;
	struct stat			 sb;
	const char			*from;
	char				*text;
	int				 ch, error, fd;
	bool				 keep;

	if (argc < 2)
		usage();
	if (strcmp(argv[1], "trace") == 0) {
		struct arc_fw_trace_req	 tq;
		struct arc_fw_trace_rsp	*tr;
		const char		*e;

		if (argc < 3 || argc > 5)
			usage();
		memset(&tq, 0, sizeof(tq));
		tq.jail = netjail;
		tq.net_filter = argv[2];
		if (argc > 3) {
			tq.has_seconds = true;
			tq.seconds = (uint32_t)strtonum(argv[3], 1, 60, &e);
			if (e != NULL)
				xo_errx(1, "ipfw trace: seconds %s: %s", argv[3],
				    e);
		}
		if (argc > 4) {
			tq.has_packets = true;
			tq.packets = (uint32_t)strtonum(argv[4], 1, 1000, &e);
			if (e != NULL)
				xo_errx(1, "ipfw trace: packets %s: %s", argv[4],
				    e);
		}
		if ((error = arc_fw_trace(cl, &tq, &tr)) != 0)
			fail(cl, error, "ipfw trace");
		error = json_out("ipfw trace", tr->ok, tr->error, tr->json,
		    tr->trace.v, tr->trace.n);
		arc_fw_trace_rsp_free(tr);
		return (error);
	}
	if (strcmp(argv[1], "rules") == 0) {
		from = NULL;
		memset(&req, 0, sizeof(req));
		req.jail = netjail;
		argc--;
		argv++;
		optind = 1;
		optreset = 1;
		while ((ch = getopt(argc, argv, "nrw:")) != -1) {
			switch (ch) {
			case 'n':
				req.dry_run = true;
				break;
			case 'r':
				req.from_rc = true;
				break;
			case 'w':
				from = optarg;
				break;
			default:
				usage();
			}
		}
		if (argc != optind || (req.dry_run && from == NULL) ||
		    (req.from_rc && from != NULL))
			usage();
		if (from != NULL) {
			if ((fd = open(from, O_RDONLY)) == -1 || fstat(fd,
			    &sb) == -1 || (text = malloc((size_t)sb.st_size +
			    1)) == NULL || read(fd, text, (size_t)sb.st_size) !=
			    sb.st_size)
				xo_err(1, "%s", from);
			close(fd);
			text[sb.st_size] = '\0';
			if ((error = arc_ipfw_rules(cl, &req, &cur)) != 0)
				fail(cl, error, "ipfw rules");
			req.sha256 = cur->sha256;
			req.conf_text = text;
		}
		if ((error = arc_ipfw_rules(cl, &req, &rsp)) != 0)
			fail(cl, error, "ipfw rules");
		if (req.from_rc && rsp->rc_file != NULL)
			xo_emit("{:rc-file/# from %s}\n", rsp->rc_file);
		if (from == NULL && rsp->conf_text != NULL && rsp->ok)
			xo_emit("{:text/%s}", rsp->conf_text);
		else if (rsp->ok)
			xo_emit("{:result/%s}\n", req.dry_run ? "ipfw has "
			    "nothing against it; left as it was" : "in place; "
			    "the one before is kept beside it");
		emit_trace(rsp->trace.v, rsp->trace.n);
		error = rsp->ok ? 0 : 1;
		if (!rsp->ok)
			xo_warnx("ipfw rules: %s", rsp->error != NULL ?
			    rsp->error : "failed");
		arc_ipfw_rules_rsp_free(rsp);
		return (error);
	}
	keep = strcmp(argv[1], "keep") == 0;
	if (keep) {
		argc--;
		argv++;
		if (argc < 2)
			usage();
	}
	memset(&sp, 0, sizeof(sp));
	sp.has_kind = true;
	sp.kind = ARC_JOB_KIND_IPFW;
	sp.verb = argv[1];
	sp.names.v = (const char *const *)(uintptr_t)(argv + 2);
	sp.names.n = (size_t)(argc - 2);
	sp.live = !keep;
	sp.persist = keep || persist;
	sp.safe = safe;
	sp.jail = netjail;
	return (submit(cl, &sp));
}

/* bridge | geneve name verb word ...: a job; with -p kept in rc.conf. */
static int
cmd_l2(struct arc_client *cl, int argc, char **argv)
{
	struct arc_job_spec	 sp;

	if (argc < 3)
		usage();
	memset(&sp, 0, sizeof(sp));
	sp.has_kind = true;
	sp.kind = strcmp(argv[0], "bridge") == 0 ? ARC_JOB_KIND_BRIDGE :
	    ARC_JOB_KIND_GENEVE;
	sp.interface = argv[1];
	sp.verb = argv[2];
	sp.names.v = (const char *const *)(uintptr_t)(argv + 3);
	sp.names.n = (size_t)(argc - 3);
	sp.persist = persist;
	sp.safe = safe;
	sp.jail = netjail;
	return (submit(cl, &sp));
}

/* storage kind [dataset]: the host's storage, as the host says it. */
static int
cmd_storage(struct arc_client *cl, int argc, char **argv)
{
	static const char *kinds[] = { "disks", "pools", "datasets",
	    "snapshots", "mounts", "importable", "health" };
	struct arc_storage_req	 req;
	struct arc_storage_rsp	*rsp;
	size_t			 i;
	int			 error;

	if (argc < 2 || argc > 3)
		usage();
	for (i = 0; i < nitems(kinds); i++)
		if (strcmp(argv[1], kinds[i]) == 0)
			break;
	if (i == nitems(kinds) || (argc == 3 && i != 3))
		usage();
	memset(&req, 0, sizeof(req));
	req.has_storage_kind = true;
	req.storage_kind = (uint8_t)i;
	req.net_filter = argc == 3 ? argv[2] : NULL;
	/* -j: what that jail's own zfs sees. */
	req.jail = netjail;
	if ((error = arc_storage(cl, &req, &rsp)) != 0)
		fail(cl, error, "storage");
	if (rsp->json != NULL)
		xo_emit("{:json/%s}\n", rsp->json);
	if (rsp->truncated)
		xo_warnx("storage %s: there are %ju, more than a reply "
		    "carries: these are the first", kinds[i],
		    (uintmax_t)rsp->total);
	emit_trace(rsp->trace.v, rsp->trace.n);
	error = rsp->ok ? 0 : 1;
	if (!rsp->ok)
		xo_warnx("storage %s: %s", kinds[i], rsp->error != NULL ?
		    rsp->error : "failed");
	arc_storage_rsp_free(rsp);
	return (error);
}

/*
 * zfs, zpool, gpart, cam, mount and umount: a job of that kind, with
 * the verb and its words.  -r and -f among the words are the job's
 * flags, not words: the host gives no word to a program as an option.
 */
static int
cmd_storage_job(struct arc_client *cl, int argc, char **argv)
{
	struct arc_job_spec	 sp;
	const char		*words[24];
	int			 i, first;

	memset(&sp, 0, sizeof(sp));
	sp.has_kind = true;
	sp.safe = safe;
	sp.jail = netjail;
	first = 2;
	if (strcmp(argv[0], "swapon") == 0 || strcmp(argv[0], "swapoff") ==
	    0) {
		sp.kind = ARC_JOB_KIND_MOUNT;
		sp.verb = argv[0];
		first = 1;
	} else if (strcmp(argv[0], "mount") == 0 || strcmp(argv[0],
	    "umount") == 0) {
		sp.kind = ARC_JOB_KIND_MOUNT;
		sp.verb = argv[0][0] == 'm' ? "mount" : "unmount";
		first = 1;
	} else {
		if (argc < 2)
			usage();
		sp.kind = strcmp(argv[0], "zfs") == 0 ? ARC_JOB_KIND_ZFS :
		    strcmp(argv[0], "zpool") == 0 ? ARC_JOB_KIND_ZPOOL :
		    strcmp(argv[0], "gpart") == 0 ? ARC_JOB_KIND_GPART :
		    ARC_JOB_KIND_CAM;
		sp.verb = argv[1];
	}
	sp.names.v = words;
	for (i = first; i < argc; i++) {
		if (strcmp(argv[i], "-r") == 0)
			sp.recursive = true;
		else if (strcmp(argv[i], "-f") == 0)
			sp.force = true;
		else if (sp.names.n < nitems(words))
			words[sp.names.n++] = argv[i];
		else
			usage();
	}
	return (submit(cl, &sp));
}

/* fstab: print it.  fstab -w new-text [-n]: put a local file in its place. */
static int
cmd_fstab(struct arc_client *cl, int argc, char **argv)
{
	struct arc_fstab_req	 req;
	struct arc_fstab_rsp	*rsp, *cur;
	struct stat		 sb;
	const char		*from;
	char			*text;
	int			 ch, error, fd;

	from = NULL;
	memset(&req, 0, sizeof(req));
	optind = 1;
	optreset = 1;
	while ((ch = getopt(argc, argv, "nw:")) != -1) {
		switch (ch) {
		case 'n':
			req.dry_run = true;
			break;
		case 'w':
			from = optarg;
			break;
		default:
			usage();
		}
	}
	if (argc != optind || (req.dry_run && from == NULL))
		usage();
	text = NULL;
	cur = NULL;
	if (from != NULL) {
		if ((fd = open(from, O_RDONLY)) == -1 || fstat(fd, &sb) == -1 ||
		    (text = malloc((size_t)sb.st_size + 1)) == NULL ||
		    read(fd, text, (size_t)sb.st_size) != sb.st_size)
			xo_err(1, "%s", from);
		close(fd);
		text[sb.st_size] = '\0';
		/* What is there now says what the new text replaces. */
		if ((error = arc_fstab(cl, &req, &cur)) != 0)
			fail(cl, error, "fstab");
		req.sha256 = cur->sha256;
		req.conf_text = text;
	}
	if ((error = arc_fstab(cl, &req, &rsp)) != 0)
		fail(cl, error, "fstab");
	if (from == NULL && rsp->conf_text != NULL)
		xo_emit("{:text/%s}", rsp->conf_text);
	else if (rsp->ok)
		xo_emit("{:result/%s}\n", req.dry_run ? "it is an fstab; left "
		    "as it was" : "in place; the one before is kept beside "
		    "it");
	emit_trace(rsp->trace.v, rsp->trace.n);
	error = rsp->ok ? 0 : 1;
	if (!rsp->ok)
		xo_warnx("fstab: %s", rsp->error != NULL ? rsp->error :
		    "failed");
	arc_fstab_rsp_free(rsp);
	if (cur != NULL)
		arc_fstab_rsp_free(cur);
	free(text);
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

/* The installed packages: by hand or automatic, size, what each is. */
static void
emit_installed(const struct arc_package *v, size_t n)
{
	size_t	i;

	xo_emit("{T:/%-32s} {T:/%-18s} {T:/%-9s} {T:/%10s} {T:/%s}\n",
	    "PACKAGE", "VERSION", "INSTALLED", "SIZE", "COMMENT");
	xo_open_list("package");
	for (i = 0; i < n; i++) {
		xo_open_instance("package");
		xo_emit("{k:name/%-32s/%s} {:installed/%-18s/%s} "
		    "{:how/%-9s/%s} {:size/%10ju} {:comment/%s}\n", v[i].name,
		    v[i].installed != NULL ? v[i].installed : "",
		    v[i].automatic ? "automatic" : "by hand",
		    (uintmax_t)v[i].size, v[i].comment != NULL ?
		    v[i].comment : "");
		xo_close_instance("package");
	}
	xo_close_list("package");
}

/*
 * packages [-i] [-r] [-4 | -6] [jail]: what has a newer version in the
 * repository; with -i, what is installed.
 */
static int
cmd_packages(struct arc_client *cl, int argc, char **argv)
{
	struct arc_packages_req	 req;
	struct arc_packages_rsp	*rsp;
	int			 ch, error;

	memset(&req, 0, sizeof(req));
	optind = 1;
	while ((ch = getopt(argc, argv, "46ir")) != -1) {
		switch (ch) {
		case '4':
		case '6':
			req.has_pkg_ip = true;
			req.pkg_ip = (uint8_t)(ch - '0');
			break;
		case 'i':
			req.has_pkg_installed = true;
			req.pkg_installed = true;
			break;
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
	if (rsp->ok && req.pkg_installed)
		emit_installed(rsp->packages.v, rsp->packages.n);
	else if (rsp->ok)
		emit_packages(rsp->packages.v, rsp->packages.n);
	/* pkg's repositories there: what -r of pkg-upgrade may name. */
	if (rsp->ok && rsp->pkg_repos.n > 0) {
		size_t	i;

		xo_open_list("repository");
		xo_emit("{Lwc:Repositories}");
		for (i = 0; i < rsp->pkg_repos.n; i++)
			xo_emit("{P: }{l:repository/%s}", rsp->pkg_repos.v[i]);
		xo_close_list("repository");
		xo_emit("\n");
	}
	emit_trace(rsp->trace.v, rsp->trace.n);
	error = rsp->ok ? 0 : 1;
	if (!rsp->ok)
		xo_warnx("packages: %s", rsp->error != NULL ? rsp->error :
		    "failed");
	arc_packages_rsp_free(rsp);
	return (error);
}

/*
 * pkg-clean [-a] [-j jail | -J]: the cache of downloaded packages, a
 * job; with -J, of every running jail, one batch of a job each.
 */
static int
cmd_pkg_clean(struct arc_client *cl, int argc, char **argv)
{
	struct arc_job_submit_req	 req;
	struct arc_job_submit_rsp	*rsp;
	struct arc_list_req		 lq;
	struct arc_list_rsp		*lr;
	struct arc_job_spec		 sp, *v;
	size_t				 i, n;
	int				 ch, error;
	bool				 jails;

	memset(&sp, 0, sizeof(sp));
	sp.has_kind = true;
	sp.kind = ARC_JOB_KIND_PKG_CLEAN;
	jails = false;
	optind = 1;
	while ((ch = getopt(argc, argv, "aJj:")) != -1) {
		switch (ch) {
		case 'a':
			sp.force = true;
			break;
		case 'J':
			jails = true;
			break;
		case 'j':
			sp.jail = optarg;
			break;
		default:
			usage();
		}
	}
	if (optind != argc || (jails && sp.jail != NULL))
		usage();
	if (!jails)
		return (submit(cl, &sp));
	memset(&lq, 0, sizeof(lq));
	if ((error = arc_list(cl, &lq, &lr)) != 0)
		fail(cl, error, "list");
	if ((v = calloc(lr->jails.n + 1, sizeof(*v))) == NULL)
		xo_err(1, "calloc");
	for (i = n = 0; i < lr->jails.n; i++) {
		if (!lr->jails.v[i].has_state || lr->jails.v[i].state !=
		    ARC_JAIL_STATE_RUNNING || lr->jails.v[i].name == NULL)
			continue;
		v[n] = sp;
		v[n].jail = lr->jails.v[i].name;
		v[n].safe = safe;
		v[n].has_safe_wait = safe && safe_wait > 0;
		v[n].safe_wait = safe_wait;
		n++;
	}
	if (n == 0) {
		xo_warnx("pkg-clean: no running jail");
		free(v);
		arc_list_rsp_free(lr);
		return (1);
	}
	memset(&req, 0, sizeof(req));
	req.batch.v = v;
	req.batch.n = n;
	if ((error = arc_job_submit(cl, &req, &rsp)) != 0)
		fail(cl, error, "queue");
	xo_open_list("job");
	for (i = 0; i < rsp->jobs.n; i++)
		emit_job(&rsp->jobs.v[i]);
	xo_close_list("job");
	error = rsp->ok ? 0 : 1;
	if (!rsp->ok)
		xo_warnx("pkg-clean: %s", rsp->error != NULL ? rsp->error :
		    "not accepted");
	arc_job_submit_rsp_free(rsp);
	arc_list_rsp_free(lr);
	free(v);
	return (error);
}

/* pkg-install [-O] [-4 | -6] [-r repo] [-j jail] package ...: a job. */
static int
cmd_pkg_install(struct arc_client *cl, int argc, char **argv)
{
	struct arc_job_spec	sp;
	int			ch;

	memset(&sp, 0, sizeof(sp));
	sp.has_kind = true;
	sp.kind = ARC_JOB_KIND_PKG_INSTALL;
	optind = 1;
	while ((ch = getopt(argc, argv, "46Oj:r:")) != -1) {
		switch (ch) {
		case '4':
		case '6':
			sp.has_pkg_ip = true;
			sp.pkg_ip = (uint8_t)(ch - '0');
			break;
		case 'O':
			sp.force = true;
			break;
		case 'r':
			sp.pkg_repo = optarg;
			break;
		case 'j':
			sp.jail = optarg;
			break;
		default:
			usage();
		}
	}
	if (optind == argc)
		usage();
	sp.names.v = (const char **)(uintptr_t)&argv[optind];
	sp.names.n = (size_t)(argc - optind);
	return (submit(cl, &sp));
}

/*
 * ipsec init | conn name local remote mode pubkey [word value ...] |
 * unconn name | up name | down name: strongSwan, a job, in the vnet
 * jail of -j when one is named.
 */
static int
cmd_ipsec(struct arc_client *cl, int argc, char **argv)
{
	struct arc_job_spec	 sp;
	const char		*errstr;
	int			 i;

	if (argc < 2)
		usage();
	memset(&sp, 0, sizeof(sp));
	sp.has_kind = true;
	sp.kind = ARC_JOB_KIND_IPSEC;
	sp.jail = netjail;
	sp.persist = persist;
	sp.verb = argv[1];
	if (strcmp(argv[1], "init") == 0 || strcmp(argv[1], "start") == 0) {
		if (argc != 2)
			usage();
		return (submit(cl, &sp));
	}
	if (argc < 3)
		usage();
	sp.conn = argv[2];
	if (strcmp(argv[1], "unconn") == 0 || strcmp(argv[1], "up") == 0 ||
	    strcmp(argv[1], "down") == 0) {
		if (argc != 3)
			usage();
		return (submit(cl, &sp));
	}
	if (strcmp(argv[1], "unchild") == 0) {
		if (argc != 4)
			usage();
		sp.child = argv[3];
		return (submit(cl, &sp));
	}
	/*
	 * conn name local remote [words]: the connection, this host and
	 * the peer by pubkey KEY, remote-cert FILE or remote-ca FILE, and
	 * with mode a child of its name; child conn name mode [words]: a
	 * child of its own.  The words come in pairs, in any order.
	 */
	if (strcmp(argv[1], "conn") == 0) {
		if (argc < 5)
			usage();
		sp.tunnel_local = argv[3];
		sp.tunnel_remote = argv[4];
		i = 5;
	} else if (strcmp(argv[1], "child") == 0) {
		if (argc < 5)
			usage();
		sp.child = argv[3];
		sp.ipsec_mode = argv[4];
		i = 5;
	} else
		usage();
	for (; i + 1 < argc; i += 2) {
		if (strcmp(argv[i], "mode") == 0)
			sp.ipsec_mode = argv[i + 1];
		else if (strcmp(argv[i], "pubkey") == 0)
			sp.pubkey = argv[i + 1];
		else if (strcmp(argv[i], "local-cert") == 0)
			sp.local_cert = argv[i + 1];
		else if (strcmp(argv[i], "remote-cert") == 0)
			sp.remote_cert = argv[i + 1];
		else if (strcmp(argv[i], "remote-ca") == 0)
			sp.remote_ca = argv[i + 1];
		else if (strcmp(argv[i], "reqid") == 0) {
			sp.has_reqid = true;
			sp.reqid = (uint32_t)strtonum(argv[i + 1], 1, 16383,
			    &errstr);
			if (errstr != NULL)
				xo_errx(2, "reqid %s: %s", argv[i + 1], errstr);
		} else if (strcmp(argv[i], "local-ts") == 0)
			sp.local_ts = argv[i + 1];
		else if (strcmp(argv[i], "remote-ts") == 0)
			sp.remote_ts = argv[i + 1];
		else if (strcmp(argv[i], "start") == 0)
			sp.start_action = argv[i + 1];
		else if (strcmp(argv[i], "local-id") == 0)
			sp.local_id = argv[i + 1];
		else if (strcmp(argv[i], "remote-id") == 0)
			sp.remote_id = argv[i + 1];
		else
			usage();
	}
	if (i != argc)
		usage();
	return (submit(cl, &sp));
}

/* pkg-upgrade [-n] [-O] [-4 | -6] [-r repo] [-j jail | -J] [package ...]:
 * -J, of every running jail, by the agent, one after the other; -r, from
 * that repository alone. */
static int
cmd_pkg_upgrade(struct arc_client *cl, int argc, char **argv)
{
	struct arc_pkg_upgrade_req	 req;
	struct arc_pkg_upgrade_rsp	*rsp;
	int				 ch, error;

	memset(&req, 0, sizeof(req));
	optind = 1;
	while ((ch = getopt(argc, argv, "46OJj:nr:")) != -1) {
		switch (ch) {
		case '4':
		case '6':
			req.has_pkg_ip = true;
			req.pkg_ip = (uint8_t)(ch - '0');
			break;
		case 'O':
			/* Packages for a newer FreeBSD too. */
			req.has_ignore_osversion = true;
			req.ignore_osversion = true;
			break;
		case 'j':
			req.jail = optarg;
			break;
		case 'J':
			req.jail = "*";
			break;
		case 'n':
			req.dry_run = true;
			break;
		case 'r':
			req.pkg_repo = optarg;
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
		sp.force = req.ignore_osversion;
		sp.has_pkg_ip = req.has_pkg_ip;
		sp.pkg_ip = req.pkg_ip;
		sp.pkg_repo = req.pkg_repo;
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

/*
 * Queue one job.  With -q say its number and leave; without, read the
 * job until it is done, as "job -w id", which is also what confirms a
 * change made in safe mode.
 */
static int
submit(struct arc_client *cl, struct arc_job_spec *sp)
{
	struct arc_job_submit_req	 req;
	struct arc_job_submit_rsp	*rsp;
	char				 id[24], *jargv[4];
	size_t				 i;
	int				 error;

	sp->safe = safe;
	sp->has_safe_wait = safe && safe_wait > 0;
	sp->safe_wait = safe_wait;
	memset(&req, 0, sizeof(req));
	req.batch.v = sp;
	req.batch.n = 1;
	if ((error = arc_job_submit(cl, &req, &rsp)) != 0)
		fail(cl, error, "queue");
	if (!queue) {
		if (!rsp->ok || rsp->jobs.n != 1) {
			xo_warnx("%s", rsp->error != NULL ? rsp->error :
			    "not accepted");
			arc_job_submit_rsp_free(rsp);
			return (1);
		}
		snprintf(id, sizeof(id), "%ju", (uintmax_t)rsp->jobs.v[0].id);
		arc_job_submit_rsp_free(rsp);
		jargv[0] = (char *)(uintptr_t)"job";
		jargv[1] = (char *)(uintptr_t)"-w";
		jargv[2] = id;
		jargv[3] = NULL;
		optreset = 1;
		return (cmd_job(cl, 3, jargv));
	}
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
	/* What is under way that is not a job, and a stop that waits. */
	if (rsp->activity != NULL)
		xo_emit("{Lwc:Under way}{:activity/%s}{d:/ (%jd s)}"
		    "{e:since/%jd}\n", rsp->activity, (intmax_t)(time(NULL) -
		    rsp->since), (intmax_t)rsp->since);
	if (rsp->stopping)
		xo_emit("{Lwc:Stopping}{:stopping/%s}\n", rsp->activity !=
		    NULL || rsp->jobs.n > 0 ? "when what is under way ends" :
		    "now");
	arc_jobs_rsp_free(rsp);
	return (0);
}

/* job [-w] id: the job and its trace; -w waits for it to finish. */
static int
cmd_job(struct arc_client *cl, int argc, char **argv)
{
	struct arc_job_req	 req;
	struct arc_job_rsp	*rsp;
	struct arc_job_confirm_req creq;
	struct arc_job_confirm_rsp *crsp;
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
		/*
		 * A safe change is made and waits to hear from us: that
		 * this request gets through is what it waits for.
		 */
		if (rsp->job->state == ARC_JOB_STATE_UNCONFIRMED) {
			memset(&creq, 0, sizeof(creq));
			creq.has_id = true;
			creq.id = req.id;
			if (arc_job_confirm(cl, &creq, &crsp) == 0)
				arc_job_confirm_rsp_free(crsp);
		}
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
	const char		*uri, *cafile, *certfile, *keyfile, *name, *errstr;
	int			 ch, error, rc;

	if ((argc = xo_parse_args(argc, argv)) < 0)
		exit(2);
	uri = PATH_SOCKET;
	cafile = certfile = keyfile = name = NULL;
	while ((ch = getopt(argc, argv, "+A:C:c:F:j:K:N:pqstW:")) != -1) {
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
		case 'F':
			fib = (uint32_t)strtonum(optarg, 0, 65535, &errstr);
			if (errstr != NULL)
				xo_errx(2, "-F %s: %s", optarg, errstr);
			break;
		case 'j':
			netjail = optarg;
			break;
		case 'p':
			persist = true;
			break;
		case 'q':
			queue = true;
			break;
		case 's':
			safe = true;
			break;
		case 'W':
			safe_wait = (uint32_t)strtonum(optarg, 10, 3600,
			    &errstr);
			if (errstr != NULL)
				xo_errx(2, "-W %s: %s", optarg, errstr);
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
	else if (strcmp(argv[0], "interface") == 0 ||
	    strcmp(argv[0], "route") == 0 || strcmp(argv[0], "ng") == 0 ||
	    strcmp(argv[0], "wg") == 0 || strcmp(argv[0], "bird") == 0)
		rc = cmd_interface(&cl, argc, argv);
	else if (strcmp(argv[0], "net") == 0)
		rc = cmd_net(&cl, argc, argv);
	else if (strcmp(argv[0], "stats") == 0 && argc == 1)
		rc = cmd_stats(&cl);
	else if (strcmp(argv[0], "ntp") == 0)
		rc = cmd_ntp(&cl, argc, argv);
	else if (strcmp(argv[0], "rtadvd") == 0)
		rc = cmd_rtadvd(&cl, argc, argv);
	else if (strcmp(argv[0], "ipsec-sa") == 0)
		rc = cmd_ipsec_sa(&cl, argc, argv);
	else if (strcmp(argv[0], "kmod") == 0)
		rc = cmd_kmod(&cl, argc, argv);
	else if (strcmp(argv[0], "jailconf") == 0)
		rc = cmd_jailconf(&cl, argc, argv);
	else if (strcmp(argv[0], "neigh") == 0)
		rc = cmd_neigh(&cl, argc, argv);
	else if (strcmp(argv[0], "carp") == 0)
		rc = cmd_carp(&cl, argc, argv);
	else if (strcmp(argv[0], "cert") == 0)
		rc = cmd_cert(&cl, argc, argv);
	else if (strcmp(argv[0], "crashes") == 0)
		rc = cmd_crashes(&cl, argc, argv);
	else if (strcmp(argv[0], "clamav") == 0)
		rc = cmd_clamav(&cl, argc, argv);
	else if (strcmp(argv[0], "system") == 0)
		rc = cmd_system(&cl, argc, argv);
	else if (strcmp(argv[0], "geom") == 0)
		rc = cmd_geom(&cl, argc, argv);
	else if (strcmp(argv[0], "sysfile") == 0)
		rc = cmd_sysfile(&cl, argc, argv);
	else if (strcmp(argv[0], "netstore") == 0)
		rc = cmd_netstore(&cl, argc, argv);
	else if (strcmp(argv[0], "nfs") == 0)
		rc = cmd_netstore_job(&cl, argc, argv, ARC_JOB_KIND_NFS);
	else if (strcmp(argv[0], "iscsi") == 0)
		rc = cmd_netstore_job(&cl, argc, argv, ARC_JOB_KIND_ISCSI);
	else if (strcmp(argv[0], "hast") == 0)
		rc = cmd_netstore_job(&cl, argc, argv, ARC_JOB_KIND_HAST);
	else if (strcmp(argv[0], "suricata") == 0)
		rc = cmd_suricata(&cl, argc, argv);
	else if (strcmp(argv[0], "poudriere") == 0)
		rc = cmd_poudriere(&cl, argc, argv);
	else if (strcmp(argv[0], "sshd") == 0)
		rc = cmd_sshd(&cl, argc, argv);
	else if (strcmp(argv[0], "capture") == 0)
		rc = cmd_capture(&cl, argc, argv);
	else if (strcmp(argv[0], "tls") == 0)
		rc = cmd_tls(&cl, argc, argv, certfile);
	else if (strcmp(argv[0], "zfskey") == 0)
		rc = cmd_zfskey(&cl, argc, argv);
	else if (strcmp(argv[0], "sysctl") == 0)
		rc = cmd_sysctl(&cl, argc, argv);
	else if (strcmp(argv[0], "ps") == 0 || strcmp(argv[0], "signal") == 0 ||
	    strcmp(argv[0], "renice") == 0 || strcmp(argv[0], "log") == 0 ||
	    strcmp(argv[0], "history") == 0 || strcmp(argv[0], "events") == 0)
		rc = cmd_gula(&cl, argc, argv);
	else if (strcmp(argv[0], "transport") == 0)
		rc = cmd_transport(&cl, argc, argv);
	else if (strcmp(argv[0], "config-export") == 0)
		rc = cmd_config_export(&cl, argc, argv);
	else if (strcmp(argv[0], "config-apply") == 0)
		rc = cmd_config_apply(&cl, argc, argv);
	else if (strcmp(argv[0], "path-check") == 0)
		rc = cmd_path_check(&cl, argc, argv);
	else if (strcmp(argv[0], "notify") == 0)
		rc = cmd_notify(&cl, argc, argv);
	else if (strcmp(argv[0], "storage") == 0)
		rc = cmd_storage(&cl, argc, argv);
	else if (strcmp(argv[0], "zfs") == 0 || strcmp(argv[0], "zpool") == 0 ||
	    strcmp(argv[0], "gpart") == 0 || strcmp(argv[0], "cam") == 0 ||
	    strcmp(argv[0], "mount") == 0 || strcmp(argv[0], "umount") == 0 ||
	    strcmp(argv[0], "swapon") == 0 || strcmp(argv[0], "swapoff") == 0)
		rc = cmd_storage_job(&cl, argc, argv);
	else if (strcmp(argv[0], "fstab") == 0)
		rc = cmd_fstab(&cl, argc, argv);
	else if (strcmp(argv[0], "ipfw") == 0)
		rc = cmd_ipfw(&cl, argc, argv);
	else if (strcmp(argv[0], "bridge") == 0 || strcmp(argv[0], "geneve") ==
	    0)
		rc = cmd_l2(&cl, argc, argv);
	else if (strcmp(argv[0], "packages") == 0)
		rc = cmd_packages(&cl, argc, argv);
	else if (strcmp(argv[0], "jobs") == 0 && argc == 1)
		rc = cmd_jobs(&cl);
	else if (strcmp(argv[0], "job") == 0)
		rc = cmd_job(&cl, argc, argv);
	else if (strcmp(argv[0], "job-cancel") == 0)
		rc = cmd_job_cancel(&cl, argc, argv);
	else if (strcmp(argv[0], "pkg-clean") == 0)
		rc = cmd_pkg_clean(&cl, argc, argv);
	else if (strcmp(argv[0], "pkg-install") == 0)
		rc = cmd_pkg_install(&cl, argc, argv);
	else if (strcmp(argv[0], "ipsec") == 0)
		rc = cmd_ipsec(&cl, argc, argv);
	else if (strcmp(argv[0], "pkg-upgrade") == 0)
		rc = cmd_pkg_upgrade(&cl, argc, argv);
	else if (strcmp(argv[0], "agent-update") == 0)
		rc = cmd_agent_update(&cl, argc, argv);
	else if (strcmp(argv[0], "agent-build") == 0)
		rc = cmd_agent_build(&cl, argc, argv);
	else if (strcmp(argv[0], "traceroute") == 0)
		rc = cmd_traceroute(&cl, argc, argv);
	else if (strcmp(argv[0], "sdwan") == 0)
		rc = cmd_sdwan(&cl, argc, argv);
	else if (strcmp(argv[0], "source-head") == 0)
		rc = cmd_source_head(&cl, argc, argv);
	else if (strcmp(argv[0], "source-log") == 0)
		rc = cmd_source_log(&cl, argc, argv);
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
