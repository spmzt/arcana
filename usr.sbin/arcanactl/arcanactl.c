/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * arcanactl: talk to a arcana-agent(8) from the command line.
 */

#include <sys/param.h>
#include <sys/capsicum.h>
#include <sys/stat.h>

#include <capsicum_helpers.h>
#include <casper/cap_fileargs.h>
#include <ctype.h>
#include <err.h>
#include <fcntl.h>
#include <libcasper.h>
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
#include <cbl_data.h>
#include <ymodel.h>
#include <ucl.h>

#include "yjsonin.h"
#include "yqueue.h"
#include "ygula.h"
#include "yhostjson.h"
#include "ystore.h"
#include "yprobes.h"
#include "ysdwan.h"
#include "ytshoot.h"
#include "yreads.h"
#include "ystream.h"
#include "zprog.h"

#define	PATH_SOCKET	"unix:/var/run/arcana-agent.sock"
#define	MAX_FRAME	(8 * 1024 * 1024)
#define	MAX_ATTRS	(1024 * 1024)
#define	MAX_DEPTH	32	/* a jail's root, its instances' routing in it */
#define	TIMEOUT_MS	(15 * 60 * 1000)

static const char *state_names[] = {
	[ARC_JAIL_STATE_RUNNING] = "running",
	[ARC_JAIL_STATE_STOPPED] = "stopped",
	[ARC_JAIL_STATE_DYING] = "dying",
	[ARC_JAIL_STATE_ABSENT] = "absent",
};

static const char *kind_names[] = {
	[ARCANA_JOBS_STEP_KIND_DAEMON] = "daemon",
	[ARCANA_JOBS_STEP_KIND_LIB] = "lib",
	[ARCANA_JOBS_STEP_KIND_SYSCALL] = "syscall",
	[ARCANA_JOBS_STEP_KIND_FILE] = "file",
	[ARCANA_JOBS_STEP_KIND_EXEC] = "exec",
};

static const char *status_names[] = {
	[ARCANA_JOBS_STEP_STATUS_OK] = "ok",
	[ARCANA_JOBS_STEP_STATUS_FAILED] = "failed",
	[ARCANA_JOBS_STEP_STATUS_INCOMPLETE] = "incomplete",
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
static void	fail(int, const char *) __dead2;
static char	*slurp(const char *);
static char	*words_joined(int, char **);

/*
 * In capability mode (capsicum(4)) once the agent is connected: the
 * files named on the command line are opened by Casper's fileargs
 * service, nothing else of the system is reachable.
 */
static fileargs_t	*files;		/* to read */
static fileargs_t	*outfiles;	/* agent-build's program, to write */
static const char *join(const char *const *, size_t);
static void	emit_jail(const struct arcana_jails_jails_jail *, bool);
static void	emit_trace(const struct arcana_jobs_step *, size_t);
static void	emit_lines(const char *, const struct cbl_bytes *);
static int	cmd_hello(cbl_conn *);
static int	cmd_list(cbl_conn *, int, char **);
static int	cmd_action(cbl_conn *, uint8_t, int, char **);
static int	cmd_address(cbl_conn *, int, char **);
static int	cmd_allow(cbl_conn *, int, char **);
static int	cmd_services(cbl_conn *);
static int	cmd_net(cbl_conn *, int, char **);
static int	cmd_stats(cbl_conn *);
static int	cmd_kmod(cbl_conn *, int, char **);
static int	cmd_sysctl(cbl_conn *, int, char **);
static int	cmd_gula(cbl_conn *, int, char **);
static int	cmd_ipfw(cbl_conn *, int, char **);
static int	cmd_l2(cbl_conn *, int, char **);
static int	cmd_transport(cbl_conn *, int, char **);
static int	cmd_config_export(cbl_conn *, int, char **);
static int	cmd_config_apply(cbl_conn *, int, char **);
static int	cmd_path_check(cbl_conn *, int, char **);
static int	cmd_notify(cbl_conn *, int, char **);
static int	cmd_storage(cbl_conn *, int, char **);
static int	cmd_storage_job(cbl_conn *, int, char **);
static int	cmd_fstab(cbl_conn *, int, char **);
static int	cmd_packages(cbl_conn *, int, char **);
static int	cmd_pkg_clean(cbl_conn *, int, char **);
static int	cmd_pkg_install(cbl_conn *, int, char **);
static int	cmd_ipsec(cbl_conn *, int, char **);
static int	cmd_pkg_upgrade(cbl_conn *, int, char **);
static void	emit_packages(const struct arcana_packages_package *, size_t);
static int	submit(cbl_conn *, struct arc_job_spec *);
static void	emit_job(const struct arc_job *);
static int	cmd_jobs(cbl_conn *);
static int	cmd_job(cbl_conn *, int, char **);
static int	cmd_reboot(cbl_conn *);
static int	cmd_interface(cbl_conn *, int, char **);
static int	cmd_job_cancel(cbl_conn *, int, char **);
static int	cmd_service(cbl_conn *, int, char **);
static void	emit_service(const struct arc_service *, bool);

static void
usage(void)
{

	xo_error("usage: arcanactl [-pqst] [-F fib] [-j jail] [-W seconds] "
	    "[-c uri] [-u user] "
	    "[-A cafile -C certfile\n                 -K keyfile] [-N name] "
	    "command\n"
	    "commands:\n"
	    "    hello\n"
	    "    get [-d datastore] [-w mode] [-o] [-x xpath] [node ...]\n"
	    "    edit [-r] [-a warning]... node value | @file\n"
	    "    set [-nx] [-d datastore] [-a warning]... path [value | @file]\n"
	    "    commit [-c seconds [-p persist]] [-i persist-id] "
	    "[-a warning]...\n"
	    "    cancel-commit [-i persist-id]\n"
	    "    discard\n"
	    "    action path [key ...] action [leaf=value ...]\n"
	    "    notifications\n"
	    "    subscribe [-n count] [-o seconds | -p seconds | -r time]\n"
	    "              [-s stop-time] [-x xpath | -f filter]\n"
	    "    list [-c]\n"
	    "    start | stop | restart | kill jail\n"
	    "    enable | disable [-a warning]... jail\n"
	    "    address add | remove [-lnp] [-i interface] jail address\n"
	    "    services\n"
	    "    services convert [-n] [-a warning]... [name ...]\n"
	    "    services release [-n] name ...\n"
	    "    service [-a warning]... name start | stop | restart | reload |\n"
	    "        enable | disable\n"
	    "    service [-a warning]... name config [-x key ...] "
	    "[key=value ...]\n"
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
	    "    route [keep] add destination gateway[@share][,gateway[@share]...] [metric n]\n"
	    "        [weight n] [source address] [name word]\n"
	    "    route [keep] delete destination [gateway] [metric n] [name word]\n"
	    "    route get address\n"
	    "    traceroute address\n"
	    "    reboot\n"
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
	    "    bird config -w new-text [-n] [-c seconds] [file]\n"
	    "    bird confirm id\n"
	    "    bird ospf [topology [protocol]]\n"
	    "    bird routes [prefix | for address] [protocol | export name]\n"
	    "        [table name] [all]\n"
	    "    stats\n"
	    "    kmod [load | unload | keep | forget module]   (kmod: get kernel)\n"
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
	    "    smtpd\n"
	    "    smtpd conf form.json | table name file | enable yes|no |\n"
	    "        pause|resume mta|mda|smtp | schedule|remove id|all | update name\n"
	    "    monitor | monitor set name=n [interface=if] [address=a] [name=value ...] |\n"
	    "        monitor remove name=n\n"
	    "    speeder\n"
	    "    speeder conf name=value ... | fec x:y[,x:y...] |\n"
	    "        enable | disable | start | stop | restart [profile=name] |\n"
	    "        remove profile=name\n"
	    "    sysfile file path | periodic name=YES|NO ... |\n"
	    "        rc kern_securelevel_enable=YES|NO kern_securelevel=N |\n"
	    "        dma smarthost=host [port=N] [tls=none|starttls|opportunistic|tls] [user=name]\n"	    "    geom class subcommand [word ...] [-P passfile]\n"
	    "    nfs exports file | server key=value ...\n"
	    "    iscsi conf file | enable yes|no\n"
	    "    hast conf file | enable yes|no | create resource |\n"
	    "        role init|primary|secondary resource\n"
	    "    suricata update | rules [q=text sid=N only=enabled|disabled|changed\n"
	    "        classtype=name offset=N limit=N | sources=1 |\n"
	    "        instance=name command=command [iface=interface] |\n"
	    "        instance=name profiling=1] |\n"
	    "        rule on=|off=|drop=|default=sid,... ... | sources |\n"
	    "        source-enable name=source [param=value ...] |\n"
	    "        source-disable|source-remove name=source |\n"
	    "        source-add name=source url=address |\n"
	    "        pcap instance=name file=path |\n"
	    "        pcap-put instance=name file=name [offset=N] [last=1] |\n"
	    "        pcap-get instance=name file=name\n"
	    "    capture [source packets seconds [filter ...]]\n"
	    "    zfskey [-n] dataset\n"
	    "    tls [status] | csr | install certfile|- [cafile]\n"
	    "    sshd [list] | banner file | set Setting [value ...] |\n"
	    "        authorize user keyfile | unauthorize user fingerprint |\n"
	    "        options user fingerprint [options] |\n"
	    "        sign ca-key-file [principal ...] | user-cas file\n"
	    "    ntp server ... | remove\n"
	    "    rtadvd interface prefix [dns ...] | interface remove\n"
	    "    allow [-n] jail allow.name=0|1|unset ...   (-p: in its file too)\n"
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
	    "    history set seconds samples [cpu%% mem%% swap%% [storage%%]] "
	    "[rules list]\n"
	    "    events [after | -f]\n"
	    "    net bridges | geneve | ipfw | nhgroups | kept-routes\n"
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
	    "    zpool destroy | export pool\n"
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
	    "    jail-base jail convert [-O] [-4 | -6] [-r repo] [-b release] "
	    "[set ...]\n"
	    "    jail-base jail upgrade [-O] [-4 | -6] [-r repo] release\n"
	    "    jobs [lanes number]\n"
	    "    job [-w] id\n"
	    "    job-cancel id\n"
	    "    agent-update [-pr] program\n"
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
fail(int error, const char *what)
{

	xo_errx(1, "%s: %s", what, strerror(error));
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
emit_jail(const struct arcana_jails_jails_jail *j, bool table)
{
	size_t	i, k;

	if (table) {
		xo_open_instance("jail");
		xo_emit("{k:name/%-16s/%s} {:state/%-8s/%s} ", j->name,
		    j->has_state && (size_t)j->state < nitems(state_names) ?
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
		for (i = 0; i < j->plugin.n; i++)
			xo_emit("{el:plugins/%s}", j->plugin.v[i]);
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
			    j->nproc, (uintmax_t)j->rss, (double)j->cpu / 100.0);
		xo_close_instance("jail");
		return;
	}

	/* One jail in detail. */
	xo_open_container("jail");
	xo_emit("{Lwc:Name}{:name/%s}\n", j->name);
	xo_emit("{Lwc:State}{:state/%s}", j->has_state &&
	    (size_t)j->state < nitems(state_names) ? state_names[j->state] :
	    "?");
	if (j->has_jid)
		xo_emit(" ({Lw:jid}{:jid/%u})", j->jid);
	xo_emit("\n");
	if (j->has_boot)
		xo_emit("{Lwc:At boot}{:boot/%s}\n", j->boot ? "started" :
		    "not started");
	if (j->hostname != NULL)
		xo_emit("{Lwc:Hostname}{:hostname/%s}\n", j->hostname);
	if (j->path != NULL)
		xo_emit("{Lwc:Path}{:path/%s}\n", j->path);
	if (j->plugin.n > 0) {
		xo_emit("{Lwc:Plugins}");
		xo_open_list("plugins");
		for (i = 0; i < j->plugin.n; i++)
			xo_emit("{P:/%s}{l:plugins/%s}", i > 0 ? " " : "",
			    j->plugin.v[i]);
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
		    "{:cpu-pct/%.1f}% CPU\n", j->nproc, (uintmax_t)j->rss,
		    (double)j->cpu / 100.0);
	if (j->param.n > 0) {
		xo_open_list("param");
		for (i = 0; i < j->param.n; i++) {
			xo_open_instance("param");
			xo_emit("{P:  }{:key/%s}", j->param.v[i].name);
			if (j->param.v[i].value.n > 0)
				xo_emit("{D: = }{d:/%s}", join(
				    j->param.v[i].value.v,
				    j->param.v[i].value.n));
			for (k = 0; k < j->param.v[i].value.n; k++)
				xo_emit("{el:value/%s}",
				    j->param.v[i].value.v[k]);
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
emit_trace(const struct arcana_jobs_step *v, size_t n)
{
	const struct arcana_jobs_step	*s;
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
		    (uintmax_t)s->duration);
		if (s->has_status && s->status != ARCANA_JOBS_STEP_STATUS_OK)
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

/* A module's rpc of that name. */
static const struct cbl_ynode *
yrpc_named(const char *name)
{
	const struct cbl_ymodule	*m;
	uint32_t			 i, k;

	for (i = 0; i < ymodel_schema.nmod; i++) {
		m = ymodel_schema.mod[i];
		for (k = 0; k < m->ntop; k++)
			if (m->top[k]->kind == CBL_YN_RPC &&
			    strcmp(m->top[k]->name, name) == 0)
				return (m->top[k]);
	}
	return (NULL);
}

/* A top-level data node of the models served, by its name. */
static const struct cbl_ynode *
ytop_named(const char *name)
{
	const struct cbl_ymodule	*m;
	const struct cbl_ynode		*n;
	uint32_t			 i, k;

	for (i = 0; i < ymodel_schema.nmod; i++) {
		m = ymodel_schema.mod[i];
		for (k = 0; k < m->ntop; k++) {
			n = m->top[k];
			if ((n->kind == CBL_YN_CONTAINER || n->kind ==
			    CBL_YN_LIST) && strcmp(n->name, name) == 0)
				return (n);
		}
	}
	return (NULL);
}

/* A top-level node of any kind (a structure too) by its name. */
static const struct cbl_ynode *
ytop_any(const char *name)
{

	for (uint32_t i = 0; i < ymodel_schema.nmod; i++)
		for (uint32_t k = 0; k < ymodel_schema.mod[i]->ntop; k++)
			if (strcmp(ymodel_schema.mod[i]->top[k]->name, name) ==
			    0)
				return (ymodel_schema.mod[i]->top[k]);
	return (NULL);
}

static void	sxf_run(cbl_conn *, const char *, const bool *);

static enum cbl_yds_name ds_named(const char *);

/*
 * get [-d datastore] [-w mode] [-o] [-x xpath] [node ...]: what the agent
 * serves of the models, by cblink's YANG family (family 1), as RFC 7951's
 * JSON: the top-level nodes named (arcanactl(8) lists them), or all of
 * them.  With -o, or -w report-all-tagged, with their annotations (RFC
 * 7952): each configuration node's origin (RFC 8342), the defaults.
 */
static int
cmd_get(cbl_conn *conn, int argc, char **argv)
{
	const struct cbl_ymodule	*m;
	const struct cbl_ynode		*n;
	struct cbl_ybuf			 b = { NULL, 0, 0 };
	cbl_msg				*req, *rep = NULL;
	cbl_yarena			*a;
	uint64_t			 sids[16];
	size_t				 ns = 0;
	uint32_t			 i, k;
	void				*data;
	char				 why[256], *out;
	const char			*xpath;
	enum cbl_yds_name		 ds;
	enum cbl_ywd			 wd;
	cbl_dtree			*t;
	bool				 first = true, origin, said;
	int				 error;

	/* -d datastore: running's or the candidate's, configuration
	 * alone (RFC 8342); -x expression: what an XPath selects. */
	xpath = NULL;
	ds = CBL_YDS_OPERATIONAL;
	said = false;
	i = 1;
	if (argc > 2 && strcmp(argv[1], "-d") == 0) {
		said = true;
		if ((ds = ds_named(argv[2])) == (enum cbl_yds_name)-1)
			xo_errx(2, "get: -d running, candidate or operational");
		i = 3;
	}
	/* -w mode: RFC 6243's: explicit, report-all, trim,
	 * report-all-tagged. */
	wd = CBL_YWD_EXPLICIT;
	if (argc > (int)i + 1 && strcmp(argv[i], "-w") == 0) {
		wd = strcmp(argv[i + 1], "report-all") == 0 ?
		    CBL_YWD_REPORT_ALL : strcmp(argv[i + 1], "trim") == 0 ?
		    CBL_YWD_TRIM : strcmp(argv[i + 1], "explicit") == 0 ?
		    CBL_YWD_EXPLICIT : strcmp(argv[i + 1],
		    "report-all-tagged") == 0 ? CBL_YWD_REPORT_ALL_TAGGED :
		    (enum cbl_ywd)-1;
		if (wd == (enum cbl_ywd)-1)
			xo_errx(2, "get: -w explicit, report-all, trim or "
			    "report-all-tagged");
		i += 2;
	}
	/* -o: the origins, the operational datastore's. */
	origin = false;
	if (argc > (int)i && strcmp(argv[i], "-o") == 0) {
		origin = true;
		i++;
	}
	if (argc > (int)i + 1 && strcmp(argv[i], "-x") == 0) {
		xpath = argv[i + 1];
		i += 2;
	}
	for (; i < (uint32_t)argc; i++) {
		if ((n = ytop_named(argv[i])) == NULL)
			xo_errx(1, "get: %s is no node the agent serves "
			    "(arcanactl(8) names them)", argv[i]);
		if (ns == nitems(sids))
			xo_errx(1, "get: %zu nodes at most", nitems(sids));
		sids[ns++] = n->sid;
	}
	if ((error = cbl_msg_new(cbl_conn_ctx(conn), CBL_YANG_FAMILY,
	    CBL_YCMD_GET, 0, &req)) != 0 || (error = cbl_msg_put_yget_opts(req,
	    sids, ns, xpath, wd, origin)) != 0 ||
	    (said && (error = cbl_msg_set_datastore(req, ds)) != 0))
		xo_errx(1, "get: %s", strerror(error));
	if ((error = cbl_request(conn, req, &rep, -1)) != 0) {
		/* The node at fault, where the agent named one. */
		n = rep != NULL && cbl_msg_err_sid(rep) != 0 ?
		    cbl_yschema_node(&ymodel_schema, cbl_msg_err_sid(rep)) : NULL;
		xo_errx(1, "get: %s%s%s", n != NULL ? n->name : "", n != NULL ?
		    ": " : "", rep != NULL && cbl_msg_err_str(rep) != NULL ?
		    cbl_msg_err_str(rep) : strerror(error));
	}
	/* Annotated: as an instance tree, which has them. */
	if (origin || wd == CBL_YWD_REPORT_ALL_TAGGED) {
		if ((t = cbl_dtree_new(&ymodel_schema)) == NULL)
			xo_err(1, "get");
		if ((error = cbl_msg_ydtree(rep, t, 0, why, sizeof(why))) != 0)
			xo_errx(1, "get: %s", why[0] != '\0' ? why :
			    strerror(error));
		if ((error = cbl_dtree_json(t, &b)) != 0)
			xo_errx(1, "get: %s", strerror(error));
		if ((out = strndup((const char *)b.p, b.len)) == NULL)
			xo_err(1, "get");
		xo_emit("{:json/%s}\n", out);
		free(out);
		cbl_ybuf_free(&b);
		cbl_dtree_free(t);
		cbl_msg_free(rep);
		return (0);
	}
	if ((a = cbl_yarena_new()) == NULL)
		xo_err(1, "get");
	/* Each module's top-level nodes the reply has, into its data. */
	for (i = 0; i < ymodel_schema.nmod; i++) {
		m = ymodel_schema.mod[i];
		if (m->size == 0 || (data = cbl_yarena_alloc(a, m->size)) ==
		    NULL)
			continue;
		memset(data, 0, m->size);
		for (k = 0; k < m->ntop; k++) {
			n = m->top[k];
			if (n->kind != CBL_YN_CONTAINER && n->kind != CBL_YN_LIST)
				continue;
			error = cbl_msg_ydecode_member(rep, n, data, a, 0, why,
			    sizeof(why));
			if (error != 0 && error != ENOENT)
				xo_errx(1, "get: %s: %s", n->name, why[0] != '\0' ?
				    why : strerror(error));
		}
		if ((error = cbl_yjson_members(m, data, &b, &first)) != 0)
			xo_errx(1, "get: %s: %s", m->name, strerror(error));
	}
	if (asprintf(&out, "{%.*s}", (int)b.len, b.p != NULL ? (const char *)
	    b.p : "") == -1)
		xo_err(1, "get");
	xo_emit("{:json/%s}\n", out);
	free(out);
	cbl_ybuf_free(&b);
	cbl_yarena_free(a);
	cbl_msg_free(rep);
	return (0);
}

/*
 * edit [-r] [-a warning]... node value: an EDIT of the candidate (with
 * -r, of running) of a top-level node, its value RFC 7951's JSON, given
 * or @file, the node's own or {"module:node": value}; "null" deletes it.
 * commit [-c seconds [-p persist]] [-i persist-id] [-a warning]...: the
 * candidate put in use, confirmed within seconds or undone; cancel-commit
 * [-i persist-id]; discard: the candidate forgotten.  A refusal a warning
 * can be accepted for says its error-app-tag, for -a.
 */
static const char	*accepts[16];
static size_t		 naccepts;

static enum cbl_yds_name
ds_named(const char *s)
{

	return (strcmp(s, "running") == 0 ? CBL_YDS_RUNNING :
	    strcmp(s, "candidate") == 0 ? CBL_YDS_CANDIDATE :
	    strcmp(s, "operational") == 0 ? CBL_YDS_OPERATIONAL :
	    (enum cbl_yds_name)-1);
}

/* A refusal, said with what may accept it; exits. */
static void
refused(const char *what, const char *msg, const char *tag)
{

	if (tag != NULL && tag[0] != '\0')
		xo_errx(1, "%s: %s (go on with -a %s)", what, msg, tag);
	xo_errx(1, "%s: %s", what, msg);
}

/* The warnings an answer has, printed. */
static void
warnings_of(const cbl_msg *rep)
{
	const struct cbl_ywarning	*w;
	cbl_yarena			*a;
	size_t				 n;

	if (rep == NULL || (a = cbl_yarena_new()) == NULL)
		return;
	if (cbl_msg_ywarnings(rep, a, &w, &n) == 0)
		for (size_t i = 0; i < n; i++)
			xo_emit("{Lw:warning}{:tag/%s}: {:text/%s}\n", w[i].tag,
			    w[i].text);
	cbl_yarena_free(a);
}

static int
cmd_edit(cbl_conn *conn, int argc, char **argv)
{
	const struct cbl_ynode	*n;
	struct ucl_parser	*p;
	ucl_object_t		*top;
	const ucl_object_t	*v;
	enum cbl_yds_name	 ds = CBL_YDS_CANDIDATE;
	char			 err[512], tag[80], key[256], *text;
	uint64_t		 errsid;
	int			 ch, error;

	optind = 1;
	while ((ch = getopt(argc, argv, "a:r")) != -1) {
		switch (ch) {
		case 'a':
			if (naccepts < nitems(accepts))
				accepts[naccepts++] = optarg;
			break;
		case 'r':
			ds = CBL_YDS_RUNNING;
			break;
		default:
			usage();
		}
	}
	if (argc - optind != 2)
		usage();
	if ((n = ytop_named(argv[optind])) == NULL)
		xo_errx(1, "edit: %s is no node the agent serves",
		    argv[optind]);
	text = argv[optind + 1][0] == '@' ? slurp(argv[optind + 1] + 1) :
	    strdup(argv[optind + 1]);
	if (text == NULL)
		xo_err(1, "edit");
	top = NULL;
	v = NULL;
	if (strcmp(text, "null") != 0) {
		if ((p = ucl_parser_new(UCL_PARSER_NO_IMPLICIT_ARRAYS)) == NULL)
			xo_err(1, "edit");
		if (!ucl_parser_add_string(p, text, 0))
			xo_errx(1, "edit: not JSON: %s", ucl_parser_get_error(p));
		top = ucl_parser_get_object(p);
		ucl_parser_free(p);
		/* {"module:node": value}: the value. */
		(void)snprintf(key, sizeof(key), "%s:%s", n->module->name,
		    n->name);
		v = ucl_object_lookup(top, key) != NULL &&
		    ucl_object_type(top) == UCL_OBJECT ?
		    ucl_object_lookup(top, key) : top;
	}
	error = yjson_edit(conn, n, v, ds, accepts, naccepts, err,
	    sizeof(err), &errsid, tag, sizeof(tag));
	ucl_object_unref(top);
	free(text);
	if (error != 0)
		refused("edit", err, tag);
	return (0);
}

/*
 * An rpc of ietf-netconf's, its input in, over conn, the accepts given:
 * 0, or an errno and what the agent said in err (NULL: not wanted), its
 * app-tag in tag.  Its warnings printed.
 */
static int
netconf_try(cbl_conn *conn, const char *name, const void *in,
    char *err, size_t errlen, char *tag, size_t taglen)
{
	const struct cbl_ynode	*rpc = NULL, *inode = NULL;
	cbl_msg			*m, *rep = NULL;
	int			 error;

	for (uint32_t i = 0; rpc == NULL && i < ymodel_schema.nmod; i++)
		if (strcmp(ymodel_schema.mod[i]->name, "ietf-netconf") == 0)
			for (uint32_t k = 0; k < ymodel_schema.mod[i]->ntop; k++)
				if (strcmp(ymodel_schema.mod[i]->top[k]->name,
				    name) == 0)
					rpc = ymodel_schema.mod[i]->top[k];
	for (uint32_t i = 0; rpc != NULL && i < rpc->nchild; i++)
		if (rpc->child[i]->kind == CBL_YN_INPUT)
			inode = rpc->child[i];
	if (inode == NULL)
		xo_errx(1, "%s: not in the tables", name);
	if ((error = cbl_msg_new(cbl_conn_ctx(conn), CBL_YANG_FAMILY,
	    CBL_YCMD_RPC, 0, &m)) != 0 || (error = cbl_msg_put_ynode(m, inode,
	    in)) != 0 || (naccepts > 0 && (error = cbl_msg_set_accept(m,
	    accepts, naccepts)) != 0))
		xo_errx(1, "%s: %s", name, strerror(error));
	if ((error = cbl_request(conn, m, &rep, -1)) != 0) {
		if (err != NULL)
			(void)snprintf(err, errlen, "%s", rep != NULL &&
			    cbl_msg_err_str(rep) != NULL ? cbl_msg_err_str(rep) :
			    strerror(error));
		if (tag != NULL)
			(void)snprintf(tag, taglen, "%s", rep != NULL &&
			    cbl_msg_err_apptag(rep) != NULL ?
			    cbl_msg_err_apptag(rep) : "");
		cbl_msg_free(rep);
		return (error);
	}
	warnings_of(rep);
	cbl_msg_free(rep);
	return (0);
}

/* The same, what it refuses said, exit 1. */
static void
netconf_rpc(cbl_conn *conn, const char *name, const void *in)
{
	char	err[512], tag[80];

	if (netconf_try(conn, name, in, err, sizeof(err), tag,
	    sizeof(tag)) != 0)
		refused(name, err, tag);
}

/*
 * Top-level node n's data, its module's struct data, put in datastore
 * ds by an EDIT, the accepts given: 0, or an errno and what the agent
 * said in err, the node at fault's SID in *errsid, its app-tag in tag.
 */
static int
yedit_data(cbl_conn *conn, const struct cbl_ynode *n, const void *data,
    enum cbl_yds_name ds, const char *const *acc, size_t nacc, char *err,
    size_t errlen, uint64_t *errsid, char *tag, size_t taglen)
{
	cbl_msg	*m, *rep = NULL;
	int	 error;

	*errsid = 0;
	tag[0] = '\0';
	if ((error = cbl_msg_new(cbl_conn_ctx(conn), CBL_YANG_FAMILY,
	    CBL_YCMD_EDIT, 0, &m)) != 0) {
		(void)snprintf(err, errlen, "%s", strerror(error));
		return (error);
	}
	if ((error = cbl_msg_set_datastore(m, ds)) == 0 && nacc > 0)
		error = cbl_msg_set_accept(m, acc, nacc);
	if (error == 0)
		error = cbl_msg_put_ymember(m, n, data);
	if (error != 0) {
		cbl_msg_free(m);
		(void)snprintf(err, errlen, "%s", strerror(error));
		return (error);
	}
	if ((error = cbl_request(conn, m, &rep, -1)) != 0) {
		(void)snprintf(err, errlen, "%s", rep != NULL &&
		    cbl_msg_err_str(rep) != NULL ? cbl_msg_err_str(rep) :
		    strerror(error));
		if (rep != NULL) {
			*errsid = cbl_msg_err_sid(rep);
			if (cbl_msg_err_apptag(rep) != NULL)
				(void)snprintf(tag, taglen, "%s",
				    cbl_msg_err_apptag(rep));
		}
	}
	cbl_msg_free(rep);
	return (error);
}

static int
cmd_commit(cbl_conn *conn, int argc, char **argv)
{
	struct ietf_netconf_commit_input	 in;
	const char				*errstr;
	char					 made[33];
	int					 ch;

	memset(&in, 0, sizeof(in));
	optind = 1;
	while ((ch = getopt(argc, argv, "a:c:i:p:")) != -1) {
		switch (ch) {
		case 'a':
			if (naccepts < nitems(accepts))
				accepts[naccepts++] = optarg;
			break;
		case 'c':
			in.confirmed = true;
			in.has_confirm_timeout = true;
			in.confirm_timeout = (uint32_t)strtonum(optarg, 1,
			    86400, &errstr);
			if (errstr != NULL)
				xo_errx(2, "commit: -c %s: %s", optarg, errstr);
			break;
		case 'i':
			in.persist_id = optarg;
			break;
		case 'p':
			in.persist = optarg;
			break;
		default:
			usage();
		}
	}
	if (argc != optind || (in.persist != NULL && !in.confirmed))
		usage();
	/* Each run is a session, whose end undoes a confirmed commit
	 * without persist (RFC 6241 8.4.1): one is made, said. */
	if (in.confirmed && in.persist == NULL) {
		(void)snprintf(made, sizeof(made), "%08x%08x%08x%08x",
		    arc4random(), arc4random(), arc4random(), arc4random());
		in.persist = made;
	}
	netconf_rpc(conn, "commit", &in);
	if (in.confirmed)
		xo_emit("{Lw:confirm within}{:seconds/%u}{L: seconds: "
		    "arcanactl commit -i }{:persist-id/%s}\n",
		    in.confirm_timeout, in.persist);
	return (0);
}

static int
cmd_cancel_commit(cbl_conn *conn, int argc, char **argv)
{
	struct ietf_netconf_cancel_commit_input	in;

	memset(&in, 0, sizeof(in));
	if (argc == 3 && strcmp(argv[1], "-i") == 0)
		in.persist_id = argv[2];
	else if (argc != 1)
		usage();
	netconf_rpc(conn, "cancel-commit", &in);
	return (0);
}

static int
cmd_discard(cbl_conn *conn, int argc, char **argv)
{
	struct ietf_netconf_discard_changes_input	in;

	(void)argv;
	if (argc != 1)
		usage();
	memset(&in, 0, sizeof(in));
	netconf_rpc(conn, "discard-changes", &in);
	return (0);
}

/* Child name of n, NULL where there is none. */
static const struct cbl_ynode *
ychild(const struct cbl_ynode *n, const char *name)
{
	uint32_t	i;

	for (i = 0; i < n->nchild; i++)
		if (strcmp(n->child[i]->name, name) == 0)
			return (n->child[i]);
	return (NULL);
}

/* One value of leaf n's, its member at p in a struct, as a person gave it. */
static void
yset(const struct cbl_ynode *n, void *p, const char *s, cbl_yarena *a)
{
	int	error;

	if ((error = cbl_yvalue_parse(n, n->type, s, (char *)p + n->off,
	    a)) != 0)
		xo_errx(1, "action: %s: %s is not one: %s", n->name, s,
		    strerror(error));
	if (n->hoff != CBL_YOFF_NONE)
		*(bool *)(void *)((char *)p + n->hoff) = true;
}

/*
 * action path [key ...] name [leaf=value ...]: an action of a module the
 * agent serves (cblink's YANG family), on the node path names from its
 * top (jails/jail), a list entry by its keys, the input's leaves given
 * as name=value; its output as RFC 7951's JSON.
 */
static int
cmd_yaction(cbl_conn *conn, int argc, char **argv)
{
	const struct cbl_ynode	*n, *act, *in, *out, *c;
	struct cbl_ybuf		 t = { NULL, 0, 0 }, b = { NULL, 0, 0 };
	const void		*vals[8];
	char			*path, *seg, *eq, why[256];
	cbl_msg			*req, *rep = NULL;
	cbl_yarena		*a;
	void			*pin, *pout, *key;
	uint32_t		 k;
	int			 i, error;

	if (argc < 2)
		xo_errx(1, "action: a node's path, its keys, the action");
	if ((a = cbl_yarena_new()) == NULL)
		xo_err(1, "action");
	/* The node, from its top-level one down by the names given. */
	path = strdup(argv[1]);
	n = strchr(argv[1], '/') == NULL && ytop_named(argv[1]) == NULL ?
	    yrpc_named(argv[1]) : NULL;
	if (n == NULL)
		while (path != NULL && (seg = strsep(&path, "/")) != NULL)
			if ((n = n == NULL ? ytop_named(seg) : ychild(n,
			    seg)) == NULL)
				xo_errx(1, "action: %s: no such node", seg);
	/* A module's rpc: the name alone, its input after it. */
	if (n != NULL && n->kind == CBL_YN_RPC) {
		act = n;
		i = 1;
		goto input;
	}
	if (n == NULL || (n->kind != CBL_YN_LIST && n->kind != CBL_YN_CONTAINER))
		xo_errx(1, "action: %s is no list or container", argv[1]);
	/* Its keys, if a list; the keys of lists above it are not taken. */
	i = 2;
	for (k = 0; n->kind == CBL_YN_LIST && k < n->nkeys; k++, i++) {
		c = n->child[n->keys[k]];
		if (i >= argc)
			xo_errx(1, "action: %s takes its %s", n->name, c->name);
		if ((key = cbl_yarena_alloc(a, c->type->csize)) == NULL)
			xo_err(1, "action");
		if ((error = cbl_yvalue_parse(c, c->type, argv[i], key, a)) != 0)
			xo_errx(1, "action: %s: %s is not one", c->name, argv[i]);
		vals[k] = key;
	}
	if (i >= argc || (act = ychild(n, argv[i])) == NULL ||
	    act->kind != CBL_YN_ACTION)
		xo_errx(1, "action: %s has no action %s", n->name, i < argc ?
		    argv[i] : "");
input:
	in = ychild(act, "input");
	out = ychild(act, "output");
	if (in == NULL || out == NULL ||
	    (pin = cbl_yarena_alloc(a, in->size)) == NULL ||
	    (pout = cbl_yarena_alloc(a, out->size)) == NULL)
		xo_errx(1, "action: %s's tables have no input or output",
		    act->name);
	for (i++; i < argc; i++) {
		if ((eq = strchr(argv[i], '=')) == NULL)
			xo_errx(1, "action: %s: an input is name=value",
			    argv[i]);
		*eq = '\0';
		if ((c = ychild(in, argv[i])) == NULL || c->kind != CBL_YN_LEAF)
			xo_errx(1, "action: %s has no input %s", act->name,
			    argv[i]);
		yset(c, pin, eq + 1, a);
	}
	if ((act != n && (error = cbl_yiid_write(n, vals, n->kind ==
	    CBL_YN_LIST ? n->nkeys : 0, &t)) != 0) ||
	    (error = cbl_msg_new(cbl_conn_ctx(conn), CBL_YANG_FAMILY,
	    CBL_YCMD_RPC, 0, &req)) != 0 ||
	    (error = cbl_msg_put_ynode(req, in, pin)) != 0 ||
	    (act != n && (error = cbl_msg_put_yaction(req, t.p, t.len)) != 0))
		xo_errx(1, "action: %s", strerror(error));
	if ((error = cbl_request(conn, req, &rep, -1)) != 0)
		xo_errx(1, "action: %s", rep != NULL && cbl_msg_err_str(rep) !=
		    NULL ? cbl_msg_err_str(rep) : strerror(error));
	if ((error = cbl_msg_ydecode(rep, out, pout, a, 0, why,
	    sizeof(why))) != 0 && error != ENOENT)
		xo_errx(1, "action: %s", why);
	if ((error = cbl_yjson(out, pout, &b)) != 0)
		xo_errx(1, "action: %s", strerror(error));
	xo_emit("{:json/%.*s}\n", (int)b.len, b.p != NULL ? (const char *)
	    b.p : "{}");
	cbl_ybuf_free(&b);
	cbl_ybuf_free(&t);
	cbl_yarena_free(a);
	cbl_msg_free(rep);
	return (0);
}

/*
 * A notification of family 1's group: RFC 8040's JSON of it, a line of
 * its own (ietf-restconf:notification, its eventTime, the notification
 * qualified by its module); one of a module these tables have not, its
 * SID.
 */
static void
ynotif_print(const cbl_msg *msg)
{
	const struct cbl_ynode	*n;
	struct cbl_ynotif	 nt;
	struct cbl_ybuf		 b = { NULL, 0, 0 };
	cbl_yarena		*a;
	void			*data;

	if ((a = cbl_yarena_new()) == NULL)
		return;
	if (cbl_msg_ynotif(msg, &nt, a) != 0)
		goto out;
	if ((n = cbl_yschema_node(&ymodel_schema, nt.sid)) == NULL ||
	    (data = cbl_yarena_alloc(a, n->size)) == NULL ||
	    cbl_ydecode(n, nt.content, nt.len, data, a, 0, NULL, 0) != 0 ||
	    cbl_yjson(n, data, &b) != 0)
		printf("{\"ietf-restconf:notification\":{\"eventTime\":\"%s\","
		    "\"sid\":\"%ju\"}}\n", nt.event_time, (uintmax_t)nt.sid);
	else
		printf("{\"ietf-restconf:notification\":{\"eventTime\":\"%s\","
		    "\"%s:%s\":%.*s}}\n", nt.event_time, n->module->name,
		    n->name, (int)b.len, (const char *)b.p);
	fflush(stdout);
out:
	cbl_ybuf_free(&b);
	cbl_yarena_free(a);
}

static void
ynotif_line(cbl_conn *conn, cbl_msg *msg, void *arg)
{

	(void)conn;
	(void)arg;
	ynotif_print(msg);
}

/* What a SUBSCRIBE stream has come to. */
struct ysubscribe {
	int		 opened, error, records, count;
	bool		 closed;
	char		 why[256];
	char		 close_text[128];
};

static void
ysub_open(cbl_stream *s, cbl_msg *accept, int error, void *arg)
{
	struct ysubscribe	*ys = arg;

	(void)s;
	ys->opened = 1;
	ys->error = error;
	if (error != 0 && accept != NULL && cbl_msg_err_str(accept) != NULL)
		strlcpy(ys->why, cbl_msg_err_str(accept), sizeof(ys->why));
}

static void
ysub_data(cbl_stream *s, cbl_msg *data, void *arg)
{
	struct ysubscribe	*ys = arg;

	ynotif_print(data);
	if (++ys->records == ys->count)
		(void)cbl_stream_close(s, 0, NULL);
}

static void
ysub_close(cbl_stream *s, int code, const char *text, void *arg)
{
	struct ysubscribe	*ys = arg;

	(void)s;
	(void)code;
	ys->closed = true;
	if (text != NULL)
		strlcpy(ys->close_text, text, sizeof(ys->close_text));
}

static const struct cbl_stream_cbs ysub_cbs = {
	.on_open = ysub_open,
	.on_data = ysub_data,
	.on_close = ysub_close,
};

/*
 * subscribe [-n count] [-o seconds | -p seconds] [-s stop-time]
 * [-x xpath | -f filter]: RFC 8639's dynamic subscription on a SUBSCRIBE
 * stream (cblink's family 1): the NETCONF stream, every event the agent
 * tells; with -p, the operational datastore pushed every that many
 * seconds (RFC 8641's periodic YANG-Push, a tenth of a second at least);
 * with -o, its changes as they are seen, -o's seconds the dampening
 * period (read every second at least), the first push the whole of it.
 * -x is the stream's or the datastore's XPath filter, -f its subtree
 * filter (RFC 6241 section 6) as JSON, or @file: null a selection node,
 * an object a containment node, a leaf's value a content match node; -s
 * a stop-time (RFC 3339), -n how many records before it ends.  A record
 * a line, RFC 8040's notification JSON.
 */

/* The subtree filter text says, as anydata name of in carries it. */
static void
subtree_arg(const struct cbl_ynode *in, const char *name, const char *arg,
    struct cbl_ybuf *b)
{
	const struct cbl_ynode	*n = NULL;
	struct ucl_parser	*p;
	ucl_object_t		*top;
	cbl_dfilter		*f;
	char			*text, why[256];
	int			 error;

	for (uint32_t i = 0; i < in->nchild; i++)
		if (strcmp(in->child[i]->name, name) == 0)
			n = in->child[i];
	if (n == NULL)
		xo_errx(1, "subscribe: no %s in the tables", name);
	if ((text = arg[0] == '@' ? slurp(arg + 1) : strdup(arg)) == NULL)
		xo_err(1, "subscribe");
	if ((p = ucl_parser_new(UCL_PARSER_NO_IMPLICIT_ARRAYS)) == NULL)
		xo_err(1, "subscribe");
	if (!ucl_parser_add_string(p, text, 0))
		xo_errx(1, "subscribe: -f: not JSON: %s",
		    ucl_parser_get_error(p));
	top = ucl_parser_get_object(p);
	ucl_parser_free(p);
	if ((error = yjson_subtree(&ymodel_schema, top, &f, why,
	    sizeof(why))) != 0)
		xo_errx(1, "subscribe: -f: %s", why[0] != '\0' ? why :
		    strerror(error));
	if ((error = cbl_dfilter_encode(f, n->sid, b)) != 0)
		xo_errx(1, "subscribe: -f: %s", strerror(error));
	cbl_dfilter_free(f);
	ucl_object_unref(top);
	free(text);
}
static int
cmd_subscribe(cbl_conn *conn, int argc, char **argv)
{
	typedef struct ietf_subscribed_notifications_establish_subscription_input
	    est_in;
	typedef struct ietf_subscribed_notifications_establish_subscription_input_yp_periodic
	    est_per;
	struct ysubscribe	 ys;
	const struct cbl_ynode	*rpc, *in;
	const struct cbl_yident	*id;
	struct pollfd		 pfd;
	cbl_stream		*s;
	cbl_msg			*m;
	est_per			 per;
	est_in			 ein;
	const char		*xpath = NULL, *stop = NULL, *replay = NULL;
	const char		*subtree = NULL;
	struct cbl_ybuf		 fb = { NULL, 0, 0 };
	double			 secs = 0, damp = 0;
	bool			 onchange = false;
	struct ietf_subscribed_notifications_establish_subscription_input_yp_on_change
				 oc;
	char			*end;
	uint32_t		 i;
	int			 error, ev, ms, k;

	memset(&ys, 0, sizeof(ys));
	for (k = 1; k + 1 < argc && argv[k][0] == '-'; k += 2) {
		if (strcmp(argv[k], "-n") == 0)
			ys.count = (int)strtol(argv[k + 1], NULL, 10);
		else if (strcmp(argv[k], "-p") == 0) {
			secs = strtod(argv[k + 1], &end);
			if (*end != '\0' || secs < 0.1)
				xo_errx(1, "subscribe: -p is seconds, a tenth "
				    "at least");
		} else if (strcmp(argv[k], "-o") == 0) {
			damp = strtod(argv[k + 1], &end);
			if (*end != '\0' || damp < 0)
				xo_errx(1, "subscribe: -o is seconds");
			onchange = true;
		} else if (strcmp(argv[k], "-s") == 0)
			stop = argv[k + 1];
		else if (strcmp(argv[k], "-r") == 0)
			replay = argv[k + 1];
		else if (strcmp(argv[k], "-x") == 0)
			xpath = argv[k + 1];
		else if (strcmp(argv[k], "-f") == 0)
			subtree = argv[k + 1];
		else
			break;
	}
	if (k != argc || (onchange && secs != 0) || (replay != NULL &&
	    (secs != 0 || onchange)) || (xpath != NULL && subtree != NULL))
		usage();
	rpc = in = NULL;
	for (i = 0; i < ymodel_schema.nmod && rpc == NULL; i++)
		if (strcmp(ymodel_schema.mod[i]->name,
		    "ietf-subscribed-notifications") == 0)
			for (uint32_t j = 0; j < ymodel_schema.mod[i]->ntop; j++)
				if (strcmp(ymodel_schema.mod[i]->top[j]->name,
				    "establish-subscription") == 0)
					rpc = ymodel_schema.mod[i]->top[j];
	for (i = 0; rpc != NULL && i < rpc->nchild; i++)
		if (rpc->child[i]->kind == CBL_YN_INPUT)
			in = rpc->child[i];
	if (in == NULL)
		xo_errx(1, "subscribe: no ietf-subscribed-notifications in "
		    "the tables");
	memset(&ein, 0, sizeof(ein));
#define	SN(x)	IETF_SUBSCRIBED_NOTIFICATIONS_ESTABLISH_SUBSCRIPTION_INPUT_##x
	if (secs == 0 && !onchange) {
		ein.target = SN(TARGET_STREAM);
		ein.stream = "NETCONF";
		if (xpath != NULL) {
			ein.stream_filter = SN(STREAM_FILTER_WITHIN_SUBSCRIPTION);
			ein.filter_spec = SN(FILTER_SPEC_STREAM_XPATH_FILTER);
			ein.stream_xpath_filter = xpath;
		} else if (subtree != NULL) {
			subtree_arg(in, "stream-subtree-filter", subtree, &fb);
			ein.stream_filter = SN(STREAM_FILTER_WITHIN_SUBSCRIPTION);
			ein.filter_spec = SN(FILTER_SPEC_STREAM_SUBTREE_FILTER);
			ein.stream_subtree_filter.p = fb.p;
			ein.stream_subtree_filter.len = fb.len;
		}
	} else {
		ein.target = SN(TARGET_DATASTORE);
		for (i = 0; i < ymodel_schema.nident; i++) {
			id = &ymodel_schema.ident[i];
			if (strcmp(id->name, "operational") == 0 &&
			    strcmp(id->module->name, "ietf-datastores") == 0) {
				ein.has_yp_datastore = true;
				ein.yp_datastore = id->sid;
			}
		}
		if (xpath != NULL) {
			ein.yp_selection_filter =
			    SN(YP_SELECTION_FILTER_WITHIN_SUBSCRIPTION);
			ein.yp_filter_spec =
			    SN(YP_FILTER_SPEC_DATASTORE_XPATH_FILTER);
			ein.yp_datastore_xpath_filter = xpath;
		} else if (subtree != NULL) {
			subtree_arg(in, "datastore-subtree-filter", subtree,
			    &fb);
			ein.yp_selection_filter =
			    SN(YP_SELECTION_FILTER_WITHIN_SUBSCRIPTION);
			ein.yp_filter_spec =
			    SN(YP_FILTER_SPEC_DATASTORE_SUBTREE_FILTER);
			ein.yp_datastore_subtree_filter.p = fb.p;
			ein.yp_datastore_subtree_filter.len = fb.len;
		}
		memset(&per, 0, sizeof(per));
		memset(&oc, 0, sizeof(oc));
		if (onchange) {
			oc.has_dampening_period = true;
			oc.dampening_period = (uint32_t)(damp * 100 + 0.5);
			ein.yp_update_trigger = SN(YP_UPDATE_TRIGGER_ON_CHANGE);
			ein.yp_on_change = &oc;
		} else {
			per.has_period = true;
			per.period = (uint32_t)(secs * 100 + 0.5);
			ein.yp_update_trigger = SN(YP_UPDATE_TRIGGER_PERIODIC);
			ein.yp_periodic = &per;
		}
	}
#undef SN
	ein.stop_time = stop;
	ein.replay_start_time = replay;
	if ((error = cbl_msg_new(cbl_conn_ctx(conn), CBL_YANG_FAMILY,
	    CBL_YCMD_SUBSCRIBE, 0, &m)) != 0 ||
	    (error = cbl_msg_put_ynode(m, in, &ein)) != 0 ||
	    (error = cbl_stream_open(conn, m, CBL_SF_PUSH, &ysub_cbs, &ys,
	    &s)) != 0)
		xo_errx(1, "subscribe: %s", strerror(error));
	cbl_ybuf_free(&fb);
	while (!ys.closed && (!ys.opened || ys.error == 0)) {
		ev = 0;
		ms = -1;
		(void)cbl_conn_interest(conn, &ev, &ms);
		pfd.fd = cbl_conn_fd(conn);
		pfd.events = ((ev & CBL_EV_READ) != 0 ? POLLIN : 0) |
		    ((ev & CBL_EV_WRITE) != 0 ? POLLOUT : 0);
		pfd.revents = 0;
		if (poll(&pfd, 1, ms) == -1)
			continue;
		ev = ((pfd.revents & (POLLIN | POLLHUP | POLLERR)) != 0 ?
		    CBL_EV_READ : 0) | ((pfd.revents & POLLOUT) != 0 ?
		    CBL_EV_WRITE : 0);
		if ((error = cbl_conn_process(conn, ev)) != 0)
			xo_errx(1, "subscribe: the host is gone: %s",
			    strerror(error));
	}
	if (ys.error != 0)
		xo_errx(1, "subscribe: %s", ys.why[0] != '\0' ? ys.why :
		    strerror(ys.error));
	if (ys.close_text[0] != '\0' && (ys.count == 0 ||
	    ys.records < ys.count))
		xo_warnx("subscribe: ended: %s", ys.close_text);
	return (0);
}

/*
 * notifications: those of the models the agent serves (cblink's YANG
 * family's group, notify), as they come, until the host goes or we are
 * stopped.
 */
static int
cmd_notifications(cbl_conn *conn)
{
	struct pollfd	 pfd;
	cbl_sub		*sub;
	int		 error, ev, ms;

	if ((error = cbl_subscribe(conn, "cblink.yang", "notify",
	    ynotif_line, NULL, &sub)) != 0)
		xo_errx(1, "notifications: %s", strerror(error));
	for (;;) {
		ev = 0;
		ms = -1;
		(void)cbl_conn_interest(conn, &ev, &ms);
		pfd.fd = cbl_conn_fd(conn);
		pfd.events = ((ev & CBL_EV_READ) != 0 ? POLLIN : 0) |
		    ((ev & CBL_EV_WRITE) != 0 ? POLLOUT : 0);
		pfd.revents = 0;
		if (poll(&pfd, 1, ms) == -1)
			continue;
		ev = ((pfd.revents & (POLLIN | POLLHUP | POLLERR)) != 0 ?
		    CBL_EV_READ : 0) | ((pfd.revents & POLLOUT) != 0 ?
		    CBL_EV_WRITE : 0);
		if ((error = cbl_conn_process(conn, ev)) != 0)
			break;
	}
	xo_errx(1, "notifications: the host is gone: %s", strerror(error));
}

/* A string of host o's, "" where it has none. */
static const char *
hstr(const ucl_object_t *o, const char *key)
{
	const char	*v;

	v = ucl_object_tostring(ucl_object_lookup(o, key));
	return (v != NULL ? v : "");
}

static int64_t
hint(const ucl_object_t *o, const char *key)
{

	return (ucl_object_toint(ucl_object_lookup(o, key)));
}

/* A list of host o's, as hello printed it. */
static void
hlist(const ucl_object_t *o, const char *key, const char *label)
{
	const ucl_object_t	*l, *e;
	ucl_object_iter_t	 it = NULL;
	bool			 first;

	if ((l = ucl_object_lookup(o, key)) == NULL || ucl_array_size(l) == 0)
		return;
	xo_emit("{Lwc:/%s}", label);
	xo_open_list(key);
	first = true;
	while ((e = ucl_object_iterate(l, &it, true)) != NULL) {
		xo_emit("{P:/%s}{l:/%s}", first ? "" : " ",
		    ucl_object_tostring(e));
		first = false;
	}
	xo_close_list(key);
	xo_emit("\n");
}

/* The host and its agent, a read of arcana-host's host. */
static int
cmd_hello(cbl_conn *conn)
{
	ucl_object_t	*h;
	char		 boot[64], err[512];
	time_t		 t;
	int		 error;

	if ((error = yh_hello(conn, &h, err, sizeof(err))) != 0)
		xo_errx(1, "hello: %s", err[0] != '\0' ? err :
		    strerror(error));
	xo_open_container("host");
	xo_emit("{Lwc:Host}{:hostname/%s}\n", hstr(h, "hostname"));
	xo_emit("{Lwc:System}{:sysname/%s} {:release/%s} {:machine/%s}\n",
	    hstr(h, "sysname"), hstr(h, "release"), hstr(h, "machine"));
	xo_emit("{Lwc:CPUs}{:ncpu/%jd}\n", (intmax_t)hint(h, "ncpu"));
	xo_emit("{Lwc:Memory}{:physmem/%jd} {U:bytes}\n",
	    (intmax_t)hint(h, "physmem"));
	t = (time_t)hint(h, "boottime");
	strftime(boot, sizeof(boot), "%F %T", localtime(&t));
	xo_emit("{Lwc:Booted}{d:/%s}{e:boottime/%jd}\n", boot, (intmax_t)t);
	xo_emit("{Lwc:Securelevel}{:securelevel/%jd}\n",
	    (intmax_t)hint(h, "securelevel"));
	xo_emit("{Lwc:Privileged}{n:privileged/%s}\n",
	    ucl_object_toboolean(ucl_object_lookup(h, "privileged")) ?
	    "true" : "false");
	xo_emit("{Lwc:arcana-agent}{:version/%s}\n", hstr(h, "version"));
	if (ucl_object_lookup(h, "build") != NULL)
		xo_emit("{Lwc:Build}{:build/%s}\n", hstr(h, "build"));
	/* What is installed there that is not the base system's. */
	hlist(h, "plugins", "Plugins");
	/* What it takes that an agent before it did not. */
	hlist(h, "features", "Features");
	xo_close_container("host");
	ucl_object_unref(h);
	return (0);
}

/*
 * The agent's steps of a request, heard while it runs (-t), arcana-jobs'
 * steps on group notify: each step by its number, its last word kept,
 * printed when asked.
 */
static struct arcana_jobs_step	*ysteps;
static size_t		 nysteps;
static cbl_sub		*ystep_sub;
static bool		 ystep_on;

static void
ystep_free(struct arcana_jobs_step *s)
{

	free((void *)(uintptr_t)s->label);
	free((void *)(uintptr_t)s->detail);
	for (size_t i = 0; i < s->argv.n; i++)
		free((void *)(uintptr_t)s->argv.v[i]);
	free((void *)(uintptr_t)s->argv.v);
	free((void *)(uintptr_t)s->output.p);
	free((void *)(uintptr_t)s->error_output.p);
}

static const void *
ybytes(const struct cbl_bytes *b)
{
	void	*p;

	if (b->len == 0)
		return (NULL);
	if ((p = malloc(b->len)) == NULL)
		xo_err(1, "trace");
	memcpy(p, b->p, b->len);
	return (p);
}

/* A step arcana-jobs' steps told, kept. */
static void
ystep_rx(cbl_conn *conn __unused, cbl_msg *msg, void *arg __unused)
{
	const struct arcana_jobs_step	*v, *t;
	struct arcana_jobs_step			*d;
	const char			**argv;
	cbl_yarena			*a;
	size_t				 i, k, n;

	if (!ystep_on || (a = cbl_yarena_new()) == NULL)
		return;
	v = yh_steps_of(msg, a, &n);
	for (i = 0; v != NULL && i < n; i++) {
		t = &v[i];
		for (k = 0; k < nysteps && ysteps[k].id != t->id; k++)
			;
		if (k == nysteps) {
			if ((ysteps = reallocarray(ysteps, nysteps + 1,
			    sizeof(*ysteps))) == NULL)
				xo_err(1, "trace");
			nysteps++;
		} else
			ystep_free(&ysteps[k]);
		d = &ysteps[k];
		*d = *t;
		d->label = t->label != NULL ? strdup(t->label) : NULL;
		d->detail = t->detail != NULL ? strdup(t->detail) : NULL;
		if ((argv = calloc(t->argv.n + 1, sizeof(*argv))) == NULL)
			xo_err(1, "trace");
		for (size_t m = 0; m < t->argv.n; m++)
			argv[m] = strdup(t->argv.v[m]);
		d->argv.v = argv;
		d->argv.n = t->argv.n;
		d->output.p = ybytes(&t->output);
		d->output.len = t->output.len;
		d->error_output.p = ybytes(&t->error_output);
		d->error_output.len = t->error_output.len;
	}
	cbl_yarena_free(a);
}

static int
ystep_cmp(const void *a, const void *b)
{
	uint32_t	x = ((const struct arcana_jobs_step *)a)->id;
	uint32_t	y = ((const struct arcana_jobs_step *)b)->id;

	return (x < y ? -1 : x > y);
}

/* The steps of what is asked from now on, heard with -t. */
static void
ytold_begin(cbl_conn *conn)
{

	if (!show_trace)
		return;
	if (ystep_sub == NULL)
		(void)cbl_subscribe(conn, "cblink.yang", "notify",
		    ystep_rx, NULL, &ystep_sub);
	ystep_on = true;
}

/* No more heard; with print, those heard printed as a trace. */
static void
ytold_end(bool print)
{

	ystep_on = false;
	if (print && nysteps > 0) {
		qsort(ysteps, nysteps, sizeof(*ysteps), ystep_cmp);
		emit_trace(ysteps, nysteps);
	}
	for (size_t i = 0; print && i < nysteps; i++)
		ystep_free(&ysteps[i]);
	if (print)
		nysteps = 0;
}

/*
 * set [-nx] [-d datastore] [-a warning]... path [value]: the node RFC
 * 8040's api-path names (/module:node/list=key,key/leaf) given value,
 * or with -x taken away, in the candidate (-d running: running itself),
 * then the candidate committed, confirmed (-n: left in the candidate).
 * The datastore's top-level node is read, changed here and sent back
 * whole in one EDIT, as RESTCONF's changes are (restconf.c); a commit
 * would take others' changes too, so a candidate that is not running is
 * refused unless -n.  A leaf's value is text, as its type reads it; a
 * container's or a list entry's RFC 7951 JSON (or @file), the node it
 * becomes, an entry's keys those of the path; a leaf-list without a
 * value in the path is given one more.
 */
#define	SEG_MAX		32
#define	SKEY_MAX	8

struct yseg {
	const struct cbl_ynode	*n;
	char			*key[SKEY_MAX];
	size_t			 nkey;
};

/* %XX in s decoded in place; false where one is not. */
static bool
pct_decoded(char *s)
{
	char	*o = s;
	int	 hi, lo;

	for (; *s != '\0'; s++) {
		if (*s != '%') {
			*o++ = *s;
			continue;
		}
		if (!isxdigit((unsigned char)s[1]) ||
		    !isxdigit((unsigned char)s[2]))
			return (false);
		hi = digittoint(s[1]);
		lo = digittoint(s[2]);
		*o++ = (char)(hi << 4 | lo);
		s += 2;
	}
	*o = '\0';
	return (true);
}

/* The child of n a segment names: "name", or "module:name". */
static const struct cbl_ynode *
yseg_child(const struct cbl_ynode *n, const char *seg)
{
	const char	*colon = strchr(seg, ':');
	const char	*name = colon != NULL ? colon + 1 : seg;
	size_t		 mlen = colon != NULL ? (size_t)(colon - seg) : 0;

	for (uint32_t i = 0; i < n->nchild; i++) {
		const struct cbl_ynode *c = n->child[i];

		if (strcmp(c->name, name) != 0 || (c->kind != CBL_YN_CONTAINER &&
		    c->kind != CBL_YN_LIST && c->kind != CBL_YN_LEAF &&
		    c->kind != CBL_YN_LEAFLIST))
			continue;
		if (colon != NULL ? strlen(c->module->name) != mlen ||
		    strncmp(c->module->name, seg, mlen) != 0 :
		    c->module != n->module)
			continue;
		return (c);
	}
	return (NULL);
}

/* path, an api-path, into its segments (in path's own memory). */
static size_t
ypath_parse(char *path, struct yseg *seg)
{
	const struct cbl_ymodule	*m;
	const struct cbl_ynode		*n = NULL;
	char				*p, *s, *eq, *colon, *k;
	size_t				 ns = 0;

	if (path[0] != '/')
		xo_errx(2, "set: %s: an api-path begins with /", path);
	for (p = path + 1; p != NULL && *p != '\0'; ) {
		s = p;
		if ((p = strchr(p, '/')) != NULL)
			*p++ = '\0';
		if (ns == SEG_MAX)
			xo_errx(1, "set: deeper than %d nodes", SEG_MAX);
		memset(&seg[ns], 0, sizeof(seg[ns]));
		if ((eq = strchr(s, '=')) != NULL)
			*eq++ = '\0';
		if (ns == 0) {
			if ((colon = strchr(s, ':')) == NULL)
				xo_errx(2, "set: %s: the top node is "
				    "module:name", s);
			*colon = '\0';
			for (uint32_t i = 0; n == NULL && i < ymodel_schema.nmod;
			    i++) {
				m = ymodel_schema.mod[i];
				for (uint32_t j = 0; strcmp(m->name, s) == 0 &&
				    j < m->ntop; j++)
					if (strcmp(m->top[j]->name, colon + 1) ==
					    0 && (m->top[j]->flags &
					    CBL_YNF_CONFIG) != 0)
						n = m->top[j];
			}
			*colon = ':';
		} else
			n = yseg_child(seg[ns - 1].n, s);
		if (n == NULL || (n->flags & CBL_YNF_CONFIG) == 0)
			xo_errx(1, "set: %s: no configuration node there", s);
		seg[ns].n = n;
		if (eq != NULL) {
			if (n->kind != CBL_YN_LIST && n->kind != CBL_YN_LEAFLIST)
				xo_errx(2, "set: %s: keys are a list's", s);
			for (k = eq; k != NULL; ) {
				if (seg[ns].nkey == SKEY_MAX)
					xo_errx(1, "set: %s: too many keys", s);
				seg[ns].key[seg[ns].nkey++] = k;
				if ((k = strchr(k, ',')) != NULL)
					*k++ = '\0';
			}
			for (size_t i = 0; i < seg[ns].nkey; i++)
				if (!pct_decoded(seg[ns].key[i]))
					xo_errx(2, "set: %s: a key's %% escape",
					    s);
			if (seg[ns].nkey != (n->kind == CBL_YN_LIST ? n->nkeys :
			    1u))
				xo_errx(2, "set: %s: %u keys", s, n->kind ==
				    CBL_YN_LIST ? n->nkeys : 1u);
		} else if (n->kind == CBL_YN_LIST && p != NULL && *p != '\0')
			xo_errx(2, "set: %s: an entry is named by its keys", s);
		ns++;
		if (n->kind == CBL_YN_LEAF || n->kind == CBL_YN_LEAFLIST) {
			if (p != NULL && *p != '\0')
				xo_errx(2, "set: %s: nothing is below a leaf",
				    s);
			break;
		}
	}
	if (ns == 0)
		xo_errx(2, "set: no node in the path");
	return (ns);
}

/* Datastore ds's top-level node top, read into a tree of its own. */
static cbl_dtree *
yds_read(cbl_conn *conn, enum cbl_yds_name ds,
    const uint64_t *sids, size_t n)
{
	cbl_msg		*req, *rep = NULL;
	cbl_dtree	*t;
	char		 why[256];
	int		 error;

	if ((error = cbl_msg_new(cbl_conn_ctx(conn), CBL_YANG_FAMILY,
	    CBL_YCMD_GET, 0, &req)) != 0 || (error = cbl_msg_put_yget_opts(req,
	    sids, n, NULL, CBL_YWD_EXPLICIT, false)) != 0 ||
	    (error = cbl_msg_set_datastore(req, ds)) != 0)
		xo_errx(1, "set: %s", strerror(error));
	if ((error = cbl_request(conn, req, &rep, -1)) != 0)
		xo_errx(1, "set: %s", rep != NULL && cbl_msg_err_str(rep) !=
		    NULL ? cbl_msg_err_str(rep) : strerror(error));
	if ((t = cbl_dtree_new(&ymodel_schema)) == NULL)
		xo_err(1, "set");
	if ((error = cbl_msg_ydtree(rep, t, 0, why, sizeof(why))) != 0)
		xo_errx(1, "set: %s", why[0] != '\0' ? why : strerror(error));
	cbl_msg_free(rep);
	return (t);
}

/* Whether the candidate is running: every node alike. */
static bool
candidate_clean(cbl_conn *conn)
{
	struct cbl_ybuf	 a = { NULL, 0, 0 }, b = { NULL, 0, 0 };
	cbl_dtree	*r, *c;
	bool		 same;

	r = yds_read(conn, CBL_YDS_RUNNING, NULL, 0);
	c = yds_read(conn, CBL_YDS_CANDIDATE, NULL, 0);
	if (cbl_dtree_encode(r, &a) != 0 || cbl_dtree_encode(c, &b) != 0)
		xo_err(1, "set");
	same = a.len == b.len && memcmp(a.p, b.p, a.len) == 0;
	cbl_ybuf_free(&a);
	cbl_ybuf_free(&b);
	cbl_dtree_free(r);
	cbl_dtree_free(c);
	return (same);
}

/* Segment s's keys as the list's (or leaf-list's) values, in a. */
static const void **
yseg_keys(const struct yseg *s, cbl_yarena *a)
{
	const void	**v;
	void		 *val;
	char		  why[256];

	if ((v = cbl_yarena_alloc(a, (s->nkey + 1) * sizeof(*v))) == NULL)
		xo_err(1, "set");
	for (size_t i = 0; i < s->nkey; i++) {
		if (yjson_text(s->n->kind == CBL_YN_LIST ?
		    s->n->child[s->n->keys[i]] : s->n, s->key[i], a, &val, why,
		    sizeof(why)) != 0)
			xo_errx(1, "set: %s", why);
		v[i] = val;
	}
	return (v);
}

static int
cmd_set(cbl_conn *conn, int argc, char **argv)
{
	struct ietf_netconf_commit_input		 cin;
	struct ietf_netconf_discard_changes_input	 din;
	struct yseg					 seg[SEG_MAX];
	const struct cbl_ynode				*n, *top;
	struct ucl_parser				*p;
	ucl_object_t					*v, *arr;
	cbl_dnode					*d, *c, *made;
	cbl_dtree					*t;
	cbl_yarena					*a;
	enum cbl_yds_name				 ds;
	const char					*value, *op, *dsname;
	char						*path, *text;
	char						 err[512], tag[80], why[256];
	char						 token[33];
	void						*val;
	uint64_t					 errsid;
	size_t						 ns;
	bool						 del, stop, committed,
							 confirmed;
	int						 ch, error;

	ds = CBL_YDS_CANDIDATE;
	del = stop = false;
	optreset = optind = 1;
	while ((ch = getopt(argc, argv, "a:d:nx")) != -1) {
		switch (ch) {
		case 'a':
			if (naccepts < nitems(accepts))
				accepts[naccepts++] = optarg;
			break;
		case 'd':
			ds = ds_named(optarg);
			if (ds != CBL_YDS_CANDIDATE && ds != CBL_YDS_RUNNING)
				xo_errx(2, "set: -d candidate or running");
			break;
		case 'n':
			stop = true;
			break;
		case 'x':
			del = true;
			break;
		default:
			usage();
		}
	}
	argc -= optind;
	argv += optind;
	if (argc < 1 || argc > 2 || (del && argc != 1) ||
	    (stop && ds == CBL_YDS_RUNNING))
		usage();
	if ((path = strdup(argv[0])) == NULL || (a = cbl_yarena_new()) ==
	    NULL)
		xo_err(1, "set");
	value = argc == 2 ? argv[1] : NULL;
	ns = ypath_parse(path, seg);
	top = seg[0].n;
	n = seg[ns - 1].n;
	if ((n->flags & CBL_YNF_KEY) != 0 && ns > 1 &&
	    seg[ns - 2].n->kind == CBL_YN_LIST)
		xo_errx(1, "set: %s: a key is the entry's name: set the entry",
		    n->name);
	if (!del && value == NULL && n->kind == CBL_YN_LEAF &&
	    n->type->kind == CBL_YT_EMPTY)
		value = "";
	else if (!del && value == NULL && (n->kind == CBL_YN_CONTAINER ||
	    (n->kind == CBL_YN_LIST && seg[ns - 1].nkey > 0) ||
	    (n->kind == CBL_YN_LEAFLIST && seg[ns - 1].nkey > 0)))
		value = n->kind == CBL_YN_LEAFLIST ? seg[ns - 1].key[0] : "{}";
	if (!del && value == NULL)
		xo_errx(2, "set: %s: a value is needed", n->name);
	if (n->kind == CBL_YN_LIST && seg[ns - 1].nkey == 0)
		xo_errx(2, "set: %s: an entry is named by its keys", n->name);
	if (ds == CBL_YDS_CANDIDATE && !stop && !candidate_clean(conn))
		xo_errx(1, "set: the candidate has changes of its own: commit "
		    "or discard them first, or set -n");

	/* The datastore's node, changed in place. */
	t = yds_read(conn, ds, &top->sid, 1);
	d = cbl_dtree_root(t);
	for (size_t i = 0; i < ns - 1; i++) {
		const struct cbl_ynode *sn = seg[i].n;

		c = sn->kind == CBL_YN_LIST ? cbl_dnode_entry(d, sn,
		    yseg_keys(&seg[i], a)) : cbl_dnode_child(d, sn);
		if (c == NULL && del)
			xo_errx(1, "set: %s: not there", sn->name);
		if (c == NULL && (error = sn->kind == CBL_YN_LIST ?
		    cbl_dnode_add_entry(d, sn, yseg_keys(&seg[i], a), &c) :
		    cbl_dnode_add(d, sn, NULL, &c)) != 0)
			xo_errx(1, "set: %s: %s", sn->name, strerror(error));
		d = c;
	}
	/* The node itself: there now, or not. */
	if (n->kind == CBL_YN_LIST)
		c = cbl_dnode_entry(d, n, yseg_keys(&seg[ns - 1], a));
	else if (n->kind == CBL_YN_LEAFLIST && (del || seg[ns - 1].nkey > 0))
		c = cbl_dnode_llentry(d, n, yseg_keys(&seg[ns - 1], a)[0]);
	else if (n->kind == CBL_YN_LEAFLIST)
		c = NULL;
	else
		c = cbl_dnode_child(d, n);
	if (del) {
		if (n->kind == CBL_YN_LEAFLIST && seg[ns - 1].nkey == 0) {
			/* All its values. */
			while ((c = cbl_dnode_child(d, n)) != NULL)
				(void)cbl_dnode_remove(c);
		} else if (c == NULL)
			xo_errx(1, "set: %s: not there", n->name);
		else if ((error = cbl_dnode_remove(c)) != 0)
			xo_errx(1, "set: %s: %s", n->name, strerror(error));
	} else if (n->kind == CBL_YN_LEAF || n->kind == CBL_YN_LEAFLIST) {
		if (yjson_text(n, value, a, &val, why, sizeof(why)) != 0)
			xo_errx(1, "set: %s", why);
		if (n->kind == CBL_YN_LEAF && c != NULL)
			error = cbl_dnode_set(c, val);
		else if (n->kind == CBL_YN_LEAFLIST &&
		    cbl_dnode_llentry(d, n, val) != NULL)
			error = 0;
		else
			error = cbl_dnode_add(d, n, val, NULL);
		if (error != 0)
			xo_errx(1, "set: %s: %s", n->name, strerror(error));
	} else {
		/* A container or an entry: what value says, in its place. */
		if ((text = value[0] == '@' ? slurp(value + 1) :
		    strdup(value)) == NULL)
			xo_err(1, "set");
		if ((p = ucl_parser_new(UCL_PARSER_NO_IMPLICIT_ARRAYS)) == NULL)
			xo_err(1, "set");
		if (!ucl_parser_add_string(p, text, 0))
			xo_errx(1, "set: not JSON: %s", ucl_parser_get_error(p));
		v = ucl_parser_get_object(p);
		ucl_parser_free(p);
		if (ucl_object_type(v) != UCL_OBJECT)
			xo_errx(1, "set: %s: its value is an object", n->name);
		if (c != NULL)
			(void)cbl_dnode_remove(c);
		arr = NULL;
		if (n->kind == CBL_YN_LIST) {
			/* Its keys, the path's; one of the value's that
			 * says otherwise refused. */
			for (uint16_t i = 0; i < n->nkeys; i++) {
				const struct cbl_ynode *kn =
				    n->child[n->keys[i]];
				const ucl_object_t *kv = ucl_object_lookup(v,
				    kn->name);

				if (kv != NULL && (ucl_object_tostring_forced(
				    kv) == NULL || strcmp(
				    ucl_object_tostring_forced(kv),
				    seg[ns - 1].key[i]) != 0))
					xo_errx(1, "set: %s: its %s is the "
					    "path's", n->name, kn->name);
				if (kv == NULL)
					ucl_object_insert_key(v,
					    ucl_object_fromstring(
					    seg[ns - 1].key[i]), kn->name, 0,
					    true);
			}
			arr = ucl_object_typed_new(UCL_ARRAY);
			ucl_array_append(arr, ucl_object_ref(v));
		}
		if ((error = yjson_node(d, n, arr != NULL ? arr : v, a, &made,
		    why, sizeof(why))) != 0)
			xo_errx(1, "set: %s", why[0] != '\0' ? why :
			    strerror(error));
		ucl_object_unref(arr);
		ucl_object_unref(v);
		free(text);
	}

	/* Sent back whole; then committed, confirmed. */
	ytold_begin(conn);
	if (yjson_edit_tree(conn, t, &top, 1, ds, accepts, naccepts, err,
	    sizeof(err), &errsid, tag, sizeof(tag)) != 0) {
		ytold_end(true);
		refused("set", err, tag);
	}
	committed = confirmed = false;
	if (ds == CBL_YDS_CANDIDATE && !stop) {
		(void)snprintf(token, sizeof(token), "%08x%08x%08x%08x",
		    arc4random(), arc4random(), arc4random(), arc4random());
		memset(&cin, 0, sizeof(cin));
		cin.confirmed = true;
		cin.persist = token;
		if (safe_wait > 0) {
			cin.has_confirm_timeout = true;
			cin.confirm_timeout = safe_wait;
		}
		if (netconf_try(conn, "commit", &cin, err, sizeof(err), tag,
		    sizeof(tag)) != 0) {
			memset(&din, 0, sizeof(din));
			(void)netconf_try(conn, "discard-changes", &din, NULL,
			    0, NULL, 0);
			ytold_end(true);
			refused("set", err, tag);
		}
		committed = true;
		/* Confirmed at once, the host still answering; with -s,
		 * left for you to. */
		if (!safe) {
			memset(&cin, 0, sizeof(cin));
			cin.persist_id = token;
			if (netconf_try(conn, "commit", &cin, err, sizeof(err),
			    tag, sizeof(tag)) != 0) {
				ytold_end(true);
				xo_errx(1, "set: committed, not confirmed: %s "
				    "(undone at its timeout)", err);
			}
			confirmed = true;
		}
	}
	ytold_end(true);
	op = del ? "delete" : "set";
	dsname = ds == CBL_YDS_RUNNING ? "running" : "candidate";
	xo_open_container("set");
	xo_emit("{:path/%s}: {:operation/%s}{L: in }{:datastore/%s}", argv[0],
	    op, dsname);
	xo_emit("{en:committed/%s}{en:confirmed/%s}", committed ? "true" :
	    "false", confirmed ? "true" : "false");
	if (confirmed)
		xo_emit("{L:, committed and confirmed}\n");
	else if (committed) {
		xo_emit("{L:, committed}\n");
		xo_emit("{Lw:confirm within}{:seconds/%u}{L: seconds: "
		    "arcanactl commit -i }{:persist-id/%s}\n", safe_wait > 0 ?
		    safe_wait : 600, token);
	} else
		xo_emit("\n");
	xo_close_container("set");
	cbl_dtree_free(t);
	cbl_yarena_free(a);
	free(path);
	return (0);
}

/*
 * A read of the models made the JSON its operation gave (ygula.c and
 * the like), data, printed as json_out() prints it, with the steps
 * heard since ytold_begin(); error and err, why it failed.
 */
static int
ydata_out(const char *what, int error, ucl_object_t *data, const char *err)
{
	unsigned char	*json;

	if (data != NULL && (json = ucl_object_emit(data,
	    UCL_EMIT_JSON_COMPACT)) != NULL) {
		xo_emit("{:json/%s}\n", (char *)json);
		free(json);
	}
	if (data != NULL)
		ucl_object_unref(data);
	ytold_end(true);
	if (error != 0)
		xo_warnx("%s: %s", what, err[0] != '\0' ? err :
		    strerror(error));
	return (error != 0 ? 1 : 0);
}

/*
 * Top-level node n of datastore ds (-1: the agent's default), decoded
 * into its module's data, data (a's).  Refused: said, exit 1.
 */
static void
yget_data(cbl_conn *conn, const struct cbl_ynode *n, int ds,
    void *data, cbl_yarena *a)
{
	cbl_msg	*req, *rep = NULL;
	char	 why[256];
	int	 error;

	if ((error = cbl_msg_new(cbl_conn_ctx(conn), CBL_YANG_FAMILY,
	    CBL_YCMD_GET, 0, &req)) != 0 || (error = cbl_msg_put_yget(req,
	    &n->sid, 1)) != 0 || (ds >= 0 && (error = cbl_msg_set_datastore(
	    req, (enum cbl_yds_name)ds)) != 0))
		xo_errx(1, "%s: %s", n->name, strerror(error));
	if ((error = cbl_request(conn, req, &rep, -1)) != 0)
		xo_errx(1, "%s: %s", n->name, rep != NULL &&
		    cbl_msg_err_str(rep) != NULL ? cbl_msg_err_str(rep) :
		    strerror(error));
	if ((error = cbl_msg_ydecode_member(rep, n, data, a, 0, why,
	    sizeof(why))) != 0 && error != ENOENT)
		xo_errx(1, "%s: %s", n->name, why);
	cbl_msg_free(rep);
}

/*
 * Action act of node n, the list entry of keys vals (nvals of them) or
 * a container's; in its input (NULL: none given), out its output (a's).
 * 0, or an errno and what the agent said in err.
 */
static int
ycall(cbl_conn *conn, const struct cbl_ynode *n,
    const void *const *vals, size_t nvals, const char *act, const void *in,
    void *out, cbl_yarena *a, char *err, size_t errlen)
{
	const struct cbl_ynode	*an, *inode, *onode;
	struct cbl_ybuf		 t = { NULL, 0, 0 };
	cbl_msg			*req, *rep = NULL;
	int			 error;

	if ((an = ychild(n, act)) == NULL || (inode = ychild(an, "input")) ==
	    NULL || (onode = ychild(an, "output")) == NULL)
		xo_errx(1, "%s: %s is not in the tables", n->name, act);
	if (in == NULL && (in = cbl_yarena_alloc(a, inode->size)) == NULL)
		xo_err(1, "%s", act);
	if ((error = cbl_yiid_write(n, (const void **)(uintptr_t)vals, nvals,
	    &t)) != 0 || (error = cbl_msg_new(cbl_conn_ctx(conn),
	    CBL_YANG_FAMILY, CBL_YCMD_RPC, 0, &req)) != 0 ||
	    (error = cbl_msg_put_ynode(req, inode, in)) != 0 ||
	    (error = cbl_msg_put_yaction(req, t.p, t.len)) != 0)
		xo_errx(1, "%s: %s", act, strerror(error));
	cbl_ybuf_free(&t);
	if ((error = cbl_request(conn, req, &rep, -1)) != 0) {
		(void)snprintf(err, errlen, "%s", rep != NULL &&
		    cbl_msg_err_str(rep) != NULL ? cbl_msg_err_str(rep) :
		    strerror(error));
		cbl_msg_free(rep);
		return (error);
	}
	if (out != NULL && (error = cbl_msg_ydecode(rep, onode, out, a, 0, err,
	    errlen)) != 0 && error != ENOENT) {
		cbl_msg_free(rep);
		return (error);
	}
	cbl_msg_free(rep);
	return (0);
}

/*
 * A plugin's module read, its top-level node top's action act given in
 * (the vnet jail -j names in it, if one): its output as RFC 7951's
 * JSON, with the steps the agent took; what it said where it could
 * not, as what failed of it.  0, or 1.
 */
static int
yplug_read(cbl_conn *conn, const char *top, const char *act,
    const void *in, const char *what)
{
	const struct cbl_ynode	*n, *an, *onode;
	struct cbl_ybuf		 b = { NULL, 0, 0 };
	cbl_yarena		*a;
	void			*out;
	char			 why[512];
	int			 error;

	n = ytop_named(top);
	if (n == NULL || (an = ychild(n, act)) == NULL || (onode = ychild(an,
	    "output")) == NULL)
		xo_errx(1, "%s: its module is not in the tables", what);
	if ((a = cbl_yarena_new()) == NULL || (out = cbl_yarena_alloc(a,
	    onode->size)) == NULL)
		xo_err(1, "%s", what);
	ytold_begin(conn);
	error = ycall(conn, n, NULL, 0, act, in, out, a, why, sizeof(why));
	ytold_end(true);
	if (error == 0 && (error = cbl_yjson(onode, out, &b)) != 0)
		(void)snprintf(why, sizeof(why), "%s", strerror(error));
	if (error == 0)
		xo_emit("{:json/%.*s}\n", (int)b.len, b.p != NULL ?
		    (const char *)b.p : "{}");
	else
		xo_warnx("%s: %s", what, why);
	cbl_ybuf_free(&b);
	cbl_yarena_free(a);
	return (error == 0 ? 0 : 1);
}

/* arcana-jails' jails, as datastore ds has them (a's). */
static const struct arcana_jails_jails *
yjails(cbl_conn *conn, int ds, cbl_yarena *a)
{
	static const struct arcana_jails_jails none;
	const struct cbl_ynode	*n;
	struct arcana_jails	 d;

	if ((n = ytop_named("jails")) == NULL)
		xo_errx(1, "jails: arcana-jails is not in the tables");
	memset(&d, 0, sizeof(d));
	yget_data(conn, n, ds, &d, a);
	return (d.jails != NULL ? d.jails : &none);
}

static const struct arcana_jails_jails_jail *
yjail_in(const struct arcana_jails_jails *js, const char *name)
{

	for (size_t i = 0; i < js->jail.n; i++)
		if (strcmp(js->jail.v[i].name, name) == 0)
			return (&js->jail.v[i]);
	return (NULL);
}

/*
 * list [-c]: the jails, running and configured, a GET of arcana-jails;
 * with -c those configured alone.
 */
static int
cmd_list(cbl_conn *conn, int argc, char **argv)
{
	const struct arcana_jails_jails	*js;
	cbl_yarena			*a;
	bool				 config_only;
	int				 ch;

	config_only = false;
	optind = 1;
	while ((ch = getopt(argc, argv, "c")) != -1) {
		switch (ch) {
		case 'c':
			config_only = true;
			break;
		default:
			usage();
		}
	}
	if (optind != argc)
		usage();
	if ((a = cbl_yarena_new()) == NULL)
		xo_err(1, "list");
	ytold_begin(conn);
	js = yjails(conn, -1, a);
	ytold_end(false);
	xo_emit("{T:/%-16s} {T:/%-8s} {T:/%4s} {T:/%-31s} {T:/%s}\n", "NAME",
	    "STATE", "JID", "ADDRESSES", "HOSTNAME");
	xo_open_list("jail");
	for (size_t i = 0; i < js->jail.n; i++)
		if (!config_only || (js->jail.v[i].has_configured &&
		    js->jail.v[i].configured))
			emit_jail(&js->jail.v[i], true);
	xo_close_list("jail");
	for (size_t i = 0; i < js->conf_error.n; i++)
		xo_warnx("%s: %s", js->conf_error.v[i].scope,
		    js->conf_error.v[i].message);
	ytold_end(true);
	cbl_yarena_free(a);
	return (0);
}

/* The jail as it is now, in detail; boot as running has it, where given. */
static void
yjail_show(cbl_conn *conn, const char *name, const bool *boot)
{
	const struct arcana_jails_jails_jail	*j;
	struct arcana_jails_jails_jail		 c;
	cbl_yarena				*a;

	if ((a = cbl_yarena_new()) == NULL)
		xo_err(1, "%s", name);
	if ((j = yjail_in(yjails(conn, -1, a), name)) != NULL) {
		c = *j;
		if (boot != NULL) {
			c.has_boot = true;
			c.boot = *boot;
		}
		emit_jail(&c, false);
	}
	cbl_yarena_free(a);
}

/*
 * enable | disable jail: started at boot or not, arcana-jails' boot in
 * the candidate, committed: jail_list and jail_enable in Arcana's
 * rc.conf file, the accepts given with -a.  What the commit refuses
 * leaves the candidate as running is.
 */
static int
jail_boot(cbl_conn *conn, const char *verb, const char *name, bool on)
{
	struct ietf_netconf_commit_input		 cin;
	struct ietf_netconf_discard_changes_input	 din;
	const struct cbl_ynode				*n;
	const struct arcana_jails_jails			*js;
	struct arcana_jails_jails_jail			*j;
	struct arcana_jails				 d;
	cbl_yarena					*a;
	char						 err[512], tag[80];
	uint64_t					 errsid;
	int						 error;

	if ((n = ytop_named("jails")) == NULL)
		xo_errx(1, "jails: arcana-jails is not in the tables");
	if ((a = cbl_yarena_new()) == NULL)
		xo_err(1, "%s", verb);
	js = yjails(conn, CBL_YDS_RUNNING, a);
	if ((j = (struct arcana_jails_jails_jail *)(uintptr_t)yjail_in(js,
	    name)) == NULL)
		xo_errx(1, "%s %s: jail '%s' is not defined", verb, name, name);
	if (!j->has_boot || j->boot != on) {
		j->has_boot = true;
		j->boot = on;
		memset(&d, 0, sizeof(d));
		d.jails = js;
		if ((error = yedit_data(conn, n, &d, CBL_YDS_CANDIDATE,
		    accepts, naccepts, err, sizeof(err), &errsid, tag,
		    sizeof(tag))) != 0)
			refused(verb, err, tag);
		memset(&cin, 0, sizeof(cin));
		if (netconf_try(conn, "commit", &cin, err, sizeof(err), tag,
		    sizeof(tag)) != 0) {
			memset(&din, 0, sizeof(din));
			(void)netconf_try(conn, "discard-changes", &din, NULL,
			    0, NULL, 0);
			refused(verb, err, tag);
		}
	}
	cbl_yarena_free(a);
	yjail_show(conn, name, &on);
	return (0);
}

/* start | stop | restart | kill jail: arcana-jails' actions. */
static int
cmd_action(cbl_conn *conn, uint8_t action, int argc, char **argv)
{
	const struct cbl_ynode	*n;
	const void		*vals[1];
	cbl_yarena		*a;
	char			 why[512];
	int			 ch, error;

	/* enable and disable: the commit's accepts, -a. */
	if (action == ARC_ACTION_ENABLE || action == ARC_ACTION_DISABLE) {
		optind = 1;
		optreset = 1;
		while ((ch = getopt(argc, argv, "a:")) != -1) {
			if (ch != 'a')
				usage();
			if (naccepts < nitems(accepts))
				accepts[naccepts++] = optarg;
		}
		/* The verb kept first, before the jail. */
		argv[optind - 1] = argv[0];
		argc -= optind - 1;
		argv += optind - 1;
	}
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
		return (submit(conn, &sp));
	}
	if (action == ARC_ACTION_ENABLE || action == ARC_ACTION_DISABLE)
		return (jail_boot(conn, argv[0], argv[1], action ==
		    ARC_ACTION_ENABLE));
	if ((n = ytop_named("jails")) == NULL || (n = ychild(n, "jail")) ==
	    NULL)
		xo_errx(1, "jails: arcana-jails is not in the tables");
	if ((a = cbl_yarena_new()) == NULL)
		xo_err(1, "%s", argv[0]);
	vals[0] = &argv[1];
	ytold_begin(conn);
	error = ycall(conn, n, vals, 1, argv[0], NULL, NULL, a, why,
	    sizeof(why));
	ytold_end(false);
	cbl_yarena_free(a);
	yjail_show(conn, argv[1], NULL);
	ytold_end(true);
	if (error != 0) {
		xo_warnx("%s %s: %s", argv[0], argv[1], why);
		return (1);
	}
	return (0);
}

static int
cmd_address(cbl_conn *conn, int argc, char **argv)
{
	struct arcana_jails_jails_jail_arcnet_address_input	 in;
	struct arcana_jails_jails_jail_arcnet_address_output	 out;
	struct {
		const char	*jail, *address, *interface;
		bool		 remove, live, persist, dry_run;
	}							 req;
	const struct cbl_ynode					*n;
	const void						*vals[1];
	cbl_yarena						*a;
	char							 why[512];
	int							 ch, error;

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
		return (submit(conn, &sp));
	}
	/* arcana-jails' jail's address action. */
	if ((n = ytop_named("jails")) == NULL || (n = ychild(n, "jail")) ==
	    NULL)
		xo_errx(1, "address: arcana-jails is not in the tables");
	if ((a = cbl_yarena_new()) == NULL)
		xo_err(1, "address");
	memset(&in, 0, sizeof(in));
	memset(&out, 0, sizeof(out));
	in.address = req.address;
	in.interface = req.interface;
	in.has_remove = in.has_live = in.has_persist = in.has_dry_run = true;
	in.remove = req.remove;
	in.live = req.live;
	in.persist = req.persist;
	in.dry_run = req.dry_run;
	vals[0] = &req.jail;
	ytold_begin(conn);
	error = ycall(conn, n, vals, 1, "address", &in, &out, a, why,
	    sizeof(why));
	ytold_end(false);
	if (error == 0 && out.diff != NULL)
		xo_emit("{:diff/%s}", out.diff);
	cbl_yarena_free(a);
	/* The jail as it is after, as arcana-jails has it. */
	if (error == 0 && !req.dry_run)
		yjail_show(conn, req.jail, NULL);
	ytold_end(true);
	if (error != 0) {
		xo_warnx("address %s: %s", req.address, why);
		return (1);
	}
	return (0);
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

typedef struct arcana_services_services_service yservice;
typedef struct arcana_services_services_service_variable yservice_var;

/* arcana-services' services, as datastore ds has them (a's). */
static const struct arcana_services_services *
yservices(cbl_conn *conn, int ds, cbl_yarena *a)
{
	static const struct arcana_services_services none;
	const struct cbl_ynode	*n;
	struct arcana_services	 d;

	if ((n = ytop_named("services")) == NULL)
		xo_errx(1, "services: arcana-services is not in the tables");
	memset(&d, 0, sizeof(d));
	yget_data(conn, n, ds, &d, a);
	return (d.services != NULL ? d.services : &none);
}

/* A service of the module as the agent's own struct, for emit_service(). */
static struct arc_service
service_of(const yservice *y)
{
	struct arc_service	s;

	memset(&s, 0, sizeof(s));
	s.name = y->name;
	s.path = y->path;
	s.rcvar = y->rcvar;
	s.has_enabled = y->has_enabled;
	s.enabled = y->enabled;
	s.has_running = y->has_running;
	s.running = y->running;
	s.has_pid = y->has_pid;
	s.pid = y->pid;
	s.status = y->status;
	return (s);
}

/* services: the rc.d scripts, a GET of arcana-services' state. */
static int
cmd_services(cbl_conn *conn)
{
	const struct arcana_services_services	*ss;
	struct arc_service			 s;
	cbl_yarena				*a;

	if ((a = cbl_yarena_new()) == NULL)
		xo_err(1, "services");
	ytold_begin(conn);
	ss = yservices(conn, CBL_YDS_OPERATIONAL, a);
	ytold_end(false);
	xo_emit("{T:/%-24s} {T:/%-8s} {T:/%-8s} {T:/%s}\n", "NAME", "ENABLED",
	    "STATE", "PID");
	xo_open_list("service");
	for (size_t i = 0; i < ss->service.n; i++) {
		s = service_of(&ss->service.v[i]);
		emit_service(&s, true);
	}
	xo_close_list("service");
	ytold_end(true);
	cbl_yarena_free(a);
	return (0);
}

/*
 * Service name as it is now, by its read action: enabled, running, what
 * it says of itself and its commands; with vars, its rc.conf variables
 * as running has them.
 */
static int
service_show(cbl_conn *conn, const char *name, bool vars)
{
	struct arcana_services_services_service_read_output	 o;
	const struct arcana_services_services			*ss;
	const struct cbl_ynode					*n;
	struct arc_service					 s;
	const void						*vals[1];
	cbl_yarena						*a;
	char							 why[512];

	if ((n = ytop_named("services")) == NULL || (n = ychild(n,
	    "service")) == NULL)
		xo_errx(1, "services: arcana-services is not in the tables");
	if ((a = cbl_yarena_new()) == NULL)
		xo_err(1, "%s", name);
	vals[0] = &name;
	memset(&o, 0, sizeof(o));
	if (ycall(conn, n, vals, 1, "read", NULL, &o, a, why,
	    sizeof(why)) != 0) {
		xo_warnx("service %s: %s", name, why);
		cbl_yarena_free(a);
		return (1);
	}
	memset(&s, 0, sizeof(s));
	s.name = name;
	s.path = o.path;
	s.rcvar = o.rcvar;
	s.has_enabled = o.has_enabled;
	s.enabled = o.enabled;
	s.has_running = o.has_running;
	s.running = o.running;
	s.has_pid = o.has_pid;
	s.pid = o.pid;
	s.status = o.status;
	emit_service(&s, false);
	if (vars) {
		if (o.description != NULL)
			xo_emit("{Lwc:Describe}{:description/%s}\n",
			    o.description);
		if (o.command.n > 0)
			xo_emit("{Lwc:Commands}{d:/%s}\n", join(o.command.v,
			    o.command.n));
		for (size_t i = 0; i < o.command.n; i++)
			xo_emit("{el:command/%s}", o.command.v[i]);
		ss = yservices(conn, CBL_YDS_RUNNING, a);
		xo_open_list("variable");
		for (size_t i = 0; i < ss->service.n; i++) {
			const yservice *y = &ss->service.v[i];

			if (strcmp(y->name, name) != 0)
				continue;
			for (size_t k = 0; k < y->variable.n; k++) {
				xo_open_instance("variable");
				xo_emit("{P:  }{k:key/%s}{D:=}{:value/%s}\n",
				    y->variable.v[k].name,
				    y->variable.v[k].value != NULL ?
				    y->variable.v[k].value : "");
				xo_close_instance("variable");
			}
		}
		xo_close_list("variable");
	}
	cbl_yarena_free(a);
	return (0);
}

/*
 * Service name's configuration changed in the candidate and committed:
 * enabled with enable 1, disabled with -1; variables vars set, or unset
 * (remove).  Every service of running goes with it, the one changed, so
 * that the commit's undo has them all; the accepts given with -a.
 * What the commit refuses leaves the candidate as running is.
 */
static void
service_commit(cbl_conn *conn, const char *verb, const char *name,
    int enable, const struct arc_variable *vars, size_t nv)
{
	struct ietf_netconf_commit_input		 cin;
	struct ietf_netconf_discard_changes_input	 din;
	const struct arcana_services_services		*ss;
	const struct cbl_ynode				*n;
	struct arcana_services				 d;
	yservice					*y = NULL;
	yservice_var					*v;
	cbl_yarena					*a;
	char						 err[512], tag[80];
	uint64_t					 errsid;
	size_t						 k, m;

	if ((n = ytop_named("services")) == NULL)
		xo_errx(1, "services: arcana-services is not in the tables");
	if ((a = cbl_yarena_new()) == NULL)
		xo_err(1, "%s", verb);
	ss = yservices(conn, CBL_YDS_RUNNING, a);
	for (k = 0; k < ss->service.n; k++)
		if (strcmp(ss->service.v[k].name, name) == 0)
			y = (yservice *)(uintptr_t)&ss->service.v[k];
	if (y == NULL)
		xo_errx(1, "%s: no rc.d script '%s'", verb, name);
	if (enable != 0) {
		y->has_enabled = true;
		y->enabled = enable > 0;
	}
	if (nv > 0) {
		if ((v = cbl_yarena_alloc(a, (y->variable.n + nv) *
		    sizeof(*v))) == NULL)
			xo_err(1, "%s", verb);
		m = 0;
		for (k = 0; k < y->variable.n; k++)
			v[m++] = y->variable.v[k];
		for (size_t i = 0; i < nv; i++) {
			for (k = 0; k < m && strcmp(v[k].name, vars[i].key) !=
			    0; k++)
				;
			if (vars[i].remove) {
				if (k < m)
					v[k] = v[--m];
				continue;
			}
			v[k].name = vars[i].key;
			v[k].value = vars[i].value != NULL ? vars[i].value : "";
			if (k == m)
				m++;
		}
		y->variable.v = v;
		y->variable.n = m;
	}
	memset(&d, 0, sizeof(d));
	d.services = ss;
	if (yedit_data(conn, n, &d, CBL_YDS_CANDIDATE, accepts, naccepts,
	    err, sizeof(err), &errsid, tag, sizeof(tag)) != 0)
		refused(verb, err, tag);
	memset(&cin, 0, sizeof(cin));
	if (netconf_try(conn, "commit", &cin, err, sizeof(err), tag,
	    sizeof(tag)) != 0) {
		memset(&din, 0, sizeof(din));
		(void)netconf_try(conn, "discard-changes", &din, NULL, 0, NULL,
		    0);
		refused(verb, err, tag);
	}
	cbl_yarena_free(a);
}

/*
 * services convert [-n] [-a warning]... [name ...]: the services' rc.conf
 * configuration moved under Arcana by arcana-services' convert action,
 * what it took (or with -n would take) a row each: the variable, its
 * value, the file and line of yours it was in, and why one was left.
 */
static int
cmd_services_convert(cbl_conn *conn, int argc, char **argv)
{
	const struct cbl_ynode				*n, *act, *in, *out;
	struct arcana_services_services_convert_input	 i;
	struct arcana_services_services_convert_output	 o;
	struct cbl_ybuf					 t = { NULL, 0, 0 };
	cbl_msg						*req, *rep = NULL;
	cbl_yarena					*a;
	char						 why[256];
	int						 ch, error;

	memset(&i, 0, sizeof(i));
	optind = 1;
	optreset = 1;
	while ((ch = getopt(argc, argv, "a:n")) != -1) {
		switch (ch) {
		case 'a':
			if (naccepts < nitems(accepts))
				accepts[naccepts++] = optarg;
			break;
		case 'n':
			i.has_dry_run = true;
			i.dry_run = true;
			break;
		default:
			usage();
		}
	}
	i.service.v = (const char *const *)argv + optind;
	i.service.n = (size_t)(argc - optind);
	if ((n = ytop_named("services")) == NULL || (act = ychild(n,
	    "convert")) == NULL || (in = ychild(act, "input")) == NULL ||
	    (out = ychild(act, "output")) == NULL)
		xo_errx(1, "services: arcana-services is not in the tables");
	if ((a = cbl_yarena_new()) == NULL)
		xo_err(1, "services");
	if ((error = cbl_yiid_write(n, NULL, 0, &t)) != 0 ||
	    (error = cbl_msg_new(cbl_conn_ctx(conn), CBL_YANG_FAMILY,
	    CBL_YCMD_RPC, 0, &req)) != 0 ||
	    (error = cbl_msg_put_ynode(req, in, &i)) != 0 ||
	    (error = cbl_msg_put_yaction(req, t.p, t.len)) != 0 ||
	    (naccepts > 0 && (error = cbl_msg_set_accept(req, accepts,
	    naccepts)) != 0))
		xo_errx(1, "services: %s", strerror(error));
	if ((error = cbl_request(conn, req, &rep, -1)) != 0)
		refused("services convert", rep != NULL && cbl_msg_err_str(rep)
		    != NULL ? cbl_msg_err_str(rep) : strerror(error), rep !=
		    NULL ? cbl_msg_err_apptag(rep) : NULL);
	memset(&o, 0, sizeof(o));
	if ((error = cbl_msg_ydecode(rep, out, &o, a, 0, why, sizeof(why))) !=
	    0 && error != ENOENT)
		xo_errx(1, "services: %s", why);
	warnings_of(rep);
	xo_emit("{T:/%-16s} {T:/%-24s} {T:/%-24s} {T:/%s}\n", "SERVICE",
	    "VARIABLE", "VALUE", "WHERE");
	xo_open_list("service");
	for (size_t k = 0; k < o.service.n; k++) {
		const struct arcana_services_services_convert_output_service *s =
		    &o.service.v[k];

		xo_open_instance("service");
		xo_emit("{e:name/%s}", s->name);
		xo_open_list("variable");
		for (size_t j = 0; j < s->variable.n; j++) {
			const struct
			    arcana_services_services_convert_output_service_variable
			    *v = &s->variable.v[j];

			xo_open_instance("variable");
			xo_emit("{d:service/%-16s} {:name/%-24s} {:value/%-24s} "
			    "{:file}:{:line/%u}", j == 0 ? s->name : "",
			    v->name, v->value != NULL ? v->value : "", v->file,
			    v->line);
			if (v->left != NULL)
				xo_emit("  left: {:left/%s}", v->left);
			xo_emit("\n");
			xo_close_instance("variable");
		}
		xo_close_list("variable");
		xo_close_instance("service");
	}
	xo_close_list("service");
	cbl_ybuf_free(&t);
	cbl_yarena_free(a);
	cbl_msg_free(rep);
	return (0);
}

/*
 * services release [-n] name...: convert's inverse, the services'
 * rc.conf configuration given back to your files by arcana-services'
 * release action; what it gave back (or with -n would) a row each: the
 * variable, the value put back and the file and line it is on, or what
 * was only dropped from Arcana's file and why.
 */
static int
cmd_services_release(cbl_conn *conn, int argc, char **argv)
{
	const struct cbl_ynode				*n, *act, *in, *out;
	struct arcana_services_services_release_input	 i;
	struct arcana_services_services_release_output	 o;
	struct cbl_ybuf					 t = { NULL, 0, 0 };
	cbl_msg						*req, *rep = NULL;
	cbl_yarena					*a;
	char						 why[256];
	int						 ch, error;

	memset(&i, 0, sizeof(i));
	optind = 1;
	optreset = 1;
	while ((ch = getopt(argc, argv, "n")) != -1) {
		switch (ch) {
		case 'n':
			i.has_dry_run = true;
			i.dry_run = true;
			break;
		default:
			usage();
		}
	}
	if (optind == argc)
		usage();
	i.service.v = (const char *const *)argv + optind;
	i.service.n = (size_t)(argc - optind);
	if ((n = ytop_named("services")) == NULL || (act = ychild(n,
	    "release")) == NULL || (in = ychild(act, "input")) == NULL ||
	    (out = ychild(act, "output")) == NULL)
		xo_errx(1, "services: arcana-services is not in the tables");
	if ((a = cbl_yarena_new()) == NULL)
		xo_err(1, "services");
	if ((error = cbl_yiid_write(n, NULL, 0, &t)) != 0 ||
	    (error = cbl_msg_new(cbl_conn_ctx(conn), CBL_YANG_FAMILY,
	    CBL_YCMD_RPC, 0, &req)) != 0 ||
	    (error = cbl_msg_put_ynode(req, in, &i)) != 0 ||
	    (error = cbl_msg_put_yaction(req, t.p, t.len)) != 0)
		xo_errx(1, "services: %s", strerror(error));
	if ((error = cbl_request(conn, req, &rep, -1)) != 0)
		refused("services release", rep != NULL && cbl_msg_err_str(rep)
		    != NULL ? cbl_msg_err_str(rep) : strerror(error), rep !=
		    NULL ? cbl_msg_err_apptag(rep) : NULL);
	memset(&o, 0, sizeof(o));
	if ((error = cbl_msg_ydecode(rep, out, &o, a, 0, why, sizeof(why))) !=
	    0 && error != ENOENT)
		xo_errx(1, "services: %s", why);
	warnings_of(rep);
	xo_emit("{T:/%-16s} {T:/%-24s} {T:/%-24s} {T:/%s}\n", "SERVICE",
	    "VARIABLE", "VALUE", "WHERE");
	xo_open_list("service");
	for (size_t k = 0; k < o.service.n; k++) {
		const struct arcana_services_services_release_output_service *s =
		    &o.service.v[k];
		bool first = true;

		xo_open_instance("service");
		xo_emit("{e:name/%s}", s->name);
		if (s->variable.n == 0)
			xo_emit("{d:service/%-16s} {d:/nothing to give back}\n",
			    s->name);
		xo_open_list("variable");
		for (size_t j = 0; j < s->variable.n; j++) {
			const struct
			    arcana_services_services_release_output_service_variable
			    *v = &s->variable.v[j];

			xo_open_instance("variable");
			xo_emit("{e:name/%s}", v->name);
			if (v->arcana_value != NULL)
				xo_emit("{e:arcana-value/%s}", v->arcana_value);
			xo_open_list("restored");
			for (size_t r = 0; r < v->restored.n; r++) {
				xo_open_instance("restored");
				xo_emit("{d:service/%-16s} {d:variable/%-24s} "
				    "{:value/%-24s} {:file}:{:line/%u}\n",
				    first ? s->name : "", r == 0 ? v->name : "",
				    v->restored.v[r].value != NULL ?
				    v->restored.v[r].value : "",
				    v->restored.v[r].file,
				    v->restored.v[r].line);
				xo_close_instance("restored");
				first = false;
			}
			xo_close_list("restored");
			if (v->dropped != NULL) {
				xo_emit("{d:service/%-16s} {d:variable/%-24s} "
				    "{d:value/%-24s} dropped: {:dropped/%s}\n",
				    first ? s->name : "", v->name,
				    v->arcana_value != NULL ? v->arcana_value :
				    "", v->dropped);
				first = false;
			}
			if (v->differs != NULL)
				xo_emit("{d:/%-16s} {d:/%-24s} differs: "
				    "{:differs/%s}\n", "", "", v->differs);
			xo_close_instance("variable");
		}
		xo_close_list("variable");
		xo_close_instance("service");
	}
	xo_close_list("service");
	cbl_ybuf_free(&t);
	cbl_yarena_free(a);
	cbl_msg_free(rep);
	return (0);
}

/*
 * service [-a warning]... name verb, or service [-a warning]... name
 * config [-x key] [key=value]: start, stop, restart and reload are
 * arcana-services' actions; enable, disable and the variables its
 * configuration, committed (service_commit()), the accepts given with
 * -a; with -q or -s, each a job, as before.  The service as it is
 * after, by its read action.
 */
static int
cmd_service(cbl_conn *conn, int argc, char **argv)
{
	static const char *verbs[] = { "start", "stop", "restart", "reload",
	    "enable", "disable" };
	const struct cbl_ynode	*n;
	struct arc_variable	*vars;
	const void		*vals[1];
	cbl_yarena		*a;
	size_t			 i, nv;
	char			 why[512], *eq;
	int			 ch, error;

	optind = 1;
	optreset = 1;
	while ((ch = getopt(argc, argv, "a:")) != -1) {
		if (ch != 'a')
			usage();
		if (naccepts < nitems(accepts))
			accepts[naccepts++] = optarg;
	}
	/* The command kept first, before the service. */
	argv[optind - 1] = argv[0];
	argc -= optind - 1;
	argv += optind - 1;
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
			return (submit(conn, &sp));
		}
		if (i == ARC_SERVICE_ACTION_ENABLE || i ==
		    ARC_SERVICE_ACTION_DISABLE) {
			service_commit(conn, argv[2], argv[1], i ==
			    ARC_SERVICE_ACTION_ENABLE ? 1 : -1, NULL, 0);
			return (service_show(conn, argv[1], false));
		}
		if ((n = ytop_named("services")) == NULL || (n = ychild(n,
		    "service")) == NULL)
			xo_errx(1, "services: arcana-services is not in the "
			    "tables");
		if ((a = cbl_yarena_new()) == NULL)
			xo_err(1, "%s", argv[2]);
		vals[0] = &argv[1];
		ytold_begin(conn);
		error = ycall(conn, n, vals, 1, argv[2], NULL, NULL, a, why,
		    sizeof(why));
		ytold_end(false);
		cbl_yarena_free(a);
		if (error != 0) {
			ytold_end(true);
			xo_warnx("service %s %s: %s", argv[1], argv[2], why);
			return (1);
		}
		error = service_show(conn, argv[1], false);
		ytold_end(true);
		return (error);
	}
	if (strcmp(argv[2], "config") != 0)
		usage();
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
	if ((queue || safe) && nv > 0) {
		struct arc_job_spec sp;

		memset(&sp, 0, sizeof(sp));
		sp.has_kind = true;
		sp.kind = ARC_JOB_KIND_SERVICE_CONFIG;
		sp.service = argv[1];
		sp.variables.v = vars;
		sp.variables.n = nv;
		error = submit(conn, &sp);
		free(vars);
		return (error);
	}
	if (nv > 0)
		service_commit(conn, "config", argv[1], 0, vars, nv);
	free(vars);
	return (service_show(conn, argv[1], true));
}

/* Whether the agent takes its program compressed (its features). */
static bool
takes_gzip(cbl_conn *conn)
{
	ucl_object_t	*h;
	char		 err[512];
	bool		 yes;
	int		 error;

	if ((error = yh_hello(conn, &h, err, sizeof(err))) != 0)
		xo_errx(1, "hello: %s", err[0] != '\0' ? err :
		    strerror(error));
	yes = yh_takes_gzip(h);
	ucl_object_unref(h);
	return (yes);
}

/*
 * A fetch the server refused (EPERM): what it showed, and with trust the
 * host keys it found as confirmed, *keys, for one more try: true.
 */
static bool
fetch_refused(const char *what, int error, ucl_object_t *data,
    const char *err, bool trust, char **keys)
{
	const ucl_object_t	*fp, *e;
	ucl_object_iter_t	 it = NULL;
	const char		*k;

	if (error != EPERM || data == NULL) {
		if (error != 0)
			xo_warnx("%s: %s", what, err[0] != '\0' ? err :
			    strerror(error));
		return (false);
	}
	fp = ucl_object_lookup(data, "fingerprints");
	while (fp != NULL && (e = ucl_object_iterate(fp, &it, true)) != NULL)
		xo_emit("{Lwc:Host key}{l:fingerprint/%s}\n",
		    ucl_object_tostring(e));
	k = ucl_object_tostring(ucl_object_lookup(data, "host_keys"));
	if (trust && *keys == NULL && k != NULL) {
		if ((*keys = strdup(k)) == NULL)
			xo_err(1, "strdup");
		return (true);
	}
	if ((k = ucl_object_tostring(ucl_object_lookup(data,
	    "deploy_key"))) != NULL)
		xo_emit("{Lwc:Deploy key}{:deploy-key/%s}\n", k);
	xo_warnx("%s: %s", what, err);
	return (false);
}

/*
 * agent-build [-y] [-i key] [-o file] repository [ref]: have the host
 * build arcana-agent from a git repository, and keep what it sends
 * back, sent compressed by an agent that can.
 */
static int
cmd_agent_build(cbl_conn *conn, int argc, char **argv)
{
	ucl_object_t	*data;
	const char	*out, *sshkey, *sha;
	char		 hex[SHA256_DIGEST_STRING_LENGTH], err[CBL_ERRMSG_MAX];
	char		*keys;
	uint8_t		*prog;
	size_t		 len;
	bool		 trust, gz;
	int		 ch, error, fd;

	out = "arcana-agent";
	sshkey = NULL;
	trust = false;
	keys = NULL;
	optreset = optind = 1;
	while ((ch = getopt(argc, argv, "i:o:y")) != -1) {
		switch (ch) {
		case 'i':
			sshkey = optarg;
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
	gz = takes_gzip(conn);
	/* arcana-agent's build. */
	for (;;) {
		ytold_begin(conn);
		error = yh_agent_build(conn, argv[optind],
		    argv[optind + 1], keys, sshkey, gz, &data, &prog, &len,
		    err, sizeof(err));
		ytold_end(true);
		if (!fetch_refused("agent-build", error, data, err,
		    trust, &keys))
			break;
		ucl_object_unref(data);
	}
	if (error != 0) {
		if (data != NULL)
			ucl_object_unref(data);
		free(keys);
		return (1);
	}
	/* What arrived is what the host says it built. */
	sha = ucl_object_tostring(ucl_object_lookup(data, "sha256"));
	if (sha == NULL || strcmp(SHA256_Data(prog, len, hex), sha) != 0)
		xo_errx(1, "agent-build: the program does not match its "
		    "SHA-256");
	if ((fd = fileargs_open(outfiles, out)) == -1 ||
	    write(fd, prog, len) != (ssize_t)len || close(fd) == -1)
		xo_err(1, "%s", out);
	xo_emit("{Lwc:Built}{:agent-version/%s}{P: }{:sha256/%s}{P: }"
	    "{:file/%s}\n", ucl_object_tostring(ucl_object_lookup(data,
	    "version")) != NULL ? ucl_object_tostring(ucl_object_lookup(data,
	    "version")) : "?", hex, out);
	if (ucl_object_lookup(data, "commit") != NULL)
		xo_emit("{Lwc:Commit}{:commit/%s}\n", ucl_object_tostring(
		    ucl_object_lookup(data, "commit")));
	ucl_object_unref(data);
	free(keys);
	free(prog);
	return (0);
}

/*
 * console-update [-y] [-i key] repository [ref]: have the host build
 * the whole tree, install it and restart the console's service.
 */
static int
cmd_console_update(cbl_conn *conn, int argc, char **argv)
{
	ucl_object_t	*data;
	const char	*sshkey;
	char		 err[CBL_ERRMSG_MAX];
	char		*keys;
	bool		 trust;
	int		 ch, error;

	sshkey = NULL;
	trust = false;
	keys = NULL;
	optreset = optind = 1;
	while ((ch = getopt(argc, argv, "i:y")) != -1) {
		switch (ch) {
		case 'i':
			sshkey = optarg;
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
	/* arcana-agent's console-update. */
	for (;;) {
		ytold_begin(conn);
		error = yh_console_update(conn, argv[optind],
		    argv[optind + 1], keys, sshkey, &data, err, sizeof(err));
		ytold_end(true);
		if (!fetch_refused("console-update", error, data, err,
		    trust, &keys))
			break;
		ucl_object_unref(data);
	}
	if (error == 0) {
		xo_emit("{Lwc:Console}{:console/installed}{d:restarting/%s}\n",
		    ", restarting");
		if (ucl_object_lookup(data, "commit") != NULL)
			xo_emit("{Lwc:Commit}{:commit/%s}\n",
			    ucl_object_tostring(ucl_object_lookup(data,
			    "commit")));
	}
	if (data != NULL)
		ucl_object_unref(data);
	free(keys);
	return (error != 0 ? 1 : 0);
}

/*
 * source-head [-y] [-i key] repository [ref]: the commit at the head of
 * the repository's branch, as the host sees it: whether there is
 * anything new to build.
 */
static int
cmd_source_head(cbl_conn *conn, int argc, char **argv)
{
	ucl_object_t	*data;
	const char	*sshkey;
	char		 err[CBL_ERRMSG_MAX];
	char		*keys;
	bool		 trust;
	int		 ch, error;

	sshkey = NULL;
	trust = false;
	keys = NULL;
	optreset = optind = 1;
	while ((ch = getopt(argc, argv, "i:y")) != -1) {
		switch (ch) {
		case 'i':
			sshkey = optarg;
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
	/* arcana-agent's source-head. */
	for (;;) {
		ytold_begin(conn);
		error = yh_source_head(conn, argv[optind],
		    argv[optind + 1], keys, sshkey, &data, err, sizeof(err));
		ytold_end(true);
		if (!fetch_refused("source-head", error, data, err,
		    trust, &keys))
			break;
		ucl_object_unref(data);
	}
	if (error == 0)
		xo_emit("{Lwc:Commit}{:commit/%s}\n", ucl_object_tostring(
		    ucl_object_lookup(data, "commit")) != NULL ?
		    ucl_object_tostring(ucl_object_lookup(data, "commit")) :
		    "");
	if (data != NULL)
		ucl_object_unref(data);
	free(keys);
	return (error != 0 ? 1 : 0);
}

/*
 * source-log [-i key] [-n count] repository [ref]: the latest commits
 * of the repository's branch, newest first, and its tags: what is new.
 */
static int
cmd_source_log(cbl_conn *conn, int argc, char **argv)
{
	unsigned char	*lj;
	ucl_object_t	*data;
	const char	*errstr, *key;
	char		 err[CBL_ERRMSG_MAX];
	uint32_t	 count;
	int		 ch, error;

	key = NULL;
	count = 0;
	optreset = optind = 1;
	while ((ch = getopt(argc, argv, "i:n:")) != -1) {
		switch (ch) {
		case 'i':
			key = optarg;
			break;
		case 'n':
			count = (uint32_t)strtonum(optarg, 1, 10000, &errstr);
			if (errstr != NULL)
				xo_errx(2, "count %s: %s", optarg, errstr);
			break;
		default:
			usage();
		}
	}
	if (argc - optind < 1 || argc - optind > 2)
		usage();
	/* arcana-agent's source-log. */
	ytold_begin(conn);
	error = yh_source_log(conn, argv[optind], argv[optind + 1], NULL,
	    key, count, &data, err, sizeof(err));
	ytold_end(true);
	if (error != 0) {
		xo_warnx("source-log: %s", err[0] != '\0' ? err :
		    strerror(error));
		return (1);
	}
	xo_emit("{Lwc:Commit}{:commit/%s}\n", ucl_object_tostring(
	    ucl_object_lookup(data, "commit")) != NULL ? ucl_object_tostring(
	    ucl_object_lookup(data, "commit")) : "");
	/* The commits and the tags as the agent lists them, JSON each. */
	lj = ucl_object_emit(ucl_object_lookup(data, "log"),
	    UCL_EMIT_JSON_COMPACT);
	xo_emit("{Lwc:Commits}{:commits/%s}\n", lj != NULL ? (char *)lj :
	    "[]");
	free(lj);
	lj = ucl_object_emit(ucl_object_lookup(data, "tags"),
	    UCL_EMIT_JSON_COMPACT);
	xo_emit("{Lwc:Tags}{:tags/%s}\n", lj != NULL ? (char *)lj : "[]");
	free(lj);
	ucl_object_unref(data);
	return (0);
}

/*
 * agent-update [-pr] program: put a new arcana-agent in place, sent
 * compressed to an agent that takes it so (its features in
 * arcana-host); as it is with -p, and to an agent before, which takes
 * no more than a frame carries.
 */
static int
cmd_agent_update(cbl_conn *conn, int argc, char **argv)
{
	ucl_object_t	*data;
	struct stat	 sb;
	char		 hex[SHA256_DIGEST_STRING_LENGTH], err[512];
	uint8_t		*prog;
	ssize_t		 n;
	size_t		 off;
	bool		 plain, restart, restarting;
	int		 ch, error, fd;

	plain = restart = false;
	optreset = optind = 1;
	while ((ch = getopt(argc, argv, "pr")) != -1) {
		switch (ch) {
		case 'p':
			plain = true;
			break;
		case 'r':
			restart = true;
			break;
		default:
			usage();
		}
	}
	if (argc - optind != 1)
		usage();
	if ((fd = fileargs_open(files, argv[optind])) == -1 ||
	    fstat(fd, &sb) == -1)
		xo_err(1, "%s", argv[optind]);
	if (sb.st_size == 0 || sb.st_size > ZPROG_MAX_PROGRAM)
		xo_errx(1, "%s: not a program an update can carry",
		    argv[optind]);
	if ((prog = malloc((size_t)sb.st_size)) == NULL)
		xo_err(1, "malloc");
	for (off = 0; off < (size_t)sb.st_size; off += (size_t)n)
		if ((n = read(fd, prog + off, (size_t)sb.st_size - off)) <= 0)
			xo_err(1, "%s", argv[optind]);
	close(fd);
	(void)SHA256_Data(prog, off, hex);
	/* arcana-agent's update; over the local socket, unsigned. */
	ytold_begin(conn);
	error = yh_agent_update(conn, prog, off, hex, NULL, 0, restart,
	    !plain && takes_gzip(conn), -1, &data, err, sizeof(err));
	ytold_end(error != EFBIG);
	if (error == EFBIG)
		xo_errx(1, "%s: %s%s", argv[optind], err, plain ?
		    "; send it without -p" : "");
	if (error != 0) {
		xo_warnx("agent-update: %s", err[0] != '\0' ? err :
		    strerror(error));
		free(prog);
		return (1);
	}
	restarting = ucl_object_toboolean(ucl_object_lookup(data,
	    "restarting"));
	xo_emit("{Lwc:Agent}{:agent-version/%s}{d:restarting/%s}\n",
	    ucl_object_tostring(ucl_object_lookup(data, "version")) != NULL ?
	    ucl_object_tostring(ucl_object_lookup(data, "version")) : "?",
	    restarting ? ", restarting" :
	    " in place; it runs from the next start");
	xo_emit("{e:restarting/%s}", restarting ? "true" : "false");
	ucl_object_unref(data);
	free(prog);
	return (0);
}

/*
 * interface name up | down, interface name add | remove address: a job,
 * waited for unless it is only queued (-q).
 */
/*
 * BIRD's configuration as running has it (arcana-bird), the host's or
 * with -j the jail's; d the data read (a's).  NULL where it has none.
 */
static const struct arcana_bird_configuration *
ybird_conf(cbl_conn *conn, struct arcana_bird *d, cbl_yarena *a)
{
	const struct cbl_ynode	*n;

	if ((n = ytop_named("bird")) == NULL)
		xo_errx(1, "bird: arcana-bird is not in the tables");
	memset(d, 0, sizeof(*d));
	yget_data(conn, n, CBL_YDS_RUNNING, d, a);
	if (d->bird == NULL)
		return (NULL);
	if (netjail == NULL)
		return (d->bird->configuration);
	for (size_t i = 0; i < d->bird->jail.n; i++)
		if (strcmp(d->bird->jail.v[i].name, netjail) == 0)
			return (d->bird->jail.v[i].configuration);
	return (NULL);
}

/*
 * bird config [file]: a file of BIRD's configuration, its main one by
 * default, as running has it.  bird config -w new-text [-n] [-c
 * seconds] [file]: put in its place by a commit, BIRD told (with -s, or
 * -c the seconds to wait, a confirmed commit, taken back unless bird
 * confirm comes in time); with -n only whether bird(8) takes it, the
 * check action.
 */
static int
cmd_bird_config(cbl_conn *conn, int argc, char **argv)
{
	struct arcana_bird_bird_check_input		 cin;
	struct ietf_netconf_commit_input		 com;
	struct ietf_netconf_discard_changes_input	 din;
	const struct arcana_bird_configuration		*c;
	struct arcana_bird_configuration		*nc;
	struct arcana_bird_configuration_file		*f;
	struct arcana_bird_bird				*b;
	struct arcana_bird_bird_jail			*jv;
	struct arcana_bird				 d;
	const struct cbl_ynode				*n;
	struct stat					 sb;
	const char					*from, *path;
	cbl_yarena					*a;
	char						*text, err[512], tag[80];
	char						 token[33];
	const char					*errstr;
	uint64_t					 errsid;
	uint32_t					 wait;
	size_t						 i, k;
	bool						 dry_run;
	int						 ch, fd;

	from = NULL;
	dry_run = false;
	wait = safe ? (safe_wait > 0 ? safe_wait : 120) : 0;
	optind = 1;
	optreset = 1;
	while ((ch = getopt(argc, argv, "c:nw:")) != -1) {
		switch (ch) {
		case 'c':
			wait = (uint32_t)strtonum(optarg, 1, 3600, &errstr);
			if (errstr != NULL)
				xo_errx(2, "bird config -c %s: %s", optarg,
				    errstr);
			break;
		case 'n':
			dry_run = true;
			break;
		case 'w':
			from = optarg;
			break;
		default:
			usage();
		}
	}
	if (argc - optind > 1 || (dry_run && from == NULL))
		usage();
	if ((a = cbl_yarena_new()) == NULL)
		xo_err(1, "bird config");
	ytold_begin(conn);
	c = ybird_conf(conn, &d, a);
	ytold_end(false);
	path = argc - optind == 1 ? argv[optind] : c != NULL && c->path !=
	    NULL ? c->path : "/usr/local/etc/bird.conf";
	for (i = 0; c != NULL && i < c->file.n; i++)
		if (strcmp(c->file.v[i].path, path) == 0)
			break;
	if (from == NULL) {
		ytold_end(true);
		if (c == NULL || i == c->file.n)
			xo_errx(1, "bird config: %s is not a file of BIRD's "
			    "configuration%s", path, c == NULL ? " (it has none)" :
			    "");
		xo_emit("{:text/%s}", c->file.v[i].text != NULL ?
		    c->file.v[i].text : "");
		for (k = 0; k < c->file.n; k++)
			if (k != i)
				xo_emit("{e:file/%s}", c->file.v[k].path);
		cbl_yarena_free(a);
		return (0);
	}
	if ((fd = fileargs_open(files, from)) == -1 || fstat(fd, &sb) == -1 ||
	    (text = malloc((size_t)sb.st_size + 1)) == NULL ||
	    read(fd, text, (size_t)sb.st_size) != sb.st_size)
		xo_err(1, "%s", from);
	close(fd);
	text[sb.st_size] = '\0';
	if (dry_run) {
		memset(&cin, 0, sizeof(cin));
		cin.jail = netjail;
		cin.path = path;
		cin.text = text;
		k = (size_t)yplug_read(conn, "bird", "check", &cin,
		    "bird config -n");
		if (k == 0)
			xo_emit("{:path/%s}: {:result/%s}\n", path, "parses; left "
			    "as it was");
		free(text);
		cbl_yarena_free(a);
		return ((int)k);
	}
	/* Running's with the file's text in its place, or the file added. */
	if ((n = ytop_named("bird")) == NULL || (b = cbl_yarena_alloc(a,
	    sizeof(*b))) == NULL || (nc = cbl_yarena_alloc(a,
	    sizeof(*nc))) == NULL || (f = cbl_yarena_alloc(a, ((c != NULL ?
	    c->file.n : 0) + 1) * sizeof(*f))) == NULL)
		xo_err(1, "bird config");
	memset(b, 0, sizeof(*b));
	memset(nc, 0, sizeof(*nc));
	if (d.bird != NULL)
		*b = *d.bird;
	k = 0;
	for (size_t m = 0; c != NULL && m < c->file.n; m++)
		f[k++] = c->file.v[m];
	if (c == NULL || i == c->file.n) {
		memset(&f[k], 0, sizeof(f[k]));
		f[k++].path = path;
		i = k - 1;
	}
	f[i].text = text;
	nc->path = c != NULL ? c->path : NULL;
	nc->file.n = k;
	nc->file.v = f;
	if (netjail == NULL)
		b->configuration = nc;
	else {
		if ((jv = cbl_yarena_alloc(a, (b->jail.n + 1) * sizeof(*jv))) ==
		    NULL)
			xo_err(1, "bird config");
		for (size_t m = 0; m < b->jail.n; m++)
			jv[m] = b->jail.v[m];
		for (k = 0; k < b->jail.n && strcmp(jv[k].name, netjail) != 0;
		    k++)
			;
		if (k == b->jail.n) {
			memset(&jv[k], 0, sizeof(jv[k]));
			jv[k].name = netjail;
			b->jail.n++;
		}
		jv[k].configuration = nc;
		b->jail.v = jv;
	}
	d.bird = b;
	ytold_begin(conn);
	if (yedit_data(conn, n, &d, CBL_YDS_CANDIDATE, accepts, naccepts,
	    err, sizeof(err), &errsid, tag, sizeof(tag)) != 0) {
		ytold_end(true);
		refused("bird config", err, tag);
	}
	memset(&com, 0, sizeof(com));
	/* Safe: a confirmed commit, BIRD's own timer beside it. */
	if (wait > 0) {
		(void)snprintf(token, sizeof(token), "%08x%08x%08x%08x",
		    arc4random(), arc4random(), arc4random(), arc4random());
		com.confirmed = true;
		com.has_confirm_timeout = true;
		com.confirm_timeout = wait;
		com.persist = token;
	}
	if (netconf_try(conn, "commit", &com, err, sizeof(err), tag,
	    sizeof(tag)) != 0) {
		memset(&din, 0, sizeof(din));
		(void)netconf_try(conn, "discard-changes", &din, NULL, 0, NULL,
		    0);
		ytold_end(true);
		refused("bird config", err, tag);
	}
	ytold_end(true);
	xo_emit("{:path/%s}: {:result/%s}\n", path, wait > 0 ? "in place, and "
	    "BIRD told; taken back unless confirmed" : "in place, and BIRD "
	    "told");
	if (wait > 0)
		xo_emit("{Lw:confirm within}{:seconds/%u}{L: seconds: arcanactl "
		    "bird confirm }{:persist-id/%s}\n", com.confirm_timeout,
		    token);
	free(text);
	cbl_yarena_free(a);
	return (0);
}

/* bird confirm id: the configuration committed with -s stays. */
static int
cmd_bird_confirm(cbl_conn *conn, const char *id)
{
	struct ietf_netconf_commit_input	in;

	memset(&in, 0, sizeof(in));
	in.persist_id = id;
	netconf_rpc(conn, "commit", &in);
	xo_emit("{:result/%s}\n", "confirmed: it stays");
	return (0);
}

/* bird ospf [topology [protocol]]: BIRD's OSPF areas, or their topology. */
static int
cmd_bird_ospf(cbl_conn *conn, int argc, char **argv)
{
	struct arcana_bird_bird_ospf_input	in;

	if (argc > 2 || (argc >= 1 && strcmp(argv[0], "topology") != 0))
		usage();
	memset(&in, 0, sizeof(in));
	in.jail = netjail;
	in.has_topology = argc >= 1;
	in.topology = argc >= 1;
	in.protocol = argc == 2 ? argv[1] : NULL;
	return (yplug_read(conn, "bird", "ospf", &in, "bird ospf"));
}

/* bird routes [words]: routes of BIRD's tables, said in birdc's words. */
static int
cmd_bird_routes(cbl_conn *conn, int argc, char **argv)
{
	struct arcana_bird_bird_routes_input	in;
	char					words[256];
	int					i;

	words[0] = '\0';
	for (i = 0; i < argc; i++) {
		if (i > 0)
			strlcat(words, " ", sizeof(words));
		if (strlcat(words, argv[i], sizeof(words)) >= sizeof(words))
			usage();
	}
	memset(&in, 0, sizeof(in));
	in.jail = netjail;
	in.filter = words[0] != '\0' ? words : NULL;
	return (yplug_read(conn, "bird", "routes", &in, "bird routes"));
}

/* route get address: the route the host would take, and the others. */
static int
cmd_route_get(cbl_conn *conn, int argc, char **argv)
{
	struct arcana_network_network_lookup_input	in = { 0 };

	if (argc != 3)
		usage();
	in.address = argv[2];
	in.has_fib = fib != 0;
	in.fib = fib;
	in.jail = netjail;
	/* arcana-network's lookup. */
	return (yplug_read(conn, "network", "lookup", &in, "route get"));
}

static int	json_out(const char *, bool, const char *, const char *,
		    const struct arcana_jobs_step *, size_t);

/* A JSON argument: as given, or the contents of a file after @. */
static const char *
json_arg(const char *arg)
{
	FILE	*fp;
	char	*text;
	size_t	len, n;

	if (arg == NULL || arg[0] != '@')
		return (arg);
	if ((fp = fileargs_fopen(files, arg + 1, "r")) == NULL)
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


/*
 * sdwan: what the edge is doing and what the probes have seen,
 * arcana-sdwan's and arcana-probe's state as the sdwan operation had
 * them; sdwan probes json: an edge's targets and links, arcana-probe's;
 * sdwan rules|steer|bird|dhcp|dns|proxy|ids json: that part of an
 * edge, arcana-sdwan's, as its operation took it.  Each committed.
 */
static int
cmd_sdwan(cbl_conn *conn, int argc, char **argv)
{
	static const char *const parts[] = { "rules", "steer", "bird", "dhcp",
	    "dns", "proxy", "ids" };
	struct ietf_netconf_commit_input		 cin;
	struct ietf_netconf_discard_changes_input	 din;
	ucl_object_t					*data;
	uint64_t					 esid;
	char						 err[512], tag[80];
	char						 what[32];
	size_t						 k;
	int						 error;
	bool						 same;

	if (argc == 1) {
		ytold_begin(conn);
		error = ysdwan_read(conn, false, 0, &data, err,
		    sizeof(err));
		return (ydata_out("sdwan", error, data, err));
	}
	if (argc != 3)
		usage();
	for (k = 0; k < nitems(parts) && strcmp(parts[k], argv[1]) != 0; k++)
		;
	if (k == nitems(parts) && strcmp(argv[1], "probes") != 0)
		usage();
	snprintf(what, sizeof(what), "sdwan %s", argv[1]);
	ytold_begin(conn);
	same = false;
	if ((k == nitems(parts) ? yprobes_edit(conn, json_arg(argv[2]),
	    err, sizeof(err), &esid, tag, sizeof(tag)) : ysdwan_edit(conn,
	    argv[1], json_arg(argv[2]), &same, err, sizeof(err), &esid, tag,
	    sizeof(tag))) != 0) {
		ytold_end(true);
		refused(what, err, tag);
	}
	/* The same as running has: set again, what is not running
	 * started. */
	if (same) {
		error = ysdwan_apply(conn, argv[1], json_arg(argv[2]), err,
		    sizeof(err));
		ytold_end(true);
		if (error != 0)
			refused(what, err, "");
		snprintf(what, sizeof(what), "sdwan-%s", argv[1]);
		return (json_out(what, true, NULL, NULL, NULL, 0));
	}
	memset(&cin, 0, sizeof(cin));
	if (netconf_try(conn, "commit", &cin, err, sizeof(err), tag,
	    sizeof(tag)) != 0) {
		memset(&din, 0, sizeof(din));
		(void)netconf_try(conn, "discard-changes", &din, NULL, 0, NULL,
		    0);
		ytold_end(true);
		refused(what, err, tag);
	}
	ytold_end(true);
	snprintf(what, sizeof(what), "sdwan-%s", argv[1]);
	return (json_out(what, true, NULL, NULL, NULL, 0));
}


/* traceroute address: arcana-troubleshoot's traceroute. */
static int
cmd_traceroute(cbl_conn *conn, int argc, char **argv)
{
	ucl_object_t	*data;
	char		 err[256];
	int		 error;

	if (argc != 2)
		usage();
	ytold_begin(conn);
	error = yts_traceroute(conn, argv[1], &data, err, sizeof(err));
	return (ydata_out("traceroute", error, data, err));
}

static int
cmd_interface(cbl_conn *conn, int argc, char **argv)
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
		return (cmd_bird_config(conn, argc - 1, argv + 1));
	if (strcmp(argv[0], "bird") == 0 && strcmp(argv[1], "routes") == 0)
		return (cmd_bird_routes(conn, argc - 2, argv + 2));
	if (strcmp(argv[0], "bird") == 0 && strcmp(argv[1], "ospf") == 0)
		return (cmd_bird_ospf(conn, argc - 2, argv + 2));
	if (strcmp(argv[0], "bird") == 0 && strcmp(argv[1], "confirm") == 0 &&
	    argc == 3)
		return (cmd_bird_confirm(conn, argv[2]));
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
		return (cmd_route_get(conn, argc, argv));
	if (strcmp(argv[0], "route") == 0) {
		/*
		 * route [keep] add destination gateway | delete destination
		 * [gw]; keep: in rc.conf alone, the kernel's table as it is.
		 */
		sp.kind = ARC_JOB_KIND_ROUTE;
		if (strcmp(argv[1], "keep") == 0) {
			if (argc < 4)
				usage();
			sp.verb = "keep";
			sp.persist = true;
			argc--;
			argv++;
		}
		sp.has_fib = fib != 0;
		sp.fib = fib;
		sp.remove = strcmp(argv[1], "delete") == 0;
		if (!sp.remove && (strcmp(argv[1], "add") != 0 || argc < 4))
			usage();
		if (strcmp(argv[1], "add") != 0 && strcmp(argv[1], "delete") !=
		    0)
			usage();
		sp.destination = argv[2];
		/* Then the gateway, and words with what follows each. */
		i = 3;
		if (i < argc && strcmp(argv[i], "metric") != 0 && strcmp(
		    argv[i], "weight") != 0 && strcmp(argv[i], "source") != 0 &&
		    strcmp(argv[i], "name") != 0)
			sp.gateway = argv[i++];
		for (; i + 1 < argc; i += 2) {
			if (strcmp(argv[i], "source") == 0) {
				sp.source = argv[i + 1];
				continue;
			}
			if (strcmp(argv[i], "name") == 0) {
				/* What rc.conf keeps it by: route_<name>. */
				sp.names.v = (const char *const *)(uintptr_t)
				    &argv[i + 1];
				sp.names.n = 1;
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
		/* keep add destination name word: the kept one renamed. */
		if (i != argc || (!sp.remove && sp.gateway == NULL &&
		    (sp.verb == NULL || sp.names.n == 0)))
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
	return (submit(conn, &sp));
}

/* The routes, connections or sockets in parts: where the stream is. */
struct nparts {
	bool	 opened, done;
	int	 error;
	char	 why[256];
};

static void
np_open(cbl_stream *s, cbl_msg *accept, int error, void *arg)
{
	struct nparts	*x = arg;

	(void)s;
	x->opened = true;
	x->error = error;
	if (error != 0) {
		x->done = true;
		if (accept != NULL && cbl_msg_err_str(accept) != NULL)
			strlcpy(x->why, cbl_msg_err_str(accept), sizeof(x->why));
	}
}

/* A part: its rows, as arcana-network's network-part has them. */
static void
np_data(cbl_stream *s, cbl_msg *data, void *arg)
{
	struct arcana_network_network_part	 d;
	struct cbl_ybuf				 b = { NULL, 0, 0 };
	const struct cbl_ynode			*n;
	cbl_yarena				*a;

	(void)arg;
	memset(&d, 0, sizeof(d));
	if ((n = ytop_any("network-part")) == NULL || (a = cbl_yarena_new()) ==
	    NULL)
		return;
	if (arcana_network_network_part_parse(data, &d, a, CBL_YD_STRICT, NULL,
	    0) != 0) {
		cbl_yarena_free(a);
		(void)cbl_stream_reset(s, EBADMSG);
		return;
	}
	if (cbl_yjson(n, &d, &b) == 0)
		xo_emit("{:json/%.*s}\n", (int)b.len, (const char *)b.p);
	cbl_ybuf_free(&b);
	cbl_yarena_free(a);
}

static void
np_hclose(cbl_stream *s, void *arg)
{
	struct nparts	*x = arg;

	x->done = true;
	(void)cbl_stream_close(s, 0, NULL);
}

static void
np_close(cbl_stream *s, int code, const char *text, void *arg)
{
	struct nparts	*x = arg;

	(void)s;
	x->done = true;
	if (code != 0) {
		x->error = code;
		strlcpy(x->why, text != NULL && text[0] != '\0' ? text :
		    strerror(code), sizeof(x->why));
	}
}

static const struct cbl_stream_cbs np_cbs = {
	.on_open = np_open,
	.on_data = np_data,
	.on_hclose = np_hclose,
	.on_close = np_close,
};

/* The arcana-parts family's network-parts stream, each part printed. */
static int
net_parts(cbl_conn *conn, int kind, int family, const char *filter)
{
	struct arcana_network_network_part	 rq;
	struct nparts				 x;
	cbl_family_info				*info;
	cbl_stream				*s;
	cbl_msg					*m;
	int					 error;

	memset(&rq, 0, sizeof(rq));
	rq.has_kind = true;
	rq.kind = kind == ARC_NET_KIND_CONNECTIONS ?
	    ARCANA_NETWORK_NETWORK_PART_KIND_CONNECTIONS : kind ==
	    ARC_NET_KIND_SOCKETS ? ARCANA_NETWORK_NETWORK_PART_KIND_SOCKETS :
	    ARCANA_NETWORK_NETWORK_PART_KIND_ROUTES;
	rq.has_family = true;
	rq.family = family;
	rq.has_fib = fib != 0;
	rq.fib = fib;
	rq.jail = netjail;
	rq.filter = filter;
	memset(&x, 0, sizeof(x));
	if ((error = cbl_resolve(conn, "arcana-parts", &info)) != 0)
		xo_errx(1, "net: the host has no arcana-parts family: %s",
		    strerror(error));
	error = cbl_msg_new(cbl_conn_ctx(conn), cbl_family_info_id(info),
	    1, CBL_F_REQUEST | CBL_F_S_OPEN, &m);
	cbl_family_info_free(info);
	if (error == 0)
		error = arcana_network_network_part_put(m, &rq);
	if (error == 0)
		error = cbl_msg_set_window(m, 2 * 1024 * 1024);
	if (error != 0 || (error = cbl_stream_open(conn, m, 0, &np_cbs,
	    &x, &s)) != 0)
		xo_errx(1, "net: %s", strerror(error));
	sxf_run(conn, "net", &x.done);
	if (x.error != 0) {
		xo_warnx("net: %s", x.why[0] != '\0' ? x.why :
		    strerror(x.error));
		return (1);
	}
	return (0);
}

/*
 * The firewall, arcana-firewall's, as the operational datastore has it:
 * the host's, or the vnet jail's (-j) by arcana-jails.
 */
static int
net_ipfw(cbl_conn *conn)
{
	struct cbl_ybuf			 b = { NULL, 0, 0 };
	const struct cbl_ynode		*n, *fn;
	const void			*f = NULL;
	struct arcana_firewall		 fd;
	cbl_yarena			*a;

	if ((a = cbl_yarena_new()) == NULL)
		xo_err(1, "net ipfw");
	if (netjail == NULL) {
		if ((n = ytop_named("firewall")) == NULL)
			xo_errx(1, "net ipfw: arcana-firewall is not in the "
			    "tables");
		memset(&fd, 0, sizeof(fd));
		yget_data(conn, n, CBL_YDS_OPERATIONAL, &fd, a);
		f = fd.firewall;
		fn = n;
	} else {
		/* A vnet jail's: arcana-network's ipfw action. */
		struct arcana_network_network_ipfw_input in = { 0 };

		cbl_yarena_free(a);
		in.jail = netjail;
		return (yplug_read(conn, "network", "ipfw", &in, "net ipfw"));
	}
	if (f == NULL)
		xo_errx(1, "net ipfw: the host told of no firewall there");
	if (cbl_yjson(fn, f, &b) != 0)
		xo_errx(1, "net ipfw: not written as JSON");
	xo_emit("{:json/%.*s}\n", (int)b.len, (const char *)b.p);
	cbl_ybuf_free(&b);
	cbl_yarena_free(a);
	return (0);
}

/*
 * The routes, arcana-network's routes action, said when the table has
 * more than was sent.
 */
static int
net_routes(cbl_conn *conn,
    const struct arcana_network_network_routes_input *in)
{
	struct arcana_network_network_routes_output	 out;
	struct cbl_ybuf					 b = { NULL, 0, 0 };
	const struct cbl_ynode				*n, *an;
	cbl_yarena					*a;
	char						 why[512];
	int						 error;

	if ((n = ytop_named("network")) == NULL || (an = ychild(n,
	    "routes")) == NULL || (an = ychild(an, "output")) == NULL)
		xo_errx(1, "net routes: arcana-network is not in the tables");
	if ((a = cbl_yarena_new()) == NULL)
		xo_err(1, "net routes");
	memset(&out, 0, sizeof(out));
	ytold_begin(conn);
	error = ycall(conn, n, NULL, 0, "routes", in, &out, a, why,
	    sizeof(why));
	ytold_end(true);
	if (error == 0 && (error = cbl_yjson(an, &out, &b)) != 0)
		(void)snprintf(why, sizeof(why), "%s", strerror(error));
	if (error == 0) {
		xo_emit("{:json/%.*s}\n", (int)b.len, (const char *)b.p);
		if (out.truncated)
			xo_warnx("net routes: the table has %ju rows, more "
			    "than a reply carries: these are the first; give "
			    "a text to search for, or -o to read on",
			    (uintmax_t)out.total);
	} else
		xo_warnx("net routes: %s", why);
	cbl_ybuf_free(&b);
	cbl_yarena_free(a);
	return (error == 0 ? 0 : 1);
}

/*
 * net kind [-4 | -6] [-o n] [text] [parts [text]]: a table of the
 * host's (or of the vnet jail -j names), arcana-network's read action
 * of the kind as RFC 7951's JSON; netgraph, wireguard and bird their
 * modules'; ipfw arcana-firewall's (get firewall).
 */
static int
cmd_net(cbl_conn *conn, int argc, char **argv)
{
	static const char *kinds[] = { "routes", "nexthops", "connections",
	    "sockets", "interfaces", "netgraph", "wireguard", "bird",
	    "bird-routes", "bridges", "geneve", "ipfw", "nhgroups",
	    "neighbours", "ipsec", "multicast", "bird-ospf", "kept-routes" };
	const char	*filter;
	size_t		 i;
	uint32_t	 offset;
	int		 ch, family;

	if (argc < 2)
		usage();
	for (i = 0; i < nitems(kinds); i++)
		if (strcmp(argv[1], kinds[i]) == 0)
			break;
	if (i == nitems(kinds))
		usage();
	/* Those of a plugin: its module's read action (Y-3). */
	if (i == ARC_NET_KIND_NETGRAPH) {
		struct arcana_netgraph_netgraph_read_input in = { 0 };

		if (argc != 2)
			usage();
		in.jail = netjail;
		return (yplug_read(conn, kinds[i], "read", &in,
		    "net netgraph"));
	}
	if (i == ARC_NET_KIND_WIREGUARD) {
		struct arcana_wireguard_wireguard_read_input in = { 0 };

		if (argc != 2)
			usage();
		in.jail = netjail;
		return (yplug_read(conn, kinds[i], "read", &in,
		    "net wireguard"));
	}
	if (i == ARC_NET_KIND_BIRD) {
		struct arcana_bird_bird_read_input in = { 0 };

		if (argc != 2)
			usage();
		in.jail = netjail;
		return (yplug_read(conn, kinds[i], "read", &in, "net bird"));
	}
	if (i == ARC_NET_KIND_BIRD_ROUTES)
		return (cmd_bird_routes(conn, argc - 2, argv + 2));
	if (i == ARC_NET_KIND_BIRD_OSPF)
		return (cmd_bird_ospf(conn, argc - 2, argv + 2));
	if (i == ARC_NET_KIND_IPFW) {
		if (argc != 2)
			usage();
		return (net_ipfw(conn));
	}
	family = 0;
	offset = 0;
	argc--;
	argv++;
	optind = 1;
	while ((ch = getopt(argc, argv, "46o:")) != -1) {
		switch (ch) {
		case 'o':
			/* Read on, after this many rows. */
			offset = (uint32_t)strtoul(optarg, NULL, 10);
			break;
		case '4':
			family = 1;
			break;
		case '6':
			family = 2;
			break;
		default:
			usage();
		}
	}
	/* In parts, each printed as it comes: nothing left out for size. */
	if (optind < argc && strcmp(argv[optind], "parts") == 0) {
		if (i != ARC_NET_KIND_ROUTES && i != ARC_NET_KIND_CONNECTIONS &&
		    i != ARC_NET_KIND_SOCKETS)
			xo_errx(1, "net %s: the routes, connections and sockets "
			    "come in parts; the rest whole", kinds[i]);
		return (net_parts(conn, (int)i, family, optind + 1 < argc ?
		    argv[optind + 1] : NULL));
	}
	filter = NULL;
	/* A text to search the routes or the neighbours for. */
	if (argc - optind == 1 && (i == ARC_NET_KIND_ROUTES ||
	    i == ARC_NET_KIND_NEIGHBOURS))
		filter = argv[optind];
	else if (optind != argc)
		usage();
	switch (i) {
	case ARC_NET_KIND_ROUTES: {
		struct arcana_network_network_routes_input in = { 0 };

		in.jail = netjail;
		in.has_family = true;
		in.family = family;
		in.filter = filter;
		in.has_fib = fib != 0;
		in.fib = fib;
		in.has_offset = offset != 0;
		in.offset = offset;
		return (net_routes(conn, &in));
	}
	case ARC_NET_KIND_NEXTHOPS:
	case ARC_NET_KIND_NHGROUPS: {
		struct arcana_network_network_nexthops_input in = { 0 };

		in.jail = netjail;
		in.has_family = true;
		in.family = family;
		in.has_fib = fib != 0;
		in.fib = fib;
		return (yplug_read(conn, "network", kinds[i], &in, kinds[i]));
	}
	case ARC_NET_KIND_NEIGHBOURS: {
		struct arcana_network_network_neighbours_input in = { 0 };

		in.jail = netjail;
		in.has_family = true;
		in.family = family;
		in.filter = filter;
		return (yplug_read(conn, "network", "neighbours", &in,
		    "net neighbours"));
	}
	case ARC_NET_KIND_CONNECTIONS:
	case ARC_NET_KIND_SOCKETS:
	case ARC_NET_KIND_INTERFACES: {
		/* The three inputs have one layout: a jail, a family. */
		struct arcana_network_network_connections_input in = { 0 };

		in.jail = netjail;
		in.has_family = true;
		in.family = family;
		return (yplug_read(conn, "network", kinds[i], &in, kinds[i]));
	}
	default: {
		/* A jail alone: bridges, geneve, ipsec, multicast,
		 * kept-routes. */
		struct arcana_network_network_bridges_input in = { 0 };

		in.jail = netjail;
		return (yplug_read(conn, "network", kinds[i], &in, kinds[i]));
	}
	}
}

/*
 * kmod: the kernel's modules and its memory, as the host says them.
 * kmod load | unload module: a job; with -p also in rc.conf's kld_list.
 * kmod keep | forget module: rc.conf's kld_list alone, the kernel as is.
 */
/* ntp server...; ntp remove: the NTP servers of the host. */
static int
cmd_ntp(cbl_conn *conn, int argc, char **argv)
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
	return (submit(conn, &sp));
}

/*
 * ipsec-sa set|clear interface reqid local remote [words]: manually
 * keyed SAs of an ipsec(4) interface; the words as the job takes them.
 */
static int
cmd_ipsec_sa(cbl_conn *conn, int argc, char **argv)
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
		return (submit(conn, &sp));
	}
	sp.has_reqid = true;
	sp.reqid = (uint32_t)strtonum(argv[3], 1, 16383, &errstr);
	if (errstr != NULL)
		xo_errx(2, "reqid %s: %s", argv[3], errstr);
	sp.tunnel_local = argv[4];
	sp.tunnel_remote = argv[5];
	sp.names.v = (const char **)(uintptr_t)&argv[6];
	sp.names.n = (size_t)argc - 6;
	return (submit(conn, &sp));
}

/*
 * rtadvd interface prefix [dns ...]; rtadvd interface remove: router
 * advertisements on an interface, for SLAAC.
 */
static int
cmd_rtadvd(cbl_conn *conn, int argc, char **argv)
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
	return (submit(conn, &sp));
}

/*
 * A jail's permissions: its allow.* parameters set on the running jail
 * and, with -p, in its file; -n leaves the running jail alone (the
 * file for the next start).
 */
static int
cmd_allow(cbl_conn *conn, int argc, char **argv)
{
	struct arc_job_spec	sp;
	bool			live;

	live = true;
	if (argc > 1 && strcmp(argv[1], "-n") == 0) {
		live = false;
		argc--;
		argv++;
	}
	if (argc < 3)
		usage();
	memset(&sp, 0, sizeof(sp));
	sp.has_kind = true;
	sp.kind = ARC_JOB_KIND_JAIL_ALLOW;
	sp.jail = argv[1];
	sp.live = live;
	sp.persist = persist;
	sp.names.v = (const char **)(uintptr_t)&argv[2];
	sp.names.n = (size_t)argc - 2;
	return (submit(conn, &sp));
}

/* A file's whole content, "-" standard input; exits on failure. */
static char *
slurp(const char *path)
{
	FILE	*fp;
	char	*buf;
	size_t	 len, cap, n;

	if ((fp = strcmp(path, "-") == 0 ? stdin : fileargs_fopen(files, path,
	    "r")) == NULL)
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
cmd_neigh(cbl_conn *conn, int argc, char **argv)
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
	return (submit(conn, &sp));
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
cmd_carp(cbl_conn *conn, int argc, char **argv)
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
	i = submit(conn, &sp);
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
cmd_zfskey(cbl_conn *conn, int argc, char **argv)
{
	char			 key[513], nkey[513], again[513], err[512];
	const char		*k, *nk;
	bool			 change;
	int			 error;

	change = argc == 3 && strcmp(argv[1], "-n") == 0;
	if (argc != 2 && !change)
		usage();
	nk = NULL;
	if (key_read(change ? "Key now (empty when it is loaded): " : "Key: ",
	    key, sizeof(key)) == NULL)
		errx(1, "no key");
	k = key[0] != '\0' ? key : NULL;
	if (change) {
		if (key_read("New key: ", nkey, sizeof(nkey)) == NULL)
			errx(1, "no new key");
		if (isatty(STDIN_FILENO)) {
			if (key_read("New key, again: ", again, sizeof(again)) ==
			    NULL || strcmp(again, nkey) != 0)
				errx(1, "the new keys differ");
			explicit_bzero(again, sizeof(again));
		}
		nk = nkey;
	}
	/* arcana-storage's load-key and change-key. */
	error = ystore_key(conn, argv[argc - 1], k, nk, NULL, err,
	    sizeof(err));
	explicit_bzero(key, sizeof(key));
	if (change)
		explicit_bzero(nkey, sizeof(nkey));
	if (error != 0)
		warnx("%s", err);
	return (error != 0 ? 1 : 0);
}

/*
 * tls [status] | csr | install certfile|- [cafile]: the agent's own TLS
 * files: what they are, a new key and a request for it (the key stays
 * there), and a certificate for that key with the CAs to trust, or the
 * CAs alone.  Over TLS, -C is the certificate the agent checks it still
 * trusts afterwards.
 */
static int
cmd_tls(cbl_conn *conn, int argc, char **argv, const char *mine)
{
	ucl_object_t	*data;
	const char	*verb, *cert, *ca, *peer;
	char		 err[512];
	int		 error;

	cert = ca = peer = NULL;
	if (argc == 1 || (argc == 2 && strcmp(argv[1], "status") == 0))
		verb = "status";
	else if (argc == 2 && strcmp(argv[1], "csr") == 0)
		verb = "csr";
	else if ((argc == 3 || argc == 4) && strcmp(argv[1], "install") == 0) {
		verb = "install";
		cert = strcmp(argv[2], "-") == 0 ? NULL : slurp(argv[2]);
		ca = argc == 4 ? slurp(argv[3]) : NULL;
		peer = mine != NULL ? slurp(mine) : NULL;
	} else
		usage();
	/* arcana-agent's tls: its state, csr or install. */
	ytold_begin(conn);
	error = yh_tls(conn, verb, cert, ca, peer, &data, err,
	    sizeof(err));
	return (ydata_out("tls", error, data, err));
}

/*
 * capture [source packets seconds [filter ...]]: packets taken with
 * tcpdump off an interface or a tap, of the host or of -j's jail; with
 * nothing, the sources there are.
 */
static int
cmd_capture(cbl_conn *conn, int argc, char **argv)
{
	ucl_object_t		*data;
	const char		*errstr, *source;
	char			*f, ebuf[256];
	size_t			 len;
	uint32_t		 packets, seconds;
	int			 i, error;

	/* arcana-troubleshoot's capture. */
	source = NULL;
	packets = seconds = 0;
	f = NULL;
	if (argc != 1) {
		if (argc < 4)
			usage();
		source = argv[1];
		packets = (uint32_t)strtonum(argv[2], 1, 500, &errstr);
		if (errstr != NULL)
			errx(2, "packets %s: %s", argv[2], errstr);
		seconds = (uint32_t)strtonum(argv[3], 1, 60, &errstr);
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
	}
	ytold_begin(conn);
	error = yts_capture(conn, netjail, source, f, seconds, packets,
	    &data, ebuf, sizeof(ebuf));
	free(f);
	return (ydata_out("capture", error, data, ebuf));
}

/*
 * sshd [list] | banner file | set Setting [value ...] | authorize user
 * keyfile | unauthorize user fingerprint | options user fingerprint
 * [options] | sign ca-key-file [principal ...] | user-cas file: the base
 * system's sshd, of the host or of -j's jail; a change is a job, and
 * with -s undone unless confirmed.
 */
static int
cmd_sshd(cbl_conn *conn, int argc, char **argv)
{
	struct arc_job_spec	 sp;
	ucl_object_t		*data;
	char			 ebuf[256];
	char			*t;
	int			 error;

	if (argc == 1 || (argc == 2 && strcmp(argv[1], "list") == 0)) {
		/* arcana-sshd's read. */
		ytold_begin(conn);
		error = yr_sshd(conn, netjail, &data, ebuf, sizeof(ebuf));
		return (ydata_out("sshd", error, data, ebuf));
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
	return (submit(conn, &sp));
}

/*
 * poudriere [list] | show-options key=value ... | make-conf name|- file|- |
 * verb [key=value ...]: poudriere(8), the host's package builder;
 * show-options reads a port's (jail= ports= set= origin=); a verb is a
 * job, which for a build, a jail or a ports tree made or updated starts
 * a run and ends (see list's runs).
 */
static int
cmd_poudriere(cbl_conn *conn, int argc, char **argv)
{
	struct arc_job_spec	 sp;
	ucl_object_t		*data;
	char			 ebuf[256];
	char			*nm;
	int			 error;

	if (argc == 1 || (argc == 2 && strcmp(argv[1], "list") == 0)) {
		/* A GET of arcana-builder. */
		error = yr_builder(conn, &data, ebuf, sizeof(ebuf));
		return (ydata_out("poudriere", error, data, ebuf));
	}
	if (strcmp(argv[1], "show-options") == 0) {
		/* arcana-builder's port-options. */
		ytold_begin(conn);
		error = yr_port_options(conn, (const char *const *)&argv[2],
		    (size_t)argc - 2, &data, ebuf, sizeof(ebuf));
		return (ydata_out("show-options", error, data, ebuf));
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
	return (submit(conn, &sp));
}

/* crashes [backtrace core [program]]: the cores dumped, and one's
 * backtrace. */
static int
cmd_crashes(cbl_conn *conn, int argc, char **argv)
{
	ucl_object_t	*data;
	char		 ebuf[256];
	int		 error;

	if (argc > 1 && (strcmp(argv[1], "backtrace") != 0 || argc < 3 ||
	    argc > 4))
		usage();
	/* arcana-crashes' read. */
	ytold_begin(conn);
	error = yr_crashes(conn, (const char *const *)&argv[1],
	    (size_t)argc - 1, &data, ebuf, sizeof(ebuf));
	return (ydata_out("crashes", error, data, ebuf));
}

/* reboot: the host, by shutdown(8) a minute from now; a job. */
static int
cmd_reboot(cbl_conn *conn)
{
	struct arc_job_spec	 sp;

	if (netjail != NULL)
		xo_errx(2, "a jail is restarted (restart jail), not rebooted");
	memset(&sp, 0, sizeof(sp));
	sp.has_kind = true;
	sp.kind = ARC_JOB_KIND_REBOOT;
	sp.safe = safe;		/* refused by the host, which says why */
	return (submit(conn, &sp));
}

/* system [file | host]: the system's own files, and settings beside. */
static int
cmd_system(cbl_conn *conn, int argc, char **argv)
{
	ucl_object_t	*data;
	char		 ebuf[256];
	int		 error;

	if (argc > 2)
		usage();
	/* arcana-system's read. */
	ytold_begin(conn);
	error = yr_system(conn, (const char *const *)&argv[1],
	    (size_t)argc - 1, &data, ebuf, sizeof(ebuf));
	return (ydata_out("system", error, data, ebuf));
}

/* geom class subcommand [word ...] [-P passfile]: geom(8), a job; a
 * GELI passphrase read from passfile. */
static int
cmd_geom(cbl_conn *conn, int argc, char **argv)
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
	return (submit(conn, &sp));
}

/* sysfile file path | periodic name=YES|NO ... | dma key=value ...: a
 * file of the system's written from path, periodic.conf's variables, or
 * dma's smart host (its password from ARCANA_DMA_PASSWORD); a job. */
static int
cmd_sysfile(cbl_conn *conn, int argc, char **argv)
{
	struct arc_job_spec	 sp;

	if (argc < 3)
		usage();
	memset(&sp, 0, sizeof(sp));
	sp.has_kind = true;
	sp.kind = ARC_JOB_KIND_SYSFILE;
	sp.verb = argv[1];
	if (strcmp(argv[1], "periodic") == 0 || strcmp(argv[1], "rc") == 0 ||
	    strcmp(argv[1], "dma") == 0) {
		sp.names.v = (const char **)(uintptr_t)&argv[2];
		sp.names.n = (size_t)argc - 2;
		/* dma's password from the environment: on no command line. */
		if (strcmp(argv[1], "dma") == 0)
			sp.text = getenv("ARCANA_DMA_PASSWORD");
	} else {
		if (argc != 3)
			usage();
		sp.text = slurp(argv[2]);
	}
	sp.jail = netjail;
	return (submit(conn, &sp));
}

/* smtpd: OpenSMTPD on the host, whole; with words, a job of it. */
static int
cmd_smtpd(cbl_conn *conn, int argc, char **argv)
{
	struct arc_job_spec	 sp;
	ucl_object_t		*data;
	char			 ebuf[256];
	char			*w[1];
	int			 error;

	if (argc == 1) {
		/* arcana-smtpd's read. */
		ytold_begin(conn);
		error = yr_smtpd(conn, netjail, &data, ebuf, sizeof(ebuf));
		return (ydata_out("smtpd", error, data, ebuf));
	}
	memset(&sp, 0, sizeof(sp));
	sp.has_kind = true;
	sp.kind = ARC_JOB_KIND_SMTPD;
	sp.verb = argv[1];
	if (strcmp(argv[1], "conf") == 0) {
		/* conf form.json [replace]: replace says the admin's own
		 * smtpd.conf is to be replaced by the form. */
		if (argc != 3 && !(argc == 4 && strcmp(argv[3], "replace") == 0))
			usage();
		sp.text = slurp(argv[2]);
		sp.force = argc == 4;
	} else if (strcmp(argv[1], "conf-text") == 0) {
		/* conf-text [check] file: the admin's smtpd.conf as text. */
		if (argc == 4 && strcmp(argv[2], "check") == 0) {
			sp.names.v = (const char **)(uintptr_t)&argv[2];
			sp.names.n = 1;
			sp.text = slurp(argv[3]);
		} else if (argc == 3)
			sp.text = slurp(argv[2]);
		else
			usage();
	} else if (strcmp(argv[1], "table") == 0 || strcmp(argv[1], "entry") ==
	    0) {
		if (argc != 4)
			usage();
		sp.names.v = (const char **)(uintptr_t)&argv[2];
		sp.names.n = 1;
		sp.text = slurp(argv[3]);
	} else if (strcmp(argv[1], "unentry") == 0) {
		/* A table's name and an entry's key. */
		if (argc != 4)
			usage();
		sp.names.v = (const char **)(uintptr_t)&argv[2];
		sp.names.n = 2;
	} else if (strcmp(argv[1], "enable") == 0) {
		if (argc != 3 || asprintf(&w[0], "enable=%s", argv[2]) == -1)
			usage();
		sp.names.v = (const char **)(uintptr_t)w;
		sp.names.n = 1;
	} else {
		if (argc != 3)
			usage();
		sp.names.v = (const char **)(uintptr_t)&argv[2];
		sp.names.n = 1;
	}
	sp.jail = netjail;
	return (submit(conn, &sp));
}

/* monitor: the tunnels measured outside SD-WAN; with words, a job. */
static int
cmd_monitor(cbl_conn *conn, int argc, char **argv)
{
	struct arc_job_spec	 sp;
	ucl_object_t		*data;
	char			 ebuf[256];
	int			 error;

	if (argc == 1) {
		/* arcana-probe's read of the monitors. */
		ytold_begin(conn);
		error = ysdwan_monitors(conn, false, 0, &data, ebuf,
		    sizeof(ebuf));
		return (ydata_out("monitors", error, data, ebuf));
	}
	memset(&sp, 0, sizeof(sp));
	sp.has_kind = true;
	sp.kind = ARC_JOB_KIND_MONITOR;
	sp.verb = argv[1];
	sp.names.v = (const char **)(uintptr_t)&argv[2];
	sp.names.n = (size_t)(argc - 2);
	sp.jail = netjail;
	return (submit(conn, &sp));
}

/* speeder: UDPspeeder's FEC relay, read; with words, a job of it. */
static int
cmd_speeder(cbl_conn *conn, int argc, char **argv)
{
	struct arc_job_spec	 sp;
	ucl_object_t		*data;
	char			 ebuf[256];
	int			 error;

	if (argc == 1) {
		/* arcana-speeder's read. */
		ytold_begin(conn);
		error = yr_speeder(conn, netjail, &data, ebuf, sizeof(ebuf));
		return (ydata_out("speeder", error, data, ebuf));
	}
	memset(&sp, 0, sizeof(sp));
	sp.has_kind = true;
	sp.kind = ARC_JOB_KIND_SPEEDER;
	sp.verb = argv[1];
	/* conf's name=value words, fec's ratios: the agent checks them. */
	sp.names.v = (const char **)(uintptr_t)&argv[2];
	sp.names.n = (size_t)(argc - 2);
	sp.jail = netjail;
	sp.safe = safe;
	return (submit(conn, &sp));
}

/* netstore [nfs | iscsi | hast]: the host's storage services. */
static int
cmd_netstore(cbl_conn *conn, int argc, char **argv)
{
	ucl_object_t	*data;
	char		 ebuf[256];
	int		 error;

	if (argc > 2)
		usage();
	/* arcana-netstore's read. */
	ytold_begin(conn);
	error = yr_netstore(conn, (const char *const *)&argv[1],
	    (size_t)argc - 1, &data, ebuf, sizeof(ebuf));
	return (ydata_out("netstore", error, data, ebuf));
}

/*
 * nfs exports file | server key=value ...; iscsi conf file | enable
 * yes|no; hast conf file | enable yes|no | create resource | role role
 * resource: the storage services changed, a job each.
 */
static int
cmd_netstore_job(cbl_conn *conn, int argc, char **argv, int kind)
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
	return (submit(conn, &sp));
}

/*
 * clamav mirrors mirror ...: freshclam.conf's DatabaseMirror lines, in
 * place of those there were; a job.
 */
static int
cmd_clamav(cbl_conn *conn, int argc, char **argv)
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
	return (submit(conn, &sp));
}

/* What a capture's stream or a pcap-log file's has come to. */
struct sxfer {
	bool	 opened, hclosed, closed;
	int	 error, code;
	char	 why[256];
	char	 json[1100];
	int64_t	 bytes;
};

static void
sxf_open(cbl_stream *s, cbl_msg *accept, int error, void *arg)
{
	struct arcana_stream_opened	 o;
	struct sxfer			*x = arg;
	cbl_yarena			*a;

	(void)s;
	x->opened = true;
	x->error = error;
	if (error != 0) {
		if (accept != NULL && cbl_msg_err_str(accept) != NULL)
			strlcpy(x->why, cbl_msg_err_str(accept), sizeof(x->why));
		return;
	}
	/* Both replies are ok and json: either reads them. */
	if (accept != NULL && (a = cbl_yarena_new()) != NULL) {
		if (ys_opened(accept, &o, a) == 0 && o.json != NULL)
			strlcpy(x->json, o.json, sizeof(x->json));
		cbl_yarena_free(a);
	}
}

/* A pcap-log file's next bytes, to the standard output. */
static void
sxf_data(cbl_stream *s, cbl_msg *data, void *arg)
{
	struct sxfer			*x = arg;
	struct arcana_stream_chunk	 d;
	cbl_yarena			*a;
	size_t				 off;
	ssize_t				 n;

	if ((a = cbl_yarena_new()) == NULL || ys_chunk(data, &d, a) != 0) {
		if (a != NULL)
			cbl_yarena_free(a);
		(void)cbl_stream_reset(s, EBADMSG);
		return;
	}
	for (off = 0; off < d.data.len; off += (size_t)n)
		if ((n = write(STDOUT_FILENO, (const char *)d.data.p + off,
		    d.data.len - off)) <= 0) {
			cbl_yarena_free(a);
			(void)cbl_stream_reset(s, EPIPE);
			return;
		}
	x->bytes += (int64_t)d.data.len;
	cbl_yarena_free(a);
}

static void
sxf_hclose(cbl_stream *s, void *arg)
{
	struct sxfer	*x = arg;

	x->hclosed = true;
	(void)cbl_stream_close(s, 0, NULL);
}

static void
sxf_close(cbl_stream *s, int code, const char *text, void *arg)
{
	struct sxfer	*x = arg;

	(void)s;
	x->closed = true;
	x->code = code;
	if (code != 0)
		strlcpy(x->why, text != NULL && text[0] != '\0' ? text :
		    strerror(code), sizeof(x->why));
}

static const struct cbl_stream_cbs sxf_cbs = {
	.on_open = sxf_open,
	.on_data = sxf_data,
	.on_hclose = sxf_hclose,
	.on_close = sxf_close,
};

/* The connection's next turn: what came read, what waits sent. */
static void
sxf_step(cbl_conn *conn, const char *what)
{
	struct pollfd	pfd;
	int		ev, ms, error;

	ev = 0;
	ms = -1;
	(void)cbl_conn_interest(conn, &ev, &ms);
	pfd.fd = cbl_conn_fd(conn);
	pfd.events = ((ev & CBL_EV_READ) != 0 ? POLLIN : 0) |
	    ((ev & CBL_EV_WRITE) != 0 ? POLLOUT : 0);
	pfd.revents = 0;
	if (poll(&pfd, 1, ms) == -1)
		return;
	ev = ((pfd.revents & (POLLIN | POLLHUP | POLLERR)) != 0 ?
	    CBL_EV_READ : 0) | ((pfd.revents & POLLOUT) != 0 ?
	    CBL_EV_WRITE : 0);
	if ((error = cbl_conn_process(conn, ev)) != 0)
		xo_errx(1, "%s: the host is gone: %s", what, strerror(error));
}

/* The connection run until done says so, or the host goes. */
static void
sxf_run(cbl_conn *conn, const char *what, const bool *done)
{

	while (!*done)
		sxf_step(conn, what);
}

/*
 * suricata pcap-put instance=name file=name [offset=N] [last=1]: the
 * standard input sent as a capture (or a part of one) for the
 * instance's replay, where it is kept said; suricata pcap-get
 * instance=name file=name: a file of the instance's pcap-log written to
 * the standard output.  Each a stream.
 */
static int
cmd_suricata_xfer(cbl_conn *conn, int argc, char **argv)
{
	struct arcana_stream_open	 rq;
	struct sxfer			 x;
	cbl_stream			*s;
	unsigned char			*buf;
	ssize_t				 n;
	bool				 put;
	int				 error;

	put = strcmp(argv[1], "pcap-put") == 0;
	memset(&x, 0, sizeof(x));
	n = 0;
	/* arcana-stream's suricata-pcap-put or -get. */
	memset(&rq, 0, sizeof(rq));
	rq.name.v = (const char *const *)&argv[2];
	rq.name.n = (size_t)argc - 2;
	if ((error = ys_open(conn, put ? YS_PCAP_PUT : YS_PCAP_GET, &rq,
	    YS_WINDOW, 0, &sxf_cbs, &x, &s)) != 0)
		xo_errx(1, "suricata %s: %s", argv[1], strerror(error));
	sxf_run(conn, argv[1], &x.opened);
	if (x.error != 0)
		xo_errx(1, "suricata %s: %s", argv[1], x.why[0] != '\0' ? x.why :
		    strerror(x.error));
	if (put) {
		if ((buf = malloc(256 * 1024)) == NULL)
			xo_err(1, "malloc");
		while (!x.closed && (n = read(STDIN_FILENO, buf, 256 * 1024)) >
		    0) {
			/* No room: the host's, given back as it writes. */
			while (!x.closed && (error = ys_send(s, buf,
			    (size_t)n)) == EAGAIN)
				sxf_step(conn, argv[1]);
			if (!x.closed && error != 0)
				xo_errx(1, "suricata %s: %s", argv[1],
				    strerror(error));
		}
		free(buf);
		if (n == -1)
			xo_err(1, "suricata %s: the standard input", argv[1]);
		if (!x.closed)
			(void)cbl_stream_half_close(s);
	}
	sxf_run(conn, argv[1], &x.closed);
	if (x.code != 0)
		xo_errx(1, "suricata %s: %s", argv[1], x.why);
	if (put)
		xo_emit("{:json/%s}\n", x.json);
	return (0);
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
cmd_suricata(cbl_conn *conn, int argc, char **argv)
{
	struct arc_job_spec	 sp;
	ucl_object_t		*data;
	char			 ebuf[256], *raw;
	int			 error;

	if (argc >= 2 && (strcmp(argv[1], "pcap-put") == 0 ||
	    strcmp(argv[1], "pcap-get") == 0))
		return (cmd_suricata_xfer(conn, argc, argv));
	if (argc >= 2 && strcmp(argv[1], "rules") == 0) {
		/* arcana-suricata's actions, as the words say. */
		ytold_begin(conn);
		error = yr_suricata(conn, (const char *const *)&argv[2],
		    (size_t)argc - 2, &data, &raw, ebuf, sizeof(ebuf));
		/* Suricata's own answer, as it wrote it. */
		if (raw != NULL) {
			xo_emit("{:json/%s}\n", raw);
			free(raw);
			if (data != NULL)
				ucl_object_unref(data);
			data = NULL;
		}
		return (ydata_out("suricata rules", error, data, ebuf));
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
	/* rule modify FILE: modify.conf's text. */
	if (strcmp(argv[1], "rule") == 0 && argc == 4 && strcmp(argv[2],
	    "modify") == 0) {
		sp.names.n = 1;
		sp.text = slurp(argv[3]);
	}
	sp.jail = netjail;
	return (submit(conn, &sp));
}

/*
 * cert [list] | add name file | remove name | trust file | untrust file |
 * rehash: the certificates OpenSSL trusts, of the host or of -j's jail;
 * a change is a job.
 */
static int
cmd_cert(cbl_conn *conn, int argc, char **argv)
{
	struct arc_job_spec	 sp;
	ucl_object_t		*data;
	char			 err[256];
	int			 error;

	if (argc == 1 || (argc == 2 && strcmp(argv[1], "list") == 0)) {
		/* arcana-host's read-certificates. */
		ytold_begin(conn);
		error = yh_certs(conn, netjail, &data, err, sizeof(err));
		return (ydata_out("certs", error, data, err));
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
	return (submit(conn, &sp));
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
cmd_jailconf(cbl_conn *conn, int argc, char **argv)
{
	struct arc_job_spec	 sp;
	ucl_object_t		*data;
	const char		*name;
	char			 err[256];
	int			 error;

	if (argc == 2 && strcmp(argv[1], "files") == 0) {
		/* arcana-jail-files' read-files. */
		ytold_begin(conn);
		error = yh_jail_files(conn, &data, err, sizeof(err));
		return (ydata_out("jail files", error, data, err));
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
	return (submit(conn, &sp));
}

/*
 * kmod: arcana-kernel, as get kernel has it.
 * kmod load | unload module: a job; with -p also in rc.conf's kld_list.
 * kmod keep | forget module: rc.conf's kld_list alone, the kernel as is.
 */
static int
cmd_kmod(cbl_conn *conn, int argc, char **argv)
{
	struct arc_job_spec	 sp;
	const char		*name;
	char			*get[] = { (char *)(uintptr_t)"get",
				    (char *)(uintptr_t)"kernel", NULL };

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
		return (submit(conn, &sp));
	}
	if (argc != 1)
		usage();
	return (cmd_get(conn, 2, get));
}

/*
 * arcana-sysctl's read action: the values whose names begin with
 * prefix, count of them (0: the agent's most) from the one after after,
 * printed as the output's JSON; *next the after of the next part, NULL
 * at the end.  With -j, a vnet jail's network's.
 */
static void
sysctl_read(cbl_conn *conn, const char *prefix, const char *after,
    uint16_t count, const char **next)
{
	const struct cbl_ynode			*n, *act, *in, *out;
	struct arcana_sysctl_sysctl_read_input	 i;
	struct arcana_sysctl_sysctl_read_output	 o;
	struct cbl_ybuf				 t = { NULL, 0, 0 }, b = { NULL, 0, 0 };
	cbl_msg					*req, *rep = NULL;
	cbl_yarena				*a;
	char					 why[256];
	int					 error;

	*next = NULL;
	if ((n = ytop_named("sysctl")) == NULL || (act = ychild(n, "read")) ==
	    NULL || (in = ychild(act, "input")) == NULL || (out = ychild(act,
	    "output")) == NULL)
		xo_errx(1, "sysctl: arcana-sysctl is not in the tables");
	if ((a = cbl_yarena_new()) == NULL)
		xo_err(1, "sysctl");
	memset(&i, 0, sizeof(i));
	i.prefix = prefix;
	i.after = after;
	i.has_count = count > 0;
	i.count = count;
	i.jail = netjail;
	if ((error = cbl_yiid_write(n, NULL, 0, &t)) != 0 ||
	    (error = cbl_msg_new(cbl_conn_ctx(conn), CBL_YANG_FAMILY,
	    CBL_YCMD_RPC, 0, &req)) != 0 ||
	    (error = cbl_msg_put_ynode(req, in, &i)) != 0 ||
	    (error = cbl_msg_put_yaction(req, t.p, t.len)) != 0)
		xo_errx(1, "sysctl: %s", strerror(error));
	if ((error = cbl_request(conn, req, &rep, -1)) != 0)
		xo_errx(1, "sysctl: %s", rep != NULL && cbl_msg_err_str(rep) !=
		    NULL ? cbl_msg_err_str(rep) : strerror(error));
	memset(&o, 0, sizeof(o));
	if ((error = cbl_msg_ydecode(rep, out, &o, a, 0, why, sizeof(why))) !=
	    0 && error != ENOENT)
		xo_errx(1, "sysctl: %s", why);
	if ((error = cbl_yjson(out, &o, &b)) != 0)
		xo_errx(1, "sysctl: %s", strerror(error));
	xo_emit("{:json/%.*s}\n", (int)b.len, b.p != NULL ? (const char *)
	    b.p : "{}");
	if (o.next != NULL && (*next = strdup(o.next)) == NULL)
		xo_err(1, "sysctl");
	cbl_ybuf_free(&b);
	cbl_ybuf_free(&t);
	cbl_yarena_free(a);
	cbl_msg_free(rep);
}

/*
 * sysctl [prefix]: the kernel's state, by arcana-sysctl's read action.
 * sysctl name=value: a job; with -p also in sysctl.conf.
 */
static int
cmd_sysctl(cbl_conn *conn, int argc, char **argv)
{
	struct arc_job_spec	 sp;
	const char		*names[2], *next, *after;
	char			*eq;

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
		return (submit(conn, &sp));
	}
	/* In parts, each printed as it comes: nothing left out for size. */
	if (argc >= 2 && strcmp(argv[1], "parts") == 0) {
		if (argc > 3)
			usage();
		after = NULL;
		do {
			sysctl_read(conn, argc == 3 ? argv[2] : NULL, after,
			    120, &next);
			free((void *)(uintptr_t)after);
			after = next;
		} while (after != NULL);
		return (0);
	}
	if (argc > 2)
		usage();
	sysctl_read(conn, argc == 2 ? argv[1] : NULL, NULL, 0, &next);
	if (next != NULL)
		xo_warnx("sysctl: the first part: go on after %s, or sysctl "
		    "parts", next);
	free((void *)(uintptr_t)next);
	return (0);
}

/* What a reply of JSON says, and how it went. */
static int
json_out(const char *what, bool ok, const char *error, const char *json,
    const struct arcana_jobs_step *steps, size_t nsteps)
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
/*
 * An event as it comes, arcana-events' notification as the events
 * reply has one: a line of its own, at once.
 */
static void
event_line(cbl_conn *conn, cbl_msg *msg, void *arg)
{
	ucl_object_t	*o;
	unsigned char	*json;

	(void)conn;
	(void)arg;
	if ((o = ygula_event_of(msg)) == NULL)
		return;
	if ((json = ucl_object_emit(o, UCL_EMIT_JSON_COMPACT)) != NULL) {
		printf("%s\n", (char *)json);
		fflush(stdout);
		free(json);
	}
	ucl_object_unref(o);
}

/*
 * The host's events as they happen, of family 1's group notify, until
 * the host goes or we are stopped: the connection is driven here,
 * nothing asked of it after.
 */
static int
follow_events(cbl_conn *conn)
{
	struct pollfd	 pfd;
	cbl_sub		*sub;
	int		 error, ev, ms;

	if ((error = cbl_subscribe(conn, "cblink.yang", "notify",
	    event_line, NULL, &sub)) != 0)
		fail(error, "events");
	for (;;) {
		ev = 0;
		ms = -1;
		(void)cbl_conn_interest(conn, &ev, &ms);
		pfd.fd = cbl_conn_fd(conn);
		pfd.events = ((ev & CBL_EV_READ) != 0 ? POLLIN : 0) |
		    ((ev & CBL_EV_WRITE) != 0 ? POLLOUT : 0);
		pfd.revents = 0;
		if (poll(&pfd, 1, ms) == -1)
			continue;
		ev = ((pfd.revents & (POLLIN | POLLHUP | POLLERR)) != 0 ?
		    CBL_EV_READ : 0) | ((pfd.revents & POLLOUT) != 0 ?
		    CBL_EV_WRITE : 0);
		if ((error = cbl_conn_process(conn, ev)) != 0)
			break;
	}
	xo_errx(1, "events: the host is gone: %s", strerror(error));
}

static int
cmd_gula(cbl_conn *conn, int argc, char **argv)
{
	struct arc_job_spec	 sp;
	uint64_t		 position;
	uint32_t		 lines;
	bool			 from;
	const char		*names[2], *e;
	ucl_object_t		*data;
	char			 err[256];
	uint32_t		 pid;
	int			 error, ch;

	if (strcmp(argv[0], "ps") == 0) {
		/* arcana-processes' list, or a process's read. */
		if (argc > 2)
			usage();
		pid = 0;
		if (argc == 2) {
			pid = (uint32_t)strtonum(argv[1], 1, 99999, &e);
			if (e != NULL)
				xo_errx(1, "ps: %s: %s", argv[1], e);
		}
		ytold_begin(conn);
		error = ygula_processes(conn, netjail, pid, &data, err,
		    sizeof(err));
		return (ydata_out("ps", error, data, err));
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
		return (submit(conn, &sp));
	}
	if (strcmp(argv[0], "events") == 0 && argc == 2 && strcmp(argv[1],
	    "-f") == 0)
		return (follow_events(conn));
	if (strcmp(argv[0], "events") == 0) {
		/* arcana-events' read. */
		uint64_t	after = 0;

		if (argc > 2)
			usage();
		if (argc == 2) {
			after = (uint64_t)strtonum(argv[1], 0, INT64_MAX, &e);
			if (e != NULL)
				xo_errx(1, "events: after %s: %s", argv[1], e);
		}
		ytold_begin(conn);
		error = ygula_events(conn, argc == 2, after, &data, err,
		    sizeof(err));
		return (ydata_out("events", error, data, err));
	}
	if (strcmp(argv[0], "history") == 0) {
		/* arcana-history's read; how it samples committed first. */
		const char	*rules = NULL;
		uint32_t	 lim[3], step = 0, keep = 0;
		uint64_t	 after = 0;
		int		 storage = -1;
		bool		 set = false, has_lim = false, has_after = false;

		/* ... rules list: the limits of devices and jails, last. */
		if (argc >= 6 && strcmp(argv[1], "set") == 0 &&
		    strcmp(argv[argc - 2], "rules") == 0) {
			rules = argv[argc - 1];
			argc -= 2;
		}
		if ((argc == 4 || argc == 7 || argc == 8) && strcmp(argv[1],
		    "set") == 0) {
			/* ... cpu mem swap [storage] */
			if (argc == 8) {
				storage = (int)strtonum(argv[7], 0, 100, &e);
				if (e != NULL)
					xo_errx(1, "history: a limit is 0 to "
					    "100");
			}
			if (argc >= 7) {
				has_lim = true;
				lim[0] = (uint32_t)strtonum(argv[4], 0, 100,
				    &e);
				if (e == NULL)
					lim[1] = (uint32_t)strtonum(argv[5], 0,
					    100, &e);
				if (e == NULL)
					lim[2] = (uint32_t)strtonum(argv[6], 0,
					    100, &e);
				if (e != NULL)
					xo_errx(1, "history: a limit is 0 to "
					    "100");
			}
			set = true;
			step = (uint32_t)strtonum(argv[2], 1, 3600, &e);
			if (e != NULL)
				xo_errx(1, "history: seconds %s: %s", argv[2],
				    e);
			keep = (uint32_t)strtonum(argv[3], 0, 5000, &e);
			if (e != NULL)
				xo_errx(1, "history: samples %s: %s", argv[3],
				    e);
		} else if (argc > 2)
			usage();
		else if (argc == 2) {
			has_after = true;
			after = (uint64_t)strtonum(argv[1], 0, INT64_MAX, &e);
			if (e != NULL)
				xo_errx(1, "history: after %s: %s", argv[1], e);
		}
		ytold_begin(conn);
		data = NULL;
		error = set ? ygula_history_set(conn, step, keep, has_lim ?
		    lim : NULL, storage, rules, err, sizeof(err)) : 0;
		if (error == 0)
			error = ygula_history(conn, has_after, after, &data,
			    err, sizeof(err));
		return (ydata_out("history", error, data, err));
	}
	/* arcana-log's read. */
	position = 0;
	lines = 0;
	from = false;
	optreset = optind = 1;
	while ((ch = getopt(argc, argv, "f:o:")) != -1) {
		switch (ch) {
		case 'f':
			from = true;
			position = (uint64_t)strtonum(optarg, 0, INT64_MAX, &e);
			if (e != NULL)
				xo_errx(1, "log: position %s: %s", optarg, e);
			break;
		case 'o':
			lines = (uint32_t)strtonum(optarg, 1, 5000, &e);
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
	ytold_begin(conn);
	error = ygula_log(conn, argc > 0 ? argv[0] : NULL, argc > 1 ?
	    argv[1] : NULL, from, position, lines, netjail, &data, err,
	    sizeof(err));
	return (ydata_out("log", error, data, err));
}

/*
 * config-export: the host as a bundle, JSON on stdout; -s with the
 * secrets.
 */
static int
cmd_config_export(cbl_conn *conn, int argc, char **argv)
{
	ucl_object_t	*data;
	char		 err[512];
	int		 error;

	if (argc > 2 || (argc == 2 && strcmp(argv[1], "-s") != 0))
		usage();
	/* arcana-agent's config-export. */
	ytold_begin(conn);
	error = yh_config_export(conn, argc == 2, &data, err, sizeof(err));
	return (ydata_out("config-export", error, data, err));
}

/*
 * config-apply [-an] [-H hostname] bundle: a bundle made this host's
 * configuration; -n only the report, -a though the hardware differs,
 * -H another host name in rc.conf.  The report, JSON, on stdout.
 */
static int
cmd_config_apply(cbl_conn *conn, int argc, char **argv)
{
	ucl_object_t	*data;
	const char	*hostname;
	char		*text, err[512];
	bool		 anyway, dry;
	int		 ch, error;

	anyway = dry = false;
	hostname = NULL;
	optind = 1;
	optreset = 1;
	while ((ch = getopt(argc, argv, "anH:")) != -1) {
		switch (ch) {
		case 'a':
			anyway = true;
			break;
		case 'n':
			dry = true;
			break;
		case 'H':
			hostname = optarg;
			break;
		default:
			usage();
		}
	}
	if (argc != optind + 1)
		usage();
	text = slurp(argv[optind]);
	/* arcana-agent's config-apply. */
	ytold_begin(conn);
	error = yh_config_apply(conn, text, dry, anyway, hostname, &data,
	    err, sizeof(err));
	free(text);
	return (ydata_out("config-apply", error, data, err));
}

/*
 * path-check: what this host does with a packet from src to dst, and
 * with its reply; -i the interface it comes in on, -F the FIB, -p tcp,
 * udp, icmp or ip, -P the port.  JSON on stdout.
 */
static int
cmd_path_check(cbl_conn *conn, int argc, char **argv)
{
	ucl_object_t	*data;
	const char	*iface, *proto;
	char		 err[256];
	uint32_t	 pfib, port;
	int		 ch, error;
	bool		 has_fib, reply;

	/* arcana-troubleshoot's path-check. */
	iface = proto = NULL;
	pfib = port = 0;
	has_fib = reply = false;
	optind = 1;
	optreset = 1;
	while ((ch = getopt(argc, argv, "F:i:p:P:r")) != -1) {
		switch (ch) {
		case 'r':
			reply = true;
			break;
		case 'F':
			has_fib = true;
			pfib = (uint32_t)strtoul(optarg, NULL, 10);
			break;
		case 'i':
			iface = optarg;
			break;
		case 'p':
			proto = optarg;
			break;
		case 'P':
			port = (uint32_t)strtoul(optarg, NULL, 10);
			break;
		default:
			usage();
		}
	}
	if (argc != optind + 2)
		usage();
	ytold_begin(conn);
	error = yts_path_check(conn, argv[optind], argv[optind + 1],
	    proto, port, iface, has_fib, pfib, netjail, reply, &data, err,
	    sizeof(err));
	return (ydata_out("path-check", error, data, err));
}

/*
 * notify chat text: a Telegram message, sent by the agent through the
 * bot whose token ARCANA_TELEGRAM_TOKEN holds (not an argument: ps(1)
 * would show it).
 */
static int
cmd_notify(cbl_conn *conn, int argc, char **argv)
{
	const char	*token;
	char		 err[256];
	int		 error;

	if (argc != 3)
		usage();
	if ((token = getenv("ARCANA_TELEGRAM_TOKEN")) == NULL ||
	    token[0] == '\0')
		xo_errx(2, "notify: the bot's token is in ARCANA_TELEGRAM_TOKEN");
	/* arcana-notify's notify. */
	ytold_begin(conn);
	error = yr_notify(conn, token, argv[1], argv[2], err, sizeof(err));
	return (ydata_out("notify", error, NULL, err));
}

/*
 * transport: the agent's listeners and the connections open to it.
 * transport retry: start the SCTP listeners that are not up.
 * transport listen uri: listen there too.  transport unlisten uri
 * [for new [keep]]: close that one; with keep, new takes its place in
 * rc.conf.
 */
static int
cmd_transport(cbl_conn *conn, int argc, char **argv)
{
	ucl_object_t	*data;
	const char	*listen, *unlisten;
	char		 err[512];
	bool		 keep, retry;
	int		 error;

	listen = unlisten = NULL;
	keep = retry = false;
	if (argc == 3 && strcmp(argv[1], "listen") == 0)
		listen = argv[2];
	else if ((argc == 3 || argc == 5 || argc == 6) && strcmp(argv[1],
	    "unlisten") == 0 && (argc == 3 || strcmp(argv[3], "for") == 0) &&
	    (argc != 6 || strcmp(argv[5], "keep") == 0)) {
		unlisten = argv[2];
		listen = argc >= 5 ? argv[4] : NULL;
		keep = argc == 6;
	} else if (argc > 2 || (argc == 2 && strcmp(argv[1], "retry") != 0))
		usage();
	else
		retry = argc == 2;
	/* arcana-agent's transport, its retry or listen action first. */
	ytold_begin(conn);
	error = yh_transport(conn, retry, listen, unlisten, keep, NULL,
	    &data, err, sizeof(err));
	return (ydata_out("transport", error, data, err));
}

/*
 * ipfw rules: arcana-firewall's kept rules, the host's or the jail's
 * (-j): read from running; from_rc, its from-rc action, the migration
 * of what the host boots now, nothing written; with text, its check
 * action (check), or put in running's place by a commit, the accepts
 * given with -a: a host's first moves its boot to Arcana's script, and
 * is refused, nothing written, unless the rules are those loaded now.
 */
static int
ipfw_rules(cbl_conn *conn, bool from_rc, const char *text, bool check)
{
	struct arcana_firewall_firewall_from_rc_input	 rin;
	struct arcana_firewall_firewall_from_rc_output	 rout;
	struct arcana_firewall_firewall_check_input	 cin;
	struct arcana_firewall_firewall_check_output	 cout;
	struct ietf_netconf_commit_input		 ci;
	struct ietf_netconf_discard_changes_input	 di;
	const struct arcana_firewall_firewall		*f;
	struct arcana_firewall_firewall			 nf;
	struct arcana_firewall_firewall_kept		 nk;
	struct arcana_firewall_firewall_jail		*jv;
	const struct cbl_ynode				*n;
	struct arcana_firewall				 d;
	cbl_yarena					*a;
	const char					*was;
	char						 why[512], tag[80];
	uint64_t					 errsid;
	size_t						 k;
	int						 error;

	if ((n = ytop_named("firewall")) == NULL)
		xo_errx(1, "ipfw rules: arcana-firewall is not in the tables");
	if ((a = cbl_yarena_new()) == NULL)
		xo_err(1, "ipfw rules");
	if (from_rc) {
		memset(&rin, 0, sizeof(rin));
		memset(&rout, 0, sizeof(rout));
		rin.jail = netjail;
		ytold_begin(conn);
		error = ycall(conn, n, NULL, 0, "from-rc", &rin, &rout, a, why,
		    sizeof(why));
		ytold_end(true);
		if (error != 0)
			xo_errx(1, "ipfw rules: %s", why);
		if (rout.rc_file != NULL)
			xo_emit("{:rc-file/# from %s}\n", rout.rc_file);
		if (rout.text != NULL)
			xo_emit("{:text/%s}", rout.text);
		cbl_yarena_free(a);
		return (0);
	}
	if (check) {
		memset(&cin, 0, sizeof(cin));
		cin.jail = netjail;
		cin.text = text;
		ytold_begin(conn);
		error = ycall(conn, n, NULL, 0, "check", &cin, &cout, a, why,
		    sizeof(why));
		ytold_end(true);
		if (error != 0)
			xo_errx(1, "ipfw rules: %s", why);
		xo_emit("{:result/ipfw has nothing against it; left as it "
		    "was}\n");
		cbl_yarena_free(a);
		return (0);
	}
	memset(&d, 0, sizeof(d));
	yget_data(conn, n, CBL_YDS_RUNNING, &d, a);
	f = d.firewall;
	was = NULL;
	if (netjail == NULL)
		was = f != NULL && f->kept != NULL ? f->kept->text : NULL;
	else
		for (k = 0; f != NULL && k < f->jail.n; k++)
			if (strcmp(f->jail.v[k].name, netjail) == 0)
				was = f->jail.v[k].text;
	if (text == NULL) {
		xo_emit("{:text/%s}", was != NULL ? was : "");
		cbl_yarena_free(a);
		return (0);
	}
	memset(&nf, 0, sizeof(nf));
	memset(&nk, 0, sizeof(nk));
	if (f != NULL)
		nf = *f;
	if (nf.kept != NULL)
		nk = *nf.kept;
	if (netjail == NULL) {
		nk.text = text;
		nf.kept = &nk;
	} else {
		if ((jv = cbl_yarena_alloc(a, (nf.jail.n + 1) *
		    sizeof(*jv))) == NULL)
			xo_err(1, "ipfw rules");
		for (k = 0; k < nf.jail.n; k++)
			jv[k] = nf.jail.v[k];
		for (k = 0; k < nf.jail.n && strcmp(jv[k].name, netjail) != 0;
		    k++)
			;
		if (k == nf.jail.n) {
			memset(&jv[k], 0, sizeof(jv[k]));
			jv[k].name = netjail;
			nf.jail.n++;
		}
		jv[k].text = text;
		nf.jail.v = jv;
	}
	d.firewall = &nf;
	if ((error = yedit_data(conn, n, &d, CBL_YDS_CANDIDATE, accepts,
	    naccepts, why, sizeof(why), &errsid, tag, sizeof(tag))) != 0)
		refused("ipfw rules", why, tag);
	memset(&ci, 0, sizeof(ci));
	if (netconf_try(conn, "commit", &ci, why, sizeof(why), tag,
	    sizeof(tag)) != 0) {
		memset(&di, 0, sizeof(di));
		(void)netconf_try(conn, "discard-changes", &di, NULL, 0, NULL,
		    0);
		refused("ipfw rules", why, tag);
	}
	xo_emit("{:result/in place; the one before is kept beside it}\n");
	cbl_yarena_free(a);
	return (0);
}

/*
 * ipfw add | delete: a rule, now; with -p kept too, and after "keep"
 * kept only.  ipfw apply: the kept rules as the whole ruleset, through
 * set 1; with -s taken back unless confirmed.  ipfw rules: the kept
 * file read, or with -w put in place, with -n only checked; with -r the
 * file rc.conf's firewall_type names, as kept rules, nothing written.
 */
static int
cmd_ipfw(cbl_conn *conn, int argc, char **argv)
{
	struct arc_job_spec		 sp;
	struct stat			 sb;
	const char			*from;
	char				*text;
	int				 ch, error, fd;
	bool				 keep;

	if (argc < 2)
		usage();
	if (strcmp(argv[1], "trace") == 0) {
		/* arcana-firewall's trace, of the host's or the jail's. */
		ucl_object_t	*data;
		const char	*e;
		char		 err[256];
		uint32_t	 seconds = 0, packets = 0;

		if (argc < 3 || argc > 5)
			usage();
		if (argc > 3) {
			seconds = (uint32_t)strtonum(argv[3], 1, 60, &e);
			if (e != NULL)
				xo_errx(1, "ipfw trace: seconds %s: %s", argv[3],
				    e);
		}
		if (argc > 4) {
			packets = (uint32_t)strtonum(argv[4], 1, 1000, &e);
			if (e != NULL)
				xo_errx(1, "ipfw trace: packets %s: %s", argv[4],
				    e);
		}
		ytold_begin(conn);
		error = yts_fw_trace(conn, netjail, argv[2], seconds,
		    packets, &data, err, sizeof(err));
		return (ydata_out("ipfw trace", error, data, err));
	}
	if (strcmp(argv[1], "rules") == 0) {
		bool	check = false, from_rc = false;

		from = NULL;
		argc--;
		argv++;
		optind = 1;
		optreset = 1;
		while ((ch = getopt(argc, argv, "a:nrw:")) != -1) {
			switch (ch) {
			case 'a':
				/* A warning the commit is to take. */
				if (naccepts < nitems(accepts))
					accepts[naccepts++] = optarg;
				break;
			case 'n':
				check = true;
				break;
			case 'r':
				from_rc = true;
				break;
			case 'w':
				from = optarg;
				break;
			default:
				usage();
			}
		}
		if (argc != optind || (check && from == NULL) || (from_rc &&
		    from != NULL))
			usage();
		text = NULL;
		if (from != NULL) {
			if ((fd = fileargs_open(files, from)) == -1 || fstat(fd,
			    &sb) == -1 || (text = malloc((size_t)sb.st_size +
			    1)) == NULL || read(fd, text, (size_t)sb.st_size) !=
			    sb.st_size)
				xo_err(1, "%s", from);
			close(fd);
			text[sb.st_size] = '\0';
		}
		return (ipfw_rules(conn, from_rc, text, check));
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
	/* replace ... --was words: the old rule's words, to tell it from
	 * another of its number. */
	if (strcmp(argv[1], "replace") == 0) {
		int	k;

		for (k = 2; k < argc; k++)
			if (strcmp(argv[k], "--was") == 0) {
				sp.names.n = (size_t)(k - 2);
				sp.text = words_joined(argc - k - 1, argv + k + 1);
				break;
			}
	}
	sp.live = !keep;
	sp.persist = keep || persist;
	sp.safe = safe;
	sp.jail = netjail;
	return (submit(conn, &sp));
}

/* Words joined by a space, a text of its own. */
static char *
words_joined(int n, char **v)
{
	char	*t;
	size_t	 len;
	int	 i;

	len = 1;
	for (i = 0; i < n; i++)
		len += strlen(v[i]) + 1;
	if ((t = calloc(1, len)) == NULL)
		xo_err(1, "calloc");
	for (i = 0; i < n; i++) {
		if (i > 0)
			strlcat(t, " ", len);
		strlcat(t, v[i], len);
	}
	return (t);
}

/* bridge | geneve name verb word ...: a job; with -p kept in rc.conf. */
static int
cmd_l2(cbl_conn *conn, int argc, char **argv)
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
	return (submit(conn, &sp));
}

/* storage kind [dataset]: the host's storage, as the host says it. */
static int
cmd_storage(cbl_conn *conn, int argc, char **argv)
{
	static const char *kinds[] = { "disks", "pools", "datasets",
	    "snapshots", "mounts", "importable", "health" };
	ucl_object_t	*data;
	unsigned char	*json;
	uint64_t	 total;
	size_t		 i;
	char		 err[512];
	bool		 truncated;

	if (argc < 2 || argc > 3)
		usage();
	for (i = 0; i < nitems(kinds); i++)
		if (strcmp(argv[1], kinds[i]) == 0)
			break;
	if (i == nitems(kinds) || (argc == 3 && i != 3))
		usage();
	/* arcana-storage's read; -j: what that jail's own zfs sees. */
	ytold_begin(conn);
	if (ystore_read(conn, (int)i, argc == 3 ? argv[2] : NULL, netjail,
	    &data, &total, &truncated, err, sizeof(err)) != 0) {
		ytold_end(true);
		xo_warnx("storage %s: %s", kinds[i], err);
		return (1);
	}
	ytold_end(true);
	if ((json = ucl_object_emit(data, UCL_EMIT_JSON_COMPACT)) != NULL)
		xo_emit("{:json/%s}\n", json);
	free(json);
	ucl_object_unref(data);
	if (truncated)
		xo_warnx("storage %s: there are %ju, more than a reply "
		    "carries: these are the first", kinds[i], (uintmax_t)total);
	return (0);
}

/*
 * zfs, zpool, gpart, cam, mount and umount: a job of that kind, with
 * the verb and its words.  -r and -f among the words are the job's
 * flags, not words: the host gives no word to a program as an option.
 */
static int
cmd_storage_job(cbl_conn *conn, int argc, char **argv)
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
	return (submit(conn, &sp));
}

/* fstab: print it.  fstab -w new-text [-n]: put a local file in its place. */
static int
cmd_fstab(cbl_conn *conn, int argc, char **argv)
{
	struct stat		 sb;
	const char		*from;
	char			*text, *cur, *sha, err[512];
	int			 ch, error, fd;
	bool			 dry;

	from = NULL;
	dry = false;
	optind = 1;
	optreset = 1;
	while ((ch = getopt(argc, argv, "nw:")) != -1) {
		switch (ch) {
		case 'n':
			dry = true;
			break;
		case 'w':
			from = optarg;
			break;
		default:
			usage();
		}
	}
	if (argc != optind || (dry && from == NULL))
		usage();
	text = NULL;
	/* arcana-storage's fstab: read with what is mounted, put in place
	 * by its replace action. */
	if ((error = ystore_fstab(conn, &cur, &sha, err, sizeof(err))) !=
	    0)
		xo_errx(1, "fstab: %s", err);
	if (from == NULL) {
		if (cur != NULL)
			xo_emit("{:text/%s}", cur);
		free(cur);
		free(sha);
		return (0);
	}
	free(cur);
	{
		if ((fd = fileargs_open(files, from)) == -1 || fstat(fd, &sb) == -1 ||
		    (text = malloc((size_t)sb.st_size + 1)) == NULL ||
		    read(fd, text, (size_t)sb.st_size) != sb.st_size)
			xo_err(1, "%s", from);
		close(fd);
		text[sb.st_size] = '\0';
	}
	/* What is there now says what the new text replaces. */
	cur = NULL;
	error = ystore_fstab_put(conn, text, sha != NULL ? sha : "", dry,
	    &cur, err, sizeof(err));
	if (error == 0)
		xo_emit("{:result/%s}\n", dry ? "it is an fstab; left as it "
		    "was" : "in place; the one before is kept beside it");
	else
		xo_warnx("fstab: %s", err);
	free(cur);
	free(sha);
	free(text);
	return (error == 0 ? 0 : 1);
}

static int
cmd_stats(cbl_conn *conn)
{
	const struct arcana_host_host_stats	*st;
	struct arcana_host			 d;
	const struct cbl_ynode			*n;
	cbl_yarena				*a;
	size_t					 i;

	/* arcana-host's host, its stats. */
	if ((n = yq_top("arcana-host", "host")) == NULL)
		xo_errx(1, "stats: arcana-host has no host");
	if ((a = cbl_yarena_new()) == NULL)
		xo_err(1, "stats");
	memset(&d, 0, sizeof(d));
	ytold_begin(conn);
	yget_data(conn, n, -1, &d, a);
	if (d.host != NULL && (st = d.host->stats) != NULL) {
		xo_open_container("stats");
		xo_emit("{Lwc:CPU}{:cpu-pct/%.1f}%\n", st->cpu / 10.0);
		xo_emit("{Lwc:Load}{:load1/%.2f} {:load5/%.2f} {:load15/%.2f}\n",
		    st->load1 / 100.0, st->load5 / 100.0, st->load15 / 100.0);
		xo_emit("{Lwc:Memory}{:mem-used/%ju} used, {:mem-inactive/%ju} "
		    "inactive, {:mem-free/%ju} free of {:mem-total/%ju} MiB\n",
		    (uintmax_t)(st->memory_used >> 20),
		    (uintmax_t)(st->memory_inactive >> 20),
		    (uintmax_t)(st->memory_free >> 20),
		    (uintmax_t)(st->memory_total >> 20));
		xo_emit("{Lwc:Swap}{:swap-used/%ju} of {:swap-total/%ju} MiB\n",
		    (uintmax_t)(st->swap_used >> 20),
		    (uintmax_t)(st->swap_total >> 20));
		xo_open_list("pool");
		for (i = 0; i < st->pool.n; i++) {
			xo_open_instance("pool");
			xo_emit("{Lwc:Pool}{:name/%s} {:alloc/%ju} of {:size/%ju} "
			    "GiB, {:health/%s}\n", st->pool.v[i].name,
			    (uintmax_t)(st->pool.v[i].allocated >> 30),
			    (uintmax_t)(st->pool.v[i].size >> 30),
			    st->pool.v[i].health != NULL ?
			    st->pool.v[i].health : "");
			xo_close_instance("pool");
		}
		xo_close_list("pool");
		xo_close_container("stats");
	}
	ytold_end(true);
	cbl_yarena_free(a);
	return (0);
}

typedef struct arcana_packages_package ypkg;

static void
emit_packages(const ypkg *v, size_t n)
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
		    "{:available/%s}\n", v[i].name, v[i].installed != NULL ?
		    v[i].installed : "", v[i].available != NULL ?
		    v[i].available : "");
		xo_close_instance("package");
	}
	xo_close_list("package");
}

/* The installed packages: by hand or automatic, size, what each is. */
static void
emit_installed(const ypkg *v, size_t n)
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
 * arcana-packages' node: the host's packages, or with jail the jail's
 * (vals[0] its key, *keyp the name); *nvals the keys.
 */
static const struct cbl_ynode *
ypkg_node(const char *jail, const char **keyp, const void **vals,
    size_t *nvals)
{
	const struct cbl_ynode	*n;

	*nvals = 0;
	if (jail == NULL)
		n = ytop_named("packages");
	else if ((n = ytop_named("jails")) != NULL && (n = ychild(n,
	    "jail")) != NULL && (n = ychild(n, "packages")) != NULL) {
		*keyp = jail;
		vals[0] = keyp;
		*nvals = 1;
	}
	if (n == NULL)
		xo_errx(1, "packages: arcana-packages is not in the tables");
	return (n);
}

/*
 * packages [-i] [-r] [-4 | -6] [jail]: what has a newer version in the
 * repository, arcana-packages' refresh action (with -r, pkg update
 * first); with -i, what is installed, its read action.
 */
static int
cmd_packages(cbl_conn *conn, int argc, char **argv)
{
	struct arcana_packages_packages_refresh_input	 ri;
	struct arcana_packages_packages_refresh_output	 ro;
	struct arcana_packages_packages_read_output	 io;
	const struct cbl_ynode				*n;
	const void					*vals[1];
	const char					*jail, *key;
	const char *const				*repos;
	cbl_yarena					*a;
	char						 why[512];
	size_t						 nvals, nrepos;
	bool						 inst;
	int						 ch, error;

	memset(&ri, 0, sizeof(ri));
	inst = false;
	optind = 1;
	while ((ch = getopt(argc, argv, "46ir")) != -1) {
		switch (ch) {
		case '4':
		case '6':
			/* ip-version's values are pkg's: 4, 6. */
			ri.has_ip_version = true;
			ri.ip_version = ch - '0';
			break;
		case 'i':
			inst = true;
			break;
		case 'r':
			ri.has_update = true;
			ri.update = true;
			break;
		default:
			usage();
		}
	}
	if (argc - optind > 1)
		usage();
	jail = argc - optind == 1 ? argv[optind] : NULL;
	n = ypkg_node(jail, &key, vals, &nvals);
	if ((a = cbl_yarena_new()) == NULL)
		xo_err(1, "packages");
	memset(&ro, 0, sizeof(ro));
	memset(&io, 0, sizeof(io));
	ytold_begin(conn);
	if (inst)
		error = ycall(conn, n, vals, nvals, "read", NULL, &io, a, why,
		    sizeof(why));
	else
		error = ycall(conn, n, vals, nvals, "refresh", &ri, &ro, a, why,
		    sizeof(why));
	ytold_end(false);
	repos = inst ? io.repository.v : ro.repository.v;
	nrepos = inst ? io.repository.n : ro.repository.n;
	if (error == 0 && inst)
		emit_installed(io.package.v, io.package.n);
	else if (error == 0)
		emit_packages(ro.package.v, ro.package.n);
	/* pkg's repositories there: what -r of pkg-upgrade may name. */
	if (error == 0 && nrepos > 0) {
		xo_open_list("repository");
		xo_emit("{Lwc:Repositories}");
		for (size_t i = 0; i < nrepos; i++)
			xo_emit("{P: }{l:repository/%s}", repos[i]);
		xo_close_list("repository");
		xo_emit("\n");
	}
	ytold_end(true);
	cbl_yarena_free(a);
	if (error != 0) {
		xo_warnx("packages: %s", why);
		return (1);
	}
	return (0);
}

/*
 * jobs lanes number: how many jobs of pkg in jails run at once,
 * arcana-jobs' lanes in the candidate, committed.
 */
static int
cmd_jobs_set(cbl_conn *conn, const char *number)
{
	struct yq_jobs	 q;
	cbl_yarena	*a;
	const char	*errstr;
	char		 err[512];
	int		 n;

	n = (int)strtonum(number, 1, 32, &errstr);
	if (errstr != NULL)
		xo_errx(2, "lanes %s: %s", number, errstr);
	if (yq_lanes(conn, n, err, sizeof(err)) != 0)
		xo_errx(1, "jobs lanes: %s", err);
	if ((a = cbl_yarena_new()) == NULL)
		xo_err(1, "jobs lanes");
	if (yq_list(conn, a, &q, err, sizeof(err)) != 0)
		xo_errx(1, "jobs: %s", err);
	xo_emit("{T:Lanes}: {:lanes/%d} jobs of pkg in jails at once\n",
	    q.lanes);
	cbl_yarena_free(a);
	return (0);
}

/*
 * jail-base jail convert [-O] [-4 | -6] [-b release] [set ...] |
 * upgrade [-O] [-4 | -6] release: a running jail's base system by pkg
 * as pkgbase, a job.
 */
static int
cmd_jail_base(cbl_conn *conn, int argc, char **argv)
{
	struct arc_job_spec	 sp;
	int			 ch;
	bool			 up;

	if (argc < 3)
		usage();
	memset(&sp, 0, sizeof(sp));
	sp.has_kind = true;
	sp.kind = ARC_JOB_KIND_JAIL_BASE;
	sp.jail = argv[1];
	sp.verb = argv[2];
	up = strcmp(argv[2], "upgrade") == 0;
	if (!up && strcmp(argv[2], "convert") != 0)
		usage();
	optind = 3;
	while ((ch = getopt(argc, argv, "46Ob:r:")) != -1) {
		switch (ch) {
		case '4':
		case '6':
			sp.has_pkg_ip = true;
			sp.pkg_ip = ch == '4' ? 4 : 6;
			break;
		case 'O':
			sp.force = true;
			break;
		case 'r':
			sp.pkg_repo = optarg;
			break;
		case 'b':
			if (up)
				usage();
			sp.release = optarg;
			break;
		default:
			usage();
		}
	}
	if (up) {
		if (optind != argc - 1)
			usage();
		sp.release = argv[optind];
	} else if (optind < argc) {
		sp.names.v = (const char **)(uintptr_t)&argv[optind];
		sp.names.n = (size_t)(argc - optind);
	}
	return (submit(conn, &sp));
}

/*
 * pkg-clean [-a] [-j jail | -J]: the cache of downloaded packages, a
 * job; with -J, of every running jail, one batch of a job each.
 */
static int
cmd_pkg_clean(cbl_conn *conn, int argc, char **argv)
{
	const struct arcana_jails_jails	*js;
	struct arc_job_spec		 sp, *v;
	struct arc_job			*jv;
	cbl_yarena			*a;
	char				 err[512];
	size_t				 i, n, nj;
	int				 ch;
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
		return (submit(conn, &sp));
	if ((a = cbl_yarena_new()) == NULL)
		xo_err(1, "pkg-clean");
	js = yjails(conn, -1, a);
	if ((v = calloc(js->jail.n + 1, sizeof(*v))) == NULL)
		xo_err(1, "calloc");
	for (i = n = 0; i < js->jail.n; i++) {
		if (!js->jail.v[i].has_state || js->jail.v[i].state !=
		    ARCANA_JAILS_JAILS_JAIL_STATE_RUNNING)
			continue;
		v[n] = sp;
		v[n].jail = js->jail.v[i].name;
		v[n].safe = safe;
		v[n].has_safe_wait = safe && safe_wait > 0;
		v[n].safe_wait = safe_wait;
		n++;
	}
	if (n == 0) {
		xo_warnx("pkg-clean: no running jail");
		free(v);
		cbl_yarena_free(a);
		return (1);
	}
	if (yq_submit(conn, v, n, a, &jv, &nj, err, sizeof(err)) != 0)
		xo_errx(1, "pkg-clean: %s", err);
	xo_open_list("job");
	for (i = 0; i < nj; i++)
		emit_job(&jv[i]);
	xo_close_list("job");
	cbl_yarena_free(a);
	free(v);
	return (0);
}

/* pkg-install [-O] [-4 | -6] [-r repo] [-j jail] package ...: a job. */
static int
cmd_pkg_install(cbl_conn *conn, int argc, char **argv)
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
	return (submit(conn, &sp));
}

/*
 * ipsec init | conn name local remote mode pubkey [word value ...] |
 * unconn name | up name | down name: strongSwan, a job, in the vnet
 * jail of -j when one is named.
 */
static int
cmd_ipsec(cbl_conn *conn, int argc, char **argv)
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
		return (submit(conn, &sp));
	}
	if (argc < 3)
		usage();
	sp.conn = argv[2];
	if (strcmp(argv[1], "unconn") == 0 || strcmp(argv[1], "up") == 0 ||
	    strcmp(argv[1], "down") == 0) {
		if (argc != 3)
			usage();
		return (submit(conn, &sp));
	}
	if (strcmp(argv[1], "unchild") == 0) {
		if (argc != 4)
			usage();
		sp.child = argv[3];
		return (submit(conn, &sp));
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
	return (submit(conn, &sp));
}

/* pkg-upgrade [-n] [-O] [-4 | -6] [-r repo] [-j jail | -J] [package ...]:
 * -J, of every running jail, by the agent, one after the other; -r, from
 * that repository alone. */
static int
cmd_pkg_upgrade(cbl_conn *conn, int argc, char **argv)
{
	struct arcana_packages_packages_upgrade_input	 ui;
	struct arcana_packages_packages_upgrade_output	 uo;
	const struct cbl_ynode				*n;
	const void					*vals[1];
	const char					*jail, *key;
	cbl_yarena					*a;
	char						 why[512];
	size_t						 nvals;
	int						 ch, error;

	memset(&ui, 0, sizeof(ui));
	jail = NULL;
	optind = 1;
	while ((ch = getopt(argc, argv, "46OJj:nr:")) != -1) {
		switch (ch) {
		case '4':
		case '6':
			/* ip-version's values are pkg's: 4, 6. */
			ui.has_ip_version = true;
			ui.ip_version = ch - '0';
			break;
		case 'O':
			/* Packages for a newer FreeBSD too. */
			ui.has_ignore_osversion = true;
			ui.ignore_osversion = true;
			break;
		case 'j':
			jail = optarg;
			break;
		case 'J':
			jail = "*";
			break;
		case 'n':
			ui.has_dry_run = true;
			ui.dry_run = true;
			break;
		case 'r':
			ui.repository = optarg;
			break;
		default:
			usage();
		}
	}
	ui.name.v = (const char *const *)(argv + optind);
	ui.name.n = (size_t)(argc - optind);
	if (queue && !ui.dry_run) {
		struct arc_job_spec sp;

		memset(&sp, 0, sizeof(sp));
		sp.has_kind = true;
		sp.kind = ARC_JOB_KIND_PKG_UPGRADE;
		sp.jail = jail;
		sp.force = ui.ignore_osversion;
		sp.has_pkg_ip = ui.has_ip_version;
		sp.pkg_ip = (uint8_t)ui.ip_version;
		sp.pkg_repo = ui.repository;
		sp.names.v = ui.name.v;
		sp.names.n = ui.name.n;
		return (submit(conn, &sp));
	}
	/* In every running jail: the host's, every-jail. */
	if (jail != NULL && strcmp(jail, "*") == 0) {
		jail = NULL;
		ui.has_every_jail = true;
		ui.every_jail = true;
	}
	n = ypkg_node(jail, &key, vals, &nvals);
	if ((a = cbl_yarena_new()) == NULL)
		xo_err(1, "pkg-upgrade");
	memset(&uo, 0, sizeof(uo));
	ytold_begin(conn);
	error = ycall(conn, n, vals, nvals, "upgrade", &ui, &uo, a, why,
	    sizeof(why));
	ytold_end(false);
	if (error == 0) {
		if (uo.has_upgraded)
			xo_emit("{Lwc:Upgraded}{:upgraded/%u}\n", uo.upgraded);
		xo_emit("{T:Still pending}:\n");
		emit_packages(uo.package.v, uo.package.n);
	}
	ytold_end(true);
	cbl_yarena_free(a);
	if (error != 0) {
		xo_warnx("pkg-upgrade: %s", why);
		return (1);
	}
	return (0);
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
submit(cbl_conn *conn, struct arc_job_spec *sp)
{
	struct arc_job	*v;
	cbl_yarena	*a;
	char		 id[24], err[512], *jargv[4];
	size_t		 i, n;

	sp->safe = safe;
	sp->has_safe_wait = safe && safe_wait > 0;
	sp->safe_wait = safe_wait;
	/* -a: the warnings a service's rc.conf change accepts, as a
	 * commit's. */
	if (naccepts > 0 && (sp->kind == ARC_JOB_KIND_SERVICE_CONFIG ||
	    (sp->kind == ARC_JOB_KIND_SERVICE_ACTION &&
	    (sp->service_action == ARC_SERVICE_ACTION_ENABLE ||
	    sp->service_action == ARC_SERVICE_ACTION_DISABLE)))) {
		sp->accept.v = accepts;
		sp->accept.n = naccepts;
	}
	if ((a = cbl_yarena_new()) == NULL)
		xo_err(1, "queue");
	if (yq_submit(conn, sp, 1, a, &v, &n, err, sizeof(err)) != 0 ||
	    n != 1) {
		xo_warnx("%s", n != 1 && err[0] == '\0' ? "not accepted" :
		    err);
		cbl_yarena_free(a);
		return (1);
	}
	if (!queue) {
		snprintf(id, sizeof(id), "%ju", (uintmax_t)v[0].id);
		cbl_yarena_free(a);
		jargv[0] = (char *)(uintptr_t)"job";
		jargv[1] = (char *)(uintptr_t)"-w";
		jargv[2] = id;
		jargv[3] = NULL;
		optreset = 1;
		return (cmd_job(conn, 3, jargv));
	}
	xo_open_list("job");
	for (i = 0; i < n; i++)
		emit_job(&v[i]);
	xo_close_list("job");
	cbl_yarena_free(a);
	return (0);
}

/* jobs: the queue, a GET of arcana-jobs' jobs. */
static int
cmd_jobs(cbl_conn *conn)
{
	struct yq_jobs	 q;
	cbl_yarena	*a;
	char		 err[512];

	if ((a = cbl_yarena_new()) == NULL)
		xo_err(1, "jobs");
	if (yq_list(conn, a, &q, err, sizeof(err)) != 0)
		xo_errx(1, "jobs: %s", err);
	xo_emit("{T:/%4s} {T:/%-9s} {T:/%s}\n", "ID", "STATE", "JOB");
	xo_open_list("job");
	for (size_t i = 0; i < q.n; i++)
		emit_job(&q.v[i]);
	xo_close_list("job");
	if (q.lanes > 0)
		xo_emit("{T:Lanes}: {:lanes/%d} jobs of pkg in jails at once\n",
		    q.lanes);
	/* What is under way that is not a job, and a stop that waits. */
	if (q.activity != NULL)
		xo_emit("{Lwc:Under way}{:activity/%s}{d:/ (%jd s)}"
		    "{e:since/%jd}\n", q.activity, (intmax_t)(time(NULL) -
		    q.since), (intmax_t)q.since);
	if (q.stopping)
		xo_emit("{Lwc:Stopping}{:stopping/%s}\n", q.activity !=
		    NULL || q.n > 0 ? "when what is under way ends" : "now");
	cbl_yarena_free(a);
	return (0);
}

/*
 * job [-w] id: the job and its trace, its read action; -w waits for it
 * to finish.
 */
static int
cmd_job(cbl_conn *conn, int argc, char **argv)
{
	struct arc_job			 j;
	const struct arcana_jobs_step	*steps;
	cbl_yarena			*a;
	char				 err[512];
	uint64_t			 id;
	size_t				 nsteps;
	bool				 wait, done, ok;
	int				 ch;

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
	id = strtoull(argv[optind], NULL, 10);
	if ((a = cbl_yarena_new()) == NULL)
		xo_err(1, "job");
	for (;;) {
		if (yq_job(conn, id, a, &j, &steps, &nsteps, err,
		    sizeof(err)) != 0) {
			xo_warnx("job %s: %s", argv[optind], err);
			cbl_yarena_free(a);
			return (1);
		}
		done = j.state == ARC_JOB_STATE_DONE ||
		    j.state == ARC_JOB_STATE_CANCELLED;
		if (done || !wait)
			break;
		/*
		 * A safe change is made and waits to hear from us: that
		 * this request gets through is what it waits for.
		 */
		if (j.state == ARC_JOB_STATE_UNCONFIRMED)
			(void)yq_confirm(conn, id, err, sizeof(err));
		/* Each read anew: the last one's go. */
		cbl_yarena_free(a);
		if ((a = cbl_yarena_new()) == NULL)
			xo_err(1, "job");
		usleep(300000);
	}
	xo_open_list("job");
	emit_job(&j);
	xo_close_list("job");
	show_trace = true;
	emit_trace(steps, nsteps);
	ok = !done || (j.state == ARC_JOB_STATE_DONE && j.ok);
	cbl_yarena_free(a);
	return (ok ? 0 : 1);
}

/* job-cancel id: its cancel action. */
static int
cmd_job_cancel(cbl_conn *conn, int argc, char **argv)
{
	struct arc_job	 j;
	cbl_yarena	*a;
	char		 err[512];

	if (argc != 2)
		usage();
	if ((a = cbl_yarena_new()) == NULL)
		xo_err(1, "job-cancel");
	if (yq_cancel(conn, strtoull(argv[1], NULL, 10), a, &j, err,
	    sizeof(err)) != 0) {
		xo_warnx("job %s: %s", argv[1], err);
		cbl_yarena_free(a);
		return (1);
	}
	xo_open_list("job");
	emit_job(&j);
	xo_close_list("job");
	cbl_yarena_free(a);
	return (0);
}

int
main(int argc, char *argv[])
{
	cbl_conn		*conn;
	cbl_ctx			*ctx;
	cbl_tls			*tls;
	const char		*uri, *cafile, *certfile, *keyfile, *name, *errstr;
	const char		*user;
	cap_rights_t		 rd, wr;
	char			**names;
	int			 ch, error, rc, i, nnames;

	if ((argc = xo_parse_args(argc, argv)) < 0)
		exit(2);
	/*
	 * Any word of the command line may name a file to read, and the
	 * file behind an @word: these, and no other, Casper opens for us
	 * once in capability mode.
	 */
	if ((names = calloc((size_t)argc * 2 + 1, sizeof(*names))) == NULL)
		xo_err(1, "calloc");
	nnames = 0;
	for (i = 0; i < argc; i++) {
		names[nnames++] = argv[i];
		if (argv[i][0] == '@' && argv[i][1] != '\0')
			names[nnames++] = argv[i] + 1;
	}
	uri = PATH_SOCKET;
	cafile = certfile = keyfile = name = user = NULL;
	while ((ch = getopt(argc, argv, "+A:C:c:F:j:K:N:pqstu:W:")) != -1) {
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
		case 'u':
			user = optarg;
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
	(void)cbl_ctx_set_limit(ctx, CBL_LIM_MAX_DEPTH, MAX_DEPTH);
	(void)cbl_ctx_set_limit(ctx, CBL_LIM_REQUEST_MS, TIMEOUT_MS);
	if ((error = cbl_conn_new(ctx, uri, 0, &conn)) != 0)
		xo_errx(1, "%s: %s", uri, strerror(error));
	if (user != NULL && (error = cbl_conn_set_user(conn, user)) != 0)
		xo_errx(2, "-u %s: %s", user, strerror(error));
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
	/*
	 * Capability mode from here (capsicum(4)): the agent's socket is
	 * connected and TLS is up; the files named on the command line
	 * come through Casper's fileargs, to read, or for agent-build's
	 * program alone to write; the time zone and the message catalogs
	 * are cached first.
	 */
	cap_rights_init(&rd, CAP_READ, CAP_FSTAT, CAP_SEEK);
	cap_rights_init(&wr, CAP_WRITE, CAP_FSTAT);
	if ((files = fileargs_init(nnames, names, O_RDONLY, 0, &rd,
	    FA_OPEN)) == NULL)
		xo_err(1, "fileargs_init");
	if (strcmp(argv[0], "agent-build") == 0 && (outfiles =
	    fileargs_init(nnames, names, O_WRONLY | O_CREAT | O_TRUNC, 0755,
	    &wr, FA_OPEN)) == NULL)
		xo_err(1, "fileargs_init");
	caph_cache_tzdata();
	caph_cache_catpages();
	if (caph_enter_casper() == -1)
		xo_err(1, "cap_enter");

	xo_open_container("arcana");
	if (strcmp(argv[0], "hello") == 0 && argc == 1)
		rc = cmd_hello(conn);
	else if (strcmp(argv[0], "get") == 0)
		rc = cmd_get(conn, argc, argv);
	else if (strcmp(argv[0], "edit") == 0)
		rc = cmd_edit(conn, argc, argv);
	else if (strcmp(argv[0], "set") == 0)
		rc = cmd_set(conn, argc, argv);
	else if (strcmp(argv[0], "commit") == 0)
		rc = cmd_commit(conn, argc, argv);
	else if (strcmp(argv[0], "cancel-commit") == 0)
		rc = cmd_cancel_commit(conn, argc, argv);
	else if (strcmp(argv[0], "discard") == 0)
		rc = cmd_discard(conn, argc, argv);
	else if (strcmp(argv[0], "action") == 0)
		rc = cmd_yaction(conn, argc, argv);
	else if (strcmp(argv[0], "notifications") == 0)
		rc = cmd_notifications(conn);
	else if (strcmp(argv[0], "subscribe") == 0)
		rc = cmd_subscribe(conn, argc, argv);
	else if (strcmp(argv[0], "list") == 0)
		rc = cmd_list(conn, argc, argv);
	else if (strcmp(argv[0], "start") == 0)
		rc = cmd_action(conn, ARC_ACTION_START, argc, argv);
	else if (strcmp(argv[0], "stop") == 0)
		rc = cmd_action(conn, ARC_ACTION_STOP, argc, argv);
	else if (strcmp(argv[0], "restart") == 0)
		rc = cmd_action(conn, ARC_ACTION_RESTART, argc, argv);
	else if (strcmp(argv[0], "kill") == 0)
		rc = cmd_action(conn, ARC_ACTION_KILL, argc, argv);
	else if (strcmp(argv[0], "enable") == 0)
		rc = cmd_action(conn, ARC_ACTION_ENABLE, argc, argv);
	else if (strcmp(argv[0], "disable") == 0)
		rc = cmd_action(conn, ARC_ACTION_DISABLE, argc, argv);
	else if (strcmp(argv[0], "address") == 0)
		rc = cmd_address(conn, argc, argv);
	else if (strcmp(argv[0], "services") == 0 && argc == 1)
		rc = cmd_services(conn);
	else if (strcmp(argv[0], "services") == 0 && strcmp(argv[1],
	    "convert") == 0)
		rc = cmd_services_convert(conn, argc - 1, argv + 1);
	else if (strcmp(argv[0], "services") == 0 && strcmp(argv[1],
	    "release") == 0)
		rc = cmd_services_release(conn, argc - 1, argv + 1);
	else if (strcmp(argv[0], "service") == 0)
		rc = cmd_service(conn, argc, argv);
	else if (strcmp(argv[0], "interface") == 0 ||
	    strcmp(argv[0], "route") == 0 || strcmp(argv[0], "ng") == 0 ||
	    strcmp(argv[0], "wg") == 0 || strcmp(argv[0], "bird") == 0)
		rc = cmd_interface(conn, argc, argv);
	else if (strcmp(argv[0], "reboot") == 0 && argc == 1)
		rc = cmd_reboot(conn);
	else if (strcmp(argv[0], "net") == 0)
		rc = cmd_net(conn, argc, argv);
	else if (strcmp(argv[0], "stats") == 0 && argc == 1)
		rc = cmd_stats(conn);
	else if (strcmp(argv[0], "ntp") == 0)
		rc = cmd_ntp(conn, argc, argv);
	else if (strcmp(argv[0], "rtadvd") == 0)
		rc = cmd_rtadvd(conn, argc, argv);
	else if (strcmp(argv[0], "allow") == 0)
		rc = cmd_allow(conn, argc, argv);
	else if (strcmp(argv[0], "ipsec-sa") == 0)
		rc = cmd_ipsec_sa(conn, argc, argv);
	else if (strcmp(argv[0], "kmod") == 0)
		rc = cmd_kmod(conn, argc, argv);
	else if (strcmp(argv[0], "jailconf") == 0)
		rc = cmd_jailconf(conn, argc, argv);
	else if (strcmp(argv[0], "neigh") == 0)
		rc = cmd_neigh(conn, argc, argv);
	else if (strcmp(argv[0], "carp") == 0)
		rc = cmd_carp(conn, argc, argv);
	else if (strcmp(argv[0], "cert") == 0)
		rc = cmd_cert(conn, argc, argv);
	else if (strcmp(argv[0], "crashes") == 0)
		rc = cmd_crashes(conn, argc, argv);
	else if (strcmp(argv[0], "clamav") == 0)
		rc = cmd_clamav(conn, argc, argv);
	else if (strcmp(argv[0], "smtpd") == 0)
		rc = cmd_smtpd(conn, argc, argv);
	else if (strcmp(argv[0], "speeder") == 0)
		rc = cmd_speeder(conn, argc, argv);
	else if (strcmp(argv[0], "monitor") == 0)
		rc = cmd_monitor(conn, argc, argv);
	else if (strcmp(argv[0], "system") == 0)
		rc = cmd_system(conn, argc, argv);
	else if (strcmp(argv[0], "geom") == 0)
		rc = cmd_geom(conn, argc, argv);
	else if (strcmp(argv[0], "sysfile") == 0)
		rc = cmd_sysfile(conn, argc, argv);
	else if (strcmp(argv[0], "netstore") == 0)
		rc = cmd_netstore(conn, argc, argv);
	else if (strcmp(argv[0], "nfs") == 0)
		rc = cmd_netstore_job(conn, argc, argv, ARC_JOB_KIND_NFS);
	else if (strcmp(argv[0], "iscsi") == 0)
		rc = cmd_netstore_job(conn, argc, argv, ARC_JOB_KIND_ISCSI);
	else if (strcmp(argv[0], "hast") == 0)
		rc = cmd_netstore_job(conn, argc, argv, ARC_JOB_KIND_HAST);
	else if (strcmp(argv[0], "suricata") == 0)
		rc = cmd_suricata(conn, argc, argv);
	else if (strcmp(argv[0], "poudriere") == 0)
		rc = cmd_poudriere(conn, argc, argv);
	else if (strcmp(argv[0], "sshd") == 0)
		rc = cmd_sshd(conn, argc, argv);
	else if (strcmp(argv[0], "capture") == 0)
		rc = cmd_capture(conn, argc, argv);
	else if (strcmp(argv[0], "tls") == 0)
		rc = cmd_tls(conn, argc, argv, certfile);
	else if (strcmp(argv[0], "zfskey") == 0)
		rc = cmd_zfskey(conn, argc, argv);
	else if (strcmp(argv[0], "sysctl") == 0)
		rc = cmd_sysctl(conn, argc, argv);
	else if (strcmp(argv[0], "ps") == 0 || strcmp(argv[0], "signal") == 0 ||
	    strcmp(argv[0], "renice") == 0 || strcmp(argv[0], "log") == 0 ||
	    strcmp(argv[0], "history") == 0 || strcmp(argv[0], "events") == 0)
		rc = cmd_gula(conn, argc, argv);
	else if (strcmp(argv[0], "transport") == 0)
		rc = cmd_transport(conn, argc, argv);
	else if (strcmp(argv[0], "config-export") == 0)
		rc = cmd_config_export(conn, argc, argv);
	else if (strcmp(argv[0], "config-apply") == 0)
		rc = cmd_config_apply(conn, argc, argv);
	else if (strcmp(argv[0], "path-check") == 0)
		rc = cmd_path_check(conn, argc, argv);
	else if (strcmp(argv[0], "notify") == 0)
		rc = cmd_notify(conn, argc, argv);
	else if (strcmp(argv[0], "storage") == 0)
		rc = cmd_storage(conn, argc, argv);
	else if (strcmp(argv[0], "zfs") == 0 || strcmp(argv[0], "zpool") == 0 ||
	    strcmp(argv[0], "gpart") == 0 || strcmp(argv[0], "cam") == 0 ||
	    strcmp(argv[0], "mount") == 0 || strcmp(argv[0], "umount") == 0 ||
	    strcmp(argv[0], "swapon") == 0 || strcmp(argv[0], "swapoff") == 0)
		rc = cmd_storage_job(conn, argc, argv);
	else if (strcmp(argv[0], "fstab") == 0)
		rc = cmd_fstab(conn, argc, argv);
	else if (strcmp(argv[0], "ipfw") == 0)
		rc = cmd_ipfw(conn, argc, argv);
	else if (strcmp(argv[0], "bridge") == 0 || strcmp(argv[0], "geneve") ==
	    0)
		rc = cmd_l2(conn, argc, argv);
	else if (strcmp(argv[0], "packages") == 0)
		rc = cmd_packages(conn, argc, argv);
	else if (strcmp(argv[0], "jobs") == 0 && argc == 1)
		rc = cmd_jobs(conn);
	else if (strcmp(argv[0], "jobs") == 0 && argc == 3 && strcmp(argv[1],
	    "lanes") == 0)
		rc = cmd_jobs_set(conn, argv[2]);
	else if (strcmp(argv[0], "jail-base") == 0)
		rc = cmd_jail_base(conn, argc, argv);
	else if (strcmp(argv[0], "job") == 0)
		rc = cmd_job(conn, argc, argv);
	else if (strcmp(argv[0], "job-cancel") == 0)
		rc = cmd_job_cancel(conn, argc, argv);
	else if (strcmp(argv[0], "pkg-clean") == 0)
		rc = cmd_pkg_clean(conn, argc, argv);
	else if (strcmp(argv[0], "pkg-install") == 0)
		rc = cmd_pkg_install(conn, argc, argv);
	else if (strcmp(argv[0], "ipsec") == 0)
		rc = cmd_ipsec(conn, argc, argv);
	else if (strcmp(argv[0], "pkg-upgrade") == 0)
		rc = cmd_pkg_upgrade(conn, argc, argv);
	else if (strcmp(argv[0], "agent-update") == 0)
		rc = cmd_agent_update(conn, argc, argv);
	else if (strcmp(argv[0], "agent-build") == 0)
		rc = cmd_agent_build(conn, argc, argv);
	else if (strcmp(argv[0], "traceroute") == 0)
		rc = cmd_traceroute(conn, argc, argv);
	else if (strcmp(argv[0], "sdwan") == 0)
		rc = cmd_sdwan(conn, argc, argv);
	else if (strcmp(argv[0], "source-head") == 0)
		rc = cmd_source_head(conn, argc, argv);
	else if (strcmp(argv[0], "source-log") == 0)
		rc = cmd_source_log(conn, argc, argv);
	else if (strcmp(argv[0], "console-update") == 0)
		rc = cmd_console_update(conn, argc, argv);
	else
		usage();
	xo_close_container("arcana");
	xo_finish();

	cbl_conn_free(conn);
	cbl_tls_free(tls);
	(void)cbl_ctx_free(ctx);
	return (rc);
}
