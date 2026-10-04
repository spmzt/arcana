/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * What the console's tests share: starting kore(1) with arcana-console.so and a
 * arcana-agent(8) in the work directory, and talking HTTP to them.
 */

#include <sys/param.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/wait.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <atf-c.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "harness.h"

char		 cookie[160];
bool		 send_xjg = true;
const char	*origin_hdr = ORIGIN;
char		 harness_origin[64] = ORIGIN;
int		 harness_port;
char		 harness_webconf[1024];	/* appended to web.conf */
static char	 kore_path[MAXPATHLEN];

static void	 terminate(const char *);
/* The console sends another build of arcana-agent than the host runs. */
bool		 harness_other_agent;
/* The agent beside the console is looked for, as outside the tests. */
bool		 harness_local_agent;
/* web.conf's local_agent is the test's own line. */
bool		 harness_webconf_only_local;

extern char	**environ;

static int	console_socket(void);
static void	show(const char *);

void
put(const char *path, const char *text)
{
	FILE	*fp;

	ATF_REQUIRE((fp = fopen(path, "w")) != NULL);
	ATF_REQUIRE(fputs(text, fp) >= 0);
	ATF_REQUIRE(fclose(fp) == 0);
}

static pid_t
spawn_in(char *const argv[], const char *out, bool own_group)
{
	posix_spawn_file_actions_t	fa;
	posix_spawnattr_t		attr;
	pid_t				pid;

	posix_spawn_file_actions_init(&fa);
	posix_spawn_file_actions_addopen(&fa, 1, out,
	    O_WRONLY | O_CREAT | O_TRUNC, 0644);
	posix_spawn_file_actions_adddup2(&fa, 1, 2);
	posix_spawnattr_init(&attr);
	if (own_group) {
		posix_spawnattr_setflags(&attr, POSIX_SPAWN_SETPGROUP);
		posix_spawnattr_setpgroup(&attr, 0);
	}
	ATF_REQUIRE_EQ_MSG(0, posix_spawn(&pid, argv[0], &fa, &attr, argv,
	    environ), "cannot run %s", argv[0]);
	posix_spawnattr_destroy(&attr);
	posix_spawn_file_actions_destroy(&fa);
	return (pid);
}

pid_t
spawn(char *const argv[], const char *out)
{

	return (spawn_in(argv, out, false));
}

/*
 * A server, in a process group of its own: kyua kills the test's group
 * when the body returns, and a kore killed before its shutdown leaks
 * its SysV shared memory segment.  The cleanup's stop() ends it.
 */
pid_t
spawn_server(char *const argv[], const char *out)
{

	return (spawn_in(argv, out, true));
}

/* Run a program to completion; true if it exited 0. */
bool
run_prog(char *const argv[])
{
	pid_t	pid;
	int	status;

	pid = spawn(argv, "run.out");
	while (waitpid(pid, &status, 0) == -1)
		if (errno != EINTR)
			return (false);
	return (WIFEXITED(status) && WEXITSTATUS(status) == 0);
}

static void
show(const char *path)
{
	FILE	*fp;
	char	 line[1024];

	if ((fp = fopen(path, "r")) == NULL)
		return;
	while (fgets(line, sizeof(line), fp) != NULL)
		fprintf(stderr, "%s: %s", path, line);
	fclose(fp);
}

void
wait_for(const char *path)
{
	int	i;

	for (i = 0; i < 200; i++) {
		if (access(path, F_OK) == 0)
			return;
		usleep(25000);
	}
	/* What the servers said goes into kyua's report. */
	show("kore.out");
	show("arcana-agent.out");
	atf_tc_fail("%s did not appear", path);
}

/*
 * A file the tests need: the configuration variable var, else rel from
 * the test's directory in the build tree, then in the source tree, else
 * where it is installed (def).
 */
const char *
locate(const atf_tc_t *tc, const char *rel, const char *var, const char *def)
{
	static char	buf[4][MAXPATHLEN];
	static int	n;
	char		*b;

	b = buf[n++ % 4];
	if (atf_tc_has_config_var(tc, var))
		return (atf_tc_get_config_var(tc, var));
	snprintf(b, MAXPATHLEN, "%s/%s", atf_tc_get_config_var(tc, "srcdir"),
	    rel);
	if (access(b, F_OK) == 0)
		return (b);
	/* Built in an object directory: the sources are elsewhere. */
	snprintf(b, MAXPATHLEN, "%s/%s", TESTSRC, rel);
	if (access(b, F_OK) == 0)
		return (b);
	return (def);
}

/*
 * arcana-agent on ./jgd.sock with a lab configuration and a stand-in for
 * jail(8), and kore on ./k.sock.  Their pids go to files for cleanup.
 */
void
start(const atf_tc_t *tc, int port, const char *webroot)
{
	char	 cwd[MAXPATHLEN], buf[4096], so[MAXPATHLEN], routes[MAXPATHLEN];
	char	 jgd[MAXPATHLEN], listen[MAXPATHLEN + 16], www[MAXPATHLEN];
	char	 send[MAXPATHLEN];
	char	 rcd[MAXPATHLEN], birdconf[MAXPATHLEN], local[MAXPATHLEN];
	const char *kore, *dh;
	char	*argv[60];
	FILE	*fp;
	pid_t	 pid;

	ATF_REQUIRE(getcwd(cwd, sizeof(cwd)) != NULL);
	kore = atf_tc_get_config_var_wd(tc, "kore", "/usr/local/bin/kore");
	dh = atf_tc_get_config_var_wd(tc, "dhparam",
	    "/usr/local/share/kore/ffdhe4096.pem");
	snprintf(jgd, sizeof(jgd), "%s", locate(tc,
	    "../../../usr.sbin/arcana-agent/arcana-agent", "arcana-agent",
	    "/usr/local/sbin/arcana-agent"));
	snprintf(so, sizeof(so), "%s", locate(tc, "../arcana-console.so", "module",
	    "/usr/local/lib/arcana/arcana-console.so"));
	snprintf(routes, sizeof(routes), "%s", locate(tc,
	    "../conf/routes.conf", "routes",
	    "/usr/local/etc/arcana/routes.conf"));
	if (access(kore, X_OK) == -1)
		atf_tc_skip("no kore at %s (set the kore variable)", kore);
	ATF_REQUIRE_MSG(access(jgd, X_OK) == 0, "no arcana-agent at %s", jgd);

	ATF_REQUIRE(mkdir("etc", 0755) == 0);
	ATF_REQUIRE(mkdir("etc/jail.conf.d", 0755) == 0);
	/* A test may have put something there to start from. */
	ATF_REQUIRE(mkdir("data", 0700) == 0 || errno == EEXIST);
	ATF_REQUIRE(mkdir("www", 0755) == 0);
	put("www/index.html", "<!doctype html><title>t</title>\n");
	harness_port = port;
	if (port != 0)
		snprintf(harness_origin, sizeof(harness_origin),
		    "http://localhost:%d", port);
	else
		snprintf(harness_origin, sizeof(harness_origin), "%s", ORIGIN);
	put("etc/jail.conf", "path = \"/jails/$name\";\n"
	    "web {\n\tip4.addr = 10.0.0.10;\n\tpersist;\n}\n"
	    "db {\n\tip4.addr = 10.0.0.20;\n}\n"
	    "gw {\n\tvnet;\n}\n");
	/*
	 * gw has a network of its own, and "runs": jls says so, jexec
	 * runs what it is given, and the helper answers for the jail.
	 */
	snprintf(buf, sizeof(buf), "#!/bin/sh\n[ \"$2\" = gw ] && { echo "
	    "\"4 new %s/jroot\"; exit 0; }\necho \"jls: jail not found\" >&2\n"
	    "exit 1\n", cwd);
	put("fake-jls", buf);
	put("fake-jexec", "#!/bin/sh\necho \"jexec $*\" >> jexec.log\nshift\n"
	    "exec \"$@\"\n");
	put("fake-helper", "#!/bin/sh\necho \"$*\" >> helper.log\n"
	    "case \"$3\" in\ninterfaces) echo '{\"interfaces\":[{\"name\":"
	    "\"epair1b\",\"up\":true,\"flags\":[\"UP\"],\"link\":\"up\",\"mtu\":"
	    "1500,\"ibytes\":1,\"obytes\":2,\"addresses\":[{\"family\":\"inet\","
	    "\"address\":\"10.99.0.2\",\"prefixlen\":24}]}],\"time\":1000}' ;;\n"
	    "exists) [ \"$4\" = epair1b ] && echo 1 || echo 0 ;;\n"
	    "up) echo 1 ;;\ncurrent) printf '1500\\t' ;;\n"
	    "prefix) [ \"$5\" = 10.99.0.2 ] && echo 10.99.0.2/24 ;;\nesac\n"
	    "exit 0\n");
	ATF_REQUIRE(chmod("fake-jls", 0755) == 0);
	ATF_REQUIRE(chmod("fake-jexec", 0755) == 0);
	ATF_REQUIRE(chmod("fake-helper", 0755) == 0);
	ATF_REQUIRE(mkdir("jroot", 0755) == 0 || errno == EEXIST);
	ATF_REQUIRE(mkdir("jroot/etc", 0755) == 0 || errno == EEXIST);
	put("jroot/etc/rc.conf", "hostname=\"gw\"\n");
	put("fake-jail", "#!/bin/sh\nfor a; do [ \"$a\" = -e ] && "
	    "exec /usr/sbin/jail \"$@\"; done\necho \"fake-jail: $*\"\n");
	ATF_REQUIRE(chmod("fake-jail", 0755) == 0);
	/* An rc.d of two scripts and stand-ins for service(8) and
	 * sysrc(8) working from ./rc.conf, as the daemon's tests have. */
	ATF_REQUIRE(mkdir("rc.d", 0755) == 0);
	put("rc.d/sshd", "#!/bin/sh\n");
	put("rc.d/ntpd", "#!/bin/sh\n");
	ATF_REQUIRE(chmod("rc.d/sshd", 0755) == 0);
	ATF_REQUIRE(chmod("rc.d/ntpd", 0755) == 0);
	put("rc.conf", "sshd_enable=\"YES\"\nsshd_flags=\"-4\"\n");
	snprintf(buf, sizeof(buf), "#!/bin/sh\nconf=%s/rc.conf\n"
	    "[ \"$1\" = -R ] && { conf=$2/etc/rc.conf; shift 2; }\n"
	    "[ \"$1\" = -i ] && shift\n"
	    "case \"$1\" in\n"
	    "-n) grep -q \"^$2=\" \"$conf\" || exit 1; sed -n \"s/^$2=\\\""
	    "\\(.*\\)\\\"\\$/\\1/p\" \"$conf\" ;;\n"
	    "-a|-A) sed -e 's/=\"\\(.*\\)\"$/: \\1/' \"$conf\" ;;\n"
	    "-x) grep -v \"^$2=\" \"$conf\" > c.new; mv c.new \"$conf\" ;;\n"
	    "*=*) k=${1%%%%=*}; v=${1#*=}; grep -v \"^$k=\" \"$conf\" > c.new; "
	    "printf '%%s=\"%%s\"\\n' \"$k\" \"$v\" >> c.new; mv c.new \"$conf\" ;;\n"
	    "esac\n", cwd);
	put("fake-sysrc", buf);
	ATF_REQUIRE(chmod("fake-sysrc", 0755) == 0);
	snprintf(buf, sizeof(buf), "#!/bin/sh\nconf=%s/rc.conf\n"
	    "if [ \"$1\" = -e ]; then for f in %s/rc.d/*; do n=${f##*/}; "
	    "grep -q \"^${n}_enable=\\\"YES\\\"\" \"$conf\" && echo \"$f\"; "
	    "done; exit 0; fi\n"
	    "case \"$2\" in\n"
	    "rcvar) echo \"${1}_enable=\\\"NO\\\"\" ;;\n"
	    "status) [ -f running.$1 ] && { echo \"$1 is running as pid 7.\"; "
	    "exit 0; }; echo \"$1 is not running.\"; exit 1 ;;\n"
	    "start|restart) [ -f slow ] && sleep 3; touch running.$1 ;;\n"
	    "stop) rm -f running.$1 ;;\n"
	    "describe) echo \"The $1 daemon.\" ;;\n"
	    "extracommands) echo reload ;;\n"
	    "esac\n", cwd, cwd);
	put("fake-service", buf);
	ATF_REQUIRE(chmod("fake-service", 0755) == 0);
	put("fake-netstat", "#!/bin/sh\necho '{\"statistics\": {\"route-information\": "
	    "{\"route-table\": {\"rt-family\": [{\"address-family\": \"Internet\", "
	    "\"rt-entry\": [{\"destination\": \"default\", \"gateway\": "
	    "\"10.0.0.1\", \"flags\": \"UGS\", \"interface-name\": \"em0\"}]}]}}}}'\n");
	ATF_REQUIRE(chmod("fake-netstat", 0755) == 0);
	/* pkg(8): ./pending holds "name-version remote" lines; upgrade -y
	 * removes the named ones, or all. */
	put("pending", "aria2-1.37.0_1 1.37.0_2\npimd-3.1.0 3.2.0\n");
	put("fake-pkg", "#!/bin/sh\n[ \"$1\" = -j ] && shift 2\n"
	    "case \"$1\" in\n"
	    "update) exit 0 ;;\n"
	    "version) [ -s pending ] || exit 1; while read nv r; do "
	    "printf '%s < needs updating (remote has %s)\\n' \"$nv\" \"$r\"; "
	    "done < pending ;;\n"
	    "upgrade) shift; d=no; [ \"$1\" = -n ] && d=yes; shift; "
	    "while read nv r; do n=${nv%-*}; if [ $# -eq 0 ] || echo \" $* \" | "
	    "grep -q \" $n \"; then echo \"Upgrading $n to $r\"; [ $d = yes ] || "
	    "{ grep -v \"^$nv \" pending > p.new; mv p.new pending; }; fi; "
	    "done < pending ;;\n"
	    "esac\n");
	ATF_REQUIRE(chmod("fake-pkg", 0755) == 0);

	/* git clone makes a tree; make "builds" by copying the agent. */
	put("fake-git", "#!/bin/sh\necho \"$*\" >> git.log\n"
	    "[ \"$1\" = -c ] && shift 2\n"
	    "[ \"$1\" = clone ] || exit 2\n"
	    "for a; do last=$a; done\n"
	    "mkdir -p \"$last/lib/libjailconf\" \"$last/usr.sbin/arcana-agent\"\n");
	ATF_REQUIRE(chmod("fake-git", 0755) == 0);
	snprintf(buf, sizeof(buf), "#!/bin/sh\ndir=$2\ncase \" $* \" in\n"
	    "*\" -V .OBJDIR \"*) echo \"$dir/obj\" ;;\n"
	    "*/usr.sbin/arcana-agent*) mkdir -p \"$dir/obj\" && "
	    "cp '%s' \"$dir/obj/arcana-agent\" ;;\nesac\n", jgd);
	/* ssh-keyscan: the key ./hostkey.pub, made by the test that asks. */
	put("fake-keyscan", "#!/bin/sh\nfor a; do last=$a; done\n"
	    "echo \"$last $(cut -d' ' -f1,2 hostkey.pub)\"\n");
	ATF_REQUIRE(chmod("fake-keyscan", 0755) == 0);
	/* ifconfig(8), for changes: what it was run with. */
	put("fake-ifconfig", "#!/bin/sh\necho \"$*\" >> ifconfig.log\n"
	    "[ \"$2\" = create ] && echo \"$1\"\nexit 0\n");
	put("fake-route", "#!/bin/sh\necho \"$*\" >> route.log\n"
	    "[ \"$2\" = get ] && printf '   route to: %s\\ndestination: "
	    "10.77.0.0\\n       mask: 255.255.0.0\\n    gateway: 10.0.0.1\\n"
	    "        fib: 0\\n  interface: em0\\n      flags: <UP,GATEWAY>"
	    "\\n' \"$4\"\nexit 0\n");
	put("fake-ngctl", "#!/bin/sh\necho \"$*\" >> ngctl.log\n"
	    "[ \"$1\" = list ] && printf '  Name: em0  Type: ether  ID: "
	    "00000002  Num hooks: 1\\n  Local hook  Peer name  Peer type  "
	    "Peer ID  Peer hook\\n  ----------  ---------  ---------  "
	    "-------  ---------\\n  lower  bridge0  bridge  0000000c  link0"
	    "\\n  Name: bridge0  Type: bridge  ID: 0000000c  Num hooks: 1\\n"
	    "  Local hook  Peer name  Peer type  Peer ID  Peer hook\\n"
	    "  ----------  ---------  ---------  -------  ---------\\n"
	    "  link0  em0  ether  00000002  lower\\n'\nexit 0\n");
	ATF_REQUIRE(chmod("fake-ngctl", 0755) == 0);
	/* wg(8): an interface that has a key once it was given one, and
	 * the peers it was given; birdc(8): a daemon with two protocols. */
	put("fake-wg", "#!/bin/sh\necho \"$*\" >> wg.log\n"
	    "key='(none)'; pub='(none)'\n"
	    "[ -f wg.key ] && { key=$(cat wg.key); "
	    "pub=HIgo9xNzJMWLKASShiTqIybxZ0U3wGLiUeJ1PKf8ykw=; }\n"
	    "case \"$1 $2 $3\" in\n"
	    "'show all dump') printf 'wg0\\t%s\\t%s\\t51820\\toff\\n' "
	    "\"$key\" \"$pub\"\n"
	    "  [ -f wg.peers ] && cat wg.peers ;;\n"
	    "'show wg0 private-key') echo \"$key\" ;;\n"
	    "'showconf wg0 ') printf '[Interface]\\nPrivateKey = %s\\n' "
	    "\"$key\" ;;\n"
	    "'set wg0 private-key') cp \"$4\" wg.key ;;\n"
	    "'set wg0 peer') [ \"$5\" = remove ] && rm -f wg.peers || "
	    "printf 'wg0\\t%s\\t(none)\\t192.0.2.9:51820\\t10.9.9.2/32\\t0"
	    "\\t0\\t0\\t0\\n' \"$4\" > wg.peers ;;\n"
	    "esac\nexit 0\n");
	put("fake-birdc", "#!/bin/sh\necho \"$*\" >> birdc.log\n"
	    "[ \"$1\" = -r ] && shift\ncase \"$*\" in\n"
	    "'show status') printf 'BIRD 2.15.1 ready.\\nBIRD 2.15.1\\n"
	    "Router ID is 192.0.2.1\\nDaemon is up and running\\n' ;;\n"
	    "'show protocols all') printf 'BIRD 2.15.1 ready.\\nName Proto Table "
	    "State Since Info\\ndevice1 Device --- up 2026-10-01 \\n"
	    "bgp_core BGP --- up 12:01:02.345 Established\\n"
	    "  Description:    Core uplink\\n  BGP state:          Established"
	    "\\n    Neighbor address: 192.0.2.1\\n    Neighbor AS:      65001"
	    "\\n    Local AS:         65000\\n  Channel ipv4\\n    State:"
	    "          UP\\n    Table:          master4\\n    Input filter:   "
	    "bgp_in\\n    Output filter:  bgp_out\\n    Routes:         845233 "
	    "imported, 12 exported, 400000 preferred\\n"
	    "bgp_edge BGP --- start 12:01:02.345 Active\\n"
	    "  BGP state:          Active\\n    Neighbor address: 198.51.100.7"
	    "\\n    Neighbor AS:      65002\\n"
	    "rpki1 RPKI --- up 2026-10-01 Established\\n"
	    "  Cache server:     rpki.example.net\\n' ;;\n"
	    "'show ospf neighbors') printf 'ospf1:\\nRouter ID Pri State DTime "
	    "Interface Router IP\\n10.0.0.2 1 Full/PtP 00:00:35 gif0 "
	    "10.255.0.2\\n' ;;\n"
	    "'show symbols table') printf 'master4 routing table\\nr4 routing "
	    "table\\n' ;;\n"
	    "'show route table master4 count') printf '845236 of 845236 routes "
	    "for 845233 networks in table master4\\n' ;;\n"
	    "'show route table r4 count') printf '512345 of 512345 routes for "
	    "512345 networks in table r4\\n' ;;\n"
	    "*) printf 'BIRD 2.15.1 ready.\\n%s: done\\n' \"$2\" ;;\n"
	    "esac\nexit 0\n");
	put("fake-bird", "#!/bin/sh\necho \"fake-bird $*\" >&2\n"
	    "grep -q BROKEN \"$3\" && { echo \"bird: $3:2:1 syntax error\" >&2; "
	    "exit 1; }\nexit 0\n");
	ATF_REQUIRE(chmod("fake-bird", 0755) == 0);
	ATF_REQUIRE(mkdir("bird", 0755) == 0 || errno == EEXIST);
	put("bird/bird.conf", "# The lab's routing.\nrouter id 192.0.2.1;\n\n"
	    "define MY_AS = 65000;\ndefine CUSTOMERS = [ (65000,100), "
	    "(65000,200) ];\ndefine BLACKHOLE_LC = [ (65000,666,0) ];\n\n"
	    "roa4 table r4;\n\nfilter bgp_in {\n\tif bgp_community ~ CUSTOMERS "
	    "then accept;\n\treject;\n}\n\nfilter bgp_out {\n\taccept;\n}\n\n"
	    "protocol device device1 {\n}\n\nprotocol bgp bgp_core {\n"
	    "\tdescription \"Core uplink\";\n\tlocal as MY_AS;\n\tneighbor "
	    "192.0.2.1 as 65001;\n\tipv4 {\n\t\timport filter bgp_in;\n"
	    "\t\texport filter bgp_out;\n\t};\n}\n\nprotocol bgp bgp_edge {\n"
	    "\tlocal as MY_AS;\n\tneighbor 198.51.100.7 as 65002;\n}\n\n"
	    "protocol rpki rpki1 {\n\troa4 { table r4; };\n\tremote "
	    "\"rpki.example.net\" port 3323;\n}\n");
	snprintf(birdconf, sizeof(birdconf), "%s/bird/bird.conf", cwd);
	ATF_REQUIRE(chmod("fake-wg", 0755) == 0);
	ATF_REQUIRE(chmod("fake-birdc", 0755) == 0);
	ATF_REQUIRE(mkdir("wg", 0700) == 0 || errno == EEXIST);
	ATF_REQUIRE(chmod("fake-route", 0755) == 0);
	ATF_REQUIRE(chmod("fake-ifconfig", 0755) == 0);
	put("fake-make", buf);
	ATF_REQUIRE(chmod("fake-make", 0755) == 0);
	snprintf(send, sizeof(send), "%s", jgd);
	if (harness_other_agent) {
		/* The same program with a byte after it: it runs, and its
		 * SHA-256 is another. */
		snprintf(send, sizeof(send), "%s/other-agent", cwd);
		snprintf(buf, sizeof(buf), "cp '%s' '%s' && printf x >> '%s'",
		    jgd, send, send);
		ATF_REQUIRE(system(buf) == 0);
	}
	/* None, unless a test is about it or names one itself. */
	if (harness_webconf_only_local)
		local[0] = '\0';
	else
		snprintf(local, sizeof(local), harness_local_agent ?
		    "local_agent = \"unix:%s/jgd.sock\";\n" :
		    "local_agent = \"\";\n", cwd);
	snprintf(buf, sizeof(buf), "rp_id = \"%s\";\norigin = \"%s\";\n"
	    "datadir = \"%s/data\";\ncookie_secure = false;\n"
	    "agent_binary = \"%s\";\n%s%s", RP_ID, harness_origin, cwd, send,
	    local, harness_webconf);
	put("web.conf", buf);
	if (port != 0)
		snprintf(listen, sizeof(listen), "bind 127.0.0.1 %d", port);
	else
		snprintf(listen, sizeof(listen), "unix %s/k.sock", cwd);
	snprintf(www, sizeof(www), "%s/www", cwd);
	snprintf(buf, sizeof(buf), "server t {\n\t%s\n\ttls no\n}\n"
	    "load %s arcw_onload\ntls_dhparam %s\nworkers 1\ntask_threads 4\n"
	    "http_body_max 1048576\nfilemap_index index.html\n"
	    "http_media_type application/wasm wasm\n"
	    "http_media_type application/manifest+json webmanifest\n"
	    "http_media_type image/svg+xml svg\n"
	    "http_media_type font/woff2 woff2\n"
	    "domain * {\n\tattach t\n\tinclude %s\n\tfilemap / %s\n}\n",
	    listen, so, dh, routes, webroot != NULL ? webroot : www);
	put("kore.conf", buf);

	snprintf(buf, sizeof(buf), "unix:%s/jgd.sock", cwd);
	argv[0] = jgd;
	argv[1] = (char *)(uintptr_t)"-F";
	argv[2] = (char *)(uintptr_t)"-l";
	argv[3] = buf;
	argv[4] = (char *)(uintptr_t)"-f";
	argv[5] = (char *)(uintptr_t)"etc/jail.conf";
	argv[6] = (char *)(uintptr_t)"-D";
	argv[7] = (char *)(uintptr_t)"etc/jail.conf.d";
	argv[8] = (char *)(uintptr_t)"-j";
	argv[9] = (char *)(uintptr_t)"./fake-jail";
	argv[10] = (char *)(uintptr_t)"-R";
	argv[11] = rcd;
	argv[12] = (char *)(uintptr_t)"-s";
	argv[13] = (char *)(uintptr_t)"./fake-service";
	argv[14] = (char *)(uintptr_t)"-y";
	argv[15] = (char *)(uintptr_t)"./fake-sysrc";
	argv[16] = (char *)(uintptr_t)"-N";
	argv[17] = (char *)(uintptr_t)"./fake-netstat";
	argv[18] = (char *)(uintptr_t)"-P";
	argv[19] = (char *)(uintptr_t)"./fake-pkg";
	argv[20] = (char *)(uintptr_t)"-U";
	argv[21] = (char *)(uintptr_t)"./installed-agent";
	argv[22] = (char *)(uintptr_t)"-B";
	argv[23] = (char *)(uintptr_t)"./build";
	argv[24] = (char *)(uintptr_t)"-G";
	argv[25] = (char *)(uintptr_t)"./fake-git";
	argv[26] = (char *)(uintptr_t)"-M";
	argv[27] = (char *)(uintptr_t)"./fake-make";
	argv[28] = (char *)(uintptr_t)"-Y";
	argv[29] = (char *)(uintptr_t)"./fake-keyscan";
	argv[30] = (char *)(uintptr_t)"-I";
	argv[31] = (char *)(uintptr_t)"./fake-ifconfig";
	argv[32] = (char *)(uintptr_t)"-r";
	argv[33] = (char *)(uintptr_t)"./fake-route";
	argv[34] = (char *)(uintptr_t)"-n";
	argv[35] = (char *)(uintptr_t)"./fake-ngctl";
	argv[36] = (char *)(uintptr_t)"-k";
	argv[37] = (char *)(uintptr_t)"./fake-wg";
	argv[38] = (char *)(uintptr_t)"-o";
	argv[39] = (char *)(uintptr_t)"./wg";
	argv[40] = (char *)(uintptr_t)"-b";
	argv[41] = (char *)(uintptr_t)"./fake-birdc";
	argv[42] = (char *)(uintptr_t)"-e";
	argv[43] = (char *)(uintptr_t)"./fake-bird";
	argv[44] = (char *)(uintptr_t)"-a";
	argv[45] = birdconf;
	argv[46] = (char *)(uintptr_t)"-L";
	argv[47] = (char *)(uintptr_t)"./fake-jls";
	argv[48] = (char *)(uintptr_t)"-x";
	argv[49] = (char *)(uintptr_t)"./fake-jexec";
	argv[50] = (char *)(uintptr_t)"-H";
	argv[51] = (char *)(uintptr_t)"./fake-helper";
	argv[52] = NULL;
	snprintf(rcd, sizeof(rcd), "%s/rc.d", cwd);
	pid = spawn_server(argv, "arcana-agent.out");
	ATF_REQUIRE((fp = fopen("arcana-agent.pid", "w")) != NULL);
	fprintf(fp, "%d\n", (int)pid);
	fclose(fp);

	snprintf(buf, sizeof(buf), "%s/web.conf", cwd);
	setenv("ARCANA_WEB_CONF", buf, 1);
	argv[0] = (char *)(uintptr_t)kore;
	argv[1] = (char *)(uintptr_t)"-f";
	argv[2] = (char *)(uintptr_t)"-n";
	argv[3] = (char *)(uintptr_t)"-r";
	argv[4] = (char *)(uintptr_t)"-c";
	argv[5] = (char *)(uintptr_t)"kore.conf";
	argv[6] = NULL;
	snprintf(kore_path, sizeof(kore_path), "%s", kore);
	pid = spawn_server(argv, "kore.out");
	ATF_REQUIRE((fp = fopen("kore.pid", "w")) != NULL);
	fprintf(fp, "%d\n", (int)pid);
	fclose(fp);
	wait_for("jgd.sock");
	if (port == 0)
		wait_for("k.sock");
	wait_for("data/setup-token");
	cookie[0] = '\0';
	send_xjg = true;
	origin_hdr = harness_origin;
}

/*
 * Stop the console and start it again, as a restart of its service
 * does; the agent, the data directory and the test's cookie stay.
 * For a console on ./k.sock.
 */
void
restart_console(void)
{
	char	*argv[7];
	FILE	*fp;
	pid_t	 pid;

	terminate("kore.pid");
	(void)unlink("k.sock");
	argv[0] = kore_path;
	argv[1] = (char *)(uintptr_t)"-f";
	argv[2] = (char *)(uintptr_t)"-n";
	argv[3] = (char *)(uintptr_t)"-r";
	argv[4] = (char *)(uintptr_t)"-c";
	argv[5] = (char *)(uintptr_t)"kore.conf";
	argv[6] = NULL;
	pid = spawn_server(argv, "kore.out");
	ATF_REQUIRE((fp = fopen("kore.pid", "w")) != NULL);
	fprintf(fp, "%d\n", (int)pid);
	fclose(fp);
	wait_for("k.sock");
}

/*
 * A request the client walks away from: sent, and the connection
 * closed without reading the answer, as a browser does when a page is
 * reloaded or a request aborted.
 */
void
http_abandon(const char *path)
{
	char	*req;
	int	 s;

	s = console_socket();
	ATF_REQUIRE(asprintf(&req, "GET %s HTTP/1.1\r\nHost: localhost:8443\r\n"
	    "Cookie: %s\r\n\r\n", path, cookie) != -1);
	(void)write(s, req, strlen(req));
	free(req);
	close(s);
}

/* SIGTERM the process in pidfile and wait up to 5 s for it to finish. */
static void
terminate(const char *pidfile)
{
	FILE	*fp;
	int	 i, pid;

	if ((fp = fopen(pidfile, "r")) == NULL)
		return;
	if (fscanf(fp, "%d", &pid) == 1 && pid > 0 && kill(pid, SIGTERM) == 0)
		for (i = 0; i < 100 && kill(pid, 0) == 0; i++)
			usleep(50000);
	fclose(fp);
}

void
stop(void)
{

	terminate("arcana-agent2.pid");
	terminate("kore.pid");
	terminate("arcana-agent.pid");
}

void
resp_free(struct resp *r)
{

	free(r->body);
	if (r->json != NULL)
		ucl_object_unref(r->json);
	memset(r, 0, sizeof(*r));
}

/* A connected socket to the console: ./k.sock, or its TCP port. */
static int
console_socket(void)
{
	struct sockaddr_un	sun;
	int			s;

	if (harness_port != 0)
		return (tcp_socket(harness_port));
	ATF_REQUIRE((s = socket(AF_UNIX, SOCK_STREAM, 0)) != -1);
	memset(&sun, 0, sizeof(sun));
	sun.sun_family = AF_UNIX;
	ATF_REQUIRE(getcwd(sun.sun_path, sizeof(sun.sun_path) - 8) != NULL);
	strlcat(sun.sun_path, "/k.sock", sizeof(sun.sun_path));
	ATF_REQUIRE_MSG(connect(s, (struct sockaddr *)&sun, sizeof(sun)) == 0,
	    "connect: %s", strerror(errno));
	return (s);
}

int
tcp_socket(int port)
{
	struct sockaddr_in	sin;
	int			s;

	ATF_REQUIRE((s = socket(AF_INET, SOCK_STREAM, 0)) != -1);
	memset(&sin, 0, sizeof(sin));
	sin.sin_len = sizeof(sin);
	sin.sin_family = AF_INET;
	sin.sin_port = htons((uint16_t)port);
	sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	ATF_REQUIRE_MSG(connect(s, (struct sockaddr *)&sin, sizeof(sin)) == 0,
	    "connect to port %d: %s", port, strerror(errno));
	return (s);
}

/* One request to the console; the session cookie is kept. */
void
http(const char *method, const char *path, const char *body, struct resp *r)
{
	char	hdrs[1024];

	snprintf(hdrs, sizeof(hdrs), "%s%s%s%s%s%s%s",
	    send_xjg ? "X-Arcana: 1\r\n" : "",
	    origin_hdr != NULL ? "Origin: " : "",
	    origin_hdr != NULL ? origin_hdr : "",
	    origin_hdr != NULL ? "\r\n" : "",
	    cookie[0] != '\0' ? "Cookie: " : "", cookie,
	    cookie[0] != '\0' ? "\r\n" : "");
	http_on(console_socket(), "localhost:8443", hdrs, method, path, body,
	    r);
}

/*
 * One HTTP/1.1 request on the connected socket s, which is closed; the
 * reply is parsed as JSON, and an arc_session cookie in it kept.
 */
void
http_on(int s, const char *host, const char *hdrs, const char *method,
    const char *path, const char *body, struct resp *r)
{
	struct ucl_parser	*p;
	char			*req, *buf, *hdr, *b, *c, *e;
	size_t			 len, cap, need;
	ssize_t			 n;

	memset(r, 0, sizeof(*r));
	ATF_REQUIRE(asprintf(&req, "%s %s HTTP/1.1\r\nHost: %s\r\n"
	    "Connection: close\r\n%sContent-Type: application/json\r\n"
	    "Content-Length: %zu\r\n\r\n%s", method, path, host, hdrs,
	    body != NULL ? strlen(body) : 0, body != NULL ? body : "") != -1);
	ATF_REQUIRE(write(s, req, strlen(req)) == (ssize_t)strlen(req));
	free(req);

	cap = 65536;
	ATF_REQUIRE((buf = malloc(cap + 1)) != NULL);
	len = 0;
	need = 0;
	for (;;) {
		if (len == cap) {
			cap *= 2;
			ATF_REQUIRE((buf = realloc(buf, cap + 1)) != NULL);
		}
		if ((n = read(s, buf + len, cap - len)) <= 0)
			break;
		len += (size_t)n;
		buf[len] = '\0';
		/* Stop at the end of the body: Kore may keep the socket. */
		if ((b = strstr(buf, "\r\n\r\n")) != NULL && need == 0) {
			if ((c = strcasestr(buf, "content-length:")) != NULL &&
			    c < b)
				need = (size_t)(b + 4 - buf) +
				    strtoul(c + 15, NULL, 10);
		}
		if (need != 0 && len >= need)
			break;
	}
	close(s);
	buf[len] = '\0';
	ATF_REQUIRE_MSG(sscanf(buf, "HTTP/1.1 %d", &r->status) == 1,
	    "bad response: %.200s", buf);
	ATF_REQUIRE((b = strstr(buf, "\r\n\r\n")) != NULL);
	*b = '\0';
	for (hdr = buf; (hdr = strcasestr(hdr, "\r\nset-cookie: ")) != NULL;
	    hdr += 2) {
		c = hdr + 14;
		if (strncmp(c, "arc_session=", 12) != 0)
			continue;
		e = c + strcspn(c, ";\r");
		if (e - c > 12)
			snprintf(cookie, sizeof(cookie), "%.*s", (int)(e - c),
			    c);
		else
			cookie[0] = '\0';
	}
	r->body = strdup(b + 4);
	free(buf);
	p = ucl_parser_new(UCL_PARSER_NO_IMPLICIT_ARRAYS |
	    UCL_PARSER_DISABLE_MACRO);
	if (r->body[0] != '\0' && ucl_parser_add_string(p, r->body, 0))
		r->json = ucl_parser_get_object(p);
	ucl_parser_free(p);
}

const char *
jstr(const struct resp *r, const char *path)
{
	const ucl_object_t	*o;

	if (r->json == NULL ||
	    (o = ucl_object_lookup_path(r->json, path)) == NULL)
		return (NULL);
	return (ucl_object_tostring_forced(o));
}

/* The jail called name in a list reply; other jails may be running. */
const ucl_object_t *
jail_named(const struct resp *r, const char *name)
{
	const ucl_object_t	*j;
	ucl_object_iter_t	 it;

	it = NULL;
	while ((j = ucl_object_iterate(ucl_object_lookup(r->json, "jails"),
	    &it, true)) != NULL)
		if (strcmp(ucl_object_tostring(ucl_object_lookup(j, "name")),
		    name) == 0)
			return (j);
	return (NULL);
}

const char *
jail_str(const struct resp *r, const char *name, const char *path)
{
	const ucl_object_t	*j, *o;

	if ((j = jail_named(r, name)) == NULL ||
	    (o = ucl_object_lookup_path(j, path)) == NULL)
		return (NULL);
	return (ucl_object_tostring_forced(o));
}

