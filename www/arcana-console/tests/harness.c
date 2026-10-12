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
void	show(const char *);

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

void
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
	char	 ntpconf[MAXPATHLEN], rtadvdconf[MAXPATHLEN];
	char	 fstab[MAXPATHLEN];
	const char *kore, *dh;
	char	*argv[104];
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
	    "case \"$3\" in\n"
	    /* The routes, as the helper reads them through netlink(4). */
	    "routes) echo '{\"destination\":\"default\",\"gateway\":"
	    "\"10.0.0.1\",\"flags\":\"UGS\",\"nhop\":1,\"mtu\":1500,"
	    "\"interface-name\":\"em0\",\"metric\":1,\"weight\":1,\"fib\":0,"
	    "\"prefixlen\":0}'; echo '#total 1' ;;\n"
	    "route-get) echo '{\"to\":\"'$4'\",\"destination\":\"10.77.0.0\","
	    "\"prefixlen\":16,\"gateway\":\"10.0.0.1\",\"fib\":\"0\","
	    "\"interface\":\"em0\",\"flags\":\"UGS\",\"metric\":1,"
	    "\"weight\":1}' ;;\n"
	    "route-add|route-del) shift; echo \"$*\" >> route.log ;;\n"
	    /* The connections and the sockets, from the kernel's lists. */
	    "pcb-conns) echo '{\"protocol\":\"tcp4\",\"receive-bytes-waiting\":"
	    "0,\"send-bytes-waiting\":0,\"local\":{\"address\":\"10.0.0.1\","
	    "\"port\":\"22\"},\"remote\":{\"address\":\"10.0.0.2\",\"port\":"
	    "\"4000\"},\"tcp-state\":\"ESTABLISHED\"}'; echo '#total 1' ;;\n"
	    "route-neighs) echo '{\"family\":\"inet\",\"address\":"
	    "\"10.0.0.2\",\"lladdr\":\"58:9c:fc:00:00:02\",\"interface-name\":"
	    "\"em0\",\"state\":\"reachable\"}'; echo '#total 1' ;;\n"
	    "pcb-socks) echo '{\"user\":\"root\",\"command\":\"sshd\",\"pid\":"
	    "1,\"fd\":3,\"proto\":\"tcp4\",\"local\":{\"address\":\"*\","
	    "\"port\":22},\"foreign\":{\"address\":\"*\",\"port\":0}}'; "
	    "echo '#total 1' ;;\n"
	    "interfaces) echo '{\"interfaces\":[{\"name\":"
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
	    "*+=*|*-=*) k=${1%%%%[+-]=*}; v=${1#*=}; o=$(sed -n \"s/^$k=\\\"\\("
	    ".*\\)\\\"\\$/\\1/p\" \"$conf\"); case \"$1\" in *+=*) case \" $o \" "
	    "in *\" $v \"*) n=$o ;; *) n=\"${o:+$o }$v\" ;; esac ;; *) n=$(echo "
	    "\" $o \" | sed \"s/ $v / /\" | xargs) ;; esac; "
	    "grep -v \"^$k=\" \"$conf\" > c.new; printf '%%s=\"%%s\"\\n' \"$k\" "
	    "\"$n\" >> c.new; mv c.new \"$conf\" ;;\n"
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
	/* netstat -O: a group of two next hops, two shares to one. */
	put("fake-netstat", "#!/bin/sh\ncase \"$*\" in *-onW*) printf '{"
	    "\"statistics\": {\"route-nhop-information\": {\"nhop-table\": "
	    "{\"rt-family\": [{\"address-family\": \"Internet\", \"nh-entry\": "
	    "['; i=1; while [ $i -le 300 ]; do [ $i -gt 1 ] && printf ,; "
	    "printf '{\"index\": %d, \"type_str\": \"gw\", \"gateway\": "
	    "\"10.0.0.%d\", \"interface-name\": \"em0\", \"mtu\": 1500, "
	    "\"refcount\": 1, \"flags\": \"UGS\"}' $i $((i % 250)); "
	    "i=$((i + 1)); done; echo ']}]}}}}'; exit 0 ;;\n"
	    "*-OnW*) echo '{"
	    "\"statistics\": {\"route-nhgrp-information\": {\"nhgrp-table\": "
	    "{\"rt-family\": [{\"address-family\": \"Internet\", "
	    "\"nhgrp-entry\": [{\"nhgrp-index\": 7, \"nhg-refcnt\": 3, "
	    "\"nhop-weights\": [{\"nh-index\": 5, \"nh-weight\": 2, "
	    "\"nh-gw\": \"10.0.0.1\", \"nh-interface\": \"em0\"}, "
	    "{\"nh-index\": 6, \"nh-weight\": 1, \"nh-gw\": \"10.0.0.2\", "
	    "\"nh-interface\": \"em1\"}]}]}]}}}}'; exit 0 ;; esac\n"
	    "echo '{\"statistics\": {\"route-information\": "
	    "{\"route-table\": {\"rt-family\": [{\"address-family\": \"Internet\", "
	    "\"rt-entry\": [{\"destination\": \"default\", \"gateway\": "
	    "\"10.0.0.1\", \"flags\": \"UGS\", \"interface-name\": \"em0\"}]}]}}}}'\n");
	ATF_REQUIRE(chmod("fake-netstat", 0755) == 0);
	/* pkg(8): ./pending holds "name-version remote" lines; upgrade -y
	 * removes the named ones, or all. */
	put("pending", "aria2-1.37.0_1 1.37.0_2\npimd-3.1.0 3.2.0\n");
	/* With ./newer-os the repository is for a newer FreeBSD: an
	 * upgrade is refused but past IGNORE_OSVERSION. */
	put("fake-pkg", "#!/bin/sh\necho \"$*\" >> pkg.log\nanyos=no\n"
	    "case \"$1\" in -4|-6) shift ;; esac\n"
	    "[ \"$1\" = -o ] && { anyos=yes; shift 2; }\n"
	    "[ \"$1\" = -j ] && shift 2\n"
	    "[ \"$1\" = upgrade ] && [ -f newer-os ] && [ $anyos = no ] && "
	    "{ printf 'Newer FreeBSD version for package curl:\\n- package: "
	    "1600010\\n- running kernel: 1600004\\nTo ignore this error set "
	    "IGNORE_OSVERSION=yes\\n' >&2; exit 1; }\n"
	    "case \"$1\" in\n"
	    "update) exit 0 ;;\n"
	    "query) printf 'aria2\\t1.37.0_1\\t0\\t5242880\\twww/aria2\\t"
	    "Download utility\\npimd\\t3.1.0\\t1\\t102400\\tnet/pimd\\t"
	    "PIM-SM daemon\\n' ;;\n"
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
	    /* The commit a clone is at; the head, from ./head. */
	    "[ \"$1\" = -C ] && [ \"$3\" = rev-parse ] && { cat head 2>/dev/null "
	    "|| echo 1111111111111111111111111111111111111111; exit 0; }\n"
	    "[ \"$1\" = ls-remote ] && { printf '%s\\tHEAD\\n' \"$(cat head "
	    "2>/dev/null || echo 1111111111111111111111111111111111111111)\"; "
	    "exit 0; }\n"
	    /* The log clone: made bare, fetched, read from ./log and ./tags. */
	    "[ \"$1\" = -C ] && [ \"$3\" = fetch ] && exit 0\n"
	    "[ \"$1\" = -C ] && [ \"$3\" = log ] && { cat commits 2>/dev/null; "
	    "exit 0; }\n"
	    "[ \"$1\" = -C ] && [ \"$3\" = for-each-ref ] && { cat tags "
	    "2>/dev/null; exit 0; }\n"
	    "[ \"$1\" = clone ] && [ \"$2\" = --bare ] && { for a; do last=$a; "
	    "done; mkdir -p \"$last\"; echo bare > \"$last/HEAD\"; exit 0; }\n"
	    "[ \"$1\" = clone ] || exit 2\n"
	    "for a; do last=$a; done\n"
	    "mkdir -p \"$last/lib/libjailconf\" \"$last/usr.sbin/arcana-agent\"\n");
	ATF_REQUIRE(chmod("fake-git", 0755) == 0);
	/* traceroute(8): the host itself first, then a hop that answers
	 * every other round, then the address. */
	put("fake-traceroute", "#!/bin/sh\nfor a; do last=$a; done\n"
	    "echo \" 1  127.0.0.1  0.100 ms\"\n"
	    "n=$(cat mtr.n 2>/dev/null || echo 0); n=$((n + 1)); echo $n > mtr.n\n"
	    "if [ $((n % 2)) = 0 ]; then echo \" 2  *\"; "
	    "else echo \" 2  198.51.100.1  5.000 ms\"; fi\n"
	    "echo \" 3  $last  9.500 ms\"\n");
	ATF_REQUIRE(chmod("fake-traceroute", 0755) == 0);
	/* setfib: the program run as it is, and said so. */
	put("fake-setfib", "#!/bin/sh\necho \"setfib $*\" >> setfib.log\n"
	    "shift 2\nexec \"$@\"\n");
	ATF_REQUIRE(chmod("fake-setfib", 0755) == 0);
	snprintf(buf, sizeof(buf), "#!/bin/sh\ndir=$2\ncase \" $* \" in\n"
	    "*\" -V .OBJDIR \"*) echo \"$dir/obj\" ;;\n"
	    "*/usr.sbin/arcana-agent*) mkdir -p \"$dir/obj\" && "
	    "cp '%s' \"$dir/obj/arcana-agent\" ;;\nesac\n", jgd);
	/* ssh-keyscan: the key ./hostkey.pub, made by the test that asks. */
	put("fake-keyscan", "#!/bin/sh\nfor a; do last=$a; done\n"
	    "echo \"$last $(cut -d' ' -f1,2 hostkey.pub)\"\n");
	ATF_REQUIRE(chmod("fake-keyscan", 0755) == 0);
	/* ifconfig(8), for changes: what it was run with. */
	put("fake-ifconfig", "#!/bin/sh\n"
	    "[ \"$*\" = -av ] && { cat ifconfig.out; exit 0; }\n"
	    "[ \"$2\" = addr ] && { printf '\\t02:00:00:00:00:01 Vlan10 "
	    "epair0a 1193 flags=0<>\\n'; exit 0; }\n"
	    "echo \"$*\" >> ifconfig.log\n"
	    "[ \"$2\" = create ] && echo \"$1\"\nexit 0\n");
	/* What ifconfig -a says: a bridge with its spanning tree and
	 * VLANs, a member with an address, and two geneve tunnels. */
	put("ifconfig.out",
	    "bridge0: flags=1008843<UP,BROADCAST,RUNNING> metric 0 mtu 1500\n"
	    "\tinet 10.7.0.1 netmask 0xffffff00 broadcast 10.7.0.255\n"
	    "\tid 58:9c:fc:10:ff:aa priority 32768 hellotime 2 fwddelay 15\n"
	    "\tmaxage 20 holdcnt 6 proto rstp maxaddr 2000 timeout 1200\n"
	    "\troot id 00:11:22:33:44:55 priority 4096 ifcost 2000 port 5\n"
	    "\tbridge flags=1<VLANFILTER> defuntagged=1\n"
	    "\tmember: epair5a flags=1c7<LEARNING,DISCOVER,STP,AUTOEDGE,PTP,"
	    "AUTOPTP>\n"
	    "\t        port 5 priority 128 path cost 2000 proto rstp\n"
	    "\t        role root state forwarding untagged 10\n"
	    "\tmember: em1 flags=143<LEARNING,DISCOVER,AUTOEDGE,AUTOPTP>\n"
	    "\t        port 6 priority 128 path cost 20000 vlan protocol "
	    "802.1q untagged 1 tagged 10-20,30\n"
	    "\tmember: tap3 flags=147<LEARNING,DISCOVER,STP,AUTOEDGE,AUTOPTP>\n"
	    "\t        port 7 priority 128 path cost 2000000 proto rstp\n"
	    "\t        role alternate state discarding\n"
	    "\tgroups: bridge\n"
	    "em1: flags=8863<UP,BROADCAST,RUNNING> metric 0 mtu 1500\n"
	    "\tinet 192.0.2.7 netmask 0xffffff00 broadcast 192.0.2.255\n"
	    "geneve0: flags=8843<UP,BROADCAST,RUNNING> metric 0 mtu 1450\n"
	    "\tgeneve mode: l2\n\tgeneve config:\n"
	    "\t\tvirtual network identifier (vni): 100\n"
	    "\t\tlocal: 198.51.100.10:6081\n"
	    "\t\tremote: 203.0.113.1:6081\n"
	    "\t\tportrange: 49152-65535, ttl: 64, df: unset\n"
	    "\t\tftable mode: learning, count: 2, max: 2000, timeout: 1200\n"
	    "geneve1: flags=8051<UP,POINTOPOINT,RUNNING> metric 0 mtu 1450\n"
	    "\tgeneve mode: l3\n\tgeneve config:\n"
	    "\t\tvirtual network identifier (vni): 42\n"
	    "\t\tlocal: [3fff::1]:6081\n"
	    "\t\tgroup: [ff08::db8:1]:6081, dev: em0\n"
	    "\t\tportrange: 49152-65535, ttl: inherit, dscp: inherit, df: "
	    "inherit\n");
	/* ipfw(8): its rules are canned, the rest is logged; a file it
	 * is to check is refused when it has the word bogus. */
	put("fake-ipfw", "#!/bin/sh\necho \"ipfw $*\" >> ipfw.log\n"
	    "[ \"$1\" = -q ] && [ -f \"$2\" ] && cat \"$2\" >> ipfw.log\n"
	    "case \"$*\" in\n"
	    "'-S show')\n"
	    "printf '00005     12      900 set 0 skipto 500 ip from any to "
	    "any out\\n'\n"
	    "printf '00020      1       60 set 0 call 9100 ip from any to "
	    "any in\\n'\n"
	    "printf '00200      0        0 set 0 check-state :default\\n'\n"
	    /* 1001 counts five packets more at each look. */
	    "n=$(cat hits 2>/dev/null || echo 3); echo $((n + 5)) > hits\n"
	    "printf '01001 %6d      180 set 0 allow tcp from any to me6 "
	    "22 in\\n' $n\n"
	    "printf '01999      9      540 set 0 return via any\\n'\n"
	    "printf '09100      0        0 set 0 deny udp from any 5678 to "
	    "any 5678 in\\n'\n"
	    "printf '65535     99     9999 set 31 deny ip from any to any"
	    "\\n' ;;\n"
	    "'table all info') printf -- '--- table(T46), set(0) ---\\n "
	    "kindex: 1, type: addr\\n' ;;\n"
	    "'table T46 list') printf -- '--- table(T46), set(0) ---\\n"
	    "10.0.0.0/8 0\\n192.0.2.0/24 0\\n' ;;\n"
	    "'-D show') printf '01001      7      560 (298s) STATE tcp "
	    "2001:db8::9 51234 <-> 2001:db8::1 22 :default\\n06101     12"
	    "     1440 (3s) STATE udp 10.0.0.5 5353 <-> 10.0.0.1 53 :default"
	    "\\n' ;;\n"
	    "'-n -q '*) grep -q bogus \"$3\" && { echo 'ipfw: line 2: bad "
	    "command bogus' >&2; exit 1; } ;;\n"
	    "'-q '*.arcana-load) cat \"$2\" > loaded.rules ;;\n"
	    "esac\nexit 0\n");
	ATF_REQUIRE(chmod("fake-ipfw", 0755) == 0);
	put("ipfw.rules", "add 00005 skipto 500 all from any to any out\n"
	    "add 00200 check-state\n"
	    "add 01001 allow tcp from any to me6 22 in\n"
	    "add 01002 allow tcp from any to me6 80 in\n"
	    "add 01999 return via any\n");
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
	    /* Each interface's line, then its peers: wg0 always, another
	     * where a peer was set on it. */
	    "'show all dump') printf 'wg0\\t%s\\t%s\\t51820\\toff\\n' "
	    "\"$key\" \"$pub\"\n"
	    "  cat wg.peers.wg0 2>/dev/null\n"
	    "  for f in wg.peers.*; do [ -f \"$f\" ] || continue; i=${f#wg.peers.}; "
	    "[ \"$i\" = wg0 ] && continue; printf '%s\\t%s\\t%s\\t51820\\toff\\n' "
	    "\"$i\" \"$key\" \"$pub\"; cat \"$f\"; done ;;\n"
	    "\"show $2 private-key\") echo \"$key\" ;;\n"
	    "\"showconf $2 \") printf '[Interface]\\nPrivateKey = %s\\n' "
	    "\"$key\" ;;\n"
	    "\"set $2 private-key\") cp \"$4\" wg.key ;;\n"
	    "\"set $2 peer\") [ \"$5\" = remove ] && rm -f wg.peers.$2 || "
	    "printf '%s\\t%s\\t(none)\\t192.0.2.9:51820\\t10.9.9.2/32\\t0"
	    "\\t0\\t0\\t0\\n' \"$2\" \"$4\" > wg.peers.$2 ;;\n"
	    "esac\nexit 0\n");
	put("fake-birdc", "#!/bin/sh\necho \"$*\" >> birdc.log\n"
	    "[ \"$1\" = -r ] && shift\n[ \"$1\" = -s ] && shift 2\n"
	    "case \"$*\" in\n"
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
	    "'show bfd sessions') printf 'bfd1:\\nIP address Interface State "
	    "Since Interval Timeout\\nfe80::2 gif0 Up 13:01:27.605 0.200 "
	    "1.000\\n' ;;\n"
	    "'show symbols table') printf 'master4 routing table\\nr4 routing "
	    "table\\n' ;;\n"
	    "'show route table master4 count') printf '845236 of 845236 routes "
	    "for 845233 networks in table master4\\n' ;;\n"
	    "'show route table r4 count') printf '512345 of 512345 routes for "
	    "512345 networks in table r4\\n' ;;\n"
	    "'configure confirm') printf 'BIRD 2.15.1 ready.\\nReconfiguration "
	    "confirmed\\n' ;;\n"
	    "configure*) printf 'BIRD 2.15.1 ready.\\nReading configuration "
	    "from bird.conf\\nReconfigured\\n' ;;\n"
	    "'show route for 10.1.2.3 count'|'show route protocol bgp_edge "
	    "count') printf '2 of 2 routes for 1 networks in table master4\\n' "
	    ";;\n"
	    "'show route for 10.1.2.3 all'|'show route for 10.1.2.3'|'show route "
	    "protocol bgp_edge') printf 'BIRD 2.15.1 ready.\\nTable master4:\\n"
	    "10.1.0.0/16          unicast [bgp_core 2026-10-01 from 192.0.2.1] "
	    "* (100) [AS65001i]\\n\\tvia 192.0.2.1 on em0\\n\\tBGP.as_path: "
	    "65001 65010\\n\\tBGP.large_community: (65001, 1, 100)\\n"
	    "                     unicast [bgp_edge 12:01:02.345] (100/20) "
	    "[AS65002?]\\n\\tvia 198.51.100.7 on gre0\\n' ;;\n"
	    "'show route protocol bgp_core count') printf '845233 of 845233 "
	    "routes for 845233 networks in table master4\\n' ;;\n"
	    "'show route'*count) printf '0 of 0 routes for 0 networks in table "
	    "master4\\n' ;;\n"
	    "'show route'*) printf 'BIRD 2.15.1 ready.\\nNetwork not found\\n' "
	    ";;\n"
	    "*) printf 'BIRD 2.15.1 ready.\\n%s: done\\n' \"$2\" ;;\n"
	    "esac\nexit 0\n");
	/* dnsmasq: --test takes any file; started by fake-setfib. */
	put("fake-dnsmasq", "#!/bin/sh\necho \"dnsmasq $*\" >> dnsmasq.log\n"
	    "exit 0\n");
	ATF_REQUIRE(chmod("fake-dnsmasq", 0755) == 0);
	put("fake-rtsol", "#!/bin/sh\necho \"rtsol $*\" >> rtsol.log\nexit 0\n");
	/* local-unbound: checkconf takes any file; started by fake-setfib. */
	put("fake-local-unbound", "#!/bin/sh\necho \"unbound $*\" >> "
	    "unbound.log\nexit 0\n");
	ATF_REQUIRE(chmod("fake-local-unbound", 0755) == 0);
	put("fake-local-unbound-checkconf", "#!/bin/sh\necho \"checkconf $*\" >> "
	    "unbound.log\nexit 0\n");
	ATF_REQUIRE(chmod("fake-local-unbound-checkconf", 0755) == 0);
	ATF_REQUIRE(chmod("fake-rtsol", 0755) == 0);
	put("fake-setkey", "#!/bin/sh\necho \"setkey $*\" >> setkey.log\n[ \"$1\" "
	    "= -f ] && cat \"$2\" >> setkey.conf\nexit 0\n");
	ATF_REQUIRE(chmod("fake-setkey", 0755) == 0);
	put("fake-bird", "#!/bin/sh\necho \"fake-bird $*\" >&2\n"
	    "grep -q BROKEN \"$3\" && { echo \"bird: $3:2:1 syntax error\" >&2; "
	    "exit 1; }\nexit 0\n");
	ATF_REQUIRE(chmod("fake-bird", 0755) == 0);
	/*
	 * Storage: zfs(8) and zpool(8) with a pool of their own to list,
	 * and with gpart, mount, umount and camcontrol logging what they
	 * are told; an fstab of the test's.
	 */
	put("fake-zfs", "#!/bin/sh\necho \"zfs $*\" >> storage.log\n"
	    "case \"$*\" in\n'list -Hp -t filesystem,volume'*)\n"
	    "printf 'tank\\tfilesystem\\t5000000\\t9000000\\t96000\\t/tank\\t"
	    "lz4\\t1.50\\t0\\t0\\tyes\\ton\\t-\\t-\\toff\\toff\\t-\\tnone\\toff\\n'\n"
	    "printf 'tank/data\\tfilesystem\\t4000000\\t9000000\\t4000000\\t"
	    "/tank/data\\tlz4\\t2.00\\t8000000\\t0\\tyes\\ton\\t-\\t-\\toff\\t"
	    "aes-256-gcm\\tunavailable\\tfile:///k\\toff\\n'"
	    "\nprintf 'tank/vol\\tvolume\\t100000\\t9000000\\t100000\\t-\\toff"
	    "\\t1.00\\t-\\t0\\t-\\t-\\ttank/data@a\\t1048576\\toff\\toff\\t-\\tnone"
	    "\\toff\\n' ;;\n"
	    "'list -Hp -t snapshot'*)\n"
	    "printf 'tank/data@b\\t10000\\t4000000\\t1759500000\\n'\n"
	    "printf 'tank/data@a\\t20000\\t3000000\\t1759400000\\n' ;;\n"
	    "'list -H -o name -s createtxg -t snapshot -d 1 tank/data') "
	    "printf 'tank/data@a\\ntank/data@b\\n' ;;\n"
	    /* A snapshot sent: what zsend.data has; received into a file. */
	    "send*) cat zsend.data ;;\n"
	    "'receive -u tank/fail') cat > /dev/null; echo \"cannot receive "
	    "new filesystem stream: destination 'tank/fail' exists\" >&2; "
	    "exit 1 ;;\n"
	    "'receive -u '*) cat > zrecv.data ;;\n"
	    "esac\nexit 0\n");
	put("fake-zpool", "#!/bin/sh\necho \"zpool $*\" >> storage.log\n"
	    "case \"$*\" in\n'list -Hp -o name,size,alloc,free,health') "
	    "printf 'tank\\t14000000\\t5000000\\t9000000\\tDEGRADED\\n' ;;\n"
	    "'list -Hp -o name,size,allocated'*) printf 'tank\\t14000000\\t"
	    "5000000\\t9000000\\t12\\t35\\t1.00\\tDEGRADED\\n' ;;\n"
	    "import) printf '   pool: spare\\n     id: 1234567890\\n  state: "
	    "ONLINE\\n' ;;\n"
	    "status) printf '  pool: tank\\n state: DEGRADED\\nstatus: One "
	    "device was taken offline.\\n  scan: scrub repaired 0B in "
	    "00:10:11 with 0 errors\\nconfig:\\n\\n\\tNAME        STATE     "
	    "READ WRITE CKSUM\\n\\ttank        DEGRADED     0     0     0\\n"
	    "\\t  mirror-0  DEGRADED     0     0     0\\n\\t    ada1p1  "
	    "ONLINE       0     0     0\\n\\t    ada2p1  OFFLINE      0     0"
	    "     0\\n\\nerrors: No known data errors\\n' ;;\nesac\nexit 0\n");
	put("fake-gpart", "#!/bin/sh\necho \"gpart $*\" >> storage.log\n"
	    "exit 0\n");
	put("fake-mount", "#!/bin/sh\necho \"mount $*\" >> storage.log\n"
	    "exit 0\n");
	put("fake-umount", "#!/bin/sh\necho \"umount $*\" >> storage.log\n"
	    "exit 0\n");
	put("fake-camcontrol", "#!/bin/sh\necho \"camcontrol $*\" >> "
	    "storage.log\nexit 0\n");
	ATF_REQUIRE(chmod("fake-zfs", 0755) == 0);
	ATF_REQUIRE(chmod("fake-zpool", 0755) == 0);
	ATF_REQUIRE(chmod("fake-gpart", 0755) == 0);
	ATF_REQUIRE(chmod("fake-mount", 0755) == 0);
	ATF_REQUIRE(chmod("fake-umount", 0755) == 0);
	ATF_REQUIRE(chmod("fake-camcontrol", 0755) == 0);
	put("fstab", "# Device\tMountpoint\tFStype\tOptions\tDump\tPass#\n"
	    "/dev/ada0p2\t/\tufs\trw\t1\t1\n/dev/ada0p3\t/mnt/data\tufs\t"
	    "rw,noatime\t2\t2\n");
	snprintf(fstab, sizeof(fstab), "%s/fstab", cwd);
	/* What the daemon has no option for: how the disks are, newfs. */
	ATF_REQUIRE(mkdir("tools", 0755) == 0 || errno == EEXIST);
	put("tools/nvmecontrol", "#!/bin/sh\nprintf 'Critical Warning State: "
	    "0x00\\nTemperature: 312 K\\nAvailable spare: 100\\nPercentage "
	    "used: 3\\nPower cycles: 120\\nPower on hours: 4567\\nUnsafe "
	    "shutdowns: 12\\nMedia errors: 0\\n'\n");
	put("tools/smartctl", "#!/bin/sh\n[ \"$4\" = /dev/da0 ] && { echo "
	    "'{\"smart_status\":{\"passed\":false},\"temperature\":"
	    "{\"current\":51},\"power_on_time\":{\"hours\":40000},"
	    "\"ata_smart_attributes\":{\"table\":[{\"id\":5,\"raw\":"
	    "{\"value\":88}}]}}'; exit 8; }\necho '{\"smart_status\":"
	    "{\"passed\":true},\"temperature\":{\"current\":34},"
	    "\"power_on_time\":{\"hours\":1200}}'\n");
	put("tools/newfs", "#!/bin/sh\necho \"newfs $*\" >> storage.log\n");
	/* squid(8), a plugin, and its certificate maker: what they were
	 * run with; a parse fails on BROKEN. */
	put("tools/squid", "#!/bin/sh\necho \"squid $*\" >> squid.log\n"
	    "[ \"$2\" = parse ] && { grep -q BROKEN \"$4\" && exit 1; exit 0; }\n"
	    "[ \"$1\" = -f ] && echo $$ > \"$(dirname \"$2\")/sdwan-proxy-sw1.pid\"\n"
	    "exit 0\n");
	put("tools/security_file_certgen", "#!/bin/sh\necho \"certgen $*\" >> "
	    "squid.log\nmkdir -p \"$3\"\n");
	/* c-icap, a plugin: started, it stays a while with its pid file
	 * where its configuration says. */
	put("tools/c-icap", "#!/bin/sh\necho \"c-icap $*\" >> squid.log\n"
	    "p=$(sed -n 's/^PidFile //p' \"$2\")\n"
	    "sleep 60 > /dev/null 2>&1 &\necho $! > \"$p\"\nexit 0\n");
	/* suricata, a plugin: checked, it takes all; run, it stays a while
	 * with its pid file where it is told. */
	put("tools/suricata", "#!/bin/sh\necho \"suricata $*\" >> squid.log\n"
	    "[ \"$1\" = -T ] && exit 0\n"
	    "sleep 60 > /dev/null 2>&1 &\necho $! > \"$4\"\nexit 0\n");
	put("tools/growfs", "#!/bin/sh\necho \"growfs $*\" >> storage.log\n");
	put("tools/swapon", "#!/bin/sh\necho \"swapon $*\" >> storage.log\n");
	put("tools/swapoff", "#!/bin/sh\necho \"swapoff $*\" >> storage.log\n");
	put("tools/fstyp", "#!/bin/sh\nexit 1\n");
	/* dtrace(1), told of a packet ipfw passed. */
	put("tools/dtrace", "#!/bin/sh\ncat \"$3\" > trace.d\necho 'P 3 0 "
	    "10.0.0.2 10.0.0.1 6 4000 22 100 em0 1'\n");
	ATF_REQUIRE(system("chmod +x tools/*") == 0);
	/* kldload(8) and kldunload(8): what they were told is logged. */
	put("fake-kldload", "#!/bin/sh\necho \"kldload $*\" >> kld.log\n"
	    "exit 0\n");
	put("fake-kldunload", "#!/bin/sh\necho \"kldunload $*\" >> kld.log\n"
	    "[ \"$1\" = zfs ] && { echo \"kldunload: can't unload file: Device "
	    "busy\" >&2; exit 1; }\nexit 0\n");
	/* sysctl(8), to set one, and the file that keeps them. */
	put("fake-sysctl", "#!/bin/sh\necho \"sysctl $*\" >> kld.log\n"
	    "[ \"$1\" = kern.nosuch=1 ] && { echo \"sysctl: unknown oid "
	    "'kern.nosuch'\" >&2; exit 1; }\nexit 0\n");
	ATF_REQUIRE(chmod("fake-sysctl", 0755) == 0);
	put("sysctl.conf", "# kept\nkern.ipc.somaxconn=1024\n");
	/* What syslogd(8) wrote, in both of its forms. */
	ATF_REQUIRE(mkdir("log", 0755) == 0 || errno == EEXIST);
	put("log/messages", "Oct  5 12:00:01 web1 kernel: em0: link state "
	    "changed to UP\nOct  5 12:00:02 web1 sshd[812]: Accepted "
	    "publickey for root from 2001:db8::9 port 51234\n"
	    "2026-10-05T12:00:03.123456+03:30 web1 cron 933 - - (root) CMD "
	    "(/usr/libexec/atrun)\n");
	put("log/auth.log", "Oct  5 11:00:00 web1 su[77]: BAD SU alice to "
	    "root on /dev/pts/1\n");
	/* And the jail's own, beneath its root. */
	ATF_REQUIRE(mkdir("jroot/log", 0755) == 0 || errno == EEXIST);
	put("jroot/log/messages", "Oct  5 12:00:05 gw sshd[9]: the jail's "
	    "own line\n");
	ATF_REQUIRE(chmod("fake-kldload", 0755) == 0);
	ATF_REQUIRE(chmod("fake-kldunload", 0755) == 0);
	ATF_REQUIRE(mkdir("bird", 0755) == 0 || errno == EEXIST);
	put("bird/bird.conf", "# The lab's routing.\nrouter id 192.0.2.1;\n\n"
	    "define MY_AS = 65000;\ndefine CUSTOMERS = [ (65000,100), "
	    "(65000,200) ];\ndefine BLACKHOLE_LC = [ (65000,666,0) ];\n"
	    "define PEERS = [\n\t# the exchange\n\t(65000,300), # ix-a\n"
	    "\t(65000,301) /* ix-b */\n];\n\n"
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
	/*
	 * swanctl(8): strongSwan running, its connections those written in
	 * conf.d, as list-conns says them, and one SA up.
	 */
	put("fake-swanctl", "#!/bin/sh\necho \"$*\" >> swanctl.log\n"
	    "case \"$1\" in\n"
	    "--list-conns) for f in swanctl/conf.d/arcana-*.conf; do\n"
	    "  [ -f \"$f\" ] || continue; n=${f##*/arcana-}; n=${n%.conf}\n"
	    "  l=$(sed -n 's/^.*local_addrs = //p' \"$f\")\n"
	    "  r=$(sed -n 's/^.*remote_addrs = //p' \"$f\")\n"
	    "  kids=$(awk '/^\t\t\t[A-Za-z0-9_-]+ \\{$/ { k = $1 } "
	    "/^\t\t\t\tmode = / { printf \"      %s {\\n        mode = %s\\n"
	    "      }\\n\", k, toupper($3) }' \"$f\")\n"
	    "  printf 'list-conn event {\\n  %s {\\n    local_addrs = [\\n"
	    "      %s\\n    ]\\n    remote_addrs = [\\n      %s\\n    ]\\n"
	    "    version = IKEv2\\n    children {\\n%s\\n    }\\n  }\\n}\\n' "
	    "\"$n\" \"$l\" \"$r\" \"$kids\"\n"
	    "done ;;\n"
	    "--list-sas) [ -f swanctl/conf.d/arcana-to-lab2.conf ] && printf "
	    "'list-sa event {\\n  to-lab2 {\\n    state = ESTABLISHED\\n"
	    "    encr-alg = AES_GCM_16\\n    child-sas {\\n      to-lab2-1 {"
	    "\\n        name = to-lab2\\n        state = INSTALLED\\n"
	    "        mode = TRANSPORT\\n        reqid = 1\\n"
	    "        bytes-in = 2048\\n        bytes-out = 4096\\n      }"
	    "\\n    }\\n  }\\n}\\n' ;;\n"
	    "esac\nexit 0\n");
	ATF_REQUIRE(chmod("fake-swanctl", 0755) == 0);
	ATF_REQUIRE(mkdir("swanctl", 0755) == 0 || errno == EEXIST);
	ATF_REQUIRE(mkdir("swanctl/conf.d", 0755) == 0 || errno == EEXIST);
	ATF_REQUIRE(mkdir("swanctl/pkcs8", 0700) == 0 || errno == EEXIST);
	ATF_REQUIRE(mkdir("swanctl/pubkey", 0755) == 0 || errno == EEXIST);
	/* A peer's certificate and a CA, for a connection to pick. */
	ATF_REQUIRE(mkdir("swanctl/x509", 0755) == 0 || errno == EEXIST);
	ATF_REQUIRE(mkdir("swanctl/x509ca", 0755) == 0 || errno == EEXIST);
	ATF_REQUIRE(system("openssl req -x509 -newkey ec -pkeyopt "
	    "ec_paramgen_curve:P-256 -nodes -keyout peer.key -out "
	    "swanctl/x509/edge-b.pem -days 30 -subj '/CN=edge-b.example' "
	    "-addext 'basicConstraints=CA:FALSE' "
	    "-addext 'subjectAltName=DNS:edge-b.example' >/dev/null 2>&1 && "
	    "openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 "
	    "-nodes -keyout ca.key -out swanctl/x509ca/lab-ca.pem -days 30 "
	    "-subj '/CN=Lab CA' -addext 'basicConstraints=critical,CA:TRUE' "
	    ">/dev/null 2>&1") == 0);
	ATF_REQUIRE(chmod("fake-wg", 0755) == 0);
	ATF_REQUIRE(chmod("fake-birdc", 0755) == 0);
	ATF_REQUIRE(mkdir("wg", 0700) == 0 || errno == EEXIST);
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
	argv[32] = (char *)(uintptr_t)"-n";
	argv[33] = (char *)(uintptr_t)"./fake-ngctl";
	argv[34] = (char *)(uintptr_t)"-k";
	argv[35] = (char *)(uintptr_t)"./fake-wg";
	argv[36] = (char *)(uintptr_t)"-o";
	argv[37] = (char *)(uintptr_t)"./wg";
	argv[38] = (char *)(uintptr_t)"-b";
	argv[39] = (char *)(uintptr_t)"./fake-birdc";
	argv[40] = (char *)(uintptr_t)"-e";
	argv[41] = (char *)(uintptr_t)"./fake-bird";
	argv[42] = (char *)(uintptr_t)"-a";
	argv[43] = birdconf;
	argv[44] = (char *)(uintptr_t)"-L";
	argv[45] = (char *)(uintptr_t)"./fake-jls";
	argv[46] = (char *)(uintptr_t)"-x";
	argv[47] = (char *)(uintptr_t)"./fake-jexec";
	argv[48] = (char *)(uintptr_t)"-H";
	argv[49] = (char *)(uintptr_t)"./fake-helper";
	argv[50] = (char *)(uintptr_t)"-T";
	argv[51] = (char *)(uintptr_t)"./fake-kldload";
	argv[52] = (char *)(uintptr_t)"-t";
	argv[53] = (char *)(uintptr_t)"./fake-kldunload";
	argv[54] = (char *)(uintptr_t)"-z";
	argv[55] = (char *)(uintptr_t)"./fake-zfs";
	argv[56] = (char *)(uintptr_t)"-Z";
	argv[57] = (char *)(uintptr_t)"./fake-zpool";
	argv[58] = (char *)(uintptr_t)"-q";
	argv[59] = (char *)(uintptr_t)"./fake-gpart";
	argv[60] = (char *)(uintptr_t)"-m";
	argv[61] = (char *)(uintptr_t)"./fake-mount";
	argv[62] = (char *)(uintptr_t)"-u";
	argv[63] = (char *)(uintptr_t)"./fake-umount";
	argv[64] = (char *)(uintptr_t)"-i";
	argv[65] = (char *)(uintptr_t)"./fake-camcontrol";
	argv[66] = (char *)(uintptr_t)"-S";
	argv[67] = fstab;
	argv[68] = (char *)(uintptr_t)"-Q";
	argv[69] = (char *)(uintptr_t)"./fake-sysctl";
	argv[70] = (char *)(uintptr_t)"-O";
	argv[71] = (char *)(uintptr_t)"sysctl.conf";
	argv[72] = (char *)(uintptr_t)"-h";
	argv[73] = (char *)(uintptr_t)"./fake-ipfw";
	argv[74] = (char *)(uintptr_t)"-J";
	argv[75] = (char *)(uintptr_t)"ipfw.rules";
	argv[76] = (char *)(uintptr_t)"-v";
	argv[77] = (char *)(uintptr_t)"log";
	argv[78] = (char *)(uintptr_t)"-1";
	argv[79] = (char *)(uintptr_t)"history.conf";
	argv[80] = (char *)(uintptr_t)"-2";
	argv[81] = (char *)(uintptr_t)"tools";
	argv[82] = (char *)(uintptr_t)"-r";
	argv[83] = (char *)(uintptr_t)"./fake-swanctl";
	argv[84] = (char *)(uintptr_t)"-5";
	argv[85] = (char *)(uintptr_t)"swanctl";
	argv[86] = (char *)(uintptr_t)"-X";
	argv[87] = (char *)(uintptr_t)"./fake-traceroute";
	argv[88] = (char *)(uintptr_t)"-3";
	argv[89] = (char *)(uintptr_t)"./fake-setfib";
	argv[90] = (char *)(uintptr_t)"-4";
	argv[91] = ntpconf;
	argv[92] = (char *)(uintptr_t)"-6";
	argv[93] = rtadvdconf;
	argv[94] = (char *)(uintptr_t)"-7";
	argv[95] = (char *)(uintptr_t)"./fake-dnsmasq";
	argv[96] = (char *)(uintptr_t)"-8";
	argv[97] = (char *)(uintptr_t)"./fake-rtsol";
	argv[98] = (char *)(uintptr_t)"-9";
	argv[99] = (char *)(uintptr_t)"./fake-setkey";
	argv[100] = (char *)(uintptr_t)"-0";
	argv[101] = (char *)(uintptr_t)"./fake-local-unbound";
	argv[102] = NULL;
	snprintf(rcd, sizeof(rcd), "%s/rc.d", cwd);
	snprintf(ntpconf, sizeof(ntpconf), "%s/ntp.conf", cwd);
	snprintf(rtadvdconf, sizeof(rtadvdconf), "%s/rtadvd.conf", cwd);
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
 * A WebSocket to the console at path, as the page opens one: with the
 * session and the console's Origin.  The socket, upgraded.
 */
int
ws_open(const char *path)
{
	char	req[1024], buf[2048];
	size_t	len;
	ssize_t	n;
	int	s;

	s = console_socket();
	snprintf(req, sizeof(req), "GET %s HTTP/1.1\r\nHost: localhost:8443\r\n"
	    "Upgrade: websocket\r\nConnection: Upgrade\r\n"
	    "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
	    "Sec-WebSocket-Version: 13\r\nOrigin: %s\r\nCookie: %s\r\n\r\n",
	    path, harness_origin, cookie);
	ATF_REQUIRE(write(s, req, strlen(req)) == (ssize_t)strlen(req));
	/* The answer's head, a byte at a time: frames may follow it. */
	len = 0;
	while (len < sizeof(buf) - 1 && (len < 4 || memcmp(buf + len - 4,
	    "\r\n\r\n", 4) != 0)) {
		if ((n = read(s, buf + len, 1)) <= 0)
			break;
		len++;
	}
	buf[len] = '\0';
	ATF_REQUIRE_MSG(strncmp(buf, "HTTP/1.1 101", 12) == 0, "not upgraded: "
	    "%.80s", buf);
	return (s);
}

/* One text frame to the console, masked as a client's must be. */
void
ws_send(int s, const char *text)
{
	unsigned char	 hdr[14], mask[4] = { 0x12, 0x34, 0x56, 0x78 };
	unsigned char	*body;
	size_t		 len, h, i;

	len = strlen(text);
	hdr[0] = 0x81;
	if (len < 126) {
		hdr[1] = 0x80 | (unsigned char)len;
		h = 2;
	} else {
		hdr[1] = 0x80 | 126;
		hdr[2] = (unsigned char)(len >> 8);
		hdr[3] = (unsigned char)len;
		h = 4;
	}
	memcpy(hdr + h, mask, 4);
	h += 4;
	ATF_REQUIRE((body = malloc(len)) != NULL);
	for (i = 0; i < len; i++)
		body[i] = (unsigned char)text[i] ^ mask[i % 4];
	ATF_REQUIRE(write(s, hdr, h) == (ssize_t)h);
	ATF_REQUIRE(write(s, body, len) == (ssize_t)len);
	free(body);
}

static bool
read_full(int s, void *p, size_t len)
{
	size_t	got;
	ssize_t	n;

	for (got = 0; got < len; got += (size_t)n)
		if ((n = read(s, (char *)p + got, len - got)) <= 0)
			return (false);
	return (true);
}

/* The next text frame from the console, whole; NULL when it is closed. */
char *
ws_recv(int s)
{
	unsigned char	 hdr[8];
	uint64_t	 len;
	char		*text;
	int		 k;

	for (;;) {
		if (!read_full(s, hdr, 2))
			return (NULL);
		len = hdr[1] & 0x7f;
		if (len == 126) {
			if (!read_full(s, hdr + 2, 2))
				return (NULL);
			len = ((uint64_t)hdr[2] << 8) | hdr[3];
		} else if (len == 127) {
			if (!read_full(s, hdr, 8))
				return (NULL);
			for (len = 0, k = 0; k < 8; k++)
				len = (len << 8) | hdr[k];
		}
		ATF_REQUIRE(len < 64 * 1024 * 1024);
		ATF_REQUIRE((text = malloc(len + 1)) != NULL);
		if (!read_full(s, text, len)) {
			free(text);
			return (NULL);
		}
		text[len] = '\0';
		/* A ping, a pong: not what is asked for. */
		if ((hdr[0] & 0x0f) == 0x1)
			return (text);
		free(text);
		if ((hdr[0] & 0x0f) == 0x8)
			return (NULL);
	}
}

/* One request with an API token and no session, as a program asks. */
void
http_bearer(const char *method, const char *path, const char *token,
    const char *body, struct resp *r)
{
	char	hdrs[1024];

	snprintf(hdrs, sizeof(hdrs), "%sAuthorization: Bearer %s\r\n",
	    send_xjg ? "X-Arcana: 1\r\n" : "", token);
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

	int			 attempt;

	memset(r, 0, sizeof(*r));
	ATF_REQUIRE(asprintf(&req, "%s %s HTTP/1.1\r\nHost: %s\r\n"
	    "Connection: close\r\n%sContent-Type: application/json\r\n"
	    "Content-Length: %zu\r\n\r\n%s", method, path, host, hdrs,
	    body != NULL ? strlen(body) : 0, body != NULL ? body : "") != -1);
	attempt = 0;
again:
	ATF_REQUIRE(write(s, req, strlen(req)) == (ssize_t)strlen(req));

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
	/*
	 * Nothing at all: the connection was dropped before it was read,
	 * which a busy worker does now and then under the whole suite.
	 * Once more, on a new connection, when the console is asked.
	 */
	if (len == 0 && attempt++ < 2 && strcmp(host, "localhost:8443") == 0) {
		fprintf(stderr, "%s %s: no answer, asked again\n", method, path);
		free(buf);
		s = console_socket();
		goto again;
	}
	free(req);
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

