/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * What the console's tests share: starting arcana-console(8) and an
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
char		 harness_server[1024];	/* and inside its server { } */
static char	 console_path[MAXPATHLEN];

static void	 terminate(const char *);
/* The console sends another build of arcana-agent than the host runs. */
bool		 harness_other_agent;
bool		 harness_newer_agent;
/* The agent beside the console is looked for, as outside the tests. */
bool		 harness_local_agent;
/* web.conf's local_agent is the test's own line. */
bool		 harness_webconf_only_local;
char		 harness_telegram_api[128];	/* the agent's Bot API, or "" */

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
 * when the body returns, before the cleanup's stop() has ended it.
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
	show("console.out");
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
 * The servers of an earlier test that never ran its cleanup (its kyua
 * killed, or the program run by hand) stay, each in its process group,
 * init's now, and load every test after: an arcana-agent on a test's
 * jgd.sock, arcana-console, chromedriver and its browsers.  A
 * test's own servers are its children, so those of tests running now
 * are left be.  Only the user's own processes are looked at.
 */
static void
sweep_orphans(void)
{

	/* The console names its supervisor "arcana-console: supervisor". */
	(void)system("ps -ax -o pid=,ppid=,pgid=,command= -U \"$(id -u)\" | "
	    "awk '$2 == 1 && ($0 ~ /arcana-agent -F -l unix:.*jgd[0-9]*\\.sock/ "
	    "|| $4 == \"arcana-console:\" && $5 == \"supervisor\" || $4 ~ /chromedriver$/ "
	    "&& $5 ~ /^--port=/) { print $3 }' | sort -u | "
	    "while read g; do kill -TERM -\"$g\" 2>/dev/null; done");
}

/*
 * arcana-agent on ./jgd.sock with a lab configuration and a stand-in for
 * jail(8), and the console on ./k.sock.  Their pids go to files for
 * cleanup.
 */
void
start(const atf_tc_t *tc, int port, const char *webroot)
{
	char	 cwd[MAXPATHLEN], buf[4096], console[MAXPATHLEN];
	char	 jgd[MAXPATHLEN], listen[MAXPATHLEN + 16], www[MAXPATHLEN];
	char	 send[MAXPATHLEN];
	char	 rcd[MAXPATHLEN], birdconf[MAXPATHLEN], local[MAXPATHLEN];
	char	 ntpconf[MAXPATHLEN], rtadvdconf[MAXPATHLEN], rootdir[MAXPATHLEN];
	char	 fstab[MAXPATHLEN], pdetc[MAXPATHLEN], surules[MAXPATHLEN];
	char	*argv[132];
	FILE	*fp;
	pid_t	 pid;

	sweep_orphans();
	ATF_REQUIRE(getcwd(cwd, sizeof(cwd)) != NULL);
	snprintf(jgd, sizeof(jgd), "%s", locate(tc,
	    "../../../usr.sbin/arcana-agent/arcana-agent", "arcana-agent",
	    "/usr/local/sbin/arcana-agent"));
	snprintf(console, sizeof(console), "%s", locate(tc, "../arcana-console",
	    "arcana-console", "/usr/local/sbin/arcana-console"));
	ATF_REQUIRE_MSG(access(console, X_OK) == 0, "no arcana-console at %s",
	    console);
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
	/* The jail's /var/run is beneath its root here: what a program is
	 * given there, it finds. */
	snprintf(buf, sizeof(buf), "#!/bin/sh\necho \"jexec $*\" >> jexec.log\n"
	    "shift\nn=0; for a; do case \"$a\" in /var/run/*) a=%s/jroot$a ;; "
	    "esac; set -- \"$@\" \"$a\"; n=$((n+1)); done\nshift $n\n"
	    "exec \"$@\"\n", cwd);
	put("fake-jexec", buf);
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
	ATF_REQUIRE(mkdir("jroot/var", 0755) == 0 || errno == EEXIST);
	ATF_REQUIRE(mkdir("jroot/var/run", 0755) == 0 || errno == EEXIST);
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
	    "[ \"$1\" = -f ] && { conf=$2; touch \"$conf\"; shift 2; }\n"
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
	    "r=$1; [ \"$1\" = speederv2 ] && r=$1${3:+-$3}\n"
	    "case \"$2\" in\n"
	    "rcvar) echo \"${1}_enable=\\\"NO\\\"\" ;;\n"
	    "enabled) grep -q \"^${1}_enable=\\\"YES\\\"\" \"$conf\" ;;\n"
	    "status|onestatus) while [ -f hold.status ]; do sleep 0.1; done; "
	    "[ -f running.$r ] && { echo \"$r is running as pid 7.\"; "
	    "exit 0; }; echo \"$r is not running.\"; exit 1 ;;\n"
	    "start|onestart|restart|onerestart) [ -f slow ] && sleep 3; "
	    "touch running.$r ;;\n"
	    "stop|onestop) rm -f running.$r ;;\n"
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
	    "{ [ \"$1\" = upgrade ] || [ \"$1\" = version ]; } && [ -f newer-os ] "
	    "&& [ $anyos = no ] && "
	    "{ printf 'Newer FreeBSD version for package curl:\\n- package: "
	    "1600010\\n- running kernel: 1600004\\nTo ignore this error set "
	    "IGNORE_OSVERSION=yes\\nError updating repositories!\\n'; "
	    "echo 'pkg: repository FreeBSD-ports contains packages for wrong "
	    "OS version: FreeBSD:16:amd64' >&2; exit 3; }\n"
	    "case \"$1\" in\n"
	    /* Its repositories, as pkg -vv says them. */
	    "-vv) printf 'Repositories:\\n  FreeBSD-ports: { \\n    url : "
	    "\\\"pkg+https://pkg.FreeBSD.org/latest\\\",\\n    enabled : yes,"
	    "\\n  }\\n  builder: { \\n    url : \\\"file:///usr/local/"
	    "poudriere/data/packages/lab\\\",\\n    enabled : no,\\n  }"
	    "\\n' ;;\n"
	    "update) exit 0 ;;\n"
	    "query) printf 'aria2\\t1.37.0_1\\t0\\t5242880\\twww/aria2\\t"
	    "Download utility\\npimd\\t3.1.0\\t1\\t102400\\tnet/pimd\\t"
	    "PIM-SM daemon\\n' ;;\n"
	    "version) [ -s pending ] || exit 1; while read nv r; do "
	    "printf '%s < needs updating (remote has %s)\\n' \"$nv\" \"$r\"; "
	    "done < pending ;;\n"
	    "upgrade) shift; [ \"$1\" = -r ] && shift 2; d=no; "
	    "[ \"$1\" = -n ] && d=yes; shift; "
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
	    /* ./slow: the head is a while coming. */
	    "[ \"$1\" = ls-remote ] && [ -f slow ] && sleep 6\n"
	    "[ \"$1\" = ls-remote ] && { printf '%s\\tHEAD\\n' \"$(cat head "
	    "2>/dev/null || echo 1111111111111111111111111111111111111111)\"; "
	    "exit 0; }\n"
	    /* The log clone: made bare, fetched, read from ./log and ./tags. */
	    "[ \"$1\" = -C ] && [ \"$3\" = config ] && exit 0\n"
	    "[ \"$1\" = -C ] && [ \"$3\" = fetch ] && { [ -f fetch-fails ] && "
	    "{ echo 'No ED25519 host key is known for git.example.org and you "
	    "have requested strict checking.' >&2; exit 128; }; exit 0; }\n"
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
	    "*\" showconfig \"*|*\" -V OPTIONS_FILE \"*) exec /usr/bin/make "
	    "\"$@\" ;;\n"
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
	    "'list 1001') printf '01001 allow tcp from any to me6 22 in\\n' "
	    ";;\n"
	    /* What path-check walks: the same rules, without counters; the
	     * troubleshoot lab's host (ts_net) has its own, fw-0.list. */
	    "'list') [ -f fw-0.list ] && { cat fw-0.list; exit 0; }; "
	    "printf '00005 skipto 500 ip from any to any out\\n00020 "
	    "call 9100 ip from any to any in\\n00200 check-state :default\\n"
	    "01001 allow tcp from any to me6 22 in\\n01999 return via any\\n"
	    "09100 deny udp from any 5678 to any 5678 in\\n65535 deny ip from "
	    "any to any\\n' ;;\n"
	    "'table all info') printf -- '--- table(T46), set(0) ---\\n "
	    "kindex: 1, type: addr\\n' ;;\n"
	    "'table T46 list') printf -- '--- table(T46), set(0) ---\\n"
	    "10.0.0.0/8 0\\n192.0.2.0/24 0\\n' ;;\n"
	    /* dummynet, as a FreeBSD 16 lab printed it. */
	    "'pipe show') printf '00001:  10.000 Mbit/s   20 ms burst 0 \\n"
	    "q131073  30 sl.plr 0.010000 0 flows (1 buckets) sched 65537 "
	    "weight 0 lmax 0 pri 0 droptail\\n sched 65537 type FIFO flags "
	    "0x1 64 buckets 0 active\\n    mask:  0x00 0x00000000/0x0000 -> "
	    "0xffffffff/0x0000\\n' ;;\n"
	    "'sched show') printf '00001:  10.000 Mbit/s   20 ms burst 0 \\n"
	    " sched 1 type WF2Q+ flags 0x1 64 buckets 0 active\\n    mask:  "
	    "0x00 0xffffff00/0x0000 -> 0x00000000/0x0000\\n   Children "
	    "flowsets: 2 \\n' ;;\n"
	    "'queue show') printf 'q00002  50 sl. 0 flows (1 buckets) sched 1 "
	    "weight 30 lmax 0 pri 0 droptail\\n' ;;\n"
	    "'-D show') printf '01001      7      560 (298s) STATE tcp "
	    "2001:db8::9 51234 <-> 2001:db8::1 22 :default\\n06101     12"
	    "     1440 (3s) STATE udp 10.0.0.5 5353 <-> 10.0.0.1 53 :default"
	    "\\n' ;;\n"
	    "'-n -q '*) grep -q bogus \"$3\" && { echo 'ipfw: line 2: bad "
	    "command bogus' >&2; exit 1; } ;;\n"
	    /* Rules read back as ipfw writes them (ipfw -n), a line out
	     * for a line in; set 0's rules listed; a script logged. */
	    "'-n /dev/stdin') sed -e 's/^add //' -e 's/ all / ip /g' ;;\n"
	    "'-S list') printf '00005 set 0 skipto 500 ip from any to any "
	    "out\\n00020 set 0 call 9100 ip from any to any in\\n00200 set 0 "
	    "check-state :default\\n01001 set 0 allow tcp from any to me6 22 "
	    "in\\n01999 set 0 return via any\\n09100 set 0 deny udp from any "
	    "5678 to any 5678 in\\n65535 set 31 deny ip from any to any\\n' ;;\n"
	    "'-S list '*) n=$(printf %05d \"$3\"); $0 -S list | grep \"^$n \" || "
	    "{ echo \"ipfw: rule $3 does not exist\" >&2; } ;;\n"
	    "'-q /dev/stdin') cat >> ipfw.log ;;\n"
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
	/*
	 * bird(8)'s check of a configuration (-p): where the host has
	 * BIRD, its own parser says, so that what the forms write is
	 * BIRD's language for real; each so checked is logged.
	 */
	put("fake-bird", "#!/bin/sh\necho \"fake-bird $*\" >&2\n"
	    "grep -q BROKEN \"$3\" && { echo \"bird: $3:2:1 syntax error\" >&2; "
	    "exit 1; }\n"
	    "if [ \"$1\" = -p ] && [ -x /usr/local/sbin/bird ]; then\n"
	    "\t/usr/local/sbin/bird -p -c \"$3\" || exit 1\n"
	    "\techo \"$3\" >> bird-real.log\nfi\nexit 0\n");
	ATF_REQUIRE(chmod("fake-bird", 0755) == 0);
	/*
	 * Storage: zfs(8) and zpool(8) with a pool of their own to list,
	 * and with gpart, mount, umount and camcontrol logging what they
	 * are told; an fstab of the test's.
	 */
	put("fake-zfs", "#!/bin/sh\necho \"zfs $*\" >> storage.log\n"
	    "case \"$*\" in\n'list -j -p -t filesystem,volume'*)\n"
	    "printf '%s\\n' '{\"output_version\":{\"command\":\"zfs list\",\"vers_major\":0,\"vers_minor\":1},\"datasets\":{\"tank\":{\"name\":\"tank\",\"type\":\"FILESYSTEM\",\"pool\":\"tank\",\"properties\":{\"type\":{\"value\":\"filesystem\"},\"used\":{\"value\":\"5000000\"},\"available\":{\"value\":\"9000000\"},\"referenced\":{\"value\":\"96000\"},\"mountpoint\":{\"value\":\"/tank\"},\"compression\":{\"value\":\"lz4\"},\"compressratio\":{\"value\":\"1.50\"},\"quota\":{\"value\":\"0\"},\"reservation\":{\"value\":\"0\"},\"mounted\":{\"value\":\"yes\"},\"canmount\":{\"value\":\"on\"},\"origin\":{\"value\":\"-\"},\"volsize\":{\"value\":\"-\"},\"readonly\":{\"value\":\"off\"},\"encryption\":{\"value\":\"off\"},\"keystatus\":{\"value\":\"-\"},\"keylocation\":{\"value\":\"none\"},\"jailed\":{\"value\":\"off\"}}},\"tank/data\":{\"name\":\"tank/data\",\"type\":\"FILESYSTEM\",\"pool\":\"tank\",\"properties\":{\"type\":{\"value\":\"filesystem\"},\"used\":{\"value\":\"4000000\"},\"available\":{\"value\":\"9000000\"},\"referenced\":{\"value\":\"4000000\"},\"mountpoint\":{\"value\":\"/tank/data\"},\"compression\":{\"value\":\"lz4\"},\"compressratio\":{\"value\":\"2.00\"},\"quota\":{\"value\":\"8000000\"},\"reservation\":{\"value\":\"0\"},\"mounted\":{\"value\":\"yes\"},\"canmount\":{\"value\":\"on\"},\"origin\":{\"value\":\"-\"},\"volsize\":{\"value\":\"-\"},\"readonly\":{\"value\":\"off\"},\"encryption\":{\"value\":\"aes-256-gcm\"},\"keystatus\":{\"value\":\"unavailable\"},\"keylocation\":{\"value\":\"file:///k\"},\"jailed\":{\"value\":\"off\"}}},\"tank/vault\":{\"name\":\"tank/vault\",\"type\":\"FILESYSTEM\",\"pool\":\"tank\",\"properties\":{\"type\":{\"value\":\"filesystem\"},\"used\":{\"value\":\"2000000\"},\"available\":{\"value\":\"9000000\"},\"referenced\":{\"value\":\"2000000\"},\"mountpoint\":{\"value\":\"/tank/vault\"},\"compression\":{\"value\":\"lz4\"},\"compressratio\":{\"value\":\"1.00\"},\"quota\":{\"value\":\"0\"},\"reservation\":{\"value\":\"0\"},\"mounted\":{\"value\":\"no\"},\"canmount\":{\"value\":\"on\"},\"origin\":{\"value\":\"-\"},\"volsize\":{\"value\":\"-\"},\"readonly\":{\"value\":\"off\"},\"encryption\":{\"value\":\"aes-256-gcm\"},\"keystatus\":{\"value\":\"unavailable\"},\"keylocation\":{\"value\":\"prompt\"},\"jailed\":{\"value\":\"off\"}}},\"tank/vol\":{\"name\":\"tank/vol\",\"type\":\"VOLUME\",\"pool\":\"tank\",\"properties\":{\"type\":{\"value\":\"volume\"},\"used\":{\"value\":\"100000\"},\"available\":{\"value\":\"9000000\"},\"referenced\":{\"value\":\"100000\"},\"mountpoint\":{\"value\":\"-\"},\"compression\":{\"value\":\"off\"},\"compressratio\":{\"value\":\"1.00\"},\"quota\":{\"value\":\"-\"},\"reservation\":{\"value\":\"0\"},\"mounted\":{\"value\":\"-\"},\"canmount\":{\"value\":\"-\"},\"origin\":{\"value\":\"tank/data@a\"},\"volsize\":{\"value\":\"1048576\"},\"readonly\":{\"value\":\"off\"},\"encryption\":{\"value\":\"off\"},\"keystatus\":{\"value\":\"-\"},\"keylocation\":{\"value\":\"none\"},\"jailed\":{\"value\":\"off\"}}}}}' ;;\n"
	    "'list -j -p -t snapshot'*)\n"
	    "printf '%s\\n' '{\"output_version\":{\"command\":\"zfs list\",\"vers_major\":0,\"vers_minor\":1},\"datasets\":{\"tank/data@b\":{\"name\":\"tank/data@b\",\"type\":\"SNAPSHOT\",\"pool\":\"tank\",\"properties\":{\"used\":{\"value\":\"10000\"},\"referenced\":{\"value\":\"4000000\"},\"creation\":{\"value\":\"1759500000\"}}},\"tank/data@a\":{\"name\":\"tank/data@a\",\"type\":\"SNAPSHOT\",\"pool\":\"tank\",\"properties\":{\"used\":{\"value\":\"20000\"},\"referenced\":{\"value\":\"3000000\"},\"creation\":{\"value\":\"1759400000\"}}}}}' ;;\n"
	    "'list -H -o name -s createtxg -t snapshot -d 1 tank/data') "
	    "printf 'tank/data@a\\ntank/data@b\\n' ;;\n"
	    /* A snapshot sent: what zsend.data has; received into a file. */
	    "send*) cat zsend.data ;;\n"
	    "'get -H -o value keylocation,keystatus,keyformat tank/vault') "
	    "printf 'prompt\\nunavailable\\npassphrase\\n' ;;\n"
	    /* What zfs read: the key, on its standard input. */
	    "'load-key tank/vault') echo \"key=$(cat)\" >> storage.log ;;\n"
	    /* Made encrypted: the passphrase it read, as it asked. */
	    "'create -o encryption=aes-256-gcm -o keyformat=passphrase -o "
	    "keylocation=prompt tank/secret') echo \"newkey=$(cat)\" >> "
	    "storage.log ;;\n"
	    "'receive -u tank/fail') cat > /dev/null; echo \"cannot receive "
	    "new filesystem stream: destination 'tank/fail' exists\" >&2; "
	    "exit 1 ;;\n"
	    "'receive -u '*) cat > zrecv.data ;;\n"
	    "esac\nexit 0\n");
	put("fake-zpool", "#!/bin/sh\necho \"zpool $*\" >> storage.log\n"
	    "case \"$*\" in\n'list -Hp -o name,size,alloc,free,health') "
	    "printf 'tank\\t14000000\\t5000000\\t9000000\\tDEGRADED\\n' ;;\n"
	    "'list -j -p -o name,size,allocated'*) printf '%s\\n' '{\"output_version\":{\"command\":\"zpool list\",\"vers_major\":0,\"vers_minor\":1},\"pools\":{\"tank\":{\"name\":\"tank\",\"type\":\"POOL\",\"state\":\"DEGRADED\",\"properties\":{\"size\":{\"value\":\"14000000\"},\"allocated\":{\"value\":\"5000000\"},\"free\":{\"value\":\"9000000\"},\"fragmentation\":{\"value\":\"12\"},\"capacity\":{\"value\":\"35\"},\"dedupratio\":{\"value\":\"1.00\"},\"health\":{\"value\":\"DEGRADED\"}}}}}' ;;\n"
	    "import) printf '   pool: spare\\n     id: 1234567890\\n  state: "
	    "ONLINE\\n' ;;\n"
	    "'status -j') printf '%s\\n' '{\"output_version\":{\"command\":\"zpool status\",\"vers_major\":0,\"vers_minor\":1},\"pools\":{\"tank\":{\"name\":\"tank\",\"state\":\"DEGRADED\",\"pool_guid\":\"1\",\"txg\":\"1\",\"spa_version\":\"5000\",\"zpl_version\":\"5\",\"status\":\"One or more devices has been taken offline by the administrator. Sufficient replicas exist for the pool to continue functioning.\",\"action\":\"Online the device using '\\''zpool online'\\''.\",\"msgid\":\"ZFS-8000-2Q\",\"moreinfo\":\"https://openzfs.github.io/openzfs-docs/msg/ZFS-8000-2Q\",\"scan_stats\":{\"function\":\"SCRUB\",\"state\":\"FINISHED\",\"start_time\":\"Sun Oct  4 02:49:49 2026\",\"end_time\":\"Sun Oct  4 03:00:00 2026\",\"errors\":\"0\"},\"vdevs\":{\"tank\":{\"name\":\"tank\",\"vdev_type\":\"root\",\"guid\":\"1\",\"class\":\"normal\",\"state\":\"DEGRADED\",\"read_errors\":\"0\",\"write_errors\":\"0\",\"checksum_errors\":\"0\",\"vdevs\":{\"mirror-0\":{\"name\":\"mirror-0\",\"vdev_type\":\"mirror\",\"guid\":\"2\",\"class\":\"normal\",\"state\":\"DEGRADED\",\"read_errors\":\"0\",\"write_errors\":\"0\",\"checksum_errors\":\"0\",\"vdevs\":{\"ada1p1\":{\"name\":\"ada1p1\",\"vdev_type\":\"disk\",\"guid\":\"3\",\"path\":\"/dev/ada1p1\",\"class\":\"normal\",\"state\":\"ONLINE\",\"read_errors\":\"0\",\"write_errors\":\"0\",\"checksum_errors\":\"0\"},\"ada2p1\":{\"name\":\"ada2p1\",\"vdev_type\":\"disk\",\"guid\":\"4\",\"path\":\"/dev/ada2p1\",\"class\":\"normal\",\"state\":\"OFFLINE\",\"read_errors\":\"0\",\"write_errors\":\"0\",\"checksum_errors\":\"0\"}}}}}},\"error_count\":\"0\",\"errlist\":[]}}}' ;;\nesac\nexit 0\n");
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
	put("tools/rm", "#!/bin/sh\nexec /bin/rm \"$@\"\n");
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
	put("tools/c-icap", "#!/bin/sh\n"
	    "[ \"$1\" = --hold ] && { echo $$ > \"$2\"; sleep 60; exit 0; }\n"
	    "echo \"c-icap $*\" >> squid.log\n"
	    "p=$(sed -n 's/^PidFile //p' \"$2\")\n"
	    "\"$0\" --hold \"$p\" > /dev/null 2>&1 &\nexit 0\n");
	/* suricata, a plugin: checked, it takes all; run, it stays a while
	 * with its pid file where it is told. */
	/* ctladm(8), hastctl(8) and showmount(8), as they answer. */
	/* OpenSMTPD, a plugin: smtpd checks a file (BROKEN fails), smtpctl
	 * answers as it does, encrypt hashes what it reads. */
	put("tools/smtpd", "#!/bin/sh\necho \"smtpd $*\" >> smtpd.log\n"
	    "[ \"$1\" = -n ] && { grep -q BROKEN \"$3\" && { echo 'smtpd: "
	    "invalid virtual ip or interface: bogus0' >&2; exit 1; }; echo "
	    "'configuration OK'; exit 0; }\nexit 0\n");
	put("tools/smtpctl", "#!/bin/sh\necho \"smtpctl $*\" >> smtpd.log\n"
	    "case \"$*\" in\n'show status') printf 'MDA running\\nMTA "
	    "running\\nSMTP running\\n' ;;\n'show stats') printf "
	    "'scheduler.delivery.ok=2\\nuptime=44\\nuptime.human=44s\\n' ;;\n"
	    "'show queue') printf '6022923fc9341b9d|local|mta|auth|root@a"
	    "|nobody@example.invalid|nobody@example.invalid|1792491081|"
	    "1792491081|3|1792491200|pending|-2|(TempFail) no route\\n' ;;\n"
	    "'update table '*|pause*|resume*) echo 'command succeeded' ;;\n"
	    "schedule*) echo '1 envelope scheduled' ;;\nremove*) echo '1 "
	    "envelope removed' ;;\nesac\nexit 0\n");
	put("tools/encrypt", "#!/bin/sh\nread -r p\necho \"encrypt <$p\" >> "
	    "smtpd.log\necho '$6$fake$hashOf$1'\n");
	ATF_REQUIRE(chmod("tools/smtpd", 0755) == 0);
	ATF_REQUIRE(chmod("tools/smtpctl", 0755) == 0);
	ATF_REQUIRE(chmod("tools/encrypt", 0755) == 0);
	/* UDPspeeder's relay, a plugin, and its lines in syslog's file. */
	put("tools/speederv2", "#!/bin/sh\nexit 0\n");
	ATF_REQUIRE(chmod("tools/speederv2", 0755) == 0);
	put("speeder.log", "Oct 23 14:22:39 h speederv2[7]: [2026-10-23 "
	    "14:22:39][INFO]fec_inner_parameter=1:2,2:3\nOct 23 14:22:49 h "
	    "speederv2[7]: [2026-10-23 14:22:49][INFO][report]client-->server:"
	    "(original:10 pkt;1000 byte) (fec:20 pkt,1500 byte)  server-->"
	    "client:(original:10 pkt;1000 byte) (fec:20 pkt;1500 byte)\nOct 23 "
	    "14:22:59 h speederv2[7]: [2026-10-23 14:22:59][INFO][report]"
	    "client-->server:(original:20 pkt;2000 byte) (fec:40 pkt,3000 byte)"
	    "  server-->client:(original:20 pkt;2000 byte) (fec:40 pkt;3000 "
	    "byte)\nOct 23 14:23:09 h speederv2[7]: [2026-10-23 14:23:09][INFO]"
	    "[report]client-->server:(original:30 pkt;3000 byte) (fec:60 pkt,"
	    "4500 byte)  server-->client:(original:30 pkt;3000 byte) (fec:60 "
	    "pkt;4500 byte)\n");
	put("tools/ctladm", "#!/bin/sh\necho \"ctladm $*\" >> netstore.log\n"
	    "case \"$1\" in devlist) echo 'LUN Backend Size (Blocks) BS "
	    "Serial Number Device ID'; echo '  0 block 2048 512 LABSERIAL0 "
	    "LABDEV0' ;; islist) echo 'ID Portal Initiator name Target name' "
	    ";; portlist) echo 'Port Online Frontend Name pp vp' ;; esac\n");
	put("tools/hastctl", "#!/bin/sh\necho \"hastctl $*\" >> netstore.log\n"
	    "case \"$1\" in status) printf 'Name\\tStatus\\tRole\\n"
	    "shared\\tcomplete\\tsecondary\\n' ;; esac\n");
	put("tools/showmount", "#!/bin/sh\necho 'Exports list on localhost:'\n"
	    "echo '/export 10.0.0.0'\n");
	put("exports", "/export -network 10.0.0.0/24\n");
	put("hast.conf", "resource shared {\n\ton lab {\n\t\tlocal /dev/md9\n"
	    "\t\tremote 10.0.0.2\n\t}\n}\n");
	/* Its command socket, as Suricata answers, gone after a while. */
	put("tools/scsrv.py", "import json, os, signal, socket, sys\n"
	    "signal.alarm(300)\np = sys.argv[1]\ntry:\n    os.unlink(p)\n"
	    "except OSError:\n    pass\ns = socket.socket(socket.AF_UNIX)\n"
	    "s.bind(p)\ns.listen(4)\nr = {\"memcap-list\": {\"message\": "
	    "[{\"name\": \"flow\", \"value\": \"32mb\"}, {\"name\": "
	    "\"stream\", \"value\": \"64mb\"}], \"return\": \"OK\"}, "
	    "\"ruleset-stats\": {\"message\": [{\"id\": 0, \"rules_loaded\": "
	    "1, \"rules_failed\": 0, \"rules_skipped\": 0}], \"return\": "
	    "\"OK\"}, \"ruleset-failed-rules\": {\"message\": [], \"return\": "
	    "\"OK\"}, \"uptime\": {\"message\": 20, \"return\": \"OK\"}, "
	    "\"iface-stat\": {\"message\": {\"pkts\": 3000, "
	    "\"invalid-checksums\": 0, \"drop\": 5, \"bypassed\": 0}, "
	    "\"return\": \"OK\"}}\nwhile True:\n    c, _ = s.accept()\n"
	    "    f = c.makefile(\"rwb\")\n    for line in f:\n"
	    "        o = json.loads(line)\n        a = {\"return\": \"OK\"} if "
	    "\"version\" in o else dict(r.get(o.get(\"command\"), {\"message\": "
	    "\"Unknown command\", \"return\": \"NOK\"}))\n"
	    "        if o.get(\"command\") == \"iface-stat\":\n"
	    "            a[\"message\"] = dict(a[\"message\"], iface=o["
	    "\"arguments\"][\"iface\"])\n        f.write((json.dumps(a) + "
	    "\"\\n\").encode())\n        f.flush()\n    c.close()\n");
	put("tools/suricata", "#!/bin/sh\n"
	    /* Started: the daemon, under its own name, its pid where told. */
	    "[ \"$1\" = --hold ] && { echo $$ > \"$2\"; sleep 60; exit 0; }\n"
	    "echo \"suricata $*\" >> squid.log\n"
	    "[ \"$1\" = --build-info ] && { printf 'This is Suricata version "
	    "8.0.7 RELEASE\\nFeatures: NETMAP HAVE_LUA\\n  Netmap support: "
	    "yes\\n  Profiling rules enabled: no\\n  Plugin support "
	    "(experimental): yes\\n'; exit 0; }\n"
	    "[ \"$1\" = -T ] && exit 0\n"
	    /* A capture replayed: an alert of it where -l says. */
	    "[ \"$3\" = -r ] && { echo '{\"timestamp\":\"2026-10-19T11:00:00"
	    ".000000+0000\",\"event_type\":\"alert\",\"src_ip\":\"10.1.1.1\","
	    "\"src_port\":1,\"dest_ip\":\"10.2.2.2\",\"dest_port\":2,\"proto\":"
	    "\"TCP\",\"alert\":{\"action\":\"allowed\",\"signature_id\":"
	    "2000009,\"rev\":1,\"signature\":\"ET REPLAYED\",\"category\":"
	    "\"\",\"severity\":1}}' >> \"$6/eve.json\"; exit 0; }\n"
	    "k=$(sed -n 's/^  filename: \\(.*\\.sock\\)$/\\1/p' \"$2\")\n"
	    "[ -n \"$k\" ] && [ -x /usr/local/bin/python3 ] && "
	    "/usr/local/bin/python3 tools/scsrv.py \"$k\" > /dev/null 2>&1 &\n"
	    "\"$0\" --hold \"$4\" > /dev/null 2>&1 &\n"
	    "d=$(sed -n 's/^default-log-dir: //p' \"$2\")\n"
	    /* Its engine started, as its log says (the agent waits for it). */
	    "[ -n \"$d\" ] && { mkdir -p \"$d\"; echo 'Notice: threads: "
	    "Engine started.' >> \"$d/suricata.log\"; }\n"
	    /* An alert in its eve.json, a second after it starts. */
	    "[ -n \"$d\" ] && (sleep 1; mkdir -p \"$d\"; echo '{\"timestamp\":"
	    "\"2026-10-19T10:00:00.000000+0000\",\"event_type\":\"alert\","
	    "\"src_ip\":\"10.0.0.9\",\"src_port\":4444,\"dest_ip\":"
	    "\"10.0.0.1\",\"dest_port\":23,\"proto\":\"TCP\",\"in_iface\":"
	    "\"lo0\",\"alert\":{\"action\":\"allowed\",\"signature_id\":"
	    "1000009,\"rev\":1,\"signature\":\"LOCAL telnet\",\"category\":"
	    "\"\",\"severity\":2}}' >> \"$d/eve.json\"; "
	    /* and two stats records, ten seconds apart. */
	    "echo '{\"timestamp\":\"2026-10-19T10:00:00.000000+0000\","
	    "\"event_type\":\"stats\",\"stats\":{\"uptime\":10,\"capture\":"
	    "{\"kernel_packets\":1000,\"kernel_drops\":5},\"decoder\":{"
	    "\"pkts\":995,\"bytes\":600000,\"invalid\":2},\"detect\":{"
	    "\"alert\":1},\"tcp\":{\"sessions\":40,\"memuse\":1000},"
	    "\"flow\":{\"total\":60,\"memuse\":4000},\"app_layer\":{\"flow\":"
	    "{\"http\":7,\"tls\":11}}}}' >> \"$d/eve.json\"; "
	    "echo '{\"timestamp\":\"2026-10-19T10:00:10.000000+0000\","
	    "\"event_type\":\"stats\",\"stats\":{\"uptime\":20,\"capture\":"
	    "{\"kernel_packets\":3000,\"kernel_drops\":5},\"decoder\":{"
	    "\"pkts\":2995,\"bytes\":1800000,\"invalid\":2},\"detect\":{"
	    "\"alert\":2},\"tcp\":{\"sessions\":90,\"memuse\":1000},"
	    "\"flow\":{\"total\":130,\"memuse\":4000},\"app_layer\":{\"flow\":"
	    "{\"http\":9,\"tls\":20,\"dns_udp\":4}}}}' >> \"$d/eve.json\") "
	    "> /dev/null 2>&1 &\n"
	    "exit 0\n");
	/* suricata-update: a ruleset of three rules where -o says, one
	 * disabled as it ships; the sids of --disable-conf commented out
	 * and those of --enable-conf not, as it does. */
	put("tools/suricata-update", "#!/bin/sh\n"
	    "echo \"suricata-update $*\" >> suricata-update.log\n"
	    "while [ $# -gt 0 ]; do case \"$1\" in -o) out=$2; shift ;; "
	    "-D) data=$2; shift ;; update-sources) mkdir -p "
	    "\"$data/update/cache\"; echo 'sources: {}' > "
	    "\"$data/update/cache/index.yaml\"; exit 0 ;; list-sources) "
	    "printf 'Name: et/open\\n  Vendor: Proofpoint\\n  Summary: "
	    "Emerging Threats Open Ruleset\\n  License: MIT\\nName: et/pro"
	    "\\n  Vendor: Proofpoint\\n  Summary: Emerging Threats Pro "
	    "Ruleset\\n  License: Commercial\\n  Parameters: secret-code"
	    "\\n'; exit 0 ;; "
	    "--enable-conf) en=$2; shift ;; --disable-conf) dis=$2; shift ;; "
	    "esac; shift; done\nmkdir -p \"$out\"; f=$out/suricata.rules\n"
	    "{ echo 'alert tcp any any -> any 22 (msg:\"ET SCAN ssh\"; "
	    "classtype:attempted-recon; sid:2000001; rev:1;)'\n"
	    "echo '# alert http any any -> any any (msg:\"ET INFO curl\"; "
	    "classtype:policy-violation; sid:2000005; rev:2;)'\n"
	    "echo 'alert dns any any -> any any (msg:\"ET DNS bad name\"; "
	    "classtype:bad-unknown; sid:2000006; rev:4;)'; } > \"$f\"\n"
	    "for s in $(grep -v '^#' \"${en:-/dev/null}\"); do sed -i '' "
	    "\"/sid:$s;/s/^# //\" \"$f\"; done\n"
	    "for s in $(grep -v '^#' \"${dis:-/dev/null}\"); do sed -i '' "
	    "\"/sid:$s;/s/^alert/# alert/\" \"$f\"; done\nexit 0\n");
	/* poudriere(8), a plugin: a jail or a tree made where it keeps
	 * them (jset, pset), a build that says what it builds and takes a
	 * second, the latest build of a set whose make.conf is there. */
	put("fake-poudriere", "#!/bin/sh\necho \"poudriere $*\" >> poudriere.log\n"
	    "e=$(pwd)/pe/poudriere.d\ncmd=$1; shift\ncase $cmd in\n"
	    "jail|ports) verb=$1; shift; n=; v=; m=http\n"
	    "\twhile getopts yj:p:v:a:m:B:U:M: o; do case $o in j|p) n=$OPTARG;; "
	    "v) v=$OPTARG;; m) m=$OPTARG;; esac; done\n"
	    "\tk=jails; [ $cmd = ports ] && k=ports\n"
	    "\tcase $verb in\n\t-c) mkdir -p $e/$k/$n; echo $m > $e/$k/$n/method; "
	    "[ $k = ports ] && echo $(pwd)/ptree > $e/$k/$n/mnt; "
	    "[ -n \"$v\" ] && echo $v > $e/$k/$n/version; echo amd64 > "
	    "$e/$k/$n/arch; echo 1792200000 > $e/$k/$n/timestamp; "
	    "echo \"[00:00:01] Created $n\" ;;\n"
	    "\t-u) echo \"[00:00:01] Updated $n\" ;;\n\t-d) rm -rf $e/$k/$n ;;\n"
	    "\tesac ;;\nbulk) echo \"[00:00:00] Building: $*\"; sleep 1; "
	    "echo '[00:00:01] Built 1 packages' ;;\n"
	    "status) [ -f $e/debug-make.conf ] && printf 'debug\\tdefault\\t"
	    "150amd64\\t2026-10-17_09h00m00s\\tdone:\\t2\\t0\\t0\\t1\\t1\\t0"
	    "\\t0\\t0\\t00:03:10\\t%s\\n' \"$(pwd)/bl\" ;;\n"
	    "esac\nexit 0\n");
	ATF_REQUIRE(chmod("fake-poudriere", 0755) == 0);
	ATF_REQUIRE(mkdir("pe", 0755) == 0 || errno == EEXIST);
	put("pe/poudriere.conf", "ZPOOL=tank\nBASEFS=/poudriere\n");
	/* A port of the trees it makes, as the ports framework says it. */
	ATF_REQUIRE(mkdir("ptree", 0755) == 0 || errno == EEXIST);
	ATF_REQUIRE(mkdir("ptree/net", 0755) == 0 || errno == EEXIST);
	ATF_REQUIRE(mkdir("ptree/net/bird3", 0755) == 0 || errno == EEXIST);
	put("ptree/net/bird3/Makefile", "PKGNAME=\tbird3-3.4.0\n"
	    "COMPLETE_OPTIONS_LIST=\tBFD BGP MRT\n"
	    "OPTIONS_FILE=\t${PORT_DBDIR}/net_bird3/options\nshowconfig:\n"
	    "\t@echo \"===> The following configuration options are "
	    "available for ${PKGNAME}:\"\n"
	    "\t@echo \"     BFD=on: Bidirectional Forwarding Detection\"\n"
	    "\t@echo \"====> Routing Protocols\"\n"
	    "\t@echo \"     BGP=on: Border Gateway Protocol\"\n"
	    "\t@echo \"     MRT=off: Dumping Routing Information in MRT "
	    "Format\"\n");
	/* The build's log directory: a port that failed, with its log. */
	ATF_REQUIRE(mkdir("bl", 0755) == 0 || errno == EEXIST);
	ATF_REQUIRE(mkdir("bl/logs", 0755) == 0 || errno == EEXIST);
	ATF_REQUIRE(mkdir("bl/logs/errors", 0755) == 0 || errno == EEXIST);
	put("bl/.poudriere.ports.failed", "devel/broken broken-1.0 build "
	    "compiler_error 42\n");
	put("bl/logs/errors/broken-1.0.log", "===> Building for broken-1.0\n"
	    "cc: error: no such file\n");
	/* tcpdump(1): its sources, a capture written, and read back;
	 * timeout(1) leaves it be. */
	ATF_REQUIRE(mkdir("tools/tmp", 0755) == 0 || errno == EEXIST);
	put("tools/timeout", "#!/bin/sh\nshift\nexec \"$@\"\n");
	put("tools/tcpdump", "#!/bin/sh\necho \"tcpdump $*\" >> tcpdump.log\n"
	    "case \"$1\" in\n-D) printf '1.em1 [Up, Running]\\n2.ipfw150 [Up]"
	    "\\n' ;;\n-n) [ \"$2\" = -tttt ] && { printf '2026-10-12 10:00:00."
	    "000001 IP 10.0.0.2 > 10.0.0.1: ICMP echo request, id 1, seq 0, "
	    "length 64\\n2026-10-12 10:00:00.000090 IP 10.0.0.1 > 10.0.0.2: "
	    "ICMP echo reply, id 1, seq 0, length 64\\n'; exit 0; }\n"
	    "while [ $# -gt 0 ]; do [ \"$1\" = -w ] && printf 'PCAPDATA' > "
	    "\"$2\"; shift; done ;;\nesac\nexit 0\n");
	ATF_REQUIRE(chmod("tools/timeout", 0755) == 0 && chmod("tools/tcpdump",
	    0755) == 0);
	/* arp(8) and ndp(8), told what to set. */
	put("tools/arp", "#!/bin/sh\necho \"arp $*\" >> neigh.log\n");
	put("tools/ndp", "#!/bin/sh\necho \"ndp $*\" >> neigh.log\n");
	ATF_REQUIRE(chmod("tools/arp", 0755) == 0 && chmod("tools/ndp", 0755)
	    == 0);
	/* certctl rehash as it is: the store made again from FreeBSD's own,
	 * those given, and those not to be trusted, by fingerprint. */
	put("tools/certctl", "#!/bin/sh\necho \"certctl $*\" >> certctl.log\n"
	    "R=$2\nfp() { openssl x509 -noout -fingerprint -sha256 -in \"$1\" | "
	    "tr -d ' '; }\nrm -rf $R/etc/ssl/certs $R/etc/ssl/untrusted\n"
	    "mkdir -p $R/etc/ssl/certs $R/etc/ssl/untrusted\nbad=\n"
	    "for f in $R/usr/local/share/certs/untrusted/*; do\n"
	    "\t[ -f \"$f\" ] || continue\n\tbad=\"$bad $(fp $f)\"\n"
	    "\tcp $f $R/etc/ssl/untrusted/$(basename $f .pem)\ndone\n"
	    "for f in $R/usr/share/certs/trusted/* "
	    "$R/usr/local/share/certs/trusted/*; do\n\t[ -f \"$f\" ] || "
	    "continue\n\tcase \"$bad\" in *$(fp $f)*) continue ;; esac\n"
	    "\tcp $f $R/etc/ssl/certs/$(basename $f .pem).0\ndone\n");
	ATF_REQUIRE(chmod("tools/certctl", 0755) == 0);
	/* sshd: -t refuses what says BAD, -T is the file's settings. */
	put("tools/sshd", "#!/bin/sh\ncase \"$1\" in\n-t)\tgrep -q BAD \"$3\" "
	    "&& { echo \"$3: Bad configuration option: BAD\" >&2; exit 255; }"
	    "\n\texit 0 ;;\n-T)\tawk '!/^[ \\t]*#/ && NF > 1 { if (tolower($1)"
	    " == \"match\") exit; k = tolower($1); $1 = \"\"; sub(/^ /, \"\"); "
	    "print k, $0 }' \"$3\"\n\tgrep -qi '^hostkey' \"$3\" || echo "
	    "\"hostkey /etc/ssh/ssh_host_ed25519_key\"\n\texit 0 ;;\nesac\n"
	    "exit 1\n");
	ATF_REQUIRE(chmod("tools/sshd", 0755) == 0);
	put("tools/ssh-keygen", "#!/bin/sh\nexec /usr/bin/ssh-keygen \"$@\"\n");
	/* The signing's own ssh-agent, and ssh-add to give it the key. */
	put("tools/ssh-agent", "#!/bin/sh\nexec /usr/bin/ssh-agent \"$@\"\n");
	put("tools/ssh-add", "#!/bin/sh\nexec /usr/bin/ssh-add \"$@\"\n");
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
	    "'kern.nosuch'\" >&2; exit 1; }\n"
	    /* IGMP's and MLD's, as -e asks them: name=value. */
	    "[ \"$1\" = -e ] && { shift; for n; do case $n in "
	    "*default_version) echo \"$n=3\" ;; *legacysupp) echo \"$n=0\" ;; "
	    "net.inet*) echo \"$n=1\" ;; esac; done; }\nexit 0\n");
	/* ifmcstat(8): an interface in two groups, one with a source. */
	put("fake-ifmcstat", "#!/bin/sh\nprintf 'em0:\\n\\tinet 10.0.0.1"
	    "\\n\\tigmpv3 rv 2 qi 125 qri 100 uri 3\\n\\t\\tgroup 224.0.0.1 "
	    "mode exclude\\n\\t\\t\\tmcast-macaddr 01:00:5e:00:00:01\\n\\t\\t"
	    "group 232.1.1.1 mode include\\n\\t\\t\\tsource 10.9.9.9\\n"
	    "\\tinet6 fe80::1%%em0 scopeid 0x1\\n\\tmldv2 flags=2<USEALLOW> rv 2 "
	    "qi 125 qri 10000 uri 3\\n\\t\\tgroup ff02::1%%em0 scopeid 0x1 mode "
	    "exclude\\n'\n");
	ATF_REQUIRE(chmod("fake-ifmcstat", 0755) == 0);
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
	    "protocol device device1 {\n}\n\ntemplate bgp ibgp_t {\n\tlocal as "
	    "MY_AS;\n\tneighbor internal;\n\tipv6 {\n\t\timport all;\n\t\texport all;\n\t};\n}\n\n"
	    "protocol bgp bgp_core {\n"
	    "\tdescription \"Core uplink\";\n\t# the old uplink: 192.0.2.9\n"
	    "\tlocal as MY_AS;\n\tneighbor "
	    "192.0.2.1 as 65001;\n\tipv4 {\n\t\timport filter bgp_in;\n"
	    "\t\texport filter bgp_out;\n\t};\n}\n\nprotocol bgp bgp_edge {\n"
	    "\tlocal as MY_AS;\n\tneighbor 198.51.100.7 as 65002;\n}\n\n"
	    "protocol rpki rpki1 {\n\troa4 { table r4; };\n\tremote "
	    "192.0.2.80 port 3323;\n}\n");
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
	if (harness_newer_agent) {
		/* A later version: the program, saying another with -V. */
		snprintf(send, sizeof(send), "%s/newer-agent", cwd);
		snprintf(buf, sizeof(buf), "#!/bin/sh\n[ \"$1\" = -V ] && "
		    "{ echo 'arcana-agent 999.0.0'; exit 0; }\nexec '%s' "
		    "\"$@\"\n", jgd);
		put("newer-agent", buf);
		ATF_REQUIRE(chmod("newer-agent", 0755) == 0);
	}
	/* None, unless a test is about it or names one itself. */
	if (harness_webconf_only_local)
		local[0] = '\0';
	else
		snprintf(local, sizeof(local), harness_local_agent ?
		    "local_agent = \"unix:%s/jgd.sock\";\n" :
		    "local_agent = \"\";\n", cwd);
	/* Mail goes into mail.out. */
	snprintf(buf, sizeof(buf), "#!/bin/sh\n{ echo \"ARGS $*\"; cat; echo "
	    "--END--; } >> %s/mail.out\n", cwd);
	ATF_REQUIRE(mkdir("tools", 0755) == 0 || errno == EEXIST);
	put("tools/sendmail", buf);
	ATF_REQUIRE(chmod("tools/sendmail", 0755) == 0);
	if (port != 0)
		snprintf(listen, sizeof(listen), "127.0.0.1:%d", port);
	else
		snprintf(listen, sizeof(listen), "unix:%s/k.sock", cwd);
	snprintf(www, sizeof(www), "%s/www", cwd);
	/* No test asks the Internet: the release feed is a port nothing
	 * listens on, refused at once.  The console stays the user's. */
	snprintf(buf, sizeof(buf), "server {\n\tlisten = [ \"%s\" ];\n"
	    "\twebroot = \"%s\";\n\tuser = \"\";\n\ttask_threads = 4;\n%s}\n"
	    "rp_id = \"%s\";\norigin = \"%s\";\n"
	    "datadir = \"%s/data\";\ncookie_secure = false;\n"
	    "agent_binary = \"%s\";\nsendmail = \"%s/tools/sendmail\";\n"
	    "update_url = \"https://127.0.0.1:9/releases/latest\";\n"
	    "%s%s", listen, webroot != NULL ? webroot : www, harness_server, RP_ID,
	    harness_origin, cwd, send, cwd, local, harness_webconf);
	put("web.conf", buf);

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
	/* The system's files under a tree of the test's: config-export
	 * reads them, and nothing reads the host's own. */
	argv[102] = (char *)(uintptr_t)"--root";
	argv[103] = rootdir;
	/* BIRD's sessions are not watched for faults by the tests'
	 * agents: a fault would come among those a test looks for. */
	argv[104] = (char *)(uintptr_t)"--bird-watch";
	argv[105] = (char *)(uintptr_t)"0";
	argv[106] = NULL;
	/* Telegram's Bot API: a sink of the test's, or a port nothing
	 * listens on; never the real one. */
	argv[106] = (char *)(uintptr_t)"--telegram-api";
	argv[107] = harness_telegram_api[0] != '\0' ? harness_telegram_api :
	    (char *)(uintptr_t)"http://127.0.0.1:9";
	/* poudriere(8), a plugin: a stand-in, its poudriere.d the test's. */
	argv[108] = (char *)(uintptr_t)"--poudriere";
	argv[109] = (char *)(uintptr_t)"./fake-poudriere";
	argv[110] = (char *)(uintptr_t)"--poudriere-etc";
	argv[111] = pdetc;
	argv[112] = (char *)(uintptr_t)"--ifmcstat";
	argv[113] = (char *)(uintptr_t)"./fake-ifmcstat";
	/* Suricata's ruleset the test's, never the host's. */
	argv[114] = (char *)(uintptr_t)"--suricata-rules";
	argv[115] = surules;
	/* The storage services' files, the test's. */
	argv[116] = (char *)(uintptr_t)"--exports";
	argv[117] = (char *)(uintptr_t)"exports";
	argv[118] = (char *)(uintptr_t)"--ctl-conf";
	argv[119] = (char *)(uintptr_t)"ctl.conf";
	argv[120] = (char *)(uintptr_t)"--hast-conf";
	argv[121] = (char *)(uintptr_t)"hast.conf";
	argv[122] = (char *)(uintptr_t)"--smtpd-conf";
	argv[123] = (char *)(uintptr_t)"./smtpd.conf";
	argv[124] = (char *)(uintptr_t)"--smtpd-dir";
	argv[125] = (char *)(uintptr_t)"smtpd.d";
	/* The lanes of pkg jobs, kept in the test's directory. */
	argv[126] = (char *)(uintptr_t)"--jobs-conf";
	argv[127] = (char *)(uintptr_t)"jobs.conf";
	argv[128] = (char *)(uintptr_t)"--speederv2-log";
	argv[129] = (char *)(uintptr_t)"speeder.log";
	argv[130] = NULL;
	snprintf(pdetc, sizeof(pdetc), "%s/pe", cwd);
	snprintf(surules, sizeof(surules), "%s/rules", cwd);
	snprintf(rootdir, sizeof(rootdir), "%s/root", cwd);
	(void)mkdir(rootdir, 0755);
	{
		char	etc[MAXPATHLEN + 16];

		snprintf(etc, sizeof(etc), "%s/root/etc", cwd);
		(void)mkdir(etc, 0755);
	}
	put("root/etc/hosts", "127.0.0.1 localhost\n");
	(void)mkdir("root/etc/defaults", 0755);
	put("root/etc/defaults/periodic.conf", "daily_clean_tmps_enable=\"NO\"\n"
	    "daily_status_disks_enable=\"YES\"\n");
	put("root/etc/rc.conf", "hostname=\"lab\"\nsshd_enable=\"YES\"\n");
	snprintf(rcd, sizeof(rcd), "%s/rc.d", cwd);
	snprintf(ntpconf, sizeof(ntpconf), "%s/ntp.conf", cwd);
	snprintf(rtadvdconf, sizeof(rtadvdconf), "%s/rtadvd.conf", cwd);
	pid = spawn_server(argv, "arcana-agent.out");
	ATF_REQUIRE((fp = fopen("arcana-agent.pid", "w")) != NULL);
	fprintf(fp, "%d\n", (int)pid);
	fclose(fp);

	snprintf(buf, sizeof(buf), "%s/web.conf", cwd);
	setenv("ARCANA_WEB_CONF", buf, 1);
	argv[0] = console;
	argv[1] = (char *)(uintptr_t)"-c";
	argv[2] = (char *)(uintptr_t)"web.conf";
	argv[3] = NULL;
	snprintf(console_path, sizeof(console_path), "%s", console);
	pid = spawn_server(argv, "console.out");
	ATF_REQUIRE((fp = fopen("console.pid", "w")) != NULL);
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

	console_stop();
	console_start();
}

/* The console alone stopped, the rest left as it is. */
void
console_stop(void)
{

	terminate("console.pid");
	(void)unlink("k.sock");
}

/* And started again, on ./k.sock. */
void
console_start(void)
{
	char	*argv[7];
	FILE	*fp;
	pid_t	 pid;

	argv[0] = console_path;
	argv[1] = (char *)(uintptr_t)"-c";
	argv[2] = (char *)(uintptr_t)"web.conf";
	argv[3] = NULL;
	pid = spawn_server(argv, "console.out");
	ATF_REQUIRE((fp = fopen("console.pid", "w")) != NULL);
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
	terminate("console.pid");
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
		/* Stop at the end of the body: the server may keep the socket. */
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

/*
 * The troubleshooter's way across places, against a network the test
 * makes up: three routers, vnet jails r1, r2 and r3 by the stand-ins,
 * each with its addresses, routes and ruleset as the agent's helper and
 * ipfw would tell them.  The client 10.1.0.2 is behind r1, the server
 * 10.3.0.2 behind r2.
 */
void
ts_net(const char *cwd, const char *r2routes, const char *r2fw)
{
	FILE	*fp;
	char	 buf[8192];

	/* jls: r1, r2, r3 are jails 11, 12, 13 with networks of their own. */
	snprintf(buf, sizeof(buf), "#!/bin/sh\ncase \"$2\" in\n"
	    "r1) echo \"11 new %s/jroot\" ;;\nr2) echo \"12 new %s/jroot\" ;;\n"
	    "r3) echo \"13 new %s/jroot\" ;;\n"
	    "gw) echo \"4 new %s/jroot\" ;;\n"
	    "*) echo \"jls: jail not found\" >&2; exit 1 ;;\nesac\n", cwd, cwd,
	    cwd, cwd);
	ATF_REQUIRE((fp = fopen("fake-jls", "w")) != NULL);
	fputs(buf, fp);
	fclose(fp);
	/* jexec: ipfw's list and tables, the jail's own. */
	ATF_REQUIRE((fp = fopen("fake-jexec", "w")) != NULL);
	fputs("#!/bin/sh\necho \"jexec $*\" >> jexec.log\nj=$1; shift\n"
	    /* A jail whose answers hang, while hang-<jid> is there. */
	    "[ -f hang-$j ] && sleep 45\n"
	    "case \"$1 $2\" in\n*fake-ipfw\\ list) cat fw-$j.list 2>/dev/null; "
	    "exit 0 ;;\n*fake-ipfw\\ table) cat fw-$j.tables 2>/dev/null; "
	    "exit 0 ;;\nesac\nexec \"$@\"\n", fp);
	fclose(fp);
	/* The helper: each jail's addresses and routes, the longest prefix
	 * that covers an address taken; every neighbour answers. */
	ATF_REQUIRE((fp = fopen("fake-helper", "w")) != NULL);
	fputs("#!/bin/sh\nj=$2\ncase \"$3\" in\n"
	    "route-addrs) cat addrs-$j 2>/dev/null; echo '{\"sysctl\":true,"
	    "\"forwarding\":1,\"forwarding6\":0,\"fw\":1,\"fw6\":0}' ;;\n"
	    "route-neighs) echo '{\"address\":\"'$5'\",\"state\":\"reachable\"}'"
	    "; echo '#total 1' ;;\n"
	    "route-get) awk -v a=\"$4\" -v fib=\"$5\" '\n"
	    "function n(s,  p) { split(s, p, \".\"); return ((p[1]*256+p[2])*256"
	    "+p[3])*256+p[4] }\n"
	    "{ split($1, q, \"/\"); l = q[2]; m = 2^32 - 2^(32-l); "
	    "if (int(n(a)/2^(32-l)) == int(n(q[1])/2^(32-l)) && l >= best) "
	    "{ best = l; d = q[1]; g = $2; i = $3 } }\n"
	    "END { if (i != \"\") printf \"{\\\"to\\\":\\\"%s\\\",\\\"destination\\\":"
	    "\\\"%s\\\",\\\"prefixlen\\\":%d,\\\"gateway\\\":\\\"%s\\\",\\\"fib\\\":"
	    "\\\"%s\\\",\\\"interface\\\":\\\"%s\\\",\\\"flags\\\":\\\"UGS\\\"}\\n\", "
	    "a, d, best, g, fib, i }' best=-1 rt-$j 2>/dev/null ;;\n"
	    "*) exit 0 ;;\nesac\nexit 0\n", fp);
	fclose(fp);
	ATF_REQUIRE(system("chmod 755 fake-jls fake-jexec fake-helper") == 0);
#define	ADDR(j, a, l, i)	"{\"address\":\"" a "\",\"prefixlen\":" #l \
	",\"interface\":\"" i "\",\"fib\":0,\"up\":true,\"loopback\":false}\n"
	ATF_REQUIRE((fp = fopen("addrs-11", "w")) != NULL);
	fputs(ADDR(11, "10.1.0.1", 24, "em0") ADDR(11, "10.12.0.1", 24,
	    "em1") ADDR(11, "10.13.0.1", 24, "em2"), fp);
	fclose(fp);
	ATF_REQUIRE((fp = fopen("addrs-12", "w")) != NULL);
	fputs(ADDR(12, "10.12.0.2", 24, "em0") ADDR(12, "10.3.0.1", 24,
	    "em1") ADDR(12, "10.23.0.2", 24, "em2"), fp);
	fclose(fp);
	ATF_REQUIRE((fp = fopen("addrs-13", "w")) != NULL);
	fputs(ADDR(13, "10.13.0.3", 24, "em0") ADDR(13, "10.23.0.3", 24,
	    "em1"), fp);
	fclose(fp);
#undef	ADDR
	/* The host itself (jail 0) is r1 too, for a page without places. */
	ATF_REQUIRE(system("cp addrs-11 addrs-0") == 0);
	ATF_REQUIRE((fp = fopen("rt-11", "w")) != NULL);
	fputs("10.1.0.0/24 link#1 em0\n10.12.0.0/24 link#2 em1\n"
	    "10.13.0.0/24 link#3 em2\n0.0.0.0/0 10.12.0.2 em1\n", fp);
	fclose(fp);
	ATF_REQUIRE(system("cp rt-11 rt-0") == 0);
	/* The host's own ruleset: none, as before the lab. */
	ATF_REQUIRE((fp = fopen("fw-0.list", "w")) != NULL);
	fclose(fp);
	ATF_REQUIRE((fp = fopen("rt-12", "w")) != NULL);
	fprintf(fp, "10.12.0.0/24 link#1 em0\n10.3.0.0/24 link#2 em1\n"
	    "10.23.0.0/24 link#3 em2\n%s", r2routes);
	fclose(fp);
	ATF_REQUIRE((fp = fopen("rt-13", "w")) != NULL);
	fputs("10.13.0.0/24 link#1 em0\n10.23.0.0/24 link#2 em1\n"
	    "10.1.0.0/24 10.13.0.1 em0\n10.3.0.0/24 10.23.0.2 em1\n", fp);
	fclose(fp);
	ATF_REQUIRE((fp = fopen("fw-12.list", "w")) != NULL);
	fputs(r2fw, fp);
	fclose(fp);
	ATF_REQUIRE((fp = fopen("fw-11.list", "w")) != NULL);
	fputs("65535 allow ip from any to any\n", fp);
	fclose(fp);
	/* r3 lets through only what it saw open, or what is new. */
	ATF_REQUIRE((fp = fopen("fw-13.list", "w")) != NULL);
	fputs("00100 check-state :default\n"
	    "00200 allow tcp from any to any setup keep-state :default\n"
	    "00300 allow icmp from any to any\n"
	    "65535 deny ip from any to any\n", fp);
	fclose(fp);
}
