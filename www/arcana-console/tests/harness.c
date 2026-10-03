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
	char	 rcd[MAXPATHLEN];
	const char *kore, *dh;
	char	*argv[40];
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
	ATF_REQUIRE(mkdir("data", 0700) == 0);
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
	    "db {\n\tip4.addr = 10.0.0.20;\n}\n");
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
	    "case \"$1\" in\n"
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
	    "start|restart) touch running.$1 ;;\n"
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
	put("fake-git", "#!/bin/sh\n[ \"$1\" = -c ] && shift 2\n"
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
	put("fake-ifconfig", "#!/bin/sh\necho \"$*\" >> ifconfig.log\n");
	put("fake-route", "#!/bin/sh\necho \"$*\" >> route.log\n");
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
	snprintf(buf, sizeof(buf), "rp_id = \"%s\";\norigin = \"%s\";\n"
	    "datadir = \"%s/data\";\ncookie_secure = false;\n"
	    "agent_binary = \"%s\";\n%s", RP_ID, harness_origin, cwd, send,
	    harness_webconf);
	put("web.conf", buf);
	if (port != 0)
		snprintf(listen, sizeof(listen), "bind 127.0.0.1 %d", port);
	else
		snprintf(listen, sizeof(listen), "unix %s/k.sock", cwd);
	snprintf(www, sizeof(www), "%s/www", cwd);
	snprintf(buf, sizeof(buf), "server t {\n\t%s\n\ttls no\n}\n"
	    "load %s arcw_onload\ntls_dhparam %s\nworkers 1\ntask_threads 4\n"
	    "http_body_max 65536\nfilemap_index index.html\n"
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
	argv[34] = NULL;
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

