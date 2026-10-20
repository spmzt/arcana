#
# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
#
# arcana-agent(8) as an unprivileged user: a daemon on a socket in the work
# directory, a configuration written here, and a stand-in for jail(8)
# that passes "-e" (reading configuration) to the real one and only
# echoes everything else.  Nothing outside the work directory changes.
#

# Programs next to the tests in the build tree, else the configuration
# variables arcana-agent and arcanactl, else the installed ones.
programs()
{
	JGD="$(atf_get_srcdir)/../arcana-agent"
	[ -f "$JGD" -a -x "$JGD" ] ||
	    JGD=$(atf_config_get arcana-agent /usr/local/sbin/arcana-agent)
	JGC="$(atf_get_srcdir)/../../arcanactl/arcanactl"
	[ -f "$JGC" -a -x "$JGC" ] ||
	    JGC=$(atf_config_get arcanactl /usr/local/sbin/arcanactl)
}

write_conf()
{
	mkdir -p etc/jail.conf.d inc
	cat > etc/jail.conf <<EOF
# Lab jails
exec.start = "/bin/sh /etc/rc";
path = "/jails/\$name";
host.hostname = "\${name}.\$domain";
\$domain = "lab.example";
.include "$(pwd)/inc/*.inc";

web {
	ip4.addr = 10.0.0.10, "10.0.0.11";
	interface = lo0;
	persist;
}

db {
	ip4.addr = "em1|192.168.5.20/24";
}
EOF
	printf 'mail {\n\tip4.addr = 10.0.0.30;\n}\n' > inc/mail.inc
	cat > etc/jail.conf.d/vpn.conf <<'EOF'
vpn {
	path = /usr/jails/vpn;
	vnet;
	vnet.interface = epair0b;
}
EOF
	cat > fake-jail <<'EOF'
#!/bin/sh
for a; do
	[ "$a" = "-e" ] && exec /usr/sbin/jail "$@"
done
echo "fake-jail: jail $*"
echo "fake-jail: on stderr" >&2
[ -f fail ] && exit 3
exit 0
EOF
	chmod +x fake-jail
}

# Two rc.d directories with scripts, an rc.conf of our own, and
# stand-ins for service(8) and sysrc(8) that work from them: "service -e"
# lists the scripts whose rcvar is YES, "status" reports from a marker
# next to the script, start/stop make and remove it, sysrc edits rc.conf.
write_rc()
{
	mkdir -p rc.d local/rc.d
	printf 'sshd_enable="YES"\nsshd_flags="-4"\nntpd_enable="NO"\n' \
	    > rc.conf
	for svc in sshd ntpd; do
		printf '#!/bin/sh\n' > rc.d/$svc
		chmod +x rc.d/$svc
	done
	printf '#!/bin/sh\n' > local/rc.d/nginx
	chmod +x local/rc.d/nginx
	printf 'not a script\n' > rc.d/README
	cat > fake-sysrc <<EOS
#!/bin/sh
conf=$(pwd)/rc.conf
echo "\$*" >> $(pwd)/sysrc.log
# -R dir: the rc.conf of what is rooted there, a jail's.
[ "\$1" = -R ] && { conf=\$2/etc/rc.conf; shift 2; }
[ "\$1" = -f ] && { conf=\$2; touch "\$conf"; shift 2; }
ign=no
[ "\$1" = -i ] && { ign=yes; shift; }
put()
{
	grep -v "^\$1=" "\$conf" > "\$conf.new"
	[ -n "\$2" ] && printf '%s="%s"\n' "\$1" "\$2" >> "\$conf.new"
	mv "\$conf.new" "\$conf"
}
case "\$1" in
-a|-A)	sed -e 's/="\(.*\)"\$/: \1/' "\$conf" ;;
-n)	grep -q "^\$2=" "\$conf" || exit 1
	sed -n "s/^\$2=\"\(.*\)\"\\\$/\1/p" "\$conf" ;;
-x)	grep -q "^\$2=" "\$conf" || { [ \$ign = yes ] && exit 0; exit 1; }
	grep -v "^\$2=" "\$conf" > "\$conf.new"; mv "\$conf.new" "\$conf" ;;
*+=*)	key=\${1%%+=*}; val=\${1#*+=}
	old=\$(sed -n "s/^\$key=\"\(.*\)\"\\\$/\1/p" "\$conf")
	# As sysrc(8): appended when not already present.
	case " \$old " in *" \$val "*) ;; *) put "\$key" "\${old:+\$old }\$val" ;; esac
	echo "\$key: \$old -> \$val" ;;
*-=*)	key=\${1%%-=*}; val=\${1#*-=}
	old=\$(sed -n "s/^\$key=\"\(.*\)\"\\\$/\1/p" "\$conf")
	new=\$(echo " \$old " | sed -e "s/ \$val / /" -e 's/^ *//' -e 's/ *\$//')
	put "\$key" "\$new" ;;
*=*)	key=\${1%%=*}; val=\${1#*=}
	grep -v "^\$key=" "\$conf" > "\$conf.new"
	printf '%s="%s"\n' "\$key" "\$val" >> "\$conf.new"
	mv "\$conf.new" "\$conf"; echo "\$key: \$val" ;;
*)	exit 1 ;;
esac
EOS
	chmod +x fake-sysrc
	cat > fake-service <<EOS
#!/bin/sh
conf=$(pwd)/rc.conf
if [ "\$1" = -e ]; then
	for f in $(pwd)/rc.d/* $(pwd)/local/rc.d/*; do
		n=\${f##*/}
		grep -q "^\${n}_enable=\"YES\"" "\$conf" && echo "\$f"
	done
	exit 0
fi
name=\$1; verb=\$2
case "\$verb" in
rcvar)		echo "# \$name"; echo "\${name}_enable=\"NO\""; echo '#   (default: "")' ;;
status)		[ -f "running.\$name" ] && { echo "\$name is running as pid 4242."; exit 0; }
		echo "\$name is not running."; exit 1 ;;
start|onestart)	touch "running.\$name"; echo "Starting \$name." ;;
stop)		rm -f "running.\$name"; echo "Stopping \$name." ;;
restart)	[ -f slow ] && sleep 2
		# Held while the test wants it under way, a minute at most.
		i=0; while [ -f hold ] && [ \$i -lt 600 ]; do sleep 0.1; i=\$((i + 1)); done
		touch "running.\$name"; echo "Restarting \$name." ;;
reload|onereload)	echo "Reloading \$name." ;;
describe)	echo "The \$name daemon." ;;
extracommands)	echo "reload configtest" ;;
*)		echo "fake-service: \$*" >&2; exit 2 ;;
esac
EOS
	chmod +x fake-service
}

# netstat(1) and sockstat(1) stand-ins: a little JSON, and the arguments
# they were given, on standard error for the trace.
write_net()
{
	cat > fake-netstat <<'EOS'
#!/bin/sh
echo "fake-netstat $*" >&2
case "$*" in
*-OnW*)	echo '{"statistics": {"route-nhgrp-information": {"nhgrp-table": {"rt-family": [{"address-family": "Internet", "nhgrp-entry": [{"nhgrp-index": 1, "nhg-refcnt": 1, "nhop-weights": [{"nh-index": 5, "nh-weight": 2, "nh-slots": 2, "nh-gw": "10.0.0.1", "nh-interface": "em0"}]}]}]}}}}' ;;
*-onW*)	echo '{"statistics": {"route-nhop-information": {"nhop-table": {"rt-family": []}}}}' ;;
*)	echo '{"statistics": {"socket": [{"protocol": "tcp4", "local": {"address": "10.0.0.1", "port": "22"}, "remote": {"address": "10.0.0.2", "port": "4000"}, "tcp-state": "ESTABLISHED"}]}}' ;;
esac
EOS
	chmod +x fake-netstat
	# The helper, which speaks netlink(4) for the routes: what it is
	# asked is logged, what it answers is canned.  ./huge is a table
	# of 3000 routes; ./covers the routes an address is in.
	[ -f fake-helper ] || cat > fake-helper <<EOS
#!/bin/sh
echo "fake-helper \$*" >&2
shift
echo "\$*" >> $(pwd)/helper.log
jid=\$1 verb=\$2
shift 2
case "\$verb" in
routes)
	if [ "\$4" != - ]; then
		[ -f $(pwd)/covers ] && cat $(pwd)/covers
		echo '{"destination":"default","gateway":"192.0.2.1","flags":"UGS","nhop":1,"mtu":1500,"interface-name":"em0","metric":1,"weight":1,"fib":0,"prefixlen":0}'
		echo "#total 5"; exit 0
	fi
	if [ -f $(pwd)/huge ] && [ "\$1" != 6 ]; then
		jot 3000 0 | awk -v f="\$3" '{ d = sprintf("10.%d.%d.0/24", int(\$1 / 250), \$1 % 250); if (f == "-" || index(d, f)) printf "{\\"destination\\":\\"%s\\",\\"gateway\\":\\"192.0.2.1\\",\\"flags\\":\\"UGS\\",\\"nhop\\":%d,\\"mtu\\":1500,\\"interface-name\\":\\"em0\\",\\"metric\\":1,\\"weight\\":1,\\"fib\\":0,\\"prefixlen\\":24}\\n", d, \$1 }'
		echo "#total 3000"; exit 0
	fi
	[ "\$1" != 6 ] && echo '{"destination":"10.0.0.0/24","gateway":"link#1","flags":"U","nhop":2,"mtu":1500,"interface-name":"em0","metric":1,"weight":1,"fib":'\$2',"prefixlen":24}'
	[ "\$1" = 0 ] && echo "#family 6"
	[ "\$1" != 4 ] && echo '{"destination":"::1","gateway":"link#2","flags":"UHS","nhop":1,"mtu":16384,"interface-name":"lo0","metric":1,"weight":1,"fib":'\$2',"prefixlen":128}'
	echo "#total 2" ;;
route-get)
	case "\$1" in 203.0.113.*) exit 1 ;; esac
	echo '{"to":"'\$1'","destination":"10.77.0.0","prefixlen":16,"gateway":"10.0.0.1","fib":"'\$2'","interface":"em0","flags":"UGS","metric":1,"weight":1}' ;;
pcb-conns)
	[ "\$1" != 6 ] && echo '{"protocol":"tcp4","receive-bytes-waiting":0,"send-bytes-waiting":0,"local":{"address":"10.0.0.1","port":"22"},"remote":{"address":"10.0.0.2","port":"4000"},"tcp-state":"ESTABLISHED"}'
	echo "#total 1" ;;
pcb-socks)
	echo '{"user":"root","command":"sshd","pid":1,"fd":3,"proto":"tcp'\$( [ "\$1" = 6 ] && echo 6 || echo 4)'","local":{"address":"*","port":22},"foreign":{"address":"*","port":0}}'
	echo "#total 1" ;;
route-neighs)
	[ "\$1" != 6 ] && echo '{"family":"inet","address":"10.0.0.2","lladdr":"58:9c:fc:00:00:02","interface-name":"em0","state":"reachable","next":120}' | grep -e "\${2#-}"
	[ "\$1" != 4 ] && echo '{"family":"inet6","address":"fe80::1%em0","lladdr":"58:9c:fc:00:00:01","interface-name":"em0","state":"stale","router":true}' | grep -e "\${2#-}"
	echo "#total 2" ;;
carp-set)
	echo "carp-set \$* key=\$(cat)" >> $(pwd)/carp.log ;;
route-add|route-del)
	echo "\$jid \$verb \$*" >> $(pwd)/route.log
	case "\$1" in 10.66.0.0/16) echo "10.66.0.0/16: the route is there already" >&2; exit 1 ;; esac ;;
esac
exit 0
EOS
	chmod +x fake-helper
}

# pkg(8) stand-in: the pending upgrades live in ./pending, one per line
# as "name-installed remote"; upgrade -y removes the named ones (or all).
write_pkg()
{
	printf 'aria2-1.37.0_1 1.37.0_2
pimd-3.1.0 3.2.0
' > pending
	cat > fake-pkg <<'EOS'
#!/bin/sh
echo "fake-pkg $*" >&2
case "$1" in -4|-6) shift ;; esac
anyos=no; [ "$1" = -o ] && { anyos=yes; shift 2; }
[ "$1" = -j ] && shift 2
case "$1" in
-vv)	printf 'Version                 : 2.3.1\nRepositories:\n  FreeBSD-ports: { \n    url             : "pkg+https://pkg.FreeBSD.org/FreeBSD:16:amd64/latest",\n    enabled         : yes,\n  }\n  builder: { \n    url             : "file:///usr/local/poudriere/data/packages/lab",\n    enabled         : no,\n  }\n' ;;
update)	exit 0 ;;
query)	printf 'aria2\t1.37.0_1\t0\t5242880\twww/aria2\tDownload utility\npimd\t3.1.0\t1\t102400\tnet/pimd\tPIM-SM daemon\n' ;;
clean)	echo "$*" >> clean.log ;;
version)
	# A repository for a newer FreeBSD: refused, as upgrade is.
	if [ -e newer -a $anyos = no ]; then
		echo 'Error updating repositories!'
		echo 'pkg: repository FreeBSD-base contains packages for wrong OS version: FreeBSD:16:amd64' >&2
		exit 3
	fi
	[ -s pending ] || exit 1
	# pkg 2 says how each repository is first.
	printf 'FreeBSD-ports repository is up to date.\nFreeBSD-ports-kmods repository is up to date.\nFreeBSD-base repository is up to date.\nAll repositories are up to date.\n'
	while read nv remote; do
		printf '%-30s <   needs updating (remote has %s)
' "$nv" "$remote"
	done < pending ;;
upgrade|install)
	# A repository for a newer FreeBSD: refused but past OSVERSION,
	# and pkg exits 0 still.
	if [ -e newer -a $anyos = no ]; then
		echo 'Error updating repositories!'
		echo 'pkg: repository FreeBSD-base contains packages for wrong OS version: FreeBSD:16:amd64' >&2
		echo "pkg: Repository FreeBSD-ports cannot be opened. 'pkg update' required" >&2
		echo 'Your packages are up to date.'
		exit 0
	fi
	[ "$1" = install ] && { echo "$*" >> install.log; exit 0; }
	shift
	[ "$1" = -r ] && { echo "upgrade from $2" >> repo.log; shift 2; }
	dry=no; [ "$1" = -n ] && dry=yes; shift
	[ -s pending ] || { echo "Your packages are up to date."; exit $([ $dry = yes ] && echo 1 || echo 0); }
	while read nv remote; do
		name=${nv%-*}
		if [ $# -eq 0 ] || echo " $* " | grep -q " $name "; then
			echo "Upgrading $name from ${nv##*-} to $remote..."
			[ $dry = yes ] || grep -v "^$nv " pending > pending.new
			[ $dry = yes ] || mv pending.new pending
		fi
	done < pending ;;
*)	exit 2 ;;
esac
EOS
	chmod +x fake-pkg
}

# Start arcana-agent on ./s.sock and wait until it answers.
start_daemon()
{
	local i

	programs
	write_conf
	SOCK="unix:$(pwd)/s.sock"
	write_rc
	write_net
	write_pkg
	"$JGD" -F -l "$SOCK" -f "$(pwd)/etc/jail.conf" \
	    -D "$(pwd)/etc/jail.conf.d" -j "$(pwd)/fake-jail" \
	    -R "$(pwd)/rc.d:$(pwd)/local/rc.d" -s "$(pwd)/fake-service" \
	    -y "$(pwd)/fake-sysrc" -N "$(pwd)/fake-netstat" \
	    -P "$(pwd)/fake-pkg" \
	    -U "$(pwd)/installed-agent" -B "$(pwd)/build" \
	    -c "$(pwd)/build.mk" -G "$(pwd)/fake-git" -M "$(pwd)/fake-make" \
	    -Y "$(pwd)/fake-keyscan" -I "$(pwd)/fake-ifconfig" \
	    -n "$(pwd)/fake-ngctl" \
	    -k "$(pwd)/fake-wg" -o "$(pwd)/wg" -b "$(pwd)/fake-birdc" \
	    -r "$(pwd)/fake-swanctl" -5 "$(pwd)/swanctl" \
	    -e "$(pwd)/fake-bird" -a "$(pwd)/bird/bird.conf" \
	    -L "$(pwd)/fake-jls" -x "$(pwd)/fake-jexec" \
	    -H "$(pwd)/fake-helper" -T "$(pwd)/fake-kldload" \
	    -t "$(pwd)/fake-kldunload" -1 "$(pwd)/history.conf" -w 2 \
	    -X "$(pwd)/fake-traceroute" -4 "$(pwd)/ntp.conf" \
	    -6 "$(pwd)/rtadvd.conf" -7 "$(pwd)/fake-dnsmasq" -8 "$(pwd)/fake-rtsol" \
	    -9 "$(pwd)/fake-setkey" -0 "$(pwd)/fake-local-unbound" \
	    --bird-watch 0 $DAEMON_ARGS \
	    > daemon.out 2>&1 &
	echo $! > daemon.pid
	for i in $(seq 1 100); do
		grep -q 'ready' daemon.out 2>/dev/null && return
		sleep 0.05
	done
	atf_fail "arcana-agent did not start: $(cat daemon.out)"
}

stop_daemon()
{
	local pid i

	[ -f daemon.pid ] || return 0
	pid=$(cat daemon.pid)
	kill "$pid" 2>/dev/null
	# Gone before anything follows: one that left later would take
	# away the socket the next one had made.
	for i in $(seq 1 100); do
		kill -0 "$pid" 2>/dev/null || break
		sleep 0.05
	done
	true
}

atf_test_case hello cleanup
hello_head()
{
	atf_set "descr" "hello reports this host"
}
hello_body()
{
	start_daemon
	[ "$(id -u)" -eq 0 ] && priv=true || priv=false
	atf_check -o match:"^System: $(uname -s) $(uname -r)" \
	    -o match:"^Privileged: ${priv}\$" -o match:'^arcana-agent: [0-9.]+$' \
	    "$JGC" -c "$SOCK" hello
}
hello_cleanup()
{
	stop_daemon
}

atf_test_case socket_mode cleanup
socket_mode_head()
{
	atf_set "descr" "The local socket is 0600 unless a group is given"
}
socket_mode_body()
{
	start_daemon
	atf_check -o match:'^srw-------' ls -l s.sock
}
socket_mode_cleanup()
{
	stop_daemon
}

atf_test_case list cleanup
list_head()
{
	atf_set "descr" "list merges configured jails, resolved by jail(8)"
}
list_body()
{
	start_daemon
	atf_check -o save:list.out "$JGC" -c "$SOCK" list
	atf_check -o match:'^web +stopped +- +10.0.0.10,10.0.0.11 +web.lab.example$' \
	    cat list.out
	atf_check -o match:'^mail +stopped +- +10.0.0.30 +mail.lab.example$' \
	    cat list.out
	atf_check -o match:'^vpn +stopped' cat list.out
	atf_check -o match:'^db +stopped +- +em1\|192.168.5.20/24' cat list.out
	atf_check -o match:'^NAME +STATE +JID +ADDRESSES +HOSTNAME$' \
	    cat list.out
}
list_cleanup()
{
	stop_daemon
}

atf_test_case conf_errors cleanup
conf_errors_head()
{
	atf_set "descr" "A broken scope is reported; the rest is listed"
}
conf_errors_body()
{
	start_daemon
	printf 'bad {\n\tpath = "/x;\n}\n' > etc/jail.conf.d/bad.conf
	atf_check -o match:'^web ' -e match:'bad.conf line 2: unterminated string' \
	    "$JGC" -c "$SOCK" list -c
	# What jail(8) only warns of is passed on too, with every jail of
	# the file listed: here a variable one jail uses and does not have.
	rm etc/jail.conf.d/bad.conf
	printf 'template {\n\tpath = /;\n\tip6.addr = "$ip6";\n}\n' \
	    > etc/jail.conf.d/template.conf
	atf_check -o match:'^web ' -o match:'^template ' \
	    -e match:'template: ip6.addr: variable "ip6" not found' \
	    "$JGC" -c "$SOCK" list -c
}
conf_errors_cleanup()
{
	stop_daemon
}

atf_test_case trace cleanup
trace_head()
{
	atf_set "descr" "-t shows library calls and programs with their output"
}
trace_body()
{
	start_daemon
	atf_check -o save:trace.out "$JGC" -t -c "$SOCK" list
	atf_check -o match:'\[daemon\] arcana-agent: list' cat trace.out
	atf_check -o match:'\[lib\] jailparam_get\(3\)' cat trace.out
	atf_check -o match:'\[exec\] .*fake-jail -f .*/etc/jail.conf -e \\037' \
	    cat trace.out
	atf_check -o match:'\| name=web\\037' cat trace.out
}
trace_cleanup()
{
	stop_daemon
}

atf_test_case start cleanup
start_head()
{
	atf_set "descr" "start runs jail(8) -c with the jail's file"
}
start_body()
{
	start_daemon
	atf_check -o save:start.out -e empty "$JGC" -t -c "$SOCK" start web
	atf_check -o match:"fake-jail -f $(pwd)/etc/jail.conf -c web: exit status 0" \
	    cat start.out
	atf_check -o match:'\| fake-jail: jail -f .* -c web$' \
	    -o match:'! fake-jail: on stderr$' cat start.out
	atf_check -o match:"\\[exec\\] .*fake-jail -f $(pwd)/etc/jail.conf.d/vpn.conf -c vpn" \
	    "$JGC" -t -c "$SOCK" start vpn
}
start_cleanup()
{
	stop_daemon
}

atf_test_case failures cleanup
failures_head()
{
	atf_set "descr" "Failed actions exit 1, say why and keep the output"
}
failures_body()
{
	start_daemon
	touch fail
	atf_check -s exit:1 -o match:'! fake-jail: on stderr' \
	    -e match:'start web: jail exited with status 3: fake-jail: on stderr' \
	    "$JGC" -t -c "$SOCK" start web
	atf_check -s exit:1 -o ignore -e match:"stop web: jail 'web' is not running" \
	    "$JGC" -c "$SOCK" stop web
	atf_check -s exit:1 -o ignore -e match:"kill web: jail 'web' is not running" \
	    "$JGC" -c "$SOCK" kill web
	atf_check -s exit:1 -o ignore -e match:"jail 'nope' is not defined" \
	    "$JGC" -c "$SOCK" start nope
	atf_check -s exit:1 -e match:'invalid jail name' \
	    "$JGC" -c "$SOCK" start ../etc
	atf_check -s exit:1 -e match:'invalid jail name' \
	    "$JGC" -c "$SOCK" start 42
}
failures_cleanup()
{
	stop_daemon
}

atf_test_case address_dry_run cleanup
address_dry_run_head()
{
	atf_set "descr" "A dry run returns the diff and changes nothing"
}
address_dry_run_body()
{
	start_daemon
	cp etc/jail.conf before
	atf_check -o match:'^-	ip4.addr = 10.0.0.10, "10.0.0.11";$' \
	    -o match:'^\+	ip4.addr = 10.0.0.10, "10.0.0.11", "10.0.0.12";$' \
	    "$JGC" -c "$SOCK" address add -pn web 10.0.0.12
	atf_check cmp -s before etc/jail.conf
}
address_dry_run_cleanup()
{
	stop_daemon
}

atf_test_case address_persist cleanup
address_persist_head()
{
	atf_set "descr" "Persistent changes edit in place, keep a backup and are re-read"
}
address_persist_body()
{
	start_daemon
	cp etc/jail.conf before
	atf_check -o match:'^IPv4: 10.0.0.10,10.0.0.11,10.0.0.12$' \
	    "$JGC" -c "$SOCK" address add -p web 10.0.0.12
	atf_check cmp -s before etc/jail.conf.arcana.bak
	atf_check -o match:'^	ip4.addr = 10.0.0.10, "10.0.0.11", "10.0.0.12";$' \
	    cat etc/jail.conf
	atf_check -o match:'^# Lab jails$' cat etc/jail.conf
	atf_check -o match:'^IPv4: 10.0.0.11,10.0.0.12$' \
	    "$JGC" -c "$SOCK" address remove -p web 10.0.0.10
	# A jail defined in an included file is edited there.
	atf_check -o ignore "$JGC" -c "$SOCK" address remove -p mail 10.0.0.30
	atf_check -s exit:1 grep ip4.addr inc/mail.inc
}
address_persist_cleanup()
{
	stop_daemon
}

atf_test_case address_refused cleanup
address_refused_head()
{
	atf_set "descr" "Address changes that cannot be made are refused"
}
address_refused_body()
{
	start_daemon
	cp etc/jail.conf before
	atf_check -s exit:1 -o ignore -e match:'is already in ip4.addr' \
	    "$JGC" -c "$SOCK" address add -p web 10.0.0.11
	atf_check -s exit:1 -o ignore -e match:'vnet jail' \
	    "$JGC" -c "$SOCK" address add -p vpn 10.0.0.50
	atf_check -s exit:1 -o ignore -e match:"jail 'web' is not running" \
	    "$JGC" -c "$SOCK" address add -l web 10.0.0.13
	atf_check -s exit:1 -o ignore -e match:'not an IP address' \
	    "$JGC" -c "$SOCK" address add -p web 10.0.0.300
	atf_check -s exit:1 -e match:'give the interface separately' \
	    "$JGC" -c "$SOCK" address add -p web 'em0|10.0.0.14'
	atf_check -s exit:1 -e match:'invalid interface name' \
	    "$JGC" -c "$SOCK" address add -p -i 'em0;x' web 10.0.0.14
	atf_check cmp -s before etc/jail.conf
}
address_refused_cleanup()
{
	stop_daemon
}

atf_test_case many_jails cleanup
many_jails_head()
{
	atf_set "descr" "a listing of hundreds of jails with their parameters fits a reply"
}
many_jails_body()
{
	start_daemon
	i=0
	while [ $i -lt 400 ]; do
		printf 'j%d {\n\tip4.addr = 10.1.%d.%d;\n\thost.hostname = j%d.lab;\n\tallow.raw_sockets;\n\tmount.devfs;\n\texec.start = "/bin/sh /etc/rc";\n\texec.stop = "/bin/sh /etc/rc.shutdown";\n}\n' \
		    $i $((i / 250)) $((i % 250)) $i >> etc/jail.conf
		i=$((i + 1))
	done
	atf_check -o save:many.out "$JGC" -c "$SOCK" list
	atf_check -o match:'^j399 ' cat many.out
	atf_check -o inline:'405\n' sh -c "grep -c '' many.out"
}
many_jails_cleanup()
{
	stop_daemon
}

atf_test_case services cleanup
services_head()
{
	atf_set "descr" "rc.d scripts listed with their state, through service(8)"
}
services_body()
{
	start_daemon
	atf_check -o save:services.out "$JGC" -c "$SOCK" services
	atf_check -o match:'^sshd +enabled +stopped' cat services.out
	atf_check -o match:'^ntpd +- ' cat services.out
	atf_check -o match:'^nginx +- ' cat services.out
	atf_check -o not-match:'README' cat services.out
	# One listing, one status per enabled service, in the trace.
	atf_check -o save:trace.out "$JGC" -t -c "$SOCK" services
	atf_check -o match:'fake-sysrc -A' cat trace.out
	atf_check -o not-match:'fake-service -e' cat trace.out
	atf_check -o match:'fake-service sshd status' cat trace.out
	atf_check -o not-match:'fake-service ntpd status' cat trace.out
}
services_cleanup()
{
	stop_daemon
}

atf_test_case service_actions cleanup
service_actions_head()
{
	atf_set "descr" "start, stop, enable and disable through service(8) and sysrc(8)"
}
service_actions_body()
{
	start_daemon
	atf_check -o match:'Running: yes' -o match:'pid 4242' \
	    "$JGC" -c "$SOCK" service sshd start
	atf_check -o match:'Running: no' "$JGC" -c "$SOCK" service sshd stop
	atf_check -o match:'Enabled: yes' "$JGC" -c "$SOCK" service ntpd enable
	atf_check -o match:'^ntpd_enable="YES"' cat rc.conf
	atf_check -o match:'Enabled: no' "$JGC" -c "$SOCK" service ntpd disable
	atf_check -o match:'^ntpd_enable="NO"' cat rc.conf
	atf_check -s exit:1 -o ignore -e match:"no rc.d script 'nope'" \
	    "$JGC" -c "$SOCK" service nope start
	atf_check -s exit:1 -e match:'invalid service name' \
	    "$JGC" -c "$SOCK" service ../etc start
	atf_check -s exit:1 -e match:'invalid service name' \
	    "$JGC" -c "$SOCK" service 'a;b' start
}
service_actions_cleanup()
{
	stop_daemon
}

atf_test_case service_config cleanup
service_config_head()
{
	atf_set "descr" "rc.conf variables of a service read and set with sysrc(8)"
}
service_config_body()
{
	start_daemon
	atf_check -o save:cfg.out "$JGC" -c "$SOCK" service sshd config
	atf_check -o match:'sshd_enable=YES' cat cfg.out
	atf_check -o match:'sshd_flags=-4' cat cfg.out
	atf_check -o not-match:'ntpd' cat cfg.out
	atf_check -o match:'Describe: The sshd daemon' cat cfg.out
	atf_check -o match:'Commands: reload,configtest' cat cfg.out
	atf_check -o match:'sshd_flags=-6 -D' \
	    "$JGC" -c "$SOCK" service sshd config 'sshd_flags=-6 -D'
	atf_check -o match:'^sshd_flags="-6 -D"' cat rc.conf
	atf_check -o not-match:'sshd_flags' \
	    "$JGC" -c "$SOCK" service sshd config -x sshd_flags
	atf_check -o not-match:'sshd_flags' cat rc.conf
	# Only the service's own variables.
	atf_check -s exit:1 -o ignore \
	    -e match:"'ntpd_enable' is not a variable of sshd" \
	    "$JGC" -c "$SOCK" service sshd config ntpd_enable=YES
	atf_check -s exit:1 -o ignore -e match:'is not a variable of sshd' \
	    "$JGC" -c "$SOCK" service sshd config 'sshd_x;y=1'
}
service_config_cleanup()
{
	stop_daemon
}

atf_test_case network cleanup
network_head()
{
	atf_set "descr" "routes as the kernel has them, through the helper; nexthops, connections and sockets as the programs' libxo JSON"
}
network_body()
{
	start_daemon
	# The routes: asked of the kernel by the helper, each with what
	# the kernel says of it; the two families in one document.
	atf_check -o save:routes.out "$JGC" -c "$SOCK" net routes -6
	atf_check -o match:'"route-table":\{"rt-family":\[\{"address-family":"Internet6","rt-entry":\[\{"destination":"::1","gateway":"link#2","flags":"UHS","nhop":1,"mtu":16384,"interface-name":"lo0","metric":1,"weight":1,"fib":0,"prefixlen":128\}\]\}\]' \
	    cat routes.out
	atf_check -o match:'fake-helper --scope-helper 0 routes 6 0 - -:' \
	    "$JGC" -t -c "$SOCK" net routes -6
	atf_check -o match:'"address-family":"Internet","rt-entry":\[\{"destination":"10.0.0.0/24"[^]]*\]\},\{"address-family":"Internet6","rt-entry":\[\{"destination":"::1"' \
	    "$JGC" -c "$SOCK" net routes
	# Both families: a run each, the entries joined.
	atf_check -o save:nh.out "$JGC" -t -c "$SOCK" net nexthops
	atf_check -o match:'fake-netstat --libxo json -onW -f inet$' cat nh.out
	atf_check -o match:'fake-netstat --libxo json -onW -f inet6$' cat nh.out
	atf_check -o match:'"rt-family"' cat nh.out
	# The connections and sockets: the kernel's own lists, read by the
	# helper here (by the daemon itself when it is its own helper).
	atf_check -o match:'fake-helper --scope-helper 0 pcb-conns 4' \
	    -o match:'"statistics":\{"socket":\[\{"protocol":"tcp4"' \
	    "$JGC" -t -c "$SOCK" net connections -4
	atf_check -o save:so.out "$JGC" -t -c "$SOCK" net sockets
	atf_check -o match:'fake-helper --scope-helper 0 pcb-socks 0' \
	    -o match:'"sockstat":\{"socket":\[\{"user":"root","command":"sshd"' cat so.out
	# The nexthop groups, what a route of several next hops points to.
	atf_check -o match:'"nhgrp-index":1,"nhg-refcnt":1,"nhop-weights":\[\{"nh-index":5,"nh-weight":2' \
	    -o match:'fake-netstat --libxo json -OnW -f inet$' \
	    "$JGC" -t -c "$SOCK" net nhgroups
	# The neighbours, of ARP and NDP, asked of the kernel.
	atf_check -o match:'fake-helper --scope-helper 0 route-neighs 0 -' \
	    -o match:'"neighbours":\[\{"family":"inet","address":"10.0.0.2".*"router":true\}\],"total":2' \
	    "$JGC" -t -c "$SOCK" net neighbours
	atf_check -o match:'^\{"neighbours":\[\{"family":"inet6"[^]]*\],"total":2\}$' \
	    "$JGC" -c "$SOCK" net neighbours -6 fe80
	atf_check -s exit:2 -e ignore "$JGC" -c "$SOCK" net tables
	# A table too large to send whole: its first rows come, with how
	# many there are; and it can be searched on the host.
	touch huge
	atf_check -o save:huge.out -e match:'the table has 3000 rows' \
	    "$JGC" -c "$SOCK" net routes -4
	atf_check -o match:'"destination":"10.0.0.0/24"' \
	    -o match:'"destination":"10.7.249.0/24"' \
	    -o not-match:'"destination":"10.8.0.0/24"' \
	    -o match:'"interface-name":"em0"' cat huge.out
	# In parts, as they are taken: all 3000, with their family in each,
	# and the sockets and connections the same way; the text searched
	# for on the host.
	atf_check -o save:parts.out "$JGC" -c "$SOCK" net routes -4 parts
	atf_check -o inline:'3000\n' sh -c "grep -o '\"destination\"' parts.out | wc -l | tr -d ' '"
	atf_check -o match:'^\[\{"family":"Internet","destination":"10.0.0.0/24"' \
	    -o not-match:'Internet6' cat parts.out
	atf_check -o match:'"family":"Internet6","destination":"::1"' \
	    "$JGC" -c "$SOCK" net routes -6 parts
	atf_check -o match:'"destination":"10.11.249.0/24"' -o not-match:'10.0.0.0/24' \
	    "$JGC" -c "$SOCK" net routes -4 parts 10.11.249.
	atf_check -o match:'^\[\{"protocol":"tcp4"' "$JGC" -c "$SOCK" net connections -4 parts
	atf_check -o match:'"command":"sshd"' "$JGC" -c "$SOCK" net sockets parts
	atf_check -s exit:1 -e ignore -o ignore "$JGC" -c "$SOCK" net nexthops parts
	atf_check -o save:found.out "$JGC" -c "$SOCK" net routes -4 10.11.249.
	atf_check -o match:'"destination":"10.11.249.0/24"' \
	    -o not-match:'"destination":"10.0.0.0/24"' cat found.out
	atf_check -o match:'"total":3000' -o match:'"truncated":"false"' \
	    "$JGC" --libxo json -c "$SOCK" net routes -4 10.11.249.
	# And read on: the rows after the first 2000, which are the rest.
	atf_check -o save:more.out -e ignore "$JGC" -c "$SOCK" net routes -4 -o 2000
	atf_check -o match:'"destination":"10.8.0.0/24"' \
	    -o not-match:'"destination":"10.7.249.0/24"' \
	    -o match:'"destination":"10.11.249.0/24"' cat more.out
	atf_check -o match:'"total":3000' -o match:'"truncated":"false"' \
	    "$JGC" --libxo json -c "$SOCK" net routes -4 -o 2000
	rm huge
}
network_cleanup()
{
	stop_daemon
}

atf_test_case packages cleanup
packages_head()
{
	atf_set "descr" "pending upgrades and pkg upgrade, on the host and in a jail, through pkg(8)"
}
packages_body()
{
	start_daemon
	atf_check -o save:pk.out "$JGC" -t -c "$SOCK" packages -r
	atf_check -o match:'^aria2 +1\.37\.0_1 +1\.37\.0_2' cat pk.out
	atf_check -o match:'^pimd +3\.1\.0 +3\.2\.0' cat pk.out
	# A repository's line is no package.
	atf_check -o not-match:'^FreeBSD' -o not-match:'^All ' cat pk.out
	atf_check -o match:'fake-pkg update -q' cat pk.out
	atf_check -o match:"fake-pkg version -vRl <" cat pk.out
	# No refresh: no pkg update.
	atf_check -o not-match:'fake-pkg update' "$JGC" -t -c "$SOCK" packages
	# A jail must be running for pkg -j; web is not.
	atf_check -s exit:1 -o ignore -e match:"jail 'web' is not running" \
	    "$JGC" -c "$SOCK" packages web
	atf_check -s exit:1 -e match:'invalid jail name' \
	    "$JGC" -c "$SOCK" packages ../x
	# Dry run changes nothing; a real one upgrades, then nothing pends.
	atf_check -o match:'fake-pkg upgrade -n pimd' -o match:'^pimd ' \
	    "$JGC" -t -c "$SOCK" pkg-upgrade -n pimd
	atf_check -o save:up.out "$JGC" -t -c "$SOCK" pkg-upgrade pimd
	atf_check -o match:'Upgraded: 1' cat up.out
	atf_check -o match:'fake-pkg upgrade -y pimd' cat up.out
	atf_check -o match:'^aria2 ' -o not-match:'^pimd ' cat up.out
	atf_check -o match:'Upgraded: 1' -o match:'nothing to upgrade' \
	    "$JGC" -c "$SOCK" pkg-upgrade
	atf_check -s exit:1 -o ignore -e match:"'a;b' is not a package name" \
	    "$JGC" -c "$SOCK" pkg-upgrade 'a;b'
	# Of every running jail, by the agent: none runs here, said so.
	atf_check -s exit:1 -o ignore -e match:'no jail is running' \
	    "$JGC" -c "$SOCK" pkg-upgrade -J
	atf_check -o match:'1 queued +pkg upgrade in every jail' \
	    "$JGC" -q -c "$SOCK" pkg-upgrade -J
	for i in $(seq 1 50); do
		"$JGC" -c "$SOCK" jobs | grep -q 'queued\|running' || break
		sleep 0.1
	done
	atf_check -s exit:1 -o match:'no jail is running' "$JGC" -c "$SOCK" job 1
	# The installed, from the host's own database: no repository.
	atf_check -o match:'^aria2 +1\.37\.0_1 +by hand +5242880 Download utility' \
	    -o match:'^pimd +3\.1\.0 +automatic' -o match:'fake-pkg query' \
	    -o not-match:'fake-pkg (version|update)' \
	    "$JGC" -t -c "$SOCK" packages -i
	# Over IPv6 only; past OSVERSION.
	atf_check -o match:'fake-pkg -6 version -vRl <' "$JGC" -t -c "$SOCK" packages -6
	atf_check -o match:'fake-pkg -4 -o IGNORE_OSVERSION=yes upgrade -n' \
	    "$JGC" -t -c "$SOCK" pkg-upgrade -n -O -4
	# pkg's repositories, enabled or not (pkg -vv); an upgrade held to
	# one of them (pkg upgrade -r, what it has newer by pkg version -R
	# -r), a name pkg has not refused; an install from one too.
	atf_check -o match:'Repositories: +FreeBSD-ports +builder' \
	    "$JGC" -c "$SOCK" packages
	atf_check -o match:'fake-pkg upgrade -r builder -n' \
	    -o match:'fake-pkg version -vR -r builder -l <' \
	    "$JGC" -t -c "$SOCK" pkg-upgrade -n -r builder
	atf_check -o inline:'upgrade from builder\n' cat repo.log
	atf_check -s exit:1 -o ignore -e match:'pkg has no repository nosuch' \
	    "$JGC" -c "$SOCK" pkg-upgrade -n -r nosuch
	atf_check -s exit:1 -o ignore -e match:"'a b' is not a repository's name" \
	    "$JGC" -c "$SOCK" pkg-upgrade -n -r 'a b'
	atf_check -o match:'done +pkg install aria2 from builder$' \
	    "$JGC" -c "$SOCK" pkg-install -r builder aria2
	atf_check -o match:'^install -r builder -y aria2$' cat install.log
	# A repository for a newer FreeBSD: no success, though pkg exits 0,
	# and IGNORE_OSVERSION named for the console to ask; past it, done.
	touch newer
	atf_check -s exit:1 -o ignore -e match:'pkg upgrade: a repository has packages for a newer FreeBSD than this one, refused unless IGNORE_OSVERSION=yes: repository FreeBSD-base contains packages for wrong OS version: FreeBSD:16:amd64; Repository FreeBSD-ports cannot be opened' \
	    "$JGC" -c "$SOCK" pkg-upgrade -n
	# The pending read too: named the same, for the console to ask
	# whether to read past it.
	atf_check -s exit:1 -o ignore -e match:'pkg version: a repository has packages for a newer FreeBSD than this one, refused unless IGNORE_OSVERSION=yes' \
	    "$JGC" -c "$SOCK" packages
	atf_check -s exit:1 -o match:'failed +pkg install aria2' \
	    "$JGC" -c "$SOCK" pkg-install aria2
	atf_check -o match:'Upgraded: 0' "$JGC" -c "$SOCK" pkg-upgrade -O
	rm newer
	# The cache cleaned, as a job; all of it with -a.
	atf_check -o match:'done +pkg clean$' "$JGC" -c "$SOCK" pkg-clean
	atf_check -o match:'done +pkg clean -a$' "$JGC" -c "$SOCK" pkg-clean -a
	atf_check -o inline:'clean -y\nclean -ay\n' cat clean.log
	# Of every running jail: none runs here, and that is said.
	atf_check -s exit:1 -e match:'no running jail' "$JGC" -c "$SOCK" pkg-clean -J
	atf_check -s exit:2 -e ignore "$JGC" -c "$SOCK" pkg-clean -J -j web
}
packages_cleanup()
{
	stop_daemon
}

atf_test_case jobs cleanup
jobs_head()
{
	atf_set "descr" "queued changes run in order, without their client, with a trace that grows"
}
jobs_body()
{
	start_daemon
	# A slow job, then two behind it; every client leaves at once.
	touch slow
	atf_check -o match:'^ +1 queued +service sshd restart' \
	    "$JGC" -q -c "$SOCK" service sshd restart
	atf_check -o match:'^ +2 queued +start web' "$JGC" -q -c "$SOCK" start web
	atf_check -o match:'^ +3 queued +service ntpd enable' \
	    "$JGC" -q -c "$SOCK" service ntpd enable
	# While the first runs: its trace so far, the rest waiting.
	sleep 0.5
	atf_check -o save:running.out "$JGC" -c "$SOCK" job 1
	atf_check -o match:'^ +1 running ' cat running.out
	atf_check -o match:'job 1: service sshd restart' cat running.out
	atf_check -o match:'fake-service sshd restart.*incomplete' cat running.out
	atf_check -o match:'^ +2 queued ' -o match:'^ +3 queued ' \
	    "$JGC" -c "$SOCK" jobs
	# One still queued can be taken back; a running one cannot.
	atf_check -o match:'^ +3 cancelled ' "$JGC" -c "$SOCK" job-cancel 3
	atf_check -s exit:1 -e match:'is running' "$JGC" -c "$SOCK" job-cancel 1
	# Wait for the second: both ran, in order, with nobody attached.
	atf_check -o save:done.out "$JGC" -c "$SOCK" job -w 2
	atf_check -o match:'^ +2 done +start web' cat done.out
	atf_check -o match:'fake-jail .* -c web' cat done.out
	atf_check -o match:'^ +1 done ' -o match:'^ +2 done ' \
	    -o match:'^ +3 cancelled ' "$JGC" -c "$SOCK" jobs
	atf_check test -f running.sshd
	atf_check -o match:'^ntpd_enable="NO"' cat rc.conf
	# A job that fails says why, and the next still runs.
	rm slow
	touch fail
	atf_check -o ignore "$JGC" -q -c "$SOCK" start db
	atf_check -o ignore "$JGC" -q -c "$SOCK" service ntpd enable
	atf_check -s exit:1 -o match:'^ +4 failed +start db: jail exited' \
	    "$JGC" -c "$SOCK" job -w 4
	atf_check -o match:'^ +5 done ' "$JGC" -c "$SOCK" job -w 5
	atf_check -o match:'^ntpd_enable="YES"' cat rc.conf
	# What a job may be is checked when it is queued.
	atf_check -s exit:1 -e match:'invalid jail name' \
	    "$JGC" -q -c "$SOCK" start ../x
	atf_check -s exit:1 -e match:'no such job' "$JGC" -c "$SOCK" job 99
}
jobs_cleanup()
{
	stop_daemon
}

atf_test_case interfaces cleanup
interfaces_head()
{
	atf_set "descr" "Interfaces are listed, and changed with ifconfig(8)"
}
interfaces_body()
{
	# ifconfig(8) for changes: what it was run with, and a refusal.
	cat > fake-ifconfig <<EOS
#!/bin/sh
echo "\$*" >> $(pwd)/ifconfig.log
case " \$* " in *" 10.9.9.9"*) echo "ifconfig: ioctl (SIOCAIFADDR): File exists" >&2; exit 1 ;; esac
exit 0
EOS
	chmod +x fake-ifconfig
	start_daemon
	# The loopback is on every host: with its addresses and flags.
	atf_check -o save:if.json "$JGC" -c "$SOCK" net interfaces
	atf_check -o match:'"name":"lo0"' -o match:'LOOPBACK' \
	    -o match:'"address":"127.0.0.1"' -o match:'"prefixlen":8' \
	    -o match:'"family":"inet6"' -o match:'"mtu":' cat if.json
	atf_check -o match:'"address":"127.0.0.1"' -o not-match:'"inet6"' \
	    "$JGC" -c "$SOCK" net interfaces -4

	# An alias on, and off again: ifconfig is run as one would run it.
	atf_check -o match:'done' -o match:'lo0: add 10.9.0.5/24' \
	    -o match:'fake-ifconfig lo0 inet 10.9.0.5/24 alias' \
	    "$JGC" -c "$SOCK" interface lo0 add 10.9.0.5/24
	atf_check -o match:'fake-ifconfig lo0 inet 10.9.0.5 -alias' \
	    "$JGC" -c "$SOCK" interface lo0 remove 10.9.0.5/24
	atf_check -o match:'fake-ifconfig lo0 inet6 2001:db8::5/128 alias' \
	    "$JGC" -c "$SOCK" interface lo0 add 2001:db8::5
	atf_check -o match:'fake-ifconfig lo0 down' \
	    "$JGC" -c "$SOCK" interface lo0 down
	atf_check -o match:'^ +[0-9]+ queued +lo0: up' \
	    "$JGC" -q -c "$SOCK" interface lo0 up
	# What ifconfig refuses fails the job, with its words.
	atf_check -s exit:1 -o match:'File exists' \
	    "$JGC" -c "$SOCK" interface lo0 add 10.9.9.9/32
	# What is not an interface or an address never reaches ifconfig.
	atf_check -s exit:1 -o match:'no interface nope0' \
	    "$JGC" -c "$SOCK" interface nope0 up
	atf_check -s exit:1 -o match:'not an IPv4 or IPv6 address' \
	    "$JGC" -c "$SOCK" interface lo0 add 10.0.0.300
	atf_check -s exit:1 -o match:'not an IPv4 or IPv6 address' \
	    "$JGC" -c "$SOCK" interface lo0 add '10.0.0.1;reboot'
	atf_check -o not-match:'nope0' -o not-match:'300' -o not-match:'reboot' \
	    cat ifconfig.log

	# Static routes: asked of the kernel by the helper, word by word.
	atf_check -o match:'route add 10.77.0.0/16 via 10.0.0.1' \
	    -o match:'fake-helper --scope-helper 0 route-add 10.77.0.0/16 10.0.0.1 - 0 0 0 -' \
	    "$JGC" -c "$SOCK" route add 10.77.0.0/16 10.0.0.1
	# With its cost, its share among those of one cost, and the address
	# sent from; kept, they are in rc.conf's route too.
	atf_check -o match:'route add 10.81.0.0/16 via 10.0.0.1 \(metric\) \(weight\) \(kept\)' \
	    -o match:'fake-helper --scope-helper 0 route-add 10.81.0.0/16 10.0.0.1 - 0 5 20 10.0.0.9' \
	    "$JGC" -p -c "$SOCK" route add 10.81.0.0/16 10.0.0.1 metric 5 weight 20 source 10.0.0.9
	atf_check -o match:'^route_[a-z0-9_]*="10.81.0.0/16 10.0.0.1 -ifa 10.0.0.9 -metric 5 -weight 20"$' \
	    cat rc.conf
	atf_check -o match:'fake-helper --scope-helper 0 route-del 10.81.0.0/16 10.0.0.1 - 0 5' \
	    "$JGC" -p -c "$SOCK" route delete 10.81.0.0/16 10.0.0.1 metric 5
	atf_check -o not-match:'10.81.0.0' cat rc.conf
	atf_check -s exit:1 -o match:'no address of the route.s family' \
	    "$JGC" -c "$SOCK" route add 10.82.0.0/16 10.0.0.1 source 2001:db8::9
	atf_check -s exit:1 -e match:'the address to send from is an address' -o ignore \
	    "$JGC" -c "$SOCK" route add 10.82.0.0/16 10.0.0.1 source '-x'
	atf_check -o match:'fake-helper --scope-helper 0 route-add 2001:db8:7::/48 2001:db8::1 - 0 0 0 -' \
	    "$JGC" -c "$SOCK" route add 2001:db8:7::/48 2001:db8::1
	atf_check -o match:'fake-helper --scope-helper 0 route-add 10.78.0.0/16 - lo0 0 0 0 -' \
	    "$JGC" -c "$SOCK" route add 10.78.0.0/16 lo0
	atf_check -o match:'fake-helper --scope-helper 0 route-add ::/0 2001:db8::1 - 0 0 0 -' \
	    "$JGC" -c "$SOCK" route add ::/0 2001:db8::1
	atf_check -o match:'fake-helper --scope-helper 0 route-del 10.77.0.0/16 - - 0 0' \
	    "$JGC" -c "$SOCK" route delete 10.77.0.0/16
	atf_check -o match:'^ +[0-9]+ queued +route delete default via 10.0.0.1' \
	    "$JGC" -q -c "$SOCK" route delete default 10.0.0.1
	# Several gateways: one route of as many next hops, each with its
	# share; not kept, not deleted as one, and each an address.
	atf_check -o match:'fake-helper --scope-helper 0 route-add 10.83.0.0/16 10.0.0.1@2,10.0.0.2 - 0 0 0 -' \
	    "$JGC" -c "$SOCK" route add 10.83.0.0/16 10.0.0.1@2,10.0.0.2
	atf_check -s exit:1 -o match:'rc.conf keeps a route of one gateway' \
	    "$JGC" -p -c "$SOCK" route add 10.84.0.0/16 10.0.0.1,10.0.0.2
	atf_check -s exit:1 -o match:'a share is from 1 to 255' \
	    "$JGC" -c "$SOCK" route add 10.84.0.0/16 10.0.0.1@0,10.0.0.2
	atf_check -s exit:1 -o match:'each of several gateways is one' \
	    "$JGC" -c "$SOCK" route add 10.84.0.0/16 10.0.0.1,em0
	atf_check -o not-match:'10.84' cat route.log
	atf_check -s exit:1 -o match:'the route is there already' \
	    "$JGC" -c "$SOCK" route add 10.66.0.0/16 10.0.0.1
	atf_check -s exit:1 -o match:'not a destination' \
	    "$JGC" -c "$SOCK" route add 10.0.0.0/33 10.0.0.1
	atf_check -s exit:1 -o match:'neither an address nor an interface' \
	    "$JGC" -c "$SOCK" route add 10.79.0.0/16 nope0
	atf_check -s exit:1 -e match:'needs a gateway' -o ignore \
	    "$JGC" -q -c "$SOCK" route add 10.79.0.0/16 ''
	atf_check -o not-match:'10.79' -o not-match:'/33' cat route.log
}
interfaces_cleanup()
{
	stop_daemon
}

atf_test_case network_more cleanup
network_more_head()
{
	atf_set "descr" "Interfaces made, set and destroyed, changes kept in rc.conf, routing tables, route lookup, netgraph"
}
network_more_body()
{
	cat > fake-ifconfig <<EOS
#!/bin/sh
echo "\$*" >> $(pwd)/ifconfig.log
case " \$* " in
*" create"*) case "\$1" in epair*) echo "\${1}a" ;; gif) echo gif7 ;; *) echo "\$1" ;; esac ;;
*" mtu 9999 "*) echo "ifconfig: ioctl SIOCSIFMTU (set mtu): Invalid argument" >&2; exit 1 ;;
esac
exit 0
EOS
	cat > fake-ngctl <<EOS
#!/bin/sh
echo "\$*" >> $(pwd)/ngctl.log
case "\$1" in
list)	cat <<EOL
There are 3 total nodes:
  Name: em0             Type: ether           ID: 00000002   Num hooks: 1
  Local hook      Peer name       Peer type    Peer ID         Peer hook      
  ----------      ---------       ---------    -------         ---------      
  lower           bridge0         bridge       0000000c        link0          
  Name: bridge0         Type: bridge          ID: 0000000c   Num hooks: 1
  Local hook      Peer name       Peer type    Peer ID         Peer hook      
  ----------      ---------       ---------    -------         ---------      
  link0           em0             ether        00000002        lower          
  Name: ngctl1234       Type: socket          ID: 00000010   Num hooks: 0
EOL
	;;
shutdown) [ "\$2" = gone: ] && { echo "ngctl: send msg: No such file or directory" >&2; exit 1; } ;;
esac
exit 0
EOS
	chmod +x fake-ifconfig fake-ngctl
	start_daemon
	# The routes an address is in, as the helper would find them.
	cat > covers <<'EOS'
{"destination":"10.77.0.0/16","gateway":"10.0.0.1","flags":"UGS","nhop":2,"mtu":1500,"interface-name":"em0","metric":1,"weight":1,"fib":0,"prefixlen":16}
{"destination":"10.77.5.0/24","gateway":"10.0.0.9","flags":"UGS","nhop":3,"mtu":1500,"interface-name":"em1","metric":1,"weight":1,"fib":0,"prefixlen":24}
{"destination":"10.77.5.5","gateway":"link#3","flags":"UH","nhop":5,"mtu":1500,"interface-name":"lo0","metric":1,"weight":1,"fib":0,"prefixlen":32}
EOS

	# An MTU and a description, live; and kept, in rc.conf.
	atf_check -o match:'fake-ifconfig lo0 mtu 9000' \
	    "$JGC" -c "$SOCK" interface lo0 mtu 9000
	atf_check -o not-match:'ifconfig_lo0' cat rc.conf
	atf_check -o match:'fake-ifconfig lo0 description uplink to core' \
	    "$JGC" -p -c "$SOCK" interface lo0 description 'uplink to core'
	atf_check -o match:'^ifconfig_lo0_descr="uplink to core"$' cat rc.conf
	atf_check -o ignore "$JGC" -p -c "$SOCK" interface lo0 mtu 1400
	atf_check -o match:'^ifconfig_lo0="mtu 1400"$' cat rc.conf
	sed -i '' -e 's|^ifconfig_lo0=.*|ifconfig_lo0="inet 127.0.0.1/8 mtu 1400 up"|' rc.conf
	atf_check -o ignore "$JGC" -p -c "$SOCK" interface lo0 mtu 1300
	atf_check -o match:'^ifconfig_lo0="inet 127.0.0.1/8 mtu 1300 up"$' \
	    cat rc.conf
	atf_check -s exit:1 -o match:'Invalid argument' \
	    "$JGC" -c "$SOCK" interface lo0 mtu 9999
	# Its routing tables: what it receives, and a tunnel's outer
	# packets; kept as words of ifconfig_<if>, 0 taken out again.
	atf_check -o match:'fake-ifconfig lo0 fib 2' -o match:'set fib' \
	    "$JGC" -p -c "$SOCK" interface lo0 fib 2
	atf_check -o match:'^ifconfig_lo0="inet 127.0.0.1/8 mtu 1300 up fib 2"$' \
	    cat rc.conf
	atf_check -o match:'fake-ifconfig lo0 tunnelfib 1' \
	    "$JGC" -c "$SOCK" interface lo0 tunnelfib 1
	atf_check -o match:'fake-ifconfig lo0 fib 0' \
	    "$JGC" -p -c "$SOCK" interface lo0 fib 0
	atf_check -o match:'^ifconfig_lo0="inet 127.0.0.1/8 mtu 1300 up"$' \
	    cat rc.conf
	atf_check -s exit:1 -o match:'without quotes' \
	    "$JGC" -p -c "$SOCK" interface lo0 description 'a"; reboot'
	# How it gets its address: DHCP by rc.conf's word and dhclient
	# (kept, as its rc script insists), SLAAC by accept_rtadv and
	# rtsol, kept in ifconfig_lo0_ipv6; static takes both off.
	printf '#!/bin/sh\necho "rtsol $*" >> %s/rtsol.log\n' "$(pwd)" > fake-rtsol
	chmod +x fake-rtsol
	atf_check -s exit:1 -o match:'say persist' "$JGC" -c "$SOCK" interface lo0 addressing dhcp
	atf_check -o match:'lo0: set addressing dhcp' "$JGC" -p -c "$SOCK" interface lo0 addressing dhcp
	atf_check -o match:'^ifconfig_lo0="DHCP inet 127.0.0.1/8 mtu 1300 up"$' cat rc.conf
	test -f running.dhclient || atf_fail "dhclient was not started"
	atf_check -o match:'fake-ifconfig lo0 inet6 accept_rtadv -ifdisabled' "$JGC" -p -c "$SOCK" interface lo0 addressing slaac
	atf_check -o match:'^ifconfig_lo0="inet 127.0.0.1/8 mtu 1300 up"$' -o match:'^ifconfig_lo0_ipv6="inet6 accept_rtadv"$' cat rc.conf
	atf_check -o match:'^rtsol lo0$' cat rtsol.log
	test ! -f running.dhclient || atf_fail "dhclient was not stopped"
	atf_check -o match:'fake-ifconfig lo0 inet6 -accept_rtadv' "$JGC" -p -c "$SOCK" interface lo0 addressing static
	atf_check -o not-match:'ifconfig_lo0_ipv6' -o match:'^ifconfig_lo0="inet 127.0.0.1/8 mtu 1300 up"$' cat rc.conf
	# was: what it had before Arcana's first DHCP or SLAAC, put back
	# (a host on SLAAC by rc.conf stays so), and let go; then nothing
	# kept, nothing changes.
	echo 'ifconfig_lo0_ipv6="inet6 accept_rtadv"' >> rc.conf
	atf_check -o ignore "$JGC" -p -c "$SOCK" interface lo0 addressing dhcp
	atf_check -o match:'^ifconfig_lo0="DHCP inet 127.0.0.1/8 mtu 1300 up"$' -o not-match:'ifconfig_lo0_ipv6' cat rc.conf
	atf_check -o ignore "$JGC" -p -c "$SOCK" interface lo0 addressing dhcp
	atf_check -o match:'addressed as before: static, SLAAC' -o match:'inet6 accept_rtadv -ifdisabled' \
	    -o match:'inet 127.0.0.1/8 mtu 1300 up' "$JGC" -t -p -c "$SOCK" interface lo0 addressing was
	atf_check -o match:'^ifconfig_lo0="inet 127.0.0.1/8 mtu 1300 up"$' -o match:'^ifconfig_lo0_ipv6="inet6 accept_rtadv"$' cat rc.conf
	test ! -f running.dhclient || atf_fail "dhclient was not stopped"
	atf_check -o match:'not kept: left as it is' "$JGC" -t -p -c "$SOCK" interface lo0 addressing was
	atf_check -o ignore "$JGC" -p -c "$SOCK" interface lo0 addressing static
	atf_check -o not-match:'ifconfig_lo0_ipv6' cat rc.conf

	# Addresses kept as aliases: numbered from 0, and without gaps
	# when one in the middle goes.
	atf_check -o ignore "$JGC" -p -c "$SOCK" interface lo0 add 10.9.0.1/24
	atf_check -o ignore "$JGC" -p -c "$SOCK" interface lo0 add 10.9.0.2/24
	atf_check -o ignore "$JGC" -p -c "$SOCK" interface lo0 add 2001:db8::3/64
	atf_check -o match:'^ifconfig_lo0_alias0="inet 10.9.0.1/24"$' \
	    -o match:'^ifconfig_lo0_alias1="inet 10.9.0.2/24"$' \
	    -o match:'^ifconfig_lo0_alias2="inet6 2001:db8::3/64"$' cat rc.conf
	atf_check -o ignore "$JGC" -p -c "$SOCK" interface lo0 remove 10.9.0.1
	atf_check -o match:'^ifconfig_lo0_alias0="inet 10.9.0.2/24"$' \
	    -o match:'^ifconfig_lo0_alias1="inet6 2001:db8::3/64"$' \
	    -o not-match:'alias2' -o not-match:'10.9.0.1/' cat rc.conf
	# 10.9.0.2 is not 10.9.0.20: only the address itself is forgotten.
	atf_check -o ignore "$JGC" -p -c "$SOCK" interface lo0 add 10.9.0.20/24
	atf_check -o ignore "$JGC" -p -c "$SOCK" interface lo0 remove 10.9.0.2
	atf_check -o match:'10.9.0.20/24' -o not-match:'10.9.0.2/24' cat rc.conf

	# A tunnel: created, given its ends, its addresses, brought up.
	atf_check -o match:'create gif7 to 198.51.100.2' \
	    -o match:'fake-ifconfig gif7 create' \
	    -o match:'fake-ifconfig gif7 tunnel 192.0.2.1 198.51.100.2' \
	    -o match:'fake-ifconfig gif7 inet 10.255.0.1/30 10.255.0.2' \
	    -o match:'fake-ifconfig gif7 mtu 1400' \
	    -o match:'fake-ifconfig gif7 description to lab' \
	    -o match:'fake-ifconfig gif7 up' \
	    "$JGC" -p -c "$SOCK" interface gif7 create tunnel 192.0.2.1 \
	    198.51.100.2 address 10.255.0.1/30 peer 10.255.0.2 mtu 1400 \
	    description 'to lab'
	atf_check -o match:'^cloned_interfaces="gif7"$' \
	    -o match:'^ifconfig_gif7="tunnel 192.0.2.1 198.51.100.2 mtu 1400 up"$' \
	    -o match:'^ifconfig_gif7_alias0="inet 10.255.0.1/30 10.255.0.2"$' \
	    -o match:'^ifconfig_gif7_descr="to lab"$' cat rc.conf
	# The kernel picks the unit of a type alone, and says which.
	atf_check -o match:'fake-ifconfig gif create' \
	    -o match:'fake-ifconfig gif7 inet6 tunnel 2001:db8::1 2001:db8::2' \
	    -o match:'fake-ifconfig gif7 inet6 fd00::1 fd00::2 prefixlen 128' \
	    "$JGC" -c "$SOCK" interface gif create tunnel 2001:db8::1 \
	    2001:db8::2 address fd00::1 peer fd00::2
	# A pair is two, kept under one name; a VLAN and a VXLAN take their
	# arguments at creation.
	atf_check -o match:'fake-ifconfig epair3 create' \
	    -o match:'fake-ifconfig epair3a up' \
	    "$JGC" -p -c "$SOCK" interface epair3 create
	atf_check -o match:'^cloned_interfaces="gif7 epair3"$' \
	    -o match:'^ifconfig_epair3a="up"$' cat rc.conf
	atf_check -o match:'fake-ifconfig vlan5 create vlan 5 vlandev lo0' \
	    "$JGC" -p -c "$SOCK" interface vlan5 create id 5 parent lo0
	atf_check -o match:'^create_args_vlan5="vlan 5 vlandev lo0"$' cat rc.conf
	atf_check -o match:'vxlan9 create vxlanid 42 vxlanlocal 192.0.2.1 vxlanremote 192.0.2.9' \
	    "$JGC" -c "$SOCK" interface vxlan9 create id 42 tunnel 192.0.2.1 192.0.2.9
	# Its tables are set before its ends and its addresses: the route
	# of its address is made in its table.
	: > ifconfig.log
	atf_check -o ignore "$JGC" -p -c "$SOCK" interface gre4 create tunnel \
	    192.0.2.1 192.0.2.2 address 10.255.1.0/31 peer 10.255.1.1 fib 3 \
	    tunnelfib 0
	atf_check -o inline:'gre4 create\ngre4 fib 3\ngre4 tunnelfib 0\ngre4 tunnel 192.0.2.1 192.0.2.2\ngre4 inet 10.255.1.0/31 10.255.1.1\ngre4 up\n' \
	    cat ifconfig.log
	atf_check -o match:'^ifconfig_gre4="tunnel 192.0.2.1 192.0.2.2 fib 3 up"$' \
	    cat rc.conf
	atf_check -o ignore "$JGC" -p -c "$SOCK" interface gre4 destroy
	atf_check -o not-match:'gre4' cat rc.conf
	# What cannot be finished is destroyed again, and not kept.
	atf_check -s exit:1 -o match:'Invalid argument' \
	    -o match:'fake-ifconfig gre1 destroy' \
	    "$JGC" -p -c "$SOCK" interface gre1 create tunnel 192.0.2.1 \
	    192.0.2.2 mtu 9999
	atf_check -o not-match:'gre1' cat rc.conf
	# What is not asked for as it must be never reaches ifconfig.
	atf_check -s exit:1 -o match:'needs both its ends' \
	    "$JGC" -c "$SOCK" interface gif8 create
	atf_check -s exit:1 -o match:'not an interface that can be made' \
	    "$JGC" -c "$SOCK" interface em9 create
	atf_check -s exit:1 -o match:"a tunnel's ends are addresses" \
	    "$JGC" -c "$SOCK" interface gif8 create tunnel 192.0.2.1 '-vnet'
	atf_check -s exit:1 -o match:'needs its tag' \
	    "$JGC" -c "$SOCK" interface vlan6 create parent lo0
	atf_check -o not-match:'gif8' -o not-match:'em9' -o not-match:'vlan6' \
	    cat ifconfig.log
	# Destroyed, and forgotten; only what was made can be.
	atf_check -o match:'fake-ifconfig gif7 destroy' \
	    "$JGC" -p -c "$SOCK" interface gif7 destroy
	atf_check -o not-match:'gif7' -o match:'^cloned_interfaces="epair3 vlan5"$' \
	    cat rc.conf
	atf_check -o match:'fake-ifconfig epair3a destroy' \
	    "$JGC" -p -c "$SOCK" interface epair3a destroy
	atf_check -o not-match:'epair3' cat rc.conf
	atf_check -s exit:1 -o match:'only cloned ones are destroyed' \
	    "$JGC" -c "$SOCK" interface em0 destroy

	# Routes: in a routing table of their own, and kept by a name.
	atf_check -o match:'fake-helper --scope-helper 0 route-add 10.77.0.0/16 10.0.0.1 - 2 0 0 -' \
	    "$JGC" -F 2 -c "$SOCK" route add 10.77.0.0/16 10.0.0.1
	atf_check -o ignore "$JGC" -p -c "$SOCK" route add 10.77.0.0/16 10.0.0.1
	atf_check -o ignore "$JGC" -p -c "$SOCK" route add 2001:db8:7::/48 2001:db8::1
	atf_check -o ignore "$JGC" -p -F 3 -c "$SOCK" route add 10.80.0.0/16 lo0
	atf_check -o match:'^static_routes="arc_10_77_0_0_16 arc_10_80_0_0_16_fib3"$' \
	    -o match:'^route_arc_10_77_0_0_16="10.77.0.0/16 10.0.0.1"$' \
	    -o match:'^route_arc_10_80_0_0_16_fib3="10.80.0.0/16 -iface lo0 -fib 3"$' \
	    -o match:'^ipv6_static_routes="arc_2001_db8_7___48"$' \
	    -o match:'^ipv6_route_arc_2001_db8_7___48="2001:db8:7::/48 2001:db8::1"$' \
	    cat rc.conf
	atf_check -o ignore "$JGC" -p -c "$SOCK" route delete 10.77.0.0/16
	atf_check -o match:'^static_routes="arc_10_80_0_0_16_fib3"$' \
	    -o not-match:'route_arc_10_77' cat rc.conf
	atf_check -o match:'fake-helper --scope-helper 0 routes 4 2 - -' \
	    "$JGC" -t -F 2 -c "$SOCK" net routes -4

	# The route to an address: the one taken, and those that cover it,
	# each with the length of its prefix.
	atf_check -o save:get.out "$JGC" -c "$SOCK" route get 10.77.5.5
	atf_check -o match:'"best":\{"to":"10.77.5.5","destination":"10.77.0.0","prefixlen":16,"gateway":"10.0.0.1","fib":"0","interface":"em0"' \
	    -o match:'"destination":"default".*"prefixlen":0' \
	    -o match:'"destination":"10.77.0.0/16".*"prefixlen":16' \
	    -o match:'"destination":"10.77.5.0/24","gateway":"10.0.0.9".*"prefixlen":24' \
	    -o match:'"destination":"10.77.5.5".*"prefixlen":32' \
	    cat get.out
	atf_check -o match:'^0 routes 0 0 - 10.77.5.5$' cat helper.log
	# No route is an answer: nothing is best, the default still covers.
	atf_check -o not-match:'"best"' -o match:'"destination":"default"' \
	    "$JGC" -c "$SOCK" route get 203.0.113.9
	atf_check -s exit:1 -e match:'not an IPv4 or IPv6 address' -o ignore \
	    "$JGC" -c "$SOCK" route get '10.0.0.1;id'
	atf_check -o match:'fake-helper --scope-helper 0 route-get 10.77.5.5 4' \
	    "$JGC" -t -F 4 -c "$SOCK" route get 10.77.5.5

	# Netgraph: the nodes with their hooks, and the few commands.
	atf_check -o match:'"name":"em0","type":"ether","id":"00000002","hooks":\[\{"hook":"lower","peer":"bridge0","peer-type":"bridge","peer-id":"0000000c","peer-hook":"link0"\}\]' \
	    -o match:'"name":"ngctl1234","type":"socket","id":"00000010","hooks":\[\]' \
	    "$JGC" -c "$SOCK" net netgraph
	atf_check -o match:'fake-ngctl mkpeer em0: bridge lower link0' \
	    "$JGC" -c "$SOCK" ng mkpeer em0: bridge lower link0
	atf_check -o match:'fake-ngctl connect em1: bridge0: lower link1' \
	    "$JGC" -c "$SOCK" ng connect em1: bridge0: lower link1
	atf_check -o match:'fake-ngctl rmhook em0: lower' \
	    "$JGC" -c "$SOCK" ng rmhook em0: lower
	atf_check -o match:'fake-ngctl name \[c\]: br' \
	    "$JGC" -c "$SOCK" ng name '[c]:' br
	atf_check -s exit:1 -o match:'No such file' \
	    "$JGC" -c "$SOCK" ng shutdown gone:
	atf_check -s exit:1 -e match:'mkpeer, connect, rmhook, shutdown or name' \
	    "$JGC" -c "$SOCK" ng msg em0: setpromisc 1
	atf_check -s exit:1 -e match:'letters, digits' \
	    "$JGC" -c "$SOCK" ng shutdown 'em0:;reboot'
	atf_check -s exit:1 -e match:'letters, digits' \
	    "$JGC" -c "$SOCK" ng mkpeer em0: bridge lower -f
	atf_check -o not-match:'msg' -o not-match:'reboot' -o not-match:' -f' \
	    cat ngctl.log
}
network_more_cleanup()
{
	stop_daemon
}

atf_test_case ipsec cleanup
ipsec_head()
{
	atf_set "descr" "strongSwan through swanctl, IKEv2 only: the host's own key, connections in tunnel and transport mode, an ipsec interface's reqid, and pkg install"
}
ipsec_body()
{
	mkdir -p swanctl/conf.d swanctl/pkcs8 swanctl/pubkey
	printf '#!/bin/sh\necho "$*" >> %s/ifconfig.log\n' "$(pwd)" > fake-ifconfig
	# What strongSwan 6.1 says, as it says it; a connection of
	# someone else's, IKEv1 and v2 both, beside one of arcana's.
	cat > conns.out <<'EOP'
list-conn event {
  gre12 {
    local_addrs = [
      10.202.0.1
    ]
    remote_addrs = [
      10.202.0.2
    ]
    version = IKEv2
    proposals {
      0 {
        encr = [
          AES_GCM_16_256
        ]
      }
    }
    local-1 {
      id = 10.202.0.1
      class = public key
      groups = [
      ]
    }
    remote-1 {
      id = 10.202.0.2
      class = public key
    }
    children {
      gre12 {
        mode = TRANSPORT
        local-ts = [
          10.202.0.1/32[gre]
        ]
        remote-ts = [
          10.202.0.2/32[gre]
        ]
      }
    }
  }
}
list-conn event {
  legacy {
    local_addrs = [
      %any
    ]
    remote_addrs = [
      198.51.100.9
    ]
    version = IKEv1/2
    children {
      legacy {
        mode = TUNNEL
      }
    }
  }
}
list-conns reply {
}
EOP
	cat > sas.out <<'EOP'
list-sa event {
  gre12 {
    uniqueid = 5
    version = 2
    state = ESTABLISHED
    local-host = 10.202.0.1
    remote-host = 10.202.0.2
    initiator-spi = 777c5aacf8abd606
    encr-alg = AES_GCM_16
    established = 339
    child-sas {
      gre12-1 {
        name = gre12
        reqid = 1
        state = INSTALLED
        mode = TRANSPORT
        spi-in = 12345678
        bytes-in = 192232
        bytes-out = 265028
        local-ts = [
          10.202.0.1/32[gre]
        ]
      }
    }
  }
}
list-sas reply {
}
EOP
	cat > fake-swanctl <<EOS
#!/bin/sh
d=$(pwd)
echo "\$*" >> \$d/swanctl.log
[ -f \$d/down ] && { echo "connecting to 'unix:///var/run/charon.vici' failed: No such file or directory" >&2; exit 1; }
case "\$1" in
--list-conns)	cat \$d/conns.out ;;
--list-sas)	cat \$d/sas.out ;;
--load-all)	[ -f \$d/refuse ] && { echo "loading connection 'x' failed: invalid value" >&2; exit 1; }
		ls \$d/swanctl/conf.d > \$d/loaded ; echo "successfully loaded" ;;
--load-creds|--initiate|--terminate|--stats) echo ok ;;
*)		exit 2 ;;
esac
EOS
	chmod +x fake-ifconfig fake-swanctl
	start_daemon

	# Read: arcana's and another's, the other's version said; the SAs
	# with their children; no key yet.
	atf_check -o save:ipsec.json "$JGC" -c "$SOCK" net ipsec
	atf_check -o match:'"running":true' -o not-match:'public-key' \
	    -o match:'"local_addrs":\["10.202.0.1"\].*"version":"IKEv2".*"children":\[\{"mode":"TRANSPORT","local-ts":\["10.202.0.1/32\[gre\]"\],"remote-ts":\["10.202.0.2/32\[gre\]"\],"name":"gre12"\}\]' \
	    -o match:'"name":"gre12".*"local-id":"10.202.0.1","remote-id":"10.202.0.2","arcana":false' \
	    -o match:'"version":"IKEv1/2"' \
	    -o match:'"sas":\[\{"uniqueid":5,"version":2,"state":"ESTABLISHED".*"children":\[\{"name":"gre12","reqid":1,"state":"INSTALLED","mode":"TRANSPORT","spi-in":"12345678","bytes-in":192232' \
	    cat ipsec.json

	# The host's key: made here, the private half for root alone, the
	# public half told; made once.
	atf_check -o match:'ipsec init' -o match:'private key: made on this host, ECDSA P-256' \
	    "$JGC" -c "$SOCK" -p ipsec init
	atf_check -o match:'^600$' stat -f %Lp swanctl/pkcs8/arcana.pem
	atf_check -o match:'BEGIN PRIVATE KEY' cat swanctl/pkcs8/arcana.pem
	atf_check -o match:'^strongswan_enable="YES"$' cat rc.conf
	PUB=$(sed -e '/-----/d' swanctl/pubkey/arcana.pub | tr -d '\n')
	atf_check -o save:pub.json "$JGC" -c "$SOCK" net ipsec
	atf_check -o ignore grep -F "\"public-key\":\"$PUB\"" pub.json
	cp swanctl/pkcs8/arcana.pem key.was
	atf_check -o ignore "$JGC" -c "$SOCK" ipsec init
	atf_check cmp key.was swanctl/pkcs8/arcana.pem

	# A connection: its file and its peer's key, IKEv2, read again.
	atf_check -o match:'ipsec conn gre12 \(transport\)' \
	    "$JGC" -c "$SOCK" ipsec conn gre12 10.202.0.1 10.202.0.2 mode transport pubkey "$PUB" \
	    local-ts '10.202.0.1[gre]' remote-ts '10.202.0.2[gre]' start start
	atf_check -o match:'^		version = 2$' -o match:'^		local_addrs = 10.202.0.1$' \
	    -o match:'^			pubkeys = arcana-gre12.pub$' \
	    -o match:'^				mode = transport$' \
	    -o match:'^				local_ts = 10.202.0.1\[gre\]$' \
	    -o match:'^				start_action = start$' \
	    -o match:'^				dpd_action = start$' \
	    -o not-match:'reqid' cat swanctl/conf.d/arcana-gre12.conf
	atf_check -o match:'BEGIN PUBLIC KEY' cat swanctl/pubkey/arcana-gre12.pub
	atf_check -o match:'^--load-all --noprompt$' cat swanctl.log
	atf_check -o match:'arcana-gre12.conf' cat loaded
	atf_check -o match:'"name":"gre12".*"arcana":true' "$JGC" -c "$SOCK" net ipsec
	# Of an ipsec interface: tunnel mode, its policies the interface's.
	atf_check -o ignore "$JGC" -c "$SOCK" ipsec conn vti12 fd00:5a::1 fd00:5a::2 \
	    mode tunnel pubkey "$PUB" reqid 100
	atf_check -o match:'^				reqid = 100$' -o match:'^				policies = no$' \
	    -o match:'^				local_ts = 0.0.0.0/0,::/0$' \
	    -o match:'^				start_action = trap$' \
	    cat swanctl/conf.d/arcana-vti12.conf

	# What is not right is refused before anything is written.
	atf_check -s exit:1 -e match:'tunnel or transport' -o ignore \
	    "$JGC" -c "$SOCK" ipsec conn x 192.0.2.1 192.0.2.2 mode beet pubkey "$PUB"
	atf_check -s exit:1 -e match:"peer's public key" -o ignore \
	    "$JGC" -c "$SOCK" ipsec conn x 192.0.2.1 192.0.2.2 mode tunnel pubkey bm90IGEga2V5
	atf_check -s exit:1 -e match:'are IPv4, or both IPv6' -o ignore \
	    "$JGC" -c "$SOCK" ipsec conn x 192.0.2.1 2001:db8::2 mode tunnel pubkey "$PUB"
	atf_check -s exit:1 -e match:'is in tunnel mode' -o ignore \
	    "$JGC" -c "$SOCK" ipsec conn x 192.0.2.1 192.0.2.2 mode transport pubkey "$PUB" reqid 5
	atf_check -s exit:1 -e match:'traffic selectors' -o ignore \
	    "$JGC" -c "$SOCK" ipsec conn x 192.0.2.1 192.0.2.2 mode tunnel pubkey "$PUB" local-ts '10.0.0.0/8 }'
	atf_check -s exit:1 -e match:'letters, digits, - and _' -o ignore \
	    "$JGC" -c "$SOCK" ipsec up '../x'
	atf_check -s exit:1 -e match:'identity is one word' -o ignore \
	    "$JGC" -c "$SOCK" ipsec conn x 192.0.2.1 192.0.2.2 mode tunnel pubkey "$PUB" remote-id 'a=b'
	test ! -f swanctl/conf.d/arcana-x.conf || atf_fail "a refused connection was written"
	# The peer known one way, and one only.
	atf_check -s exit:1 -e match:'one way' -o ignore \
	    "$JGC" -c "$SOCK" ipsec conn x 192.0.2.1 192.0.2.2
	atf_check -s exit:1 -e match:'one way' -o ignore \
	    "$JGC" -c "$SOCK" ipsec conn x 192.0.2.1 192.0.2.2 pubkey "$PUB" remote-cert peer.pem
	# Children of their own: gre12's kept as the connection is
	# written again without a mode; one added, named; one taken away.
	atf_check -o match:'ipsec conn gre12' "$JGC" -c "$SOCK" ipsec conn gre12 \
	    10.202.0.1 10.202.0.2 pubkey "$PUB" remote-id peer.example
	atf_check -o match:'^			gre12 \{$' -o match:'mode = transport' \
	    -o match:'id = peer.example' cat swanctl/conf.d/arcana-gre12.conf
	atf_check -o match:'"children":\{"gre12":\{"mode":"transport"' \
	    cat swanctl/conf.d/arcana-gre12.json
	atf_check -o match:'ipsec child gre12 lan' "$JGC" -c "$SOCK" ipsec child gre12 lan tunnel \
	    local-ts 10.1.0.0/24 remote-ts 10.2.0.0/24 start start
	atf_check -o match:'^			gre12 \{$' -o match:'^			lan \{$' \
	    -o match:'local_ts = 10.1.0.0/24' -o match:'start_action = start' \
	    cat swanctl/conf.d/arcana-gre12.conf
	atf_check -s exit:1 -o match:'no connection nope' -e ignore \
	    "$JGC" -c "$SOCK" ipsec child nope lan tunnel
	atf_check -s exit:1 -o match:'has no child far' -e ignore \
	    "$JGC" -c "$SOCK" ipsec unchild gre12 far
	atf_check -o match:'ipsec unchild gre12 lan' "$JGC" -c "$SOCK" ipsec unchild gre12 lan
	atf_check -o not-match:'lan \{' -o match:'^			gre12 \{$' \
	    cat swanctl/conf.d/arcana-gre12.conf
	# The connection known by what it tells of itself: its children.
	atf_check -o match:'"model":\{"children":\{"gre12":' \
	    -o match:'"remote_id":"peer.example"' "$JGC" -c "$SOCK" net ipsec
	# Certificates in x509 and x509ca, read: a peer known by its own,
	# or by the CA that signed it, needs no key pasted.
	mkdir -p swanctl/x509 swanctl/x509ca
	openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
	    -keyout ca.key -out swanctl/x509ca/lab-ca.pem -days 2 \
	    -subj '/CN=Lab CA' -addext 'basicConstraints=critical,CA:TRUE' >/dev/null 2>&1
	openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
	    -keyout peer.key -out swanctl/x509/peer.pem -days 2 \
	    -subj '/CN=peer.example' -addext 'basicConstraints=CA:FALSE' \
	    -addext 'subjectAltName=DNS:peer.example,IP:10.202.0.2' >/dev/null 2>&1
	echo "not a cert" > swanctl/x509/junk.pem
	atf_check -o save:certs.json "$JGC" -c "$SOCK" net ipsec
	atf_check -o match:'"file":"peer.pem","where":"x509","subject":"CN=peer.example","issuer":"CN=peer.example",[^}]*"ca":false,"self_signed":true,"names":\["peer.example","10.202.0.2"\],"sha256":"[0-9a-f:]+"' \
	    -o match:'"file":"lab-ca.pem","where":"x509ca",[^}]*"ca":true' \
	    -o match:'"file":"junk.pem","where":"x509","error":"not a certificate in PEM"' \
	    cat certs.json
	atf_check -s exit:1 -o match:'nope.pem is not in swanctl.s x509' -e ignore \
	    "$JGC" -c "$SOCK" ipsec conn bycert 10.202.0.1 10.202.0.2 remote-cert nope.pem
	atf_check -s exit:1 -e match:'remote-id' -o ignore \
	    "$JGC" -c "$SOCK" ipsec conn byca 10.202.0.1 10.202.0.2 remote-ca lab-ca.pem
	atf_check -o match:'ipsec conn bycert' "$JGC" -c "$SOCK" ipsec conn bycert \
	    10.202.0.1 10.202.0.2 mode tunnel remote-cert peer.pem
	atf_check -o match:'certs = peer.pem' -o match:'pubkeys = arcana.pub' \
	    -o not-match:'arcana-bycert.pub' cat swanctl/conf.d/arcana-bycert.conf
	test ! -f swanctl/pubkey/arcana-bycert.pub || atf_fail "a key where none was given"
	atf_check -o match:'ipsec conn byca' "$JGC" -c "$SOCK" ipsec conn byca \
	    10.202.0.1 10.202.0.2 mode tunnel remote-ca lab-ca.pem remote-id peer.example local-cert peer.pem
	atf_check -o match:'cacerts = lab-ca.pem' -o match:'certs = peer.pem' \
	    -o match:'id = peer.example' cat swanctl/conf.d/arcana-byca.conf
	atf_check -o ignore "$JGC" -c "$SOCK" ipsec unconn byca
	test ! -f swanctl/conf.d/arcana-byca.json || atf_fail "the model stayed"

	# Refused by strongSwan: the files as they were.
	cp swanctl/conf.d/arcana-gre12.conf gre12.was
	touch refuse
	atf_check -s exit:1 -o match:'failed' -e ignore \
	    "$JGC" -c "$SOCK" ipsec conn gre12 10.202.0.1 10.202.0.9 mode transport pubkey "$PUB"
	atf_check -s exit:1 -o ignore -e ignore \
	    "$JGC" -c "$SOCK" ipsec conn fresh 10.202.0.1 10.202.0.9 mode tunnel pubkey "$PUB"
	rm refuse
	atf_check cmp gre12.was swanctl/conf.d/arcana-gre12.conf
	test ! -f swanctl/conf.d/arcana-fresh.conf || atf_fail "a refused connection stayed"
	test ! -f swanctl/pubkey/arcana-fresh.pub || atf_fail "a refused key stayed"

	# Up, down; taken away, its SAs ended first.
	atf_check -o match:'ipsec up gre12' "$JGC" -c "$SOCK" ipsec up gre12
	atf_check -o ignore "$JGC" -c "$SOCK" ipsec down gre12
	atf_check -o match:'^--initiate --child gre12 --timeout 20$' \
	    -o match:'^--terminate --ike gre12 --timeout 10$' cat swanctl.log
	atf_check -o ignore "$JGC" -c "$SOCK" ipsec unconn vti12
	atf_check -o match:'^--terminate --ike vti12 --force$' cat swanctl.log
	test ! -f swanctl/conf.d/arcana-vti12.conf || atf_fail "unconn left the file"
	test ! -f swanctl/pubkey/arcana-vti12.pub || atf_fail "unconn left the key"

	# The daemon away: said so, and started by start.
	touch down
	atf_check -o match:'"running":false' "$JGC" -c "$SOCK" net ipsec
	atf_check -o match:'fake-service strongswan onestart' \
	    "$JGC" -c "$SOCK" ipsec start
	rm down

	# An ipsec interface with its reqid; IPv6 ends said to be so.
	atf_check -o ignore "$JGC" -c "$SOCK" -p interface ipsec0 create reqid 100 \
	    tunnel fd00:5a::1 fd00:5a::2
	atf_check -o match:'^ipsec0 create reqid 100$' \
	    -o match:'^ipsec0 inet6 tunnel fd00:5a::1 fd00:5a::2$' cat ifconfig.log
	atf_check -o match:'^create_args_ipsec0="reqid 100"$' \
	    -o match:'^ifconfig_ipsec0="inet6 tunnel fd00:5a::1 fd00:5a::2 up"$' cat rc.conf
	atf_check -s exit:1 -o match:"an ipsec interface's" -e ignore \
	    "$JGC" -c "$SOCK" interface gre0 create reqid 5 tunnel 192.0.2.1 192.0.2.2
	atf_check -s exit:1 -o match:'both IPv4 or both IPv6' -e ignore \
	    "$JGC" -c "$SOCK" interface gif0 create tunnel 192.0.2.1 2001:db8::2

	# Packages installed, there or in a jail; a name is a name.
	atf_check -o match:'pkg install strongswan and more' \
	    -e ignore "$JGC" -c "$SOCK" pkg-install -6 strongswan wireguard-tools
	atf_check -o match:'^install -y strongswan wireguard-tools$' cat install.log
	atf_check -s exit:1 -o match:'is not a package name' -e ignore \
	    "$JGC" -c "$SOCK" pkg-install 'a;b'
	atf_check -o match:'Plugins: strongswan' "$JGC" -c "$SOCK" hello
}
ipsec_cleanup()
{
	stop_daemon
}

atf_test_case vpn cleanup
vpn_head()
{
	atf_set "descr" "WireGuard interfaces and their peers, with keys that stay on the host; BIRD through birdc"
}
vpn_body()
{
	PEER='xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg='
	PUB='HIgo9xNzJMWLKASShiTqIybxZ0U3wGLiUeJ1PKf8ykw='
	mkdir wg
	printf '#!/bin/sh\necho "$*" >> %s/ifconfig.log\n' "$(pwd)" > fake-ifconfig
	cat > fake-wg <<EOS
#!/bin/sh
d=$(pwd)
echo "\$*" >> \$d/wg.log
prev=
for a; do
	[ "\$prev" = preshared-key ] && { cat "\$a" > \$d/psk.got; ls -la "\$a" | cut -c1-10 > \$d/psk.mode; echo "\$a" > \$d/psk.path; }
	prev=\$a
done
key="(none)"; pub="(none)"
[ -f \$d/wg.key ] && { key=\$(cat \$d/wg.key); pub=$PUB; }
case "\$1 \$2 \$3" in
"show all dump")
	printf 'wg0\t%s\t%s\t51820\toff\n' "\$key" "\$pub"
	printf 'wg0\t%s\t(none)\t192.0.2.9:51820\t10.9.9.2/32,fd00::2/128\t1700000000\t1024\t2048\t25\n' $PEER
	printf 'wg1\t(none)\t(none)\t0\toff\n' ;;
"show wg0 private-key") echo "\$key" ;;
"showconf wg0 ")
	printf '[Interface]\nListenPort = 51820\nPrivateKey = %s\n\n[Peer]\nPublicKey = %s\nAllowedIPs = 10.9.9.2/32\n' "\$key" $PEER ;;
"set wg0 private-key") cp "\$4" \$d/wg.key; ls -la "\$4" | cut -c1-10 > \$d/wg.keymode ;;
"set wg9 "*) echo "Unable to modify interface: No such device" >&2; exit 1 ;;
esac
exit 0
EOS
	cat > fake-birdc <<EOS
#!/bin/sh
echo "\$*" >> $(pwd)/birdc.log
[ "\$1" = -r ] && shift
# A daemon that is not there, one that goes away when told to read its
# configuration, and one that does not take what it reads.
[ -e $(pwd)/bird.dead ] && { echo "birdc: Unable to connect to server control socket (/var/run/bird.ctl): No such file or directory" >&2; exit 1; }
if [ "\$1" = configure ] && [ -e $(pwd)/bird.dies ]; then
	touch $(pwd)/bird.dead
	echo "birdc: Connection closed by server" >&2
	exit 1
fi
if [ "\$1" = configure ] && [ -e $(pwd)/bird.refuses ]; then
	printf 'BIRD 2.15.1 ready.\nReading configuration from bird.conf\nbird.conf:3:1 Unknown instruction\n'
	exit 0
fi
case "\$*" in
"show status") printf 'BIRD 2.15.1 ready.\nBIRD 2.15.1\nRouter ID is 192.0.2.1\nHostname is lab\nDaemon is up and running\n' ;;
"show protocols all") cat <<EOP ;;
BIRD 2.15.1 ready.
Name       Proto      Table      State  Since         Info
device1    Device     ---        up     2026-10-01    

kernel1    Kernel     master4    up     2026-10-01    
  Channel ipv4
    State:          UP
    Table:          master4
    Input filter:   ACCEPT
    Output filter:  ACCEPT
    Routes:         0 imported, 3 exported, 0 preferred

bgp_core   BGP        ---        up     12:01:02.345  Established   
  Description:    Core uplink
  BGP state:          Established
    Neighbor address: 192.0.2.1
    Neighbor AS:      65001
    Local AS:         65000
    Neighbor ID:      192.0.2.1
    Hold timer:       150.012/240
  Channel ipv4
    State:          UP
    Table:          master4
    Input filter:   bgp_in
    Output filter:  bgp_out
    Routes:         845233 imported, 12 exported, 400000 preferred
  Channel ipv6
    State:          UP
    Table:          master6
    Input filter:   bgp_in
    Output filter:  REJECT
    Routes:         190000 imported, 0 exported, 180000 preferred

bgp_edge   BGP        ---        start  12:01:02.345  Active        Socket: Connection refused
  BGP state:          Active
    Neighbor address: 198.51.100.7
    Neighbor AS:      65002
    Local AS:         65000
    Last error:       Socket: Connection refused

rpki1      RPKI       ---        up     2026-10-01    Established
  Cache server:     rpki.example.net
  Status:           Established
  Serial number:    42
EOP
"show ospf neighbors") printf 'BIRD 2.15.1 ready.\nospf1:\nRouter ID   \tPri\t     State     \tDTime\tInterface  Router IP\n10.0.0.2    \t  1\tFull/PtP  \t00:00:35\tgif0       10.255.0.2\n' ;;
"show bfd sessions") printf 'BIRD 2.15.1 ready.\nbfd1:\nIP address                Interface  State      Since         Interval  Timeout\nfe80::1                   gif0       Up         13:01:27.605    0.200    1.000\nfe80::2                   gre1       Down       13:02:00.000    1.000    0.000\n' ;;
"show symbols table") printf 'BIRD 2.15.1 ready.\nmaster4    routing table\nr4         routing table\n' ;;
"show route table master4 count") printf 'BIRD 2.15.1 ready.\n845236 of 845236 routes for 845233 networks in table master4\n' ;;
"show route table r4 count") printf 'BIRD 2.15.1 ready.\n512345 of 512345 routes for 512345 networks in table r4\n' ;;
"restart nope") printf 'BIRD 2.15.1 ready.\nNo protocols match\n' ;;
restart*|reload*|enable*|disable*) printf 'BIRD 2.15.1 ready.\n%s: done\n' "\$2" ;;
configure) printf 'BIRD 2.15.1 ready.\nReading configuration from /usr/local/etc/bird.conf\nReconfigured\n' ;;
"configure timeout 2") printf 'BIRD 2.15.1 ready.\nReconfigured\n' ;;
"configure confirm") printf 'BIRD 2.15.1 ready.\nReconfiguration confirmed\n' ;;
"show route for 10.1.2.3 count") printf 'BIRD 2.15.1 ready.\n2 of 2 routes for 1 networks in table master4\n' ;;
"show route for 10.1.2.3 all") cat <<EOP ;;
BIRD 2.15.1 ready.
Table master4:
10.1.0.0/16          unicast [bgp_core 2026-10-01 from 192.0.2.1] * (100) [AS65001i]
	via 192.0.2.1 on em0
	Type: BGP univ
	BGP.as_path: 65001 65010
	BGP.large_community: (65001, 1, 100)
                     unicast [bgp_edge 12:01:02.345] (100/20) [AS65002?]
	via 198.51.100.7 on gre0
	via 198.51.100.9 on gre1
EOP
"show route table master6 count") printf 'BIRD 2.15.1 ready.\n0 of 0 routes for 0 networks in table master6\n' ;;
"show route table master6") printf 'BIRD 2.15.1 ready.\n' ;;
"show route protocol bgp_core count") printf 'BIRD 2.15.1 ready.\n950000 of 950000 routes for 950000 networks in table master4\n' ;;
"show route 10.9.0.0/16 count") printf 'BIRD 2.15.1 ready.\n0 of 0 routes for 0 networks in table master4\n' ;;
"show route 10.9.0.0/16") printf 'BIRD 2.15.1 ready.\nNetwork not found\n' ;;
esac
exit 0
EOS
	# bird(8), to parse: it takes what has no BROKEN in it.
	cat > fake-bird <<EOS
#!/bin/sh
echo "fake-bird \$*" >&2
grep -q BROKEN "\$3" && { echo "bird: \$3:2:1 syntax error, unexpected CF_SYM_UNDEFINED" >&2; exit 1; }
exit 0
EOS
	mkdir -p bird/peers
	printf 'router id 192.0.2.1;\ninclude "peers/*.conf";\nfilter bgp_in {\n\taccept;\n}\n' > bird/bird.conf
	printf 'protocol bgp bgp_edge { neighbor 198.51.100.7 as 65002; }\n' > bird/peers/edge.conf
	chmod +x fake-ifconfig fake-wg fake-birdc fake-bird
	start_daemon

	# An interface without a key, and one to be given one: made on
	# the host, read by wg(8) from a file that is gone afterwards.
	atf_check -o match:'"name":"wg0","private-key":false,"listen-port":51820' \
	    -o match:'"name":"wg1"' -o not-match:'none' \
	    "$JGC" -c "$SOCK" net wireguard
	atf_check -o match:'wg0: wireguard init' -o match:'made on this host' \
	    -o match:'fake-wg set wg0 listen-port 51820' \
	    "$JGC" -c "$SOCK" wg wg0 init 51820
	atf_check -o match:'^set wg0 private-key .*/wg/\.wg0\.key\.' cat wg.log
	atf_check -o match:'^-rw-------$' cat wg.keymode
	atf_check -o match:'^[A-Za-z0-9+/]{43}=$' cat wg.key
	atf_check -o empty find wg -type f
	KEY=$(cat wg.key)
	# One it has is kept: its peers know it by that one.
	atf_check -o ignore "$JGC" -c "$SOCK" wg wg0 init
	atf_check -o inline:"$KEY\n" cat wg.key

	# What is told of it: the public key, and of the private one only
	# that there is one.  Not in the reading, not in its trace, not in
	# a job's.
	atf_check -o save:wg.out "$JGC" -t -c "$SOCK" net wireguard
	atf_check -o match:"\"name\":\"wg0\",\"private-key\":true,\"public-key\":\"$PUB\"" \
	    -o match:"\"public-key\":\"$PEER\",\"preshared-key\":false,\"endpoint\":\"192.0.2.9:51820\",\"allowed-ips\":\[\"10.9.9.2/32\",\"fd00::2/128\"\],\"latest-handshake\":1700000000,\"rx\":1024,\"tx\":2048,\"keepalive\":25" \
	    -o match:'not kept: it has keys in it' cat wg.out
	atf_check -s exit:1 grep -qF "$KEY" wg.out

	# A peer, as wg(8) takes it; and gone again.
	atf_check -o match:"fake-wg set wg0 peer $PEER endpoint 192.0.2.9:51820 allowed-ips 10.9.9.2/32,fd00::2/128 persistent-keepalive 25" \
	    "$JGC" -c "$SOCK" wg wg0 peer "$PEER" endpoint 192.0.2.9:51820 \
	    allowed-ips 10.9.9.2/32,fd00::2/128 keepalive 25
	atf_check -o match:"fake-wg set wg0 peer $PEER endpoint \[2001:db8::9\]:51820" \
	    "$JGC" -c "$SOCK" wg wg0 peer "$PEER" endpoint '[2001:db8::9]:51820'
	# With a preshared key: given to wg(8) in a file of the agent's,
	# 0600, there only while it is read; not in an argument, a title
	# or the trace.
	PSK=$(printf 'a%.0s' $(seq 1 43))=
	printf '%s\n' "$PSK" > psk.in
	atf_check -o save:psk.out "$JGC" -t -c "$SOCK" wg wg0 peer "$PEER" preshared-key psk.in
	atf_check -o inline:"$PSK\n" cat psk.got
	atf_check -o inline:'-rw-------\n' cat psk.mode
	atf_check -s exit:1 test -e "$(cat psk.path)"
	atf_check -s exit:1 grep -qF "$PSK" psk.out
	atf_check -s exit:1 grep -qF "$PSK" wg.log
	atf_check -s exit:1 grep -qF "$PSK" daemon.out
	atf_check -s exit:1 -e match:'a preshared key is a peer' -o ignore \
	    "$JGC" -c "$SOCK" wg wg0 unpeer "$PEER" preshared-key psk.in
	atf_check -o match:"fake-wg set wg0 peer $PEER remove" \
	    "$JGC" -c "$SOCK" wg wg0 unpeer "$PEER"
	atf_check -s exit:1 -o match:'No such device' \
	    "$JGC" -c "$SOCK" wg wg9 unpeer "$PEER"
	: > wg.log
	atf_check -s exit:1 -e match:'44 characters of base64' -o ignore \
	    "$JGC" -c "$SOCK" wg wg0 peer 'not-a-key'
	atf_check -s exit:1 -e match:'an address or a name, and a port' -o ignore \
	    "$JGC" -c "$SOCK" wg wg0 peer "$PEER" endpoint '192.0.2.9 51820'
	atf_check -s exit:1 -e match:'an address or a name, and a port' -o ignore \
	    "$JGC" -c "$SOCK" wg wg0 peer "$PEER" endpoint '-x:1'
	atf_check -s exit:1 -e match:'with their prefix lengths' -o ignore \
	    "$JGC" -c "$SOCK" wg wg0 peer "$PEER" allowed-ips '10.0.0.0/40'
	atf_check -s exit:1 -e match:'the interface is wg and its number' -o ignore \
	    "$JGC" -c "$SOCK" wg em0 init
	atf_check -s exit:1 -e match:'not in safe mode' -o ignore \
	    "$JGC" -s -c "$SOCK" wg wg0 init
	atf_check -o empty cat wg.log

	# Kept for a boot: written as wg-quick(8) reads it, for nobody
	# else to read, and rc.conf told to bring it up.
	printf 'cloned_interfaces="wg0 gif1"\nifconfig_wg0="up"\n' >> rc.conf
	atf_check -o save:keep.out "$JGC" -p -t -c "$SOCK" wg wg0 peer "$PEER" \
	    allowed-ips 10.9.9.2/32
	atf_check -s exit:1 grep -qF "$KEY" keep.out
	atf_check -o match:'^\[Interface\]$' cat wg/wg0.conf
	atf_check grep -qxF "PrivateKey = $KEY" wg/wg0.conf
	atf_check grep -qxF "PublicKey = $PEER" wg/wg0.conf
	atf_check -o match:'^-rw-------' ls -l wg/wg0.conf
	atf_check -o match:'^wireguard_interfaces="wg0"$' \
	    -o match:'^wireguard_enable="YES"$' \
	    -o match:'^cloned_interfaces="gif1"$' -o not-match:'ifconfig_wg0' \
	    cat rc.conf
	# Destroyed and forgotten: the file goes with it.
	atf_check -o match:'fake-ifconfig wg0 destroy' \
	    "$JGC" -p -c "$SOCK" interface wg0 destroy
	atf_check test ! -e wg/wg0.conf
	atf_check -o not-match:'wg0' cat rc.conf

	# BIRD: what it says of itself and of its protocols, asked for
	# without the right to change anything.
	atf_check -o save:bird.json "$JGC" -c "$SOCK" net bird
	atf_check -o match:'"status":\["BIRD 2.15.1","Router ID is 192.0.2.1","Hostname is lab","Daemon is up and running"\]' \
	    -o match:'"name":"device1","proto":"Device","table":"---","state":"up","since":"2026-10-01","info":""' \
	    -o match:'"name":"bgp_core","proto":"BGP","table":"---","state":"up","since":"12:01:02.345","info":"Established"' \
	    -o match:'"name":"bgp_edge".*"state":"start".*"info":"Active        Socket: Connection refused"' \
	    cat bird.json
	# Of a neighbour: who it is, and of each channel its filters and
	# how many routes came and went.
	atf_check -o match:'"description":"Core uplink","bgp-state":"Established","neighbor":"192.0.2.1","neighbor-as":"65001","local-as":"65000","neighbor-id":"192.0.2.1"' \
	    -o match:'"name":"ipv4","state":"UP","table":"master4","input-filter":"bgp_in","output-filter":"bgp_out","routes":"845233 imported, 12 exported, 400000 preferred","imported":845233,"exported":12' \
	    -o match:'"name":"ipv6".*"output-filter":"REJECT".*"imported":190000,"exported":0' \
	    -o match:'"neighbor":"198.51.100.7","neighbor-as":"65002".*"last-error":"Socket: Connection refused"' \
	    -o match:'"cache":"rpki.example.net","rpki-status":"Established","serial":"42"' \
	    -o match:'"ospf":\[\{"proto":"ospf1","router-id":"10.0.0.2","pri":"1","state":"Full/PtP","dtime":"00:00:35","interface":"gif0","address":"10.255.0.2"\}\]' \
	    -o match:'"bfd":\[\{"proto":"bfd1","address":"fe80::1","interface":"gif0","state":"Up","since":"13:01:27.605","interval":"0.200","timeout":"1.000"\},\{"proto":"bfd1","address":"fe80::2","interface":"gre1","state":"Down"' \
	    -o match:'"tables":\[\{"name":"master4","routes":845236,"networks":845233\},\{"name":"r4","routes":512345,"networks":512345\}\]' \
	    cat bird.json
	atf_check -o match:'^-r show status$' -o match:'^-r show protocols all$' \
	    cat birdc.log
	atf_check -o match:'bird restart bgp_core' \
	    -o match:'fake-birdc restart bgp_core' \
	    "$JGC" -c "$SOCK" bird restart bgp_core
	atf_check -o match:'fake-birdc reload all' \
	    "$JGC" -c "$SOCK" bird reload all
	atf_check -o match:'fake-birdc disable bgp_edge' \
	    "$JGC" -c "$SOCK" bird disable bgp_edge
	# The host says which plugins it has: those whose program is there.
	# wg(8) is the base system's, not a plugin.
	atf_check -o match:'Plugins: bird( |$)' -o not-match:'Plugins:.*wireguard' "$JGC" -c "$SOCK" hello
	atf_check -o match:'fake-birdc configure' -o match:'Reconfigured' \
	    "$JGC" -c "$SOCK" bird configure
	# birdc ends well whatever was answered: what it said counts.
	atf_check -s exit:1 -o match:'No protocols match' \
	    "$JGC" -c "$SOCK" bird restart nope
	atf_check -s exit:1 -e match:'letters, digits and _' -o ignore \
	    "$JGC" -c "$SOCK" bird restart 'bgp1;down'
	atf_check -s exit:1 -e match:'enable, disable, restart, reload or configure' -o ignore \
	    "$JGC" -c "$SOCK" bird down now
	atf_check -o not-match:'down' cat birdc.log

	# Its configuration: read whole, with the files it includes; put
	# back whole, once bird(8) has parsed it, and the daemon told.
	atf_check -o match:'^router id 192.0.2.1;$' -o match:'filter bgp_in' \
	    "$JGC" -c "$SOCK" bird config
	atf_check -o match:'bird/peers/edge.conf' \
	    "$JGC" --libxo json -c "$SOCK" bird config
	atf_check -o match:'neighbor 198.51.100.7' \
	    "$JGC" -c "$SOCK" bird config "$(pwd)/bird/peers/edge.conf"
	sed -e 's/accept;/reject;/' bird/bird.conf > new.conf
	: > birdc.log
	atf_check -o match:'parses; left as it was' \
	    "$JGC" -c "$SOCK" bird config -n -w new.conf
	atf_check -o match:'accept;' -o not-match:'reject;' cat bird/bird.conf
	atf_check -o empty cat birdc.log
	atf_check -o match:'in place, and BIRD told' -o match:'fake-bird -p -c' \
	    "$JGC" -t -c "$SOCK" bird config -w new.conf
	atf_check -o match:'reject;' cat bird/bird.conf
	atf_check -o match:'accept;' cat bird/bird.conf.arcana-old
	atf_check -o match:'^configure$' cat birdc.log
	# What bird does not take does not stay, and the daemon is not told.
	: > birdc.log
	printf 'router id 192.0.2.1;\nBROKEN\n' > bad.conf
	atf_check -s exit:1 -e match:'bird does not take it' \
	    -e match:'syntax error' -o ignore \
	    "$JGC" -c "$SOCK" bird config -w bad.conf
	atf_check -o match:'reject;' -o not-match:'BROKEN' cat bird/bird.conf
	atf_check -o empty cat birdc.log
	# A file it includes is put back the same way; another is not one
	# of its files, wherever it is.
	printf 'protocol bgp bgp_edge { neighbor 198.51.100.8 as 65002; }\n' > edge.new
	atf_check -o match:'in place' \
	    "$JGC" -c "$SOCK" bird config -w edge.new "$(pwd)/bird/peers/edge.conf"
	atf_check -o match:'198.51.100.8' cat bird/peers/edge.conf
	atf_check -s exit:1 -e match:"not a file of BIRD's configuration" -o ignore \
	    "$JGC" -c "$SOCK" bird config "$(pwd)/rc.conf"
	atf_check -s exit:1 -e match:"not a file of BIRD's configuration" -o ignore \
	    "$JGC" -c "$SOCK" bird config -w edge.new "$(pwd)/bird/../rc.conf"
	atf_check -s exit:1 -e match:"not a file of BIRD's configuration" -o ignore \
	    "$JGC" -c "$SOCK" bird config -w edge.new "$(pwd)/bird/peers/x.sh"
	atf_check -o not-match:'bgp_edge' cat rc.conf

	# BIRD's routes, said in birdc's words; an address alone is the
	# route that covers it.  Each route with where it leads, and with
	# all, what it carries.
	atf_check -o save:r.json "$JGC" -c "$SOCK" bird routes 10.1.2.3 all
	atf_check -o match:'"table":"master4","prefix":"10.1.0.0/16","type":"unicast","protocol":"bgp_core","from":"192.0.2.1","since":"2026-10-01","primary":true,"preference":"100","info":"AS65001i"' \
	    -o match:'"nexthops":\[\{"via":"192.0.2.1","interface":"em0"\}\]' \
	    -o match:'"attrs":\["Type: BGP univ","BGP.as_path: 65001 65010","BGP.large_community: \(65001, 1, 100\)"\]' \
	    -o match:'"prefix":"10.1.0.0/16","type":"unicast","protocol":"bgp_edge","since":"12:01:02.345","primary":false,"preference":"100/20","info":"AS65002\?"' \
	    -o match:'\{"via":"198.51.100.7","interface":"gre0"\},\{"via":"198.51.100.9","interface":"gre1"\}' \
	    -o match:'"count":2' cat r.json
	atf_check -o match:'"routes":\[\]' "$JGC" -c "$SOCK" bird routes table master6
	atf_check -o match:'"message":"Network not found"' \
	    "$JGC" -c "$SOCK" bird routes 10.9.0.0/16
	# A neighbour's whole table is counted, not carried.
	atf_check -s exit:1 -e match:'950000 routes: more than the 2000 shown' \
	    -o ignore "$JGC" -c "$SOCK" bird routes protocol bgp_core
	atf_check -o not-match:'^-r show route protocol bgp_core$' cat birdc.log
	# Only birdc's words for routes, and names that are names.
	atf_check -s exit:1 -e match:"in birdc's words" -o ignore \
	    "$JGC" -c "$SOCK" bird routes where 'net ~ 10.0.0.0/8'
	atf_check -s exit:1 -e match:"in birdc's words" -o ignore \
	    "$JGC" -c "$SOCK" bird routes protocol 'bgp;down'
	atf_check -s exit:1 -e match:"in birdc's words" -o ignore \
	    "$JGC" -c "$SOCK" bird routes table

	# In safe mode BIRD is told to take the change back by itself when
	# its time is up, and the file goes back with it.
	sed -e 's/reject;/accept; # safe/' bird/bird.conf > safe.conf
	: > birdc.log
	atf_check -o match:'taken back unless confirmed' \
	    "$JGC" -s -c "$SOCK" bird config -w safe.conf
	atf_check -o match:'^configure timeout 2$' cat birdc.log
	atf_check -o match:'# safe' cat bird/bird.conf
	# Another change waits for this one.
	atf_check -s exit:1 -e match:'waits to be confirmed' -o ignore \
	    "$JGC" -c "$SOCK" bird config -w safe.conf
	for i in $(seq 1 80); do
		grep -q '# safe' bird/bird.conf || break
		sleep 0.1
	done
	atf_check -o match:'reject;' -o not-match:'# safe' cat bird/bird.conf
	atf_check -s exit:1 -e match:'no change to BIRD waits' -o ignore \
	    "$JGC" -c "$SOCK" bird confirm
	# Confirmed, it stays.
	for i in $(seq 1 50); do
		"$JGC" -s -c "$SOCK" bird config -w safe.conf > out 2>&1 && break
		sleep 0.1
	done
	atf_check -o match:'taken back unless confirmed' cat out
	atf_check -o match:'confirmed: it stays' "$JGC" -c "$SOCK" bird confirm
	atf_check -o match:'^configure confirm$' cat birdc.log
	sleep 5
	atf_check -o match:'# safe' cat bird/bird.conf

	# What BIRD itself does not take does not stay in the file: what
	# it says of a file it cannot read has no word "error" in it.
	sed -e 's/# safe/# two/' bird/bird.conf > two.conf
	touch bird.refuses
	atf_check -s exit:1 -e match:'BIRD did not take it, and the file is as it was' \
	    -e match:'Unknown instruction' -o ignore \
	    "$JGC" -c "$SOCK" bird config -w two.conf
	atf_check -o match:'# safe' -o not-match:'# two' cat bird/bird.conf
	atf_check -s exit:1 -o match:'BIRD did not take its configuration' \
	    "$JGC" -c "$SOCK" bird configure
	rm bird.refuses
	# A daemon that goes away while it is told is not undone after:
	# the file parses, and stays for it to read when it is started.
	touch bird.dies
	atf_check -s exit:1 -e match:'BIRD stopped answering when told to read' \
	    -e match:'The file is in place and parses' -o ignore \
	    "$JGC" -c "$SOCK" bird config -w two.conf
	atf_check -o match:'# two' cat bird/bird.conf
	rm bird.dies
	# One that does not run: nothing in safe mode; without it the file
	# is put in place, for when it is started.
	sed -e 's/# two/# twob/' bird/bird.conf > twob.conf
	atf_check -s exit:1 -e match:'BIRD does not answer: nothing can be changed in safe mode' \
	    -o ignore "$JGC" -s -c "$SOCK" bird config -w twob.conf
	atf_check -o match:'# two$' cat bird/bird.conf
	atf_check -s exit:1 -e match:'reads it when it is started' -o ignore \
	    "$JGC" -c "$SOCK" bird config -w twob.conf
	atf_check -o match:'# twob' cat bird/bird.conf
	rm bird.dead
	sed -e 's/# twob/# two/' bird/bird.conf > two.conf
	atf_check -o match:'in place, and BIRD told' \
	    "$JGC" -c "$SOCK" bird config -w two.conf
	# What parsed is never left out because BIRD could not: but what
	# does not parse never gets there, dead or not.
	touch bird.dead
	printf 'router id 192.0.2.1;\nBROKEN\n' > bad.conf
	atf_check -s exit:1 -e match:'bird does not take it' -o ignore \
	    "$JGC" -c "$SOCK" bird config -w bad.conf
	atf_check -o match:'# two' -o not-match:'BROKEN' cat bird/bird.conf
	rm bird.dead
	# One that goes away while a change waits has no timer left, and
	# is not undone after either: the file stays.
	sed -e 's/# two/# gone/' bird/bird.conf > gone.conf
	atf_check -o match:'taken back unless confirmed' \
	    "$JGC" -s -c "$SOCK" bird config -w gone.conf
	touch bird.dead
	sleep 6
	atf_check -o match:'# gone' cat bird/bird.conf
	rm bird.dead
	sed -e 's/# gone/# two/' bird/bird.conf > two.conf
	for i in $(seq 1 50); do
		"$JGC" -c "$SOCK" bird config -w two.conf > out 2>&1 && break
		sleep 0.1
	done
	atf_check -o match:'in place, and BIRD told' cat out
	# While one waits, BIRD is not told to read its configuration:
	# that would stop its own timer.
	sed -e 's/# two/# three/' bird/bird.conf > three.conf
	for i in $(seq 1 50); do
		"$JGC" -s -c "$SOCK" bird config -w three.conf > out 2>&1 && break
		sleep 0.1
	done
	atf_check -o match:'taken back unless confirmed' cat out
	atf_check -s exit:1 -o match:'waits to be confirmed' \
	    "$JGC" -c "$SOCK" bird configure
	# Left alone it is taken back, and BIRD told to read the file as
	# it was; a file somebody changed meanwhile is left to them.
	: > birdc.log
	for i in $(seq 1 80); do
		grep -q '# three' bird/bird.conf || break
		sleep 0.1
	done
	atf_check -o match:'# two' -o not-match:'# three' cat bird/bird.conf
	for i in $(seq 1 30); do
		grep -q '^configure$' birdc.log && break
		sleep 0.1
	done
	atf_check -o match:'^configure$' cat birdc.log
	for i in $(seq 1 50); do
		"$JGC" -s -c "$SOCK" bird config -w three.conf > out 2>&1 && break
		sleep 0.1
	done
	atf_check -o match:'taken back unless confirmed' cat out
	printf '# somebody else\n' >> bird/bird.conf
	sleep 6
	atf_check -o match:'# three' -o match:'# somebody else' cat bird/bird.conf
}
vpn_cleanup()
{
	stop_daemon
}

atf_test_case sdwan_jail cleanup
sdwan_jail_head()
{
	atf_set "descr" "SD-WAN at an edge that is a vnet jail: its rules," \
	    "tables and steering its own, run by its own ipfw (jexec), the" \
	    "file of rules beneath its root, its network's sysctls set" \
	    "there, kept in files of its own and applied again at a start," \
	    "the host's beside them"
}
sdwan_jail_body()
{
	local d="$(pwd)"

	R=$d/jroot
	mkdir -p "$R/var/run"
	cat > fake-jls <<EOS
#!/bin/sh
case "\$2" in
gateway) echo "4 new $R" ;;
*) echo "jls: jail \"\$2\" not found" >&2; exit 1 ;;
esac
EOS
	# jexec: logged; the rule file the jail's ipfw would read, read
	# where the jail has it; a sysctl never run on the host.
	cat > fake-jexec <<EOS
#!/bin/sh
echo "jexec \$*" >> $d/jexec.log
shift
for a; do last=\$a; done
case "\$last" in /var/run/arcana-sdwan-*) cat "$R\$last" >> $d/jail-rules.log ;; esac
case "\$1 \$2" in */sysctl\ -e) echo "net.fibs=4"; exit 0 ;; esac
case "\$1" in */sysctl) exit 0 ;; esac
exec "\$@"
EOS
	cat > fake-ipfw <<EOS
#!/bin/sh
echo "ipfw \$*" >> $d/ipfw.log
exit 0
EOS
	chmod +x fake-jls fake-jexec fake-ipfw
	printf '#!/bin/sh\nexit 0\n' > fake-kldload
	chmod +x fake-kldload
	DAEMON_ARGS="-h $d/fake-ipfw -2 $d/tools"
	mkdir -p tools
	start_daemon

	# The jail's rules: run by its ipfw, from a file beneath its root.
	atf_check -o empty "$JGC" -c "$SOCK" sdwan rules \
	    '{"jail":"gateway","set":30,"tables":[{"name":"sw1_p0","valtype":"ipv4","entries":[]}],"rules":["00500 fwd tablearg ip from any to table(sw1_p0)"]}'
	atf_check -o match:"^jexec 4 $d/fake-ipfw -q /var/run/arcana-sdwan-rules.load$" \
	    -o match:"^jexec 4 [^ ]*sysctl net.inet.ipsec.filtertunnel=1$" \
	    cat jexec.log
	atf_check -o match:'^table sw1_p0 create type addr valtype ipv4$' \
	    -o match:'^add 00500 set 30 fwd tablearg ip from any to table\(sw1_p0\)$' \
	    cat jail-rules.log
	test -e "$R/var/run/arcana-sdwan-rules.load" && \
	    atf_fail "the file of rules stayed in the jail"
	# Its steering, by its own ipfw too.
	atf_check -o empty "$JGC" -c "$SOCK" sdwan steer \
	    '{"jail":"gateway","entries":[{"table":"sw1_p0","prefix":"10.20.0.0/24","candidates":[{"id":"t1","via":"100.64.0.1"}]}]}'
	atf_check -o match:'^jexec 4 [^ ]*fake-ipfw -q table sw1_p0_alt atomic add 10.20.0.0/24 100.64.0.1$' \
	    -o match:'^jexec 4 [^ ]*fake-ipfw -q table sw1_p0 swap sw1_p0_alt$' \
	    cat jexec.log
	# The host's own: none, and not the jail's.
	atf_check -o match:'"rules":\{"set":0,"rules":0,"tables":\[\],' \
	    -o match:'"edges":\[\{"jail":"gateway","rules":\{"set":30,"rules":1,"tables":\["sw1_p0"\],"objects":0,"counters":\[\]\},"steer":\[\{"table":"sw1_p0","prefix":"10.20.0.0/24","chosen":0,' \
	    -o match:'"steered":true\}\]' "$JGC" -c "$SOCK" sdwan
	# The host's beside it, its ipfw not jexec'd.
	atf_check -o empty "$JGC" -c "$SOCK" sdwan rules \
	    '{"set":31,"tables":[],"rules":["00600 count ip from any to any"]}'
	atf_check -o match:"^ipfw -q $d/[^ ]*sdwan-rules.json.load$" cat ipfw.log
	atf_check -o match:'"rules":\{"set":31,"rules":1,' \
	    -o match:'"edges":\[\{"jail":"gateway","rules":\{"set":30,' \
	    "$JGC" -c "$SOCK" sdwan
	# Each kept in its own file; the jail's applied again at a start.
	test -f "$(dirname "$d/history.conf")/sdwan-rules@gateway.json" || \
	    atf_fail "the jail's rules are not kept"
	test -f "$(dirname "$d/history.conf")/sdwan-steer@gateway.json" || \
	    atf_fail "the jail's steering is not kept"
	stop_daemon
	: > jexec.log
	start_daemon
	atf_check -o match:"^jexec 4 $d/fake-ipfw -q /var/run/arcana-sdwan-rules.load$" \
	    -o match:'^jexec 4 [^ ]*fake-ipfw -q table sw1_p0 swap sw1_p0_alt$' \
	    cat jexec.log
	atf_check -o match:'"edges":\[\{"jail":"gateway","rules":\{"set":30,' \
	    "$JGC" -c "$SOCK" sdwan
	# Its network's sysctls are its own: set by its sysctl, kept in its
	# own sysctl.conf; the kernel's are not set from here.
	mkdir -p "$R/etc"
	atf_check -o match:'done +gateway: sysctl net.fibs=4 \(kept\)$' \
	    "$JGC" -c "$SOCK" -p -j gateway sysctl net.fibs=4
	atf_check -o match:"^jexec 4 [^ ]*sysctl net.fibs=4$" cat jexec.log
	atf_check -o inline:'net.fibs=4\n' cat "$R/etc/sysctl.conf"
	# Read as its own sysctl reads them; only its network's.
	atf_check -o match:'^\{"values":\[\{"name":"net.fibs","value":"4"\}\],"kept":\[\]\}$' \
	    "$JGC" -c "$SOCK" -j gateway sysctl net.fibs
	atf_check -o match:"^jexec 4 [^ ]*sysctl -e -- net.fibs$" cat jexec.log
	atf_check -s exit:1 -e match:"under its network's, net." -o ignore \
	    "$JGC" -c "$SOCK" -j gateway sysctl kern.ostype
	atf_check -s exit:1 -e match:"its network's \\(net\\.\\*\\)" -o ignore \
	    "$JGC" -c "$SOCK" -j gateway sysctl kern.maxproc=100
	# Its probes a list of its own: the host's set after it stay its,
	# each kept in its own file; at a start, both again.
	atf_check -o empty "$JGC" -c "$SOCK" sdwan probes \
	    '{"jail":"gateway","targets":[{"id":"t1","address":"100.64.0.1"}]}'
	atf_check -o empty "$JGC" -c "$SOCK" sdwan probes \
	    '[{"id":"t1","address":"100.64.0.2"}]'
	atf_check -o match:'"targets":\[\{"id":"t1","address":"100.64.0.2","family":"inet","fib":0,.*\{"id":"t1","address":"100.64.0.1","family":"inet","jail":"gateway",.*"edges":\[\{"jail":"gateway",.*"candidates":\[\{"id":"t1","via":"100.64.0.1","state":"unknown"\}' \
	    "$JGC" -c "$SOCK" sdwan
	test -f sdwan-probes@gateway.json || atf_fail "the jail's probes are not kept"
	stop_daemon
	start_daemon
	atf_check -o match:'"address":"100.64.0.2"' \
	    -o match:'"address":"100.64.0.1","family":"inet","jail":"gateway"' \
	    "$JGC" -c "$SOCK" sdwan
	# Its list emptied: the host's stays, the jail's file goes.
	atf_check -o empty "$JGC" -c "$SOCK" sdwan probes '{"jail":"gateway","targets":[]}'
	atf_check -o match:'"targets":\[\{"id":"t1","address":"100.64.0.2","family":"inet","fib":0,' \
	    -o not-match:'"jail":"gateway","fib"' "$JGC" -c "$SOCK" sdwan
	test -f sdwan-probes@gateway.json && atf_fail "the jail's probe file stayed"
	atf_check -s exit:1 -e match:'invalid jail name' -o ignore \
	    "$JGC" -c "$SOCK" sdwan probes '{"jail":"a/b","targets":[]}'
	# The links an edge watches (Mplify 119's interface faults): lo0
	# has its link; one with none is a fault, cleared once it is not
	# watched.
	atf_check -o empty "$JGC" -c "$SOCK" sdwan probes \
	    '{"targets":[{"id":"t1","address":"100.64.0.2"}],"links":[{"interface":"lo0","id":"uni-hq","role":"uni"},{"interface":"nosuch0","id":"a-inet","role":"ucs"}]}'
	atf_check -o match:'"type":"interface","severity":"Major","was":"Major","object":"a-inet","by":"link","description":"the UCS end point a-inet has no link on nosuch0","cleared":false' \
	    -o not-match:'"object":"uni-hq"' "$JGC" -c "$SOCK" sdwan
	atf_check -o empty "$JGC" -c "$SOCK" sdwan probes \
	    '{"targets":[{"id":"t1","address":"100.64.0.2"}],"links":[]}'
	atf_check -o match:'"object":"a-inet","by":"link",[^}]*"cleared":true' \
	    "$JGC" -c "$SOCK" sdwan
	atf_check -s exit:1 -e match:'each link has an interface and an id' -o ignore \
	    "$JGC" -c "$SOCK" sdwan probes '{"targets":[],"links":[{"interface":"a b","id":"x"}]}'
	atf_check -s exit:1 -e match:'JSON array, or an object' -o ignore \
	    "$JGC" -c "$SOCK" sdwan probes '{"links":[]}'
	# Its steering and rules emptied: their files go, and a start makes
	# no edge of it.
	atf_check -o empty "$JGC" -c "$SOCK" sdwan steer '{"jail":"gateway","entries":[]}'
	atf_check -o empty "$JGC" -c "$SOCK" sdwan rules \
	    '{"jail":"gateway","set":30,"tables":[],"rules":[]}'
	test -f sdwan-rules@gateway.json -o -f sdwan-steer@gateway.json && \
	    atf_fail "the emptied jail's files stayed"
	stop_daemon
	start_daemon
	atf_check -o match:'"edges":\[\]' "$JGC" -c "$SOCK" sdwan
	# Refused: a jail that is no jail's name, or does not run.
	atf_check -s exit:1 -e match:'invalid jail name' -o ignore \
	    "$JGC" -c "$SOCK" sdwan rules '{"jail":"a b","set":30,"tables":[],"rules":[]}'
	atf_check -s exit:1 -e match:'nosuch' -o ignore \
	    "$JGC" -c "$SOCK" sdwan rules '{"jail":"nosuch","set":30,"tables":[],"rules":["00500 count ip from any to any"]}'
}
sdwan_jail_cleanup()
{
	stop_daemon
}

atf_test_case vnet cleanup
vnet_head()
{
	atf_set "descr" "The network of a jail that has one of its own, worked on from the host"
}
vnet_body()
{
	PEER='xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg='
	# The jail's root, with its own rc.conf, BIRD and WireGuard files.
	R=$(pwd)/jroot
	mkdir -p "$R/etc" "$R$(pwd)/bird" "$R$(pwd)/wg"
	printf 'hostname="gateway"\n' > "$R/etc/rc.conf"
	printf 'router id 10.0.0.1;\nfilter gw_in {\n\taccept;\n}\n' > "$R$(pwd)/bird/bird.conf"
	# jls: gateway runs with a network of its own, web shares the
	# host's, and nothing else runs.
	cat > fake-jls <<EOS
#!/bin/sh
case "\$2" in
gateway) echo "4 new $R" ;;
web) echo "7 inherit $(pwd)/web" ;;
*) echo "jls: jail \"\$2\" not found" >&2; exit 1 ;;
esac
EOS
	# jexec: the program, "in the jail": what it was given is logged.
	cat > fake-jexec <<EOS
#!/bin/sh
echo "jexec \$*" >> $(pwd)/jexec.log
shift
exec "\$@"
EOS
	# The helper, which would attach to the jail: its answers.
	cat > fake-helper <<EOS
#!/bin/sh
echo "fake-helper \$*" >&2
echo "\$*" >> $(pwd)/helper.log
case "\$3" in
routes) echo '{"destination":"default","gateway":"10.99.0.1","flags":"UGS","nhop":1,"mtu":1500,"interface-name":"epair91b","metric":1,"weight":1,"fib":0,"prefixlen":0}'; echo "#total 1" ;;
route-get) echo '{"to":"'\$4'","destination":"default","prefixlen":0,"gateway":"10.99.0.1","fib":"0","interface":"epair91b","flags":"UGS","metric":1,"weight":1}' ;;
interfaces) echo '{"interfaces":[{"name":"epair91b","up":true,"mtu":1500,"addresses":[{"family":"inet","address":"10.99.0.2","prefixlen":24}]},{"name":"wg0","up":true,"mtu":1420,"addresses":[{"family":"inet","address":"10.255.0.1","prefixlen":30}]}],"time":1000}' ;;
exists) case "\$4" in epair91b|wg0|lo0) echo 1 ;; *) echo 0 ;; esac ;;
up) echo 1 ;;
sysctl-int) [ -f $(pwd)/fw-on ] && echo 1 || echo 0 ;;
current) printf '1500\t0\t-1\tto the host' ;;
prefix) [ "\$5" = 10.99.0.2 ] && echo 10.99.0.2/24 ;;
esac
exit 0
EOS
	printf '#!/bin/sh\necho "$*" >> %s/ifconfig.log\n' "$(pwd)" > fake-ifconfig
	printf '#!/bin/sh\necho "$*" >> %s/sysrc.log\nexit 1\n' "$(pwd)" > sysrc-log
	cat > fake-wg <<EOS
#!/bin/sh
echo "\$*" >> $(pwd)/wg.log
case "\$1 \$2 \$3" in
"show all dump") printf 'wg0\t(none)\t(none)\t51820\toff\n' ;;
"show wg0 private-key") echo "(none)" ;;
"showconf wg0 ") printf '[Interface]\nListenPort = 51820\nPrivateKey = KEY\n' ;;
"set wg0 private-key") test -r "$R\$4" && echo "read \$4" >> $(pwd)/wg.log ;;
esac
exit 0
EOS
	cat > fake-birdc <<EOS
#!/bin/sh
echo "\$*" >> $(pwd)/birdc.log
[ "\$1" = -r ] && shift
case "\$*" in
"show status") printf 'BIRD 2.15.1 ready.\nBIRD 2.15.1\nRouter ID is 10.0.0.1\n' ;;
"show protocols all") printf 'BIRD 2.15.1 ready.\nName Proto Table State Since Info\nbgp_up BGP --- up 2026-10-01 Established\n    Neighbor address: 192.0.2.1\n    Neighbor AS:      65001\n' ;;
configure) printf 'Reconfigured\n' ;;
esac
exit 0
EOS
	printf '#!/bin/sh\necho "bird $*" >> %s/birdc.log\ngrep -q BROKEN "%s$3" && { echo "syntax error" >&2; exit 1; }\nexit 0\n' "$(pwd)" "$R" > fake-bird
	chmod +x fake-jls fake-jexec fake-helper fake-ifconfig fake-wg fake-birdc fake-bird
	printf '#!/bin/sh\necho "ipfw $*" >> %s/ipfw.log\nexit 0\n' "$(pwd)" > fake-ipfw
	chmod +x fake-ipfw
	DAEMON_ARGS="-h $(pwd)/fake-ipfw"
	start_daemon

	# Its interfaces: read by the helper, which attaches to the jail;
	# the host's are still the host's.
	atf_check -o match:'"name":"epair91b"' -o match:'"address":"10.99.0.2"' \
	    -o not-match:'"name":"lo0"' "$JGC" -j gateway -c "$SOCK" net interfaces
	atf_check -o match:'^--scope-helper 4 interfaces - 0$' cat helper.log
	atf_check -o match:'"name":"lo0"' -o not-match:'epair91b' \
	    "$JGC" -c "$SOCK" net interfaces
	# Its bridges and geneve tunnels: ifconfig told the jail once.
	atf_check -o ignore "$JGC" -j gateway -c "$SOCK" net bridges
	atf_check -o match:'^-j 4 -av$' cat ifconfig.log
	# Its routes and its route to an address: the host's programs,
	# told which jail.
	atf_check -o match:'fake-helper --scope-helper 4 routes 4 0 - -' \
	    "$JGC" -t -j gateway -c "$SOCK" net routes -4
	atf_check -o match:'"gateway":"10.99.0.1","fib":"0","interface":"epair91b"' \
	    "$JGC" -j gateway -c "$SOCK" route get 192.0.2.9
	atf_check -o match:'^--scope-helper 4 route-get 192.0.2.9 0$' cat helper.log

	# A change there: ifconfig and route with the jail, the job named
	# after it, what is kept kept in the jail's own rc.conf.
	atf_check -o match:'gateway: epair91b: add 10.99.0.5/24' \
	    -o match:'fake-ifconfig -j 4 epair91b inet 10.99.0.5/24 alias' \
	    "$JGC" -p -j gateway -c "$SOCK" interface epair91b add 10.99.0.5/24
	atf_check -o match:'^ifconfig_epair91b_alias0="inet 10.99.0.5/24"$' \
	    cat "$R/etc/rc.conf"
	atf_check -o not-match:'10.99.0.5' cat rc.conf
	atf_check -o match:'fake-helper --scope-helper 4 route-add 10.77.0.0/16 10.99.0.1 - 0 0 0 -' \
	    "$JGC" -j gateway -c "$SOCK" route add 10.77.0.0/16 10.99.0.1
	# Its firewall is its own: ipfw is run in the jail, not on the host.
	atf_check -o match:'gateway' -o match:'fake-jexec 4 .*/fake-ipfw -q add 100 allow ip from any to any' \
	    "$JGC" -j gateway -c "$SOCK" ipfw add 100 allow ip from any to any
	atf_check -o match:'done' "$JGC" -j gateway -c "$SOCK" ipfw table T46 add 10.0.0.1
	atf_check -o match:'"loaded":true' "$JGC" -j gateway -c "$SOCK" net ipfw
	# On or off as the jail's own network has it, read inside it.
	atf_check -o match:'sysctl-int net.inet.ip.fw.enable' cat helper.log
	if kldstat -q -m ipfw; then
		atf_check -o match:'"enabled":false' "$JGC" -j gateway -c "$SOCK" net ipfw
		touch fw-on
		atf_check -o match:'"enabled":true' "$JGC" -j gateway -c "$SOCK" net ipfw
	fi
	atf_check -o match:'^jexec 4 .*/fake-ipfw -q table T46 add 10.0.0.1$' \
	    -o match:'^jexec 4 .*/fake-ipfw -S show$' cat jexec.log
	# An interface is one of the jail's, or it is not there.
	atf_check -s exit:1 -o match:'no interface em0 in that jail' \
	    "$JGC" -j gateway -c "$SOCK" interface em0 up
	# Safe mode in a jail: what was there is found there, and put back
	# there.
	: > ifconfig.log
	atf_check -o match:'queued' "$JGC" -q -s -j gateway -c "$SOCK" \
	    interface epair91b remove 10.99.0.2
	for i in $(seq 1 100); do
		"$JGC" -c "$SOCK" jobs | grep -q 'unconfirmed\|queued\|running' ||
		    break
		sleep 0.1
	done
	atf_check -o match:'^-j 4 epair91b inet 10.99.0.2 -alias$' \
	    -o match:'^-j 4 epair91b inet 10.99.0.2/24 alias$' cat ifconfig.log

	# WireGuard there: the jail's own wg, through jexec; the key is
	# made in the jail's directory, where the jail's wg reads it, and
	# what is kept is the jail's file.
	atf_check -o match:'made in the jail' \
	    -o match:'fake-jexec 4 .*/fake-wg set wg0 listen-port 51820' \
	    "$JGC" -p -j gateway -c "$SOCK" wg wg0 init 51820
	atf_check -o match:'^read .*/wg/\.wg0\.key\.' cat wg.log
	atf_check -o match:'^Address = 10.255.0.1/30$' -o match:'^MTU = 1420$' \
	    -o match:'^PrivateKey = KEY$' cat "$R$(pwd)/wg/wg0.conf"
	atf_check -o match:'^wireguard_interfaces="wg0"$' cat "$R/etc/rc.conf"
	atf_check test ! -e wg/wg0.conf
	atf_check -o not-match:'wireguard' cat rc.conf

	# BIRD there: the jail's birdc and bird, its configuration read and
	# put back beneath the jail's root.
	atf_check -o match:'"name":"bgp_up".*"neighbor":"192.0.2.1"' \
	    "$JGC" -j gateway -c "$SOCK" net bird
	atf_check -o match:'jexec 4 .*/fake-birdc -r show status' cat jexec.log
	atf_check -o match:'^router id 10.0.0.1;$' \
	    "$JGC" -j gateway -c "$SOCK" bird config
	sed -e 's/accept;/reject;/' "$R$(pwd)/bird/bird.conf" > new.conf
	atf_check -o match:'in place, and BIRD told' \
	    "$JGC" -j gateway -c "$SOCK" bird config -w new.conf
	atf_check -o match:'reject;' cat "$R$(pwd)/bird/bird.conf"
	atf_check -o match:'accept;' cat "$R$(pwd)/bird/bird.conf.arcana-old"
	atf_check -o match:"jexec 4 .*/fake-bird -p -c $(pwd)/bird/bird.conf" \
	    -o match:'jexec 4 .*/fake-birdc configure' cat jexec.log
	# What the jail's bird refuses does not stay there either.
	printf 'BROKEN\n' > bad.conf
	atf_check -s exit:1 -e match:'bird does not take it' -o ignore \
	    "$JGC" -j gateway -c "$SOCK" bird config -w bad.conf
	atf_check -o match:'reject;' -o not-match:'BROKEN' \
	    cat "$R$(pwd)/bird/bird.conf"
	# A file of the jail that is a link out of it is not followed: the
	# jail's root may make any name there lead anywhere.
	printf 'secret of the host\n' > outside.conf
	ln -s "$(pwd)/outside.conf" "$R$(pwd)/bird/leak.conf"
	atf_check -s exit:1 -o not-match:'secret' -e not-match:'secret' \
	    "$JGC" -j gateway -c "$SOCK" bird config "$(pwd)/bird/leak.conf"
	rm -rf "$R$(pwd)/bird"
	ln -s "$(pwd)" "$R$(pwd)/bird"
	atf_check -s exit:1 -o not-match:'secret' -e not-match:'secret' \
	    "$JGC" -j gateway -c "$SOCK" bird config "$(pwd)/bird/outside.conf"

	# A jail without a network of its own has none to work on, and
	# one that does not run has none now.
	atf_check -s exit:1 -e match:'has no network of its own' -o ignore \
	    "$JGC" -j web -c "$SOCK" net interfaces
	atf_check -s exit:1 -e match:'is not running' -o ignore \
	    "$JGC" -j nope -c "$SOCK" net routes
	atf_check -s exit:1 -o match:'has no network of its own' \
	    "$JGC" -j web -c "$SOCK" interface lo0 up
	atf_check -s exit:1 -e match:'invalid jail name' -o ignore \
	    "$JGC" -j 'a;b' -c "$SOCK" net routes

	# An interface of the host given to the jail: the host's ifconfig,
	# not told to work in the jail; kept, it is the jail's
	# vnet.interface in jail.conf.
	printf 'gateway {\n\tvnet;\n\tvnet.interface = "epair91b";\n}\n' \
	    >> etc/jail.conf
	: > ifconfig.log
	atf_check -o match:'give lo0 to gateway \(kept\)' -o match:'done' \
	    "$JGC" -p -c "$SOCK" interface lo0 give gateway
	atf_check -o match:'^lo0 vnet 4$' -o not-match:'-j 4' cat ifconfig.log
	atf_check -o match:'vnet.interface = "epair91b", "lo0";' \
	    cat etc/jail.conf
	# And taken back: out of the jail, and out of the file.
	atf_check -o match:'take lo0 back from gateway' \
	    -o match:'fake-ifconfig lo0 -vnet 4' \
	    "$JGC" -p -c "$SOCK" interface lo0 take gateway
	atf_check -o match:'vnet.interface = "epair91b";' \
	    -o not-match:'"lo0"' cat etc/jail.conf
	# What the file has already stays as it is written.
	atf_check -o match:'done' \
	    "$JGC" -p -c "$SOCK" interface epair91b take gateway
	atf_check -o not-match:'epair91b' cat etc/jail.conf
	# Only what is there moves, and only to a jail with a network.
	atf_check -s exit:1 -o match:'the jail gateway has no interface em9' \
	    "$JGC" -c "$SOCK" interface em9 take gateway
	atf_check -s exit:1 -o match:'the host has no interface em9' \
	    "$JGC" -c "$SOCK" interface em9 give gateway
	atf_check -s exit:1 -o match:'has no network of its own' \
	    "$JGC" -c "$SOCK" interface lo0 give web
	atf_check -s exit:1 -o match:'is not running' \
	    "$JGC" -c "$SOCK" interface lo0 give nope
	# In safe mode, unconfirmed, the jail gives it back.
	: > ifconfig.log
	atf_check -o match:'queued' "$JGC" -q -s -c "$SOCK" \
	    interface lo0 give gateway
	for i in $(seq 1 100); do
		"$JGC" -c "$SOCK" jobs | grep -q 'unconfirmed\|queued\|running' ||
		    break
		sleep 0.1
	done
	atf_check -o match:'^lo0 vnet 4$' -o match:'^lo0 -vnet 4$' \
	    cat ifconfig.log
	# A new pair for the jail is made on the host; one that cannot be
	# given, as here where no pair is really made, is destroyed again.
	printf '#!/bin/sh\necho "$*" >> %s/ifconfig.log\n[ "$*" = "epair create" ] && echo epair7a\nexit 0\n' "$(pwd)" > fake-ifconfig
	: > ifconfig.log
	atf_check -s exit:1 -o match:'give epair to gateway' \
	    -o match:'the host has no interface epair7b' \
	    "$JGC" -c "$SOCK" interface epair give gateway
	atf_check -o match:'^epair create$' -o match:'^epair7a destroy$' \
	    -o not-match:'vnet' cat ifconfig.log
	# With a bridge named, its end on the host is put in it, and up.
	: > ifconfig.log
	atf_check -s exit:1 -o match:'give epair to gateway, on bridge0' \
	    "$JGC" -c "$SOCK" interface epair give gateway bridge0
	atf_check -o match:'^bridge0 addm epair7a$' -o match:'^epair7a up$' \
	    cat ifconfig.log
	atf_check -s exit:1 -e match:"a new epair's end" -o ignore \
	    "$JGC" -c "$SOCK" interface lo0 give gateway bridge0

	# IPsec there: the jail's own strongSwan, a plugin of the jail's
	# when its swanctl is installed in it; its key, its connections
	# and its daemon the jail's, through jexec, and nothing of it on
	# the host.
	mkdir -p "$R$(pwd)/swanctl/conf.d" "$R$(pwd)/swanctl/pkcs8" \
	    "$R$(pwd)/swanctl/pubkey"
	cat > fake-swanctl <<EOS
#!/bin/sh
echo "\$*" >> $(pwd)/swanctl.log
case "\$1" in
--list-conns|--list-sas) ;;
--stats) [ -f $(pwd)/running.strongswan ] || { echo "connecting to 'unix:///var/run/charon.vici' failed" >&2; exit 1; } ;;
esac
exit 0
EOS
	chmod +x fake-swanctl
	mkdir -p "$R$(pwd)"
	cp fake-swanctl "$R$(pwd)/fake-swanctl"
	atf_check -o match:'"kernel":(true|false)' -o match:'"running":true' \
	    "$JGC" -j gateway -c "$SOCK" net ipsec
	atf_check -o match:'private key: made in the jail' \
	    -o match:'fake-jexec 4 .*/fake-swanctl --load-creds' \
	    "$JGC" -p -j gateway -c "$SOCK" ipsec init
	atf_check -o match:'BEGIN PRIVATE KEY' \
	    cat "$R$(pwd)/swanctl/pkcs8/arcana.pem"
	atf_check test ! -e swanctl/pkcs8/arcana.pem
	atf_check -o match:'^strongswan_enable="YES"$' cat "$R/etc/rc.conf"
	atf_check -o not-match:'strongswan' cat rc.conf
	PUB=$(sed -e '/-----/d' "$R$(pwd)/swanctl/pubkey/arcana.pub" | tr -d '\n')
	atf_check -o match:'ipsec conn to-host \(tunnel\)' \
	    -o match:'fake-jexec 4 .*/fake-swanctl --load-all' \
	    "$JGC" -j gateway -c "$SOCK" ipsec conn to-host 10.99.0.2 \
	    10.99.0.1 mode tunnel pubkey "$PUB"
	atf_check -o match:'^		local_addrs = 10.99.0.2$' \
	    cat "$R$(pwd)/swanctl/conf.d/arcana-to-host.conf"
	atf_check test ! -e swanctl/conf.d/arcana-to-host.conf
	# Its daemon started in it, by its own rc.d script.
	atf_check -o match:'fake-jexec 4 .*/fake-service strongswan onestart' \
	    "$JGC" -j gateway -c "$SOCK" ipsec start
}
vnet_cleanup()
{
	stop_daemon
}

atf_test_case notify cleanup
notify_head()
{
	atf_set "descr" "A Telegram message by a bot: posted as JSON to the Bot API, the token in no trace nor log"
	atf_set "timeout" "60"
}
notify_body()
{
	local port pid

	port=$((30000 + $$ % 20000))
	DAEMON_ARGS="--telegram-api http://127.0.0.1:$port"
	start_daemon
	# The Bot API as nc(1), with what it answers.
	printf 'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 11\r\nConnection: close\r\n\r\n{"ok":true}' > reply
	nc -N -l 127.0.0.1 "$port" < reply > req.txt &
	pid=$!
	sleep 0.5
	atf_check -o match:'Telegram sendMessage to chat -100' -o not-match:'abc_DEF' \
	    env ARCANA_TELEGRAM_TOKEN=123:abc_DEF "$JGC" -t -c "$SOCK" notify -100 'disk full on web'
	wait "$pid"
	atf_check -o match:'^POST /bot123:abc_DEF/sendMessage HTTP/1' \
	    -o match:'"chat_id":-100' -o match:'"text":"disk full on web"' cat req.txt
	# Refused by the Bot API: said, with what it most likely means.
	printf 'HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\nContent-Length: 59\r\nConnection: close\r\n\r\n{"ok":false,"error_code":400,"description":"chat not found"}' > reply
	nc -N -l 127.0.0.1 "$port" < reply > req.txt &
	pid=$!
	sleep 0.5
	atf_check -s exit:1 -e match:'no such chat, or the bot is not in it' -o ignore \
	    env ARCANA_TELEGRAM_TOKEN=123:abc_DEF "$JGC" -c "$SOCK" notify @no_such_chan hi
	wait "$pid"
	# Neither a token nor a chat that is not one is sent.
	atf_check -s exit:1 -e match:'as BotFather gives it' -o ignore \
	    env ARCANA_TELEGRAM_TOKEN='x y' "$JGC" -c "$SOCK" notify 5 hi
	atf_check -s exit:1 -e match:'a chat is a number' -o ignore \
	    env ARCANA_TELEGRAM_TOKEN=123:abc_DEF "$JGC" -c "$SOCK" notify 'x;y' hi
	atf_check -s exit:2 -e match:'ARCANA_TELEGRAM_TOKEN' "$JGC" -c "$SOCK" notify 5 hi
	if grep -q abc_DEF daemon.out; then
		atf_fail "the token is in the agent's log"
	fi
}
notify_cleanup()
{
	stop_daemon
}

atf_test_case safe_mode cleanup
safe_mode_head()
{
	atf_set "descr" "A safe change stays when confirmed, and is undone when not"
	atf_set "timeout" "60"
}
safe_mode_body()
{
	printf '#!/bin/sh\necho "$*" >> %s/ifconfig.log\n' "$(pwd)" > fake-ifconfig
	chmod +x fake-ifconfig
	start_daemon

	# A client that waits for the job is heard from again: it stays.
	atf_check -o match:'done' -o match:'safe mode' \
	    -o match:'confirmed: it stays' \
	    "$JGC" -s -c "$SOCK" interface lo0 add 10.9.0.6/24
	atf_check -o match:'^lo0 inet 10.9.0.6/24 alias$' \
	    -o not-match:'10.9.0.6 -alias' cat ifconfig.log

	# The client's rollback timer in place of the daemon's own -w.
	atf_check -o match:'the timer was 15 s' \
	    -o match:'confirmed: it stays' \
	    "$JGC" -t -s -W 15 -c "$SOCK" interface lo0 add 10.9.0.7/24
	atf_check -s exit:2 -e match:'too small' \
	    "$JGC" -s -W 5 -c "$SOCK" interface lo0 add 10.9.0.7/24

	# One that is not heard from again: each change is taken back.
	atf_check -o match:'queued' "$JGC" -q -s -c "$SOCK" interface lo0 add 10.9.0.8/24
	atf_check -o match:'queued' "$JGC" -q -s -c "$SOCK" interface lo0 down
	atf_check -o match:'queued' "$JGC" -q -s -c "$SOCK" interface lo0 remove 127.0.0.1
	atf_check -o match:'queued' "$JGC" -q -s -c "$SOCK" route add 10.77.0.0/16 10.0.0.1
	atf_check -o match:'queued' "$JGC" -q -s -c "$SOCK" route delete 10.78.0.0/16 10.0.0.1
	# While the first waits, it says so, and until when.
	sleep 1
	atf_check -o match:'unconfirmed' "$JGC" -c "$SOCK" jobs
	for i in $(seq 1 200); do
		"$JGC" -c "$SOCK" jobs | grep -q 'unconfirmed\|queued\|running' ||
		    break
		sleep 0.1
	done
	atf_check -s exit:1 -o match:'not confirmed within 2 s: undone' \
	    "$JGC" -c "$SOCK" job 3
	atf_check -o match:'^lo0 inet 10.9.0.8/24 alias$' \
	    -o match:'^lo0 inet 10.9.0.8 -alias$' \
	    -o match:'^lo0 down$' -o match:'^lo0 up$' \
	    -o match:'^lo0 inet 127.0.0.1 -alias$' \
	    -o match:'^lo0 inet 127.0.0.1/8 alias$' cat ifconfig.log
	atf_check -o match:'^0 route-add 10.77.0.0/16 10.0.0.1 - 0 0 0 -$' \
	    -o match:'^0 route-del 10.77.0.0/16 10.0.0.1 - 0 0$' \
	    -o match:'^0 route-del 10.78.0.0/16 10.0.0.1 - 0 0$' \
	    -o match:'^0 route-add 10.78.0.0/16 10.0.0.1 - 0 0 0 -$' cat route.log
	atf_check -o match:'not confirmed in time: undoing it' cat daemon.out

	# A route deleted without its gateway could not be put back.
	atf_check -s exit:1 -e match:'name its gateway' -o ignore \
	    "$JGC" -q -s -c "$SOCK" route delete 10.79.0.0/16

	# One cancelled while it waits to be confirmed is undone then, not
	# when its timer of a minute runs out.
	atf_check -o save:q.out "$JGC" -q -s -W 60 -c "$SOCK" interface lo0 \
	    add 10.9.0.9/24
	id=$(awk '/queued/ {print $1; exit}' q.out)
	for i in $(seq 1 100); do
		"$JGC" -c "$SOCK" jobs | grep -q "^ *$id unconfirmed" && break
		sleep 0.1
	done
	atf_check -o ignore "$JGC" -c "$SOCK" job-cancel "$id"
	for i in $(seq 1 100); do
		"$JGC" -c "$SOCK" jobs | grep -q "^ *$id \(unconfirmed\|running\)" ||
		    break
		sleep 0.1
	done
	[ $i -lt 100 ] || atf_fail "the cancelled change was not undone at once"
	atf_check -s exit:1 -o match:'cancelled by the client while it waited: undone now' \
	    "$JGC" -c "$SOCK" job "$id"
	atf_check -o match:'^lo0 inet 10.9.0.9 -alias$' cat ifconfig.log
	# One at work, or done, is not taken back, and says which.
	atf_check -s exit:1 -e match:'has finished' "$JGC" -c "$SOCK" job-cancel "$id"

	# The same for what else can be taken back: an interface made, a
	# service stopped, its variables, each put back as it was; and
	# what was kept in rc.conf with the change is forgotten with it.
	: > ifconfig.log
	touch running.sshd
	atf_check -o match:'queued' "$JGC" -q -s -p -c "$SOCK" interface gif4 \
	    create tunnel 192.0.2.1 192.0.2.2
	atf_check -o match:'queued' "$JGC" -q -s -c "$SOCK" service sshd stop
	atf_check -o match:'queued' "$JGC" -q -s -c "$SOCK" service sshd \
	    config sshd_flags=-6 sshd_extra=yes
	atf_check -o match:'queued' "$JGC" -q -s -p -c "$SOCK" interface lo0 \
	    add 10.9.0.30/24
	for i in $(seq 1 200); do
		"$JGC" -c "$SOCK" jobs | grep -q 'unconfirmed\|queued\|running' ||
		    break
		sleep 0.1
	done
	atf_check -o match:'^gif4 create$' -o match:'^gif4 destroy$' \
	    cat ifconfig.log
	atf_check -o not-match:'gif4' -o not-match:'sshd_extra' \
	    -o not-match:'10.9.0.30' -o match:'^sshd_flags="-4"$' cat rc.conf
	atf_check test -f running.sshd
	# What was so already is left so: an interface that was up is not
	# brought down for having been told to come up, a service that
	# ran is not stopped for having been started.
	: > ifconfig.log
	atf_check -o match:'queued' "$JGC" -q -s -c "$SOCK" interface lo0 up
	atf_check -o match:'queued' "$JGC" -q -s -c "$SOCK" interface lo0 \
	    add 127.0.0.1/8
	atf_check -o match:'queued' "$JGC" -q -s -c "$SOCK" service sshd start
	for i in $(seq 1 200); do
		"$JGC" -c "$SOCK" jobs | grep -q 'unconfirmed\|queued\|running' ||
		    break
		sleep 0.1
	done
	atf_check -o match:'^lo0 up$' -o not-match:'down' \
	    -o not-match:'127.0.0.1 -alias' cat ifconfig.log
	atf_check test -f running.sshd
	atf_check -o match:'it was so before, and is left so' \
	    "$JGC" -c "$SOCK" jobs
	# Addressing undone: as it was before the change (SLAAC by
	# rc.conf), not static.
	echo 'ifconfig_lo0_ipv6="inet6 accept_rtadv"' >> rc.conf
	atf_check -o match:'queued' "$JGC" -q -s -p -c "$SOCK" interface lo0 \
	    addressing dhcp
	for i in $(seq 1 200); do
		"$JGC" -c "$SOCK" jobs | grep -q 'unconfirmed\|queued\|running' ||
		    break
		sleep 0.1
	done
	atf_check -o match:'^ifconfig_lo0_ipv6="inet6 accept_rtadv"$' \
	    -o not-match:'DHCP' cat rc.conf
	atf_check -o match:'^lo0 inet6 accept_rtadv -ifdisabled$' cat ifconfig.log
	# And stays when confirmed.
	atf_check -o match:'confirmed: it stays' \
	    "$JGC" -s -c "$SOCK" service sshd config sshd_flags=-6
	atf_check -o match:'^sshd_flags="-6"$' cat rc.conf
	# What cannot be taken back is not taken in safe mode.
	atf_check -s exit:1 -e match:'cannot be undone' -o ignore \
	    "$JGC" -q -s -c "$SOCK" service sshd restart
	atf_check -s exit:1 -e match:'not in safe mode' -o ignore \
	    "$JGC" -q -s -c "$SOCK" interface gif4 destroy
	atf_check -s exit:1 -e match:'not in safe mode' -o ignore \
	    "$JGC" -q -s -c "$SOCK" ng shutdown em0:

	# A variable's name is given to sysrc(8), which evaluates it: one
	# that is more than a name never gets there, in a job or without;
	# nor does a value rc.conf would read as more than a value.
	: > sysrc.log
	atf_check -s exit:1 -e match:"name is letters, digits and _" -o ignore \
	    "$JGC" -q -s -c "$SOCK" service sshd config 'x:-$(id)=1'
	atf_check -s exit:1 -e match:"name is letters, digits and _" -o ignore \
	    "$JGC" -q -s -c "$SOCK" service sshd config -x '-a'
	atf_check -s exit:1 -e match:'rc.conf would read it as more' -o ignore \
	    "$JGC" -q -c "$SOCK" service sshd config 'sshd_flags=a"; id; "'
	atf_check -s exit:1 -e match:'is not a variable of sshd' -o ignore \
	    "$JGC" -c "$SOCK" service sshd config 'x:-$(id)=1'
	atf_check -s exit:1 -e match:'rc.conf would read it as more' -o ignore \
	    "$JGC" -c "$SOCK" service sshd config 'sshd_flags=$(id)'
	# One that is refused leaves the ones before it unwritten.
	atf_check -s exit:1 -e match:'is not a variable of sshd' -o ignore \
	    "$JGC" -c "$SOCK" service sshd config sshd_first=1 other_x=2
	atf_check -o not-match:'id' -o not-match:'sshd_first' cat rc.conf
	atf_check -o not-match:'id' -o not-match:'x:' cat sysrc.log

	# The queue has an end: jobs that wait hold memory.
	atf_check -o match:'queued' "$JGC" -q -s -c "$SOCK" interface lo0 down
	for i in $(seq 1 255); do
		"$JGC" -q -c "$SOCK" interface lo0 up > /dev/null ||
		    atf_fail "job $i was refused"
	done
	atf_check -s exit:1 -e match:'too many jobs wait already' -o ignore \
	    "$JGC" -q -c "$SOCK" interface lo0 up
	# Confirming what does not wait is refused.
}
safe_mode_cleanup()
{
	stop_daemon
}

atf_test_case agent_restart cleanup
agent_restart_head()
{
	atf_set "descr" "After an update the service really runs the new program"
	atf_set "timeout" "90"
}
agent_restart_body()
{
	programs
	write_conf
	write_rc
	write_net
	write_pkg
	SOCK="unix:$(pwd)/s.sock"
	# The installed program, and a newer build of it.
	cp "$JGD" installed
	cp "$JGD" newer
	printf x >> newer
	# service(8) for arcana_agent as rc.subr does it: stop the daemon
	# by its pid, wait for it to go, start the installed program.
	cat > run-agent <<EOS
#!/bin/sh
cd $(pwd)
./installed -F -l "$SOCK" -f "$(pwd)/etc/jail.conf" \\
    -D "$(pwd)/etc/jail.conf.d" -j "$(pwd)/fake-jail" \\
    -R "$(pwd)/rc.d" -s "$(pwd)/rc-service" >> daemon.out 2>&1 &
echo \$! > daemon.pid
EOS
	cat > rc-service <<EOS
#!/bin/sh
cd $(pwd)
[ "\$1 \$2" = "arcana_agent restart" ] || exit 2
pid=\$(cat daemon.pid)
kill "\$pid"
while kill -0 "\$pid" 2>/dev/null; do sleep 0.1; done
echo "stopped \$pid" >> restarts
exec ./run-agent
EOS
	chmod +x run-agent rc-service
	./run-agent
	for i in $(seq 1 100); do
		grep -q ready daemon.out 2>/dev/null && break
		sleep 0.05
	done
	old=$(sha256 -q installed)
	new=$(sha256 -q newer)
	atf_check -o match:"Build: +$old" "$JGC" -c "$SOCK" hello
	first=$(cat daemon.pid)

	atf_check -o match:'restarting' "$JGC" -c "$SOCK" agent-update -r newer
	atf_check cmp -s newer installed
	# The daemon that answers next is another process, the new build.
	for i in $(seq 1 300); do
		[ -f restarts ] && "$JGC" -c "$SOCK" hello 2>/dev/null |
		    grep -q "Build: *$new" && break
		sleep 0.1
	done
	atf_check -o match:"Build: +$new" "$JGC" -c "$SOCK" hello
	atf_check test "$(cat daemon.pid)" != "$first"
	atf_check -o match:"stopped $first" cat restarts

	# The daemon restarted through itself, as a job: it does not wait
	# for the service(8) that waits for it.
	mkdir -p rc.d
	printf '#!/bin/sh\n' > rc.d/arcana_agent
	chmod +x rc.d/arcana_agent
	second=$(cat daemon.pid)
	atf_check -o match:'queued' "$JGC" -q -c "$SOCK" service arcana_agent restart
	for i in $(seq 1 100); do
		[ "$(cat daemon.pid)" != "$second" ] &&
		    "$JGC" -c "$SOCK" hello > /dev/null 2>&1 && break
		sleep 0.1
	done
	[ "$(cat daemon.pid)" != "$second" ] ||
	    atf_fail "not restarted: $("$JGC" -t -c "$SOCK" job 1 2>&1)"
	atf_check -o match:"stopped $second" cat restarts
	atf_check -o match:'^Host:' "$JGC" -c "$SOCK" hello
}
agent_restart_cleanup()
{
	stop_daemon
}

atf_test_case traceroute cleanup
traceroute_head()
{
	atf_set "descr" "One round of traceroute, as JSON: each hop's address, time and loss"
}
traceroute_body()
{
	# traceroute(8) as it prints: the header on standard error, a
	# line a hop, a lost probe a star, what it noted after the time.
	cat > fake-traceroute <<'EOS'
#!/bin/sh
for a; do last=$a; done
echo "traceroute to $last ($last), 30 hops max, 40 byte packets" >&2
echo "$0 $*" >> "$(dirname $0)/traceroute.log"
echo " 1  10.0.0.1  0.312 ms"
echo " 2  *"
echo " 3  198.51.100.7  12.5 ms !H"
echo " 4  $last  20.125 ms"
EOS
	cp fake-traceroute fake-traceroute6
	chmod +x fake-traceroute fake-traceroute6
	start_daemon
	atf_check -o match:'"hops":\[\{"ttl":1,"address":"10.0.0.1","rtt":0\.312[0-9]*\},\{"ttl":2,"lost":true\},\{"ttl":3,"address":"198.51.100.7","rtt":12\.5[0-9]*,"note":"!H"\}' \
	    -o match:'"reached":true' "$JGC" -c "$SOCK" traceroute 192.0.2.9
	atf_check -o match:'fake-traceroute -n -q 1 -w 1 -m 30 192.0.2.9$' \
	    cat traceroute.log
	# IPv6 by traceroute6.
	atf_check -o match:'"family":"inet6"' -o match:'"reached":true' \
	    "$JGC" -c "$SOCK" traceroute 2001:db8::9
	atf_check -o match:'fake-traceroute6 -n -q 1 -w 1 -m 30 2001:db8::9$' \
	    cat traceroute.log
	atf_check -s exit:1 -e match:'address to trace' -o ignore \
	    "$JGC" -c "$SOCK" traceroute example.org
}
traceroute_cleanup()
{
	stop_daemon
}

atf_test_case sdwan cleanup
sdwan_head()
{
	atf_set "descr" "The tunnels to measure: set, kept for the next start, read back with their state; without root each says so"
}
sdwan_body()
{
	# ipfw(8) as a stand-in: what it was run with, and the file it was
	# given to read.
	cat > fake-ipfw <<EOS
#!/bin/sh
echo "ipfw \$*" >> $(pwd)/ipfw.log
[ "\$1" = -q ] && [ -f "\$2" ] && cat "\$2" >> $(pwd)/ipfw.log
[ "\$*" = "-S show" ] && printf '00012      2      168 set 30 deny log tcp from any to table(sw1_s0d4) 80,443\n00100      1        1 set 0 allow ip from any to any\n00999      5      500 set 30 count ip from any to any\n'
exit 0
EOS
	chmod +x fake-ipfw
	printf '#!/bin/sh\necho "kldload $*" >> %s/kldload.log\nexit 0\n' "$(pwd)" > fake-kldload
	chmod +x fake-kldload
	DAEMON_ARGS="-h $(pwd)/fake-ipfw -3 $(pwd)/fake-setfib -2 $(pwd)/tools --suricata-rules $(pwd)/rules"
	start_daemon
	atf_check -o match:'"targets":\[\]' -o match:'"probing":true' \
	    -o match:'"rules":\{"set":0,"rules":0,"tables":\[\],"objects":0,"counters":\[\]\}' \
	    -o match:'"steer":\[\],"steered":false' "$JGC" -c "$SOCK" sdwan
	# What is not a target list.
	atf_check -s exit:1 -e match:'JSON array' -o ignore \
	    "$JGC" -c "$SOCK" sdwan probes '{"id":"x"}'
	atf_check -s exit:1 -e match:'id and an address' -o ignore \
	    "$JGC" -c "$SOCK" sdwan probes '[{"id":"x"}]'
	atf_check -s exit:1 -e match:'is not an address' -o ignore \
	    "$JGC" -c "$SOCK" sdwan probes '[{"id":"x","address":"nowhere"}]'
	atf_check -s exit:1 -e match:'interval' -o ignore \
	    "$JGC" -c "$SOCK" sdwan probes '[{"id":"x","address":"127.0.0.1","interval":1}]'
	atf_check -s exit:1 -e match:'there twice' -o ignore \
	    "$JGC" -c "$SOCK" sdwan probes '[{"id":"x","address":"127.0.0.1"},{"id":"x","address":"::1"}]'
	# Two targets, with their settings and the defaults.
	atf_check -o empty "$JGC" -c "$SOCK" sdwan probes \
	    '[{"id":"acme/a-b","address":"100.64.0.1","fib":1,"interval":200,"dscp":46},{"id":"v6","address":"fd00::2","eval":500}]'
	atf_check -o save:sd.json "$JGC" -c "$SOCK" sdwan
	atf_check -o match:'"id":"acme/a-b","address":"100.64.0.1","family":"inet","fib":1,"state":"(error|unknown|up|down)"' \
	    -o match:'"interval":200,"size":64,"eval":1000,"dscp":46' \
	    -o match:'"id":"v6","address":"fd00::2","family":"inet6","fib":0' \
	    -o match:'"eval":500' cat sd.json
	if [ "$(id -u)" != 0 ]; then
		atf_check -o match:'"state":"error","error":"socket: [^"]*needs root' \
		    cat sd.json
	fi
	# Kept beside history.conf, and read again at the next start.
	f=$(find . -name sdwan-probes.json)
	atf_check -o match:'"id":"v6"' cat "$f"
	stop_daemon
	start_daemon
	atf_check -o match:'"id":"acme/a-b"' -o match:'"id":"v6"' \
	    "$JGC" -c "$SOCK" sdwan
	# All of them stopped.
	atf_check -o empty "$JGC" -c "$SOCK" sdwan probes '[]'
	atf_check -o match:'"targets":\[\]' "$JGC" -c "$SOCK" sdwan

	# The rules: what is not a ruleset; one applied, its set emptied
	# and filled while disabled, the tables made, the file loaded.
	atf_check -s exit:1 -e match:'2 to 31' -o ignore "$JGC" -c "$SOCK" sdwan rules \
	    '{"set":1,"tables":[],"rules":["10 allow ip from any to any"]}'
	atf_check -s exit:1 -e match:'no set of its own' -o ignore "$JGC" -c "$SOCK" sdwan rules \
	    '{"set":30,"tables":[],"rules":["10 allow ip from any to any set 0"]}'
	atf_check -s exit:1 -e match:'valtype' -o ignore "$JGC" -c "$SOCK" sdwan rules \
	    '{"set":30,"tables":[{"name":"t","valtype":"nat"}],"rules":[]}'
	atf_check -s exit:1 -e match:'no rules are applied' -o ignore "$JGC" -c "$SOCK" sdwan steer \
	    '{"entries":[{"table":"nowhere","prefix":"10.20.0.0/24","candidates":[{"id":"t1","via":"100.64.0.1"}]}]}'
	: > ipfw.log
	atf_check -o empty "$JGC" -c "$SOCK" sdwan rules \
	    '{"set":30,"tables":[{"name":"sw1_zone","valtype":"skipto","entries":[["10.1.0.0/16","12"],["0.0.0.0/0","13"]]},{"name":"sw1_z0p0_4","valtype":"ipv4"}],"rules":["10 skipto tablearg ip from table(sw1_zone) to any in recv lo1","12 fwd tablearg ip4 from any to table(sw1_z0p0_4)","12 deny ip from any to any","99 count ip from any to any"]}'
	atf_check -o match:'^ipfw -q set disable 30$' \
	    -o match:'^ipfw -q -f delete set 30$' \
	    -o match:'^table sw1_zone create type addr valtype skipto$' \
	    -o match:'^table sw1_zone atomic add 10.1.0.0/16 12 0.0.0.0/0 13$' \
	    -o match:'^table sw1_z0p0_4 create type addr valtype ipv4$' \
	    -o match:'^add 10 set 30 skipto tablearg ip from table\(sw1_zone\) to any in recv lo1$' \
	    -o match:'^add 12 set 30 deny ip from any to any$' \
	    -o match:'^ipfw -q set enable 30$' cat ipfw.log
	# Disabled, loaded, enabled: in that order.
	atf_check -o inline:'1\n' sh -c "grep -n 'set disable 30' ipfw.log | cut -d: -f1 | head -1"
	atf_check -o match:'"rules":\{"set":30,"rules":4,"tables":\["sw1_zone","sw1_z0p0_4"\],"objects":0,"counters":' \
	    "$JGC" -c "$SOCK" sdwan
	atf_check -s exit:1 -e match:'not one of the rules' -o ignore "$JGC" -c "$SOCK" sdwan steer \
	    '{"entries":[{"table":"nowhere","prefix":"10.20.0.0/24","candidates":[{"id":"t1","via":"100.64.0.1"}]}]}'
	# The steering: the first candidate not down goes in, beside the
	# table in use, and is swapped in.
	: > ipfw.log
	atf_check -o empty "$JGC" -c "$SOCK" sdwan steer \
	    '{"entries":[{"table":"sw1_z0p0_4","prefix":"10.20.0.0/24","candidates":[{"id":"t1","via":"100.64.0.1"},{"id":"t2","via":"100.64.0.3"}]},{"table":"sw1_z0p0_4","prefix":"10.30.0.0/24","candidates":[{"id":"t2","via":"100.64.0.3"}]}]}'
	atf_check -o match:'^ipfw -q table sw1_z0p0_4_alt create type addr valtype ipv4$' \
	    -o match:'^ipfw -q table sw1_z0p0_4_alt atomic add 10.20.0.0/24 100.64.0.1 10.30.0.0/24 100.64.0.3$' \
	    -o match:'^ipfw -q table sw1_z0p0_4 swap sw1_z0p0_4_alt$' cat ipfw.log
	atf_check -o match:'"steer":\[\{"table":"sw1_z0p0_4","prefix":"10.20.0.0/24","chosen":0,"candidates":\[\{"id":"t1","via":"100.64.0.1","state":"not probed"\}' \
	    -o match:'"steered":true' "$JGC" -c "$SOCK" sdwan
	# Kept, both, and applied again at the next start.
	: > ipfw.log
	stop_daemon
	start_daemon
	atf_check -o match:'^add 12 set 30 deny ip from any to any$' \
	    -o match:'^ipfw -q table sw1_z0p0_4 swap sw1_z0p0_4_alt$' cat ipfw.log
	# Objects: dummynet pipes and queues, nat instances, made before
	# the rules, their modules loaded, deleted with the rules, queues
	# before their pipes; nothing a shell would read.
	atf_check -s exit:1 -e match:'an object is' -o ignore "$JGC" -c "$SOCK" sdwan rules \
	    '{"set":30,"tables":[],"objects":["pipe 3000 config bw 1Mbit/s; reboot"],"rules":["10 allow ip from any to any"]}'
	atf_check -s exit:1 -e match:'an object is' -o ignore "$JGC" -c "$SOCK" sdwan rules \
	    '{"set":30,"tables":[],"objects":["table t create"],"rules":["10 allow ip from any to any"]}'
	: > ipfw.log
	: > kldload.log
	atf_check -o empty "$JGC" -c "$SOCK" sdwan rules \
	    '{"set":30,"tables":[{"name":"sw1_known","valtype":"legacy","entries":[["10.1.0.0/24","0"]]}],"objects":["pipe 3000 config bw 5000000bit/s","queue 3001 config pipe 3000 weight 75","nat 3001 config ip 198.51.100.1"],"rules":["11 nat 3001 ip4 from table(sw1_known) to not table(sw1_known) out xmit vtnet0","12 queue 3001 ip from any to any","99 count ip from any to any"]}'
	atf_check -o match:'^pipe 3000 config bw 5000000bit/s$' \
	    -o match:'^queue 3001 config pipe 3000 weight 75$' \
	    -o match:'^nat 3001 config ip 198.51.100.1$' \
	    -o match:'^table sw1_known create type addr$' \
	    -o match:'^add 12 set 30 queue 3001 ip from any to any$' cat ipfw.log
	atf_check -o inline:'yes\n' sh -c "test \$(grep -n '^pipe 3000' ipfw.log | cut -d: -f1 | head -1) -lt \$(grep -n '^add 12' ipfw.log | cut -d: -f1 | head -1) && echo yes"
	atf_check -o match:'dummynet' -o match:'ipfw_nat' cat kldload.log
	atf_check -o match:'"objects":3' "$JGC" -c "$SOCK" sdwan
	# Only a table's entries changed (a list fetched anew): the table
	# filled beside itself and swapped in; the rules not reloaded.
	: > ipfw.log
	atf_check -o empty "$JGC" -c "$SOCK" sdwan rules \
	    '{"set":30,"tables":[{"name":"sw1_known","valtype":"legacy","entries":[["10.1.0.0/24","0"],["10.2.0.0/24","0"]]}],"objects":["pipe 3000 config bw 5000000bit/s","queue 3001 config pipe 3000 weight 75","nat 3001 config ip 198.51.100.1"],"rules":["11 nat 3001 ip4 from table(sw1_known) to not table(sw1_known) out xmit vtnet0","12 queue 3001 ip from any to any","99 count ip from any to any"]}'
	atf_check -o match:'^ipfw -q table sw1_known_alt create type addr$' \
	    -o match:'^ipfw -q table sw1_known_alt atomic add 10.1.0.0/24 0 10.2.0.0/24 0$' \
	    -o match:'^ipfw -q table sw1_known swap sw1_known_alt$' \
	    -o not-match:'set disable 30' -o not-match:'^add 12 ' cat ipfw.log
	atf_check -o match:'"objects":3' "$JGC" -c "$SOCK" sdwan
	# BIRD instances: a bad list refused; one started in its table by
	# setfib once its file parses, told to read it again when running,
	# stopped when not named; listed with its protocols.
	cat > fake-bird <<EOS
#!/bin/sh
echo "bird \$*" >> $(pwd)/bird.log
grep -q BROKEN "\$3" && { echo "bird: \$3:1:1 syntax error" >&2; exit 1; }
exit 0
EOS
	cat > fake-birdc <<EOS
#!/bin/sh
echo "birdc \$*" >> $(pwd)/birdc.log
sock="\$2"; shift 2
[ -e "\$sock" ] || { echo "birdc: Unable to connect to server control socket (\$sock): No such file or directory" >&2; exit 1; }
case "\$*" in
'show status') printf 'BIRD 3.3.2 ready.\nBIRD 3.3.2\nDaemon is up and running\n' ;;
'show protocols') printf 'BIRD 3.3.2 ready.\nName       Proto      Table      State  Since         Info\ndevice1    Device     ---        up     21:00:00.000  \nuni_hq_0   BGP        ---        start  21:00:00.000  Active        Socket: Connection refused\n' ;;
'show bfd sessions') st=Up; [ -e $(pwd)/bfd.down ] && st=Down; printf 'BIRD 3.3.2 ready.\nbfd1:\nIP address                Interface  State      Since         Interval  Timeout\n100.64.0.1                gre100     %s         21:00:00.000    0.200    0.600\n' "\$st" ;;
configure) printf 'BIRD 3.3.2 ready.\nReading configuration from %s\nReconfigured\n' "\$sock" ;;
down) rm -f "\$sock" ;;
esac
exit 0
EOS
	cat > fake-setfib <<EOS
#!/bin/sh
echo "setfib \$*" >> $(pwd)/setfib.log
shift 2
case "\$1" in
# dnsmasq -C conf -x pid: started, says the pid file, this agent's pid.
*dnsmasq) "\$1" --hold "\$5" & ;;
# local-unbound -c conf: started, says the pid file named in the conf.
*local-unbound) p=\$(sed -n 's/.*pidfile: "\(.*\)"/\1/p' "\$3"); "\$1" --hold "\$p" & ;;
# squid -f conf: started, says the pid file named in the conf.
*squid) echo "squid \$*" >> $(pwd)/squid.log; p=\$(sed -n 's/^pid_filename //p' "\$3"); "\$1" --hold "\$p" & ;;
# c-icap -f conf: started, says the pid file named in the conf.
*c-icap) echo "c-icap \$*" >> $(pwd)/squid.log; p=\$(sed -n 's/^PidFile //p' "\$3"); "\$1" --hold "\$p" & ;;
# bird -c conf -s sock -P pid: started, says the socket.
*) shift 3; touch "\$2" ;;
esac
exit 0
EOS
	cat > fake-dnsmasq <<EOS
#!/bin/sh
[ "\$1" = --hold ] && { echo \$\$ > "\$2"; i=0; while [ \$i -lt 300 ]; do sleep 1; i=\$((i+1)); done; exit 0; }
echo "dnsmasq \$*" >> $(pwd)/dnsmasq.log
[ "\$1" = --test ] && { grep -q BROKEN "\$3" && { echo "dnsmasq: bad option at line 1 of \$3" >&2; exit 1; }; exit 0; }
exit 0
EOS
	cat > fake-local-unbound <<EOS
#!/bin/sh
[ "\$1" = --hold ] && { echo \$\$ > "\$2"; i=0; while [ \$i -lt 300 ]; do sleep 1; i=\$((i+1)); done; exit 0; }
echo "unbound \$*" >> $(pwd)/unbound.log
exit 0
EOS
	cat > fake-local-unbound-checkconf <<EOS
#!/bin/sh
echo "checkconf \$*" >> $(pwd)/unbound.log
grep -q BROKEN "\$1" && { echo "unbound-checkconf: error: syntax error" >&2; exit 1; }
exit 0
EOS
	# squid(8) and its certificate maker, in the tools directory (-2).
	mkdir -p tools
	cat > tools/squid <<EOS
#!/bin/sh
[ "\$1" = --hold ] && { echo \$\$ > "\$2"; i=0; while [ \$i -lt 300 ]; do sleep 1; i=\$((i+1)); done; exit 0; }
echo "squid \$*" >> $(pwd)/squid.log
[ "\$2" = parse ] && { grep -q BROKEN "\$4" && { echo "FATAL: Bungled \$4" >&2; exit 1; }; exit 0; }
exit 0
EOS
	cat > tools/security_file_certgen <<EOS
#!/bin/sh
echo "certgen \$*" >> $(pwd)/squid.log
mkdir -p "\$3"
EOS
	printf '#!/bin/sh\n[ "$1" = --hold ] && { echo $$ > "$2"; i=0; while [ $i -lt 300 ]; do sleep 1; i=$((i+1)); done; exit 0; }\nexit 0\n' > tools/c-icap
	# suricata: -T checks, and refuses BROKEN, and a ruleset whose rule
	# negates any as Suricata does; run, it writes an alert and a flow
	# to eve.json in its log directory, says its pid, and notes a USR2.
	# Suricata's command socket, as it answers: a version, then a
	# command a line; gone by itself after two minutes.
	cat > tools/scsrv.py <<'EOS'
import json, os, signal, socket, sys
signal.alarm(120)
p = sys.argv[1]
try:
    os.unlink(p)
except OSError:
    pass
s = socket.socket(socket.AF_UNIX)
s.bind(p)
s.listen(4)
r = {"uptime": {"message": 42, "return": "OK"},
     "memcap-list": {"message": [{"name": "flow", "value": "32mb"}], "return": "OK"},
     "ruleset-stats": {"message": [{"id": 0, "rules_loaded": 2, "rules_failed": 1, "rules_skipped": 0}], "return": "OK"},
     "ruleset-profile": {"message": "Unknown command", "return": "NOK"},
     "iface-stat": {"message": {"pkts": 7, "invalid-checksums": 0, "drop": 1, "bypassed": 0}, "return": "OK"}}
while True:
    c, _ = s.accept()
    f = c.makefile("rwb")
    for line in f:
        o = json.loads(line)
        a = {"return": "OK"} if "version" in o else dict(r.get(o.get("command"), {"message": "Unknown command", "return": "NOK"}))
        if o.get("command") == "iface-stat":
            a["message"] = dict(a["message"], iface=o["arguments"]["iface"])
        f.write((json.dumps(a) + "\n").encode())
        f.flush()
    c.close()
EOS
	cat > tools/suricata <<EOS
#!/bin/sh
# Started: the daemon, under its own name, its pid in the file given.
[ "\$1" = --hold ] && { echo \$\$ > "\$2"; trap "echo usr2 >> $(pwd)/suricata.log" USR2; i=0; while [ \$i -lt 300 ]; do sleep 1; i=\$((i+1)); done; exit 0; }
echo "suricata \$*" >> $(pwd)/suricata.log
# A capture replayed (-r, -l its directory): an alert of it.
[ "\$3" = -r ] && { printf '%s\\n' '{"timestamp":"2026-10-19T11:00:00.000000+0000","event_type":"alert","src_ip":"10.1.1.1","src_port":1,"dest_ip":"10.2.2.2","dest_port":2,"proto":"TCP","alert":{"action":"allowed","signature_id":2000009,"rev":1,"signature":"ET REPLAYED","category":"","severity":1}}' >> "\$6/eve.json"; exit 0; }
[ "\$1" = --build-info ] && { printf 'This is Suricata version 8.0.7 RELEASE\nFeatures: IPFW NETMAP HAVE_LUA RUST\n  IPFW support:                            yes\n  Netmap support:                          yes v14+\n  Hyperscan support:                       no\n  Profiling enabled:                       no\n  Profiling rules enabled:                 no\n  Plugin support (experimental):           yes\n'; exit 0; }
k=\$(sed -n 's/^  filename: \(.*\.sock\)\$/\1/p' "\$2" 2>/dev/null)
[ -n "\$k" ] && [ "\$1" != -T ] && /usr/local/bin/python3 $(pwd)/tools/scsrv.py "\$k" > /dev/null 2>&1 &
[ "\$1" = -T ] && { grep -q BROKEN "\$3" && { [ "\$5" = logging.outputs.0.console.enabled=yes ] && echo "E: detect: rule BROKEN at line 1" >&2; exit 1; }
r=\$(sed -n 's/^  - \(.*\/suricata.rules\)\$/\\1/p' "\$3")
[ -n "\$r" ] && grep -q NEGATED "\$r" && { echo "i: suricata: This is Suricata"; { echo "E: detect: Complete IP space negated. Rule address range is NIL."; echo "E: detect: error parsing signature \\"alert\\" from file \$r at line 1"; echo "E: suricata: Loading signatures failed."; } >&2; exit 1; }
exit 0; }
d=\$(sed -n 's/^default-log-dir: //p' "\$2")
printf '%s\\n' '{"timestamp":"2026-10-12T18:00:00.000000+0000","event_type":"flow","src_ip":"10.30.0.2"}' \\
    '{"timestamp":"2026-10-12T18:00:01.000000+0000","in_iface":"wg5","event_type":"alert","src_ip":"10.30.0.2","src_port":40000,"dest_ip":"10.20.0.1","dest_port":80,"proto":"TCP","alert":{"action":"allowed","signature_id":1000001,"rev":1,"signature":"ARCANA test \\"quoted\\"","category":"","severity":2}}' >> "\$d/eve.json"
# As Suricata does: a pid file there refuses the start, said in its log;
# FAILSTART in the configuration fails it.
[ -f "\$4" ] && { echo "[1 - Main] 2026-10-19 Error: pidfile: pid file '\$4' exists but appears stale" >> "\$d/suricata.log"; exit 1; }
grep -q FAILSTART "\$2" && { echo "[1 - Main] 2026-10-19 Error: suricata: this start fails" >> "\$d/suricata.log"; exit 1; }
"\$0" --hold "\$4" &
exit 0
EOS
	# suricata-update: the ruleset written where -o says, a rule
	# disabled as it ships; the sids of --enable-conf, --disable-conf
	# and --drop-conf turned on, off and to drop, as it does.
	cat > tools/suricata-update <<'EOS'
#!/bin/sh
echo "suricata-update $*" >> @LOG@
while [ $# -gt 0 ]; do
	case "$1" in
	-o) out=$2; shift ;;
	-D) data=$2; shift ;;
	update-sources)
		mkdir -p "$data/update/cache"; echo 'sources: {}' > "$data/update/cache/index.yaml"
		exit 0 ;;
	list-sources)
		printf '\033[1;36mName\033[0m: \033[1;35met/open\033[0m\n  \033[1;36mVendor\033[0m: \033[1;35mProofpoint\033[0m\n  \033[1;36mSummary\033[0m: \033[1;35mEmerging Threats Open Ruleset\033[0m\n  \033[1;36mLicense\033[0m: \033[1;35mMIT\033[0m\n'
		printf '\033[1;36mName\033[0m: \033[1;35met/pro\033[0m\n  \033[1;36mVendor\033[0m: \033[1;35mProofpoint\033[0m\n  \033[1;36mSummary\033[0m: \033[1;35mEmerging Threats Pro Ruleset\033[0m\n  \033[1;36mLicense\033[0m: \033[1;35mCommercial\033[0m\n  \033[1;36mParameters\033[0m: \033[1;35msecret-code\033[0m\n'
		exit 0 ;;
	--enable-conf) en=$2; shift ;;
	--disable-conf) dis=$2; shift ;;
	--drop-conf) drop=$2; shift ;;
	esac
	shift
done
mkdir -p "$out"
f=$out/suricata.rules
{
	echo '# Emerging Threats Open'
	echo 'alert tcp any any -> any 22 (msg:"ET"; sid:2000001;)'
	echo '# alert http any any -> any any (msg:"ET INFO curl \"UA\""; flow:established; classtype:policy-violation; sid:2000005; rev:2; metadata:signature_severity Minor, created_at 2020_01_01;)'
	echo 'alert dns any any -> any any (msg:"ET DNS query of a bad name"; classtype:bad-unknown; sid:2000006; rev:4;)'
} > "$f"
for s in $(grep -v '^#' "${en:-/dev/null}"); do
	sed -i '' "/sid:$s;/s/^# //" "$f"
done
for s in $(grep -v '^#' "${dis:-/dev/null}"); do
	sed -i '' "/sid:$s;/s/^alert/# alert/" "$f"
done
for s in $(grep -v '^#' "${drop:-/dev/null}"); do
	sed -i '' "/sid:$s;/s/alert /drop /" "$f"
done
EOS
	sed -i '' "s|@LOG@|$(pwd)/suricata-update.log|" tools/suricata-update
	chmod +x tools/squid tools/security_file_certgen tools/c-icap tools/suricata tools/suricata-update
	chmod +x fake-bird fake-birdc fake-setfib fake-dnsmasq fake-local-unbound fake-local-unbound-checkconf
	atf_check -s exit:1 -e match:'an instance is' -o ignore "$JGC" -c "$SOCK" sdwan bird \
	    '{"instances":[{"name":"../x","fib":1,"conf":"router id 1.1.1.1;"}]}'
	atf_check -s exit:1 -e match:'named twice' -o ignore "$JGC" -c "$SOCK" sdwan bird \
	    '{"instances":[{"name":"sw1","fib":1,"conf":"a"},{"name":"sw1","fib":2,"conf":"b"}]}'
	atf_check -s exit:1 -e match:'does not take it' -o ignore "$JGC" -c "$SOCK" sdwan bird \
	    '{"instances":[{"name":"sw1","fib":1,"conf":"BROKEN"}]}'
	atf_check -o empty "$JGC" -c "$SOCK" sdwan bird \
	    '{"instances":[{"name":"sw1","fib":1,"conf":"router id 100.64.0.0;\nprotocol device {}\n"}]}'
	atf_check -o match:'^setfib -F 1 .*fake-bird -c .*sdwan-bird-sw1.conf -s .*sdwan-bird-sw1.ctl -P .*sdwan-bird-sw1.pid$' cat setfib.log
	atf_check -o match:'^router id 100.64.0.0;$' cat "$(dirname "$f")/sdwan-bird-sw1.conf"
	atf_check -o match:'"bird":\[\{"name":"sw1","fib":1,"running":true,"protocols":\[\{"name":"device1","proto":"Device","state":"up"\},\{"name":"uni_hq_0","proto":"BGP","state":"start","info":"Active        Socket: Connection refused"\}\]' \
	    "$JGC" -c "$SOCK" sdwan
	# BFD: the sessions read every second into the sdwan read; a
	# session down is an event and the steering takes BFD's word over
	# the probe's where there is a session: the second candidate then.
	for i in $(seq 1 30); do
		"$JGC" -c "$SOCK" sdwan | grep -q '"bfd":\[{"address":"100.64.0.1","interface":"gre100","state":"up"' && break
		sleep 0.2
	done
	atf_check -o match:'"bfd":\[\{"address":"100.64.0.1","interface":"gre100","state":"up","since":"21:00:00.000"\}\]' \
	    "$JGC" -c "$SOCK" sdwan
	atf_check -o empty "$JGC" -c "$SOCK" sdwan steer \
	    '{"entries":[{"table":"sw1_known","prefix":"10.1.0.0/24","candidates":[{"id":"t1","via":"100.64.0.1"},{"id":"t2","via":"100.64.0.3"}]}]}'
	atf_check -o match:'"chosen":0,"candidates":\[\{"id":"t1","via":"100.64.0.1","state":"not probed","bfd":"up"\}' \
	    "$JGC" -c "$SOCK" sdwan
	touch bfd.down
	for i in $(seq 1 30); do
		"$JGC" -c "$SOCK" sdwan | grep -q '"chosen":1' && break
		sleep 0.2
	done
	atf_check -o match:'"chosen":1,"candidates":\[\{"id":"t1","via":"100.64.0.1","state":"not probed","bfd":"down"\}' \
	    "$JGC" -c "$SOCK" sdwan
	atf_check -o match:'"kind":"sdwan-tunnel","data":\{"id":"t1","address":"100.64.0.1","interface":"gre100","state":"down","by":"bfd"\}' \
	    -o match:'"kind":"sdwan-fault","data":\{"type":"bfd","severity":"Major","object":"t1","by":"bfd","description":"BFD to 100.64.0.1 on gre100 is down","state":"set"\}' \
	    "$JGC" -c "$SOCK" events
	# A fault of the day, open; cleared when BFD is up again.
	atf_check -o match:'"faults":\[[^]]*\{"t":[0-9]+,"type":"bfd","severity":"Major","was":"Major","object":"t1","by":"bfd","description":"BFD to 100.64.0.1 on gre100 is down","cleared":false\}' \
	    "$JGC" -c "$SOCK" sdwan
	test -f sdwan-faults.json || atf_fail "the faults are not kept"
	rm -f bfd.down
	for i in $(seq 1 30); do
		"$JGC" -c "$SOCK" sdwan | grep -q '"chosen":0' && break
		sleep 0.2
	done
	atf_check -o match:'"chosen":0' "$JGC" -c "$SOCK" sdwan
	atf_check -o match:'"type":"bfd","severity":"Cleared","was":"Major","object":"t1","by":"bfd","description":"BFD to 100.64.0.1 on gre100 is up","cleared":true,"cleared_at":[0-9]+' \
	    "$JGC" -c "$SOCK" sdwan
	atf_check -o empty "$JGC" -c "$SOCK" sdwan bird \
	    '{"instances":[{"name":"sw1","fib":1,"conf":"router id 100.64.0.0;\nprotocol device {}\nprotocol static {}\n"}]}'
	atf_check -o match:'configure$' cat birdc.log
	atf_check -o inline:'1\n' sh -c "grep -c '^setfib' setfib.log"
	atf_check -o empty "$JGC" -c "$SOCK" sdwan bird '{"instances":[]}'
	atf_check -o match:'down$' cat birdc.log
	test ! -f "$(dirname "$f")/sdwan-bird-sw1.conf" || atf_fail "the instance's file stayed"
	atf_check -o match:'"bird":\[\]' "$JGC" -c "$SOCK" sdwan
	# The counters of the set's rules, as ipfw -S show has them, in the
	# read: the console counts what a security policy denied by them.
	atf_check -o match:'"counters":\[\{"rule":12,"pkts":2,"bytes":168,"text":"deny log tcp from any to table\(sw1_s0d4\) 80,443"\},\{"rule":999,"pkts":5,"bytes":500,"text":"count ip from any to any"\}\]' \
	    "$JGC" -c "$SOCK" sdwan
	# No rules: the set emptied, the tables gone, the objects deleted.
	: > ipfw.log
	atf_check -o empty "$JGC" -c "$SOCK" sdwan rules '{"set":30,"tables":[],"rules":[]}'
	atf_check -o match:'^ipfw -q table sw1_known destroy$' \
	    -o match:'^ipfw -q nat 3001 delete$' \
	    -o match:'^ipfw -q queue 3001 delete$' \
	    -o match:'^ipfw -q pipe 3000 delete$' cat ipfw.log
	atf_check -o inline:'yes\n' sh -c "test \$(grep -n '^ipfw -q queue 3001 delete' ipfw.log | cut -d: -f1 | head -1) -lt \$(grep -n '^ipfw -q pipe 3000 delete' ipfw.log | cut -d: -f1 | head -1) && echo yes"
	atf_check -o match:'"rules":\{"set":0,' "$JGC" -c "$SOCK" sdwan
	# DHCP instances (dnsmasq): a bad list refused, one not taken by
	# dnsmasq --test not run; one started in its table with the pid and
	# lease files added to its file; listed with the leases it gave;
	# stopped when not named.
	atf_check -s exit:1 -e match:'does not take it' -o ignore "$JGC" -c "$SOCK" sdwan dhcp \
	    '{"instances":[{"name":"sw1","fib":1,"conf":"BROKEN"}]}'
	atf_check -o empty "$JGC" -c "$SOCK" sdwan dhcp \
	    '{"instances":[{"name":"sw1","fib":1,"conf":"port=0\ninterface=lo1\ndhcp-range=10.1.0.2,10.1.0.254,255.255.255.0,12h"}]}'
	atf_check -o match:'^setfib -F 1 .*fake-dnsmasq -C .*sdwan-dhcp-sw1.conf -x .*sdwan-dhcp-sw1.pid$' cat setfib.log
	atf_check -o match:'^dnsmasq --test -C .*sdwan-dhcp-sw1.conf$' cat dnsmasq.log
	atf_check -o match:'^interface=lo1$' -o match:'^pid-file=.*sdwan-dhcp-sw1.pid$' -o match:'^dhcp-leasefile=.*sdwan-dhcp-sw1.leases$' \
	    cat "$(dirname "$f")/sdwan-dhcp-sw1.conf"
	printf '1791716017 00:11:22:33:44:55 10.1.0.50 host1 01:00:11:22:33:44:55\nduid 00:01:00:01\n1791716099 123456 2001:db8:1::100 host2 00:01:00:01:aa\n' \
	    > "$(dirname "$f")/sdwan-dhcp-sw1.leases"
	atf_check -o match:'"dhcp":\[\{"name":"sw1","fib":1,"running":true,"leases":\[\{"expires":1791716017,"id":"00:11:22:33:44:55","address":"10.1.0.50","name":"host1"\},\{"expires":1791716099,"id":"123456","address":"2001:db8:1::100","name":"host2"\}\]\}\]' \
	    "$JGC" -c "$SOCK" sdwan
	atf_check -o empty "$JGC" -c "$SOCK" sdwan dhcp '{"instances":[]}'
	test ! -f "$(dirname "$f")/sdwan-dhcp-sw1.conf" || atf_fail "the dhcp instance's file stayed"
	atf_check -o match:'"dhcp":\[\]' "$JGC" -c "$SOCK" sdwan
	# DNS filters (the base system's unbound): one not taken by
	# local-unbound-checkconf not run; one started in its table with
	# the pid file and the run as root added to its file; listed;
	# stopped when not named.
	atf_check -s exit:1 -e match:'does not take it' -o ignore "$JGC" -c "$SOCK" sdwan dns \
	    '{"instances":[{"name":"sw1","fib":1,"conf":"BROKEN"}]}'
	atf_check -o empty "$JGC" -c "$SOCK" sdwan dns \
	    '{"instances":[{"name":"sw1","fib":1,"conf":"server:\n\tinterface: 10.1.0.1\n\tlocal-zone: \"ads.example.\" always_nxdomain\n"}]}'
	atf_check -o match:'^setfib -F 1 .*fake-local-unbound -c .*sdwan-dns-sw1.conf$' cat setfib.log
	atf_check -o match:'^checkconf .*sdwan-dns-sw1.conf$' cat unbound.log
	atf_check -o match:'^	interface: 10.1.0.1$' -o match:'^	pidfile: ".*sdwan-dns-sw1.pid"$' -o match:'^	username: ""$' \
	    cat "$(dirname "$f")/sdwan-dns-sw1.conf"
	atf_check -o match:'"dns":\[\{"name":"sw1","fib":1,"running":true\}\]' "$JGC" -c "$SOCK" sdwan
	atf_check -o empty "$JGC" -c "$SOCK" sdwan dns '{"instances":[]}'
	test ! -f "$(dirname "$f")/sdwan-dns-sw1.conf" || atf_fail "the dns instance's file stayed"
	atf_check -o match:'"dns":\[\]' "$JGC" -c "$SOCK" sdwan
	# The proxies (Squid, a plugin): one not taken by squid -k parse not
	# run; one started in its table, its places filled, its CA made by
	# openssl once and told; the certificate cache made for inspect;
	# a running one reconfigured; stopped when not named.
	atf_check -s exit:1 -e match:'does not take it' -o ignore "$JGC" -c "$SOCK" sdwan proxy \
	    '{"instances":[{"name":"sw1","fib":1,"mode":"sni","conf":"BROKEN","deny":""}]}'
	atf_check -o empty "$JGC" -c "$SOCK" sdwan proxy \
	    '{"instances":[{"name":"sw1","fib":1,"mode":"sni","conf":"pid_filename @PID@\nhttps_port 10.1.0.1:3129 intercept ssl-bump tls-cert=@CA@\nacl denied_site ssl::server_name \"@DENY@\"\n","deny":".bad.example\n"}]}'
	atf_check -o match:'^setfib -F 1 .*tools/squid -f .*sdwan-proxy-sw1.conf$' cat setfib.log
	atf_check -o match:'^squid -k parse -f .*sdwan-proxy-sw1.conf$' cat squid.log
	atf_check -o match:'^pid_filename .*sdwan-proxy-sw1.pid$' -o match:'tls-cert=.*sdwan-proxy-sw1.pem$' -o match:'ssl::server_name ".*sdwan-proxy-sw1.deny"$' \
	    cat "$(dirname "$f")/sdwan-proxy-sw1.conf"
	atf_check -o match:'^\.bad\.example$' cat "$(dirname "$f")/sdwan-proxy-sw1.deny"
	atf_check -o match:'BEGIN CERTIFICATE' -o match:'BEGIN PRIVATE KEY' cat "$(dirname "$f")/sdwan-proxy-sw1.pem"
	atf_check -o match:'"proxy":\[\{"name":"sw1","fib":1,"mode":"sni","running":true,"ca":"-----BEGIN CERTIFICATE-----' "$JGC" -c "$SOCK" sdwan
	cp "$(dirname "$f")/sdwan-proxy-sw1.crt" ca.was
	atf_check -o empty "$JGC" -c "$SOCK" sdwan proxy \
	    '{"instances":[{"name":"sw1","fib":1,"mode":"inspect","conf":"pid_filename @PID@\nsslcrtd_program @CERTGEN@ -s @SSLDB@ -M 4MB\n","deny":""}]}'
	atf_check -o match:'^squid -k reconfigure -f .*sdwan-proxy-sw1.conf$' -o match:'^certgen -c -s .*sdwan-proxy-sw1.ssl_db -M 4MB$' cat squid.log
	atf_check -o match:'^sslcrtd_program .*tools/security_file_certgen -s .*sdwan-proxy-sw1.ssl_db -M 4MB$' cat "$(dirname "$f")/sdwan-proxy-sw1.conf"
	atf_check cmp -s ca.was "$(dirname "$f")/sdwan-proxy-sw1.crt"
	# Malware scanned: c-icap of the instance's own, started first in its
	# table, its pid file and command socket placed, told in the read;
	# gone with the instance.
	atf_check -o empty "$JGC" -c "$SOCK" sdwan proxy \
	    '{"instances":[{"name":"sw1","fib":1,"mode":"sni","conf":"pid_filename @PID@\nicap_enable on\n","deny":"","icap":"PidFile @ICAPPID@\nCommandsSocket @ICAPCMD@\nPort 127.0.0.1:1354\n"}]}'
	atf_check -o match:'^setfib -F 1 .*tools/c-icap -f .*sdwan-icap-sw1.conf$' cat setfib.log
	atf_check -o match:'^PidFile .*sdwan-icap-sw1.pid$' -o match:'^CommandsSocket .*sdwan-icap-sw1.ctl$' \
	    cat "$(dirname "$f")/sdwan-icap-sw1.conf"
	atf_check -o match:'"proxy":\[\{"name":"sw1","fib":1,"mode":"sni","running":true,"icap":true' "$JGC" -c "$SOCK" sdwan
	ipid=$(cat "$(dirname "$f")/sdwan-icap-sw1.pid")
	atf_check -o empty "$JGC" -c "$SOCK" sdwan proxy '{"instances":[]}'
	test ! -f "$(dirname "$f")/sdwan-proxy-sw1.conf" || atf_fail "the proxy instance's file stayed"
	test ! -f "$(dirname "$f")/sdwan-icap-sw1.conf" || atf_fail "the c-icap file stayed"
	kill -0 "$ipid" 2>/dev/null && atf_fail "c-icap still runs"
	atf_check -o match:'"proxy":\[\]' "$JGC" -c "$SOCK" sdwan
	# The Security section's own (group security, named sec-): kept
	# apart, neither list stopping the other's; its forms told back.
	atf_check -o empty "$JGC" -c "$SOCK" sdwan proxy \
	    '{"instances":[{"name":"sw1","fib":1,"mode":"sni","conf":"pid_filename @PID@\n","deny":""}]}'
	atf_check -s exit:1 -e match:'named sec-' -o ignore "$JGC" -c "$SOCK" sdwan proxy \
	    '{"group":"security","instances":[{"name":"web","fib":0,"mode":"sni","conf":"pid_filename @PID@\n","deny":""}]}'
	atf_check -s exit:1 -e match:'named sec-' -o ignore "$JGC" -c "$SOCK" sdwan proxy \
	    '{"instances":[{"name":"sec-web","fib":0,"mode":"sni","conf":"pid_filename @PID@\n","deny":""}]}'
	atf_check -o empty "$JGC" -c "$SOCK" sdwan proxy \
	    '{"group":"security","instances":[{"name":"sec-web","fib":0,"mode":"sni","conf":"pid_filename @PID@\n","deny":"","spec":{"name":"sec-web","listen":["10.1.0.1"]}}]}'
	atf_check -o match:'"name":"sw1",[^]]*"group":"sdwan"' -o match:'"name":"sec-web",[^]]*"group":"security"' \
	    -o match:'"security_proxy":\[\{"name":"sec-web","listen":\["10.1.0.1"\]\}\]' "$JGC" -c "$SOCK" sdwan
	atf_check -o empty "$JGC" -c "$SOCK" sdwan proxy '{"instances":[]}'
	atf_check -o match:'"proxy":\[\{"name":"sec-web"' "$JGC" -c "$SOCK" sdwan
	atf_check -o empty "$JGC" -c "$SOCK" sdwan proxy '{"group":"security","instances":[]}'
	atf_check -o match:'"proxy":\[\]' -o match:'"security_proxy":\[\]' "$JGC" -c "$SOCK" sdwan
	# Intrusion detection (SASE-4): Suricata of each instance checked,
	# started on its interfaces, its alerts read into events and the
	# read; the same files again leave it be; gone with the instance.
	atf_check -s exit:1 -e match:'watches no interface' -o ignore "$JGC" -c "$SOCK" sdwan ids \
	    '{"instances":[{"name":"sw1","interfaces":[],"conf":"x"}]}'
	atf_check -s exit:1 -e match:'its interfaces are names' -o ignore "$JGC" -c "$SOCK" sdwan ids \
	    '{"instances":[{"name":"sw1","interfaces":["wg5; rm"],"conf":"x"}]}'
	# Its reason, which Suricata says only where it logs: on the console
	# for the check.
	atf_check -s exit:1 -e match:'suricata does not take it: E: detect: rule BROKEN at line 1' -o ignore "$JGC" -c "$SOCK" sdwan ids \
	    '{"instances":[{"name":"sw1","interfaces":["wg5"],"conf":"BROKEN"}]}'
	ids='{"instances":[{"name":"sw1","interfaces":["wg5"],"conf":"default-log-dir: @LOGDIR@\nrule-files:\n  - @RULES@\nclassification-file: @CLASSIFICATION@\nreference-config-file: @REFERENCE@\n","rules":"alert tcp any any -> any 80 (sid:1000001;)\n"}]}'
	atf_check -o empty "$JGC" -c "$SOCK" sdwan ids "$ids"
	atf_check -o match:'^suricata -T -c .*sdwan-ids-sw1.yaml --set logging.outputs.0.console.enabled=yes$' \
	    -o match:'^suricata -c .*sdwan-ids-sw1.yaml --pidfile .*sdwan-ids-sw1.pid --pcap -D$' cat suricata.log
	atf_check -o match:'^default-log-dir: .*sdwan-ids-sw1.d$' -o match:'^  - .*sdwan-ids-sw1.rules$' \
	    -o match:'^classification-file: /usr/local/etc/suricata/classification.config' \
	    -o match:'^reference-config-file: /usr/local/etc/suricata/reference.config' \
	    cat "$(dirname "$f")/sdwan-ids-sw1.yaml"
	atf_check -o match:'sid:1000001' cat "$(dirname "$f")/sdwan-ids-sw1.rules"
	sleep 2
	atf_check -o match:'"ids":\[\{"name":"sw1","interfaces":\["wg5"\],"mode":"detect","running":true,"alerts_seen":1,"alerts":\[\{"name":"sw1","time":"2026-10-12T18:00:01' \
	    -o match:'"signature":"ARCANA test quoted","category":"","severity":2' "$JGC" -c "$SOCK" sdwan
	atf_check -o match:'"kind":"sdwan-ids","data":\{"name":"sw1",.*"src":"10.30.0.2","sport":40000,"dst":"10.20.0.1","dport":80,"proto":"TCP","iface":"wg5","sid":1000001' \
	    "$JGC" -c "$SOCK" events
	spid=$(cat "$(dirname "$f")/sdwan-ids-sw1.pid")
	atf_check -o match:'suricata sw1 on 1 interface, detects: as it was' "$JGC" -t -c "$SOCK" sdwan ids "$ids"
	atf_check -o inline:"$spid\n" cat "$(dirname "$f")/sdwan-ids-sw1.pid"
	# One that prevents: run on its divert port; not running, a
	# Critical fault (what it guards passes nothing), cleared once it
	# runs again.
	atf_check -s exit:1 -e match:'its divert is a port' -o ignore "$JGC" -c "$SOCK" sdwan ids \
	    '{"instances":[{"name":"sw1","interfaces":["wg5"],"conf":"x","divert":70000}]}'
	ipsd=$(echo "$ids" | sed 's/"name":"sw1",/"name":"sw1","divert":8001,/')
	atf_check -o match:'suricata sw1 on 1 interface, prevents by divert 8001: started' \
	    "$JGC" -t -c "$SOCK" sdwan ids "$ipsd"
	atf_check -o match:'^suricata -c .*sdwan-ids-sw1.yaml --pidfile .*sdwan-ids-sw1.pid -d 8001 -D$' cat suricata.log
	atf_check -o match:'"ids":\[\{"name":"sw1","interfaces":\["wg5"\],"mode":"prevent","divert":8001,"running":true' \
	    "$JGC" -c "$SOCK" sdwan
	kill "$(cat "$(dirname "$f")/sdwan-ids-sw1.pid")"
	sleep 2
	atf_check -o match:'"kind":"sdwan-fault","data":\{"type":"ids","severity":"Critical","object":"sw1","by":"suricata","description":"Suricata sw1, which prevents, is not running' \
	    "$JGC" -c "$SOCK" events
	atf_check -o empty "$JGC" -c "$SOCK" sdwan ids "$ipsd"
	sleep 2
	atf_check -o match:'"kind":"sdwan-fault","data":\{"type":"ids","severity":"Cleared","object":"sw1","description":"Suricata sw1 runs again"' \
	    "$JGC" -c "$SOCK" events
	atf_check -o empty "$JGC" -c "$SOCK" sdwan ids '{"instances":[]}'
	test ! -f "$(dirname "$f")/sdwan-ids-sw1.yaml" || atf_fail "the suricata file stayed"
	kill -0 "$spid" 2>/dev/null && atf_fail "suricata still runs"
	atf_check -o match:'"ids":\[\]' "$JGC" -c "$SOCK" sdwan
	# Made again, its old alerts are not told again: the one it writes
	# now is.
	atf_check -o empty "$JGC" -c "$SOCK" sdwan ids "$ids"
	sleep 2
	atf_check -o match:'"alerts_seen":1,' "$JGC" -c "$SOCK" sdwan
	atf_check -o inline:'4\n' sh -c "grep -c '\"event_type\":\"alert\"' '$(dirname "$f")/sdwan-ids-sw1.d/eve.json'"
	# Its statistics: each stats record of eve.json a point, Suricata's
	# totals, its flows by protocol the latest's; a stats record is no
	# alert.
	for st in '"timestamp":"2026-10-19T10:00:00.000000+0000","event_type":"stats","stats":{"uptime":10,"capture":{"kernel_packets":1000,"kernel_drops":5},"decoder":{"pkts":995,"bytes":600000,"invalid":2},"detect":{"alert":3},"tcp":{"sessions":40,"memuse":1000,"reassembly_memuse":2000},"flow":{"total":60,"memuse":4000},"app_layer":{"flow":{"http":7,"tls":11}}}' \
	    '"timestamp":"2026-10-19T10:00:10.000000+0000","event_type":"stats","stats":{"uptime":20,"capture":{"kernel_packets":3000,"kernel_drops":5},"decoder":{"pkts":2995,"bytes":1800000,"invalid":2},"detect":{"alert":4},"tcp":{"sessions":90,"memuse":1000,"reassembly_memuse":2000},"flow":{"total":130,"memuse":4000},"app_layer":{"flow":{"http":9,"tls":20,"dns_udp":4}}}'; do
		echo "{$st}" >> "$(dirname "$f")/sdwan-ids-sw1.d/eve.json"
	done
	sleep 2
	atf_check -o match:'"alerts_seen":1,' \
	    -o match:'"stats":\{"fields":\["t","uptime","packets","drops","bytes","alerts","invalid","sessions","flows","memuse"\],"series":\[\[1792404000,10,1000,5,600000,3,2,40,60,7000\],\[1792404010,20,3000,5,1800000,4,2,90,130,7000\]\],"flows":\{"http":9,"tls":20,"dns_udp":4\}\}' \
	    "$JGC" -c "$SOCK" sdwan
	# The Security section's Suricata beside SD-WAN's: each list its
	# own, what was read of the other's kept.
	atf_check -o empty "$JGC" -c "$SOCK" sdwan ids \
	    '{"group":"security","instances":[{"name":"sec-lan","interfaces":["wg5"],"conf":"default-log-dir: @LOGDIR@\nrule-files:\n  - @RULES@\n","spec":{"name":"sec-lan"}}]}'
	atf_check -o match:'"ids":\[\{"name":"sw1",.*"alerts_seen":1,.*\{"name":"sec-lan",' \
	    -o match:'"security_ids":\[\{"name":"sec-lan"\}\]' "$JGC" -c "$SOCK" sdwan
	atf_check -o empty "$JGC" -c "$SOCK" sdwan ids '{"instances":[]}'
	atf_check -o match:'"ids":\[\{"name":"sec-lan"' "$JGC" -c "$SOCK" sdwan
	atf_check -o empty "$JGC" -c "$SOCK" sdwan ids '{"group":"security","instances":[]}'
	atf_check -o match:'"ids":\[\]' "$JGC" -c "$SOCK" sdwan
	# The ruleset suricata-update keeps: not fetched yet, its line is
	# left out and the instance runs on its own rules, saying so.
	rs='{"instances":[{"name":"sw1","interfaces":["wg5"],"conf":"default-log-dir: @LOGDIR@\nrule-files:\n  - @RULES@\n  - @RULESET@\n","rules":"alert tcp any any -> any 80 (sid:1000001;)\n"}]}'
	atf_check -o match:'suricata sw1 on 1 interface, detects: started.*the ruleset is not fetched yet' \
	    "$JGC" -t -c "$SOCK" sdwan ids "$rs"
	atf_check -o not-match:'suricata.rules' cat "$(dirname "$f")/sdwan-ids-sw1.yaml"
	atf_check -o not-match:'ids_ruleset' "$JGC" -c "$SOCK" sdwan
	# Fetched by the suricata job: the instance applied again takes it,
	# and is told to read its rules again; the read says when.
	atf_check -o match:'done' "$JGC" -c "$SOCK" suricata update
	atf_check -o match:"^suricata-update --no-test --no-reload --suricata .*/tools/suricata -o $(pwd)/rules -D $(pwd) --enable-conf .*/suricata-enable.conf --disable-conf .*/suricata-disable.conf --drop-conf .*/suricata-drop.conf\$" \
	    cat suricata-update.log
	# The ruleset's rules, a page at a time: one disabled as it ships
	# is a line commented out; a comment is no rule.
	atf_check -o match:'"total":3,"enabled":2,"matched":3' \
	    -o match:'\{"sid":2000005,"gid":1,"rev":2,"action":"alert","msg":"ET INFO curl \\"UA\\"","classtype":"policy-violation","severity":"Minor","enabled":false,"rule":"alert http' \
	    "$JGC" -c "$SOCK" suricata rules
	atf_check -o match:'"matched":1,.*"sid":2000006,' -o not-match:'"sid":2000001,' \
	    "$JGC" -c "$SOCK" suricata rules q=bad\ NAME
	atf_check -o match:'"matched":1,.*"sid":2000005,' "$JGC" -c "$SOCK" suricata rules only=disabled
	atf_check -o match:'"matched":1,.*"sid":2000005,' "$JGC" -c "$SOCK" suricata rules classtype=policy-violation
	atf_check -o match:'"matched":3,"offset":1,"limit":1,"rules":\[\{"sid":2000005,[^]]*\]\}' \
	    "$JGC" -c "$SOCK" suricata rules offset=1 limit=1
	atf_check -s exit:1 -e match:'only is enabled, disabled or changed' "$JGC" -c "$SOCK" suricata rules only=x
	atf_check -s exit:1 -e match:'searched by q=' "$JGC" -c "$SOCK" suricata rules color=red
	# Set by sid, as jobs: kept, given to suricata-update from what was
	# fetched (--offline), and holding when the ruleset is fetched again.
	atf_check -s exit:1 -e match:'sid is a number' "$JGC" -c "$SOCK" suricata rule on=abc
	atf_check -s exit:1 -e match:'on=, off=, drop= or default=' "$JGC" -c "$SOCK" suricata rule up=1
	atf_check -o match:'done +suricata rules set: on=2000005 \.\.\.' \
	    "$JGC" -c "$SOCK" suricata rule on=2000005 off=2000001 drop=2000006
	atf_check -o match:' --offline$' tail -1 suricata-update.log
	atf_check -o match:'"total":3,"enabled":2,"matched":3' \
	    -o match:'"sid":2000001,[^}]*"enabled":false,"state":"off"' \
	    -o match:'"sid":2000005,[^}]*"enabled":true,"state":"on"' \
	    -o match:'"sid":2000006,[^}]*"action":"drop",[^}]*"enabled":true,"state":"drop"' \
	    "$JGC" -c "$SOCK" suricata rules
	atf_check -o match:'"changed":3,.*"matched":3' "$JGC" -c "$SOCK" suricata rules only=changed
	atf_check -o match:'done' "$JGC" -c "$SOCK" suricata update
	atf_check -o not-match:'offline' tail -1 suricata-update.log
	atf_check -o match:'"sid":2000001,[^}]*"enabled":false,"state":"off"' "$JGC" -c "$SOCK" suricata rules sid=2000001
	atf_check -o match:'done' "$JGC" -c "$SOCK" suricata rule default=2000001,2000005,2000006
	atf_check -o match:'"changed":0,.*"total":3,"enabled":2' "$JGC" -c "$SOCK" suricata rules
	# Rule sources: none known until the index is fetched, Emerging
	# Threats Open the default; then the index's, each enabled or not
	# by a file of the data directory's that the agent writes, a
	# secret code in it alone, root's.
	atf_check -o match:'"index":false,"sources":\[\],"default_et_open":true' \
	    "$JGC" -c "$SOCK" suricata rules sources=1
	atf_check -o match:'done +suricata-update: the index of rule sources fetched' \
	    "$JGC" -c "$SOCK" suricata sources
	atf_check -o match:'"index":true,"sources":\[\{"name":"et/open","vendor":"Proofpoint","summary":"Emerging Threats Open Ruleset","license":"MIT"\},\{"name":"et/pro",[^}]*"parameters":"secret-code"\}\],"default_et_open":true' \
	    "$JGC" -c "$SOCK" suricata rules sources=1
	atf_check -o match:'done +suricata enable et/pro' -o not-match:'S3CRET' \
	    -e not-match:'S3CRET' \
	    "$JGC" -t -c "$SOCK" suricata source-enable name=et/pro secret-code=S3CRET
	atf_check -o inline:"source: 'et/pro'\nparams:\n  secret-code: 'S3CRET'\n" cat update/sources/et-pro.yaml
	atf_check -o match:'^-rw-------' ls -l update/sources/et-pro.yaml
	atf_check -o not-match:'S3CRET' "$JGC" -c "$SOCK" jobs
	atf_check -o match:'"name":"et/pro",[^}]*"state":"enabled"\}.*"default_et_open":false' \
	    "$JGC" -c "$SOCK" suricata rules sources=1
	atf_check -o match:'done' "$JGC" -c "$SOCK" suricata source-disable name=et/pro
	test -f update/sources/et-pro.yaml.disabled || atf_fail "et/pro is not kept disabled"
	atf_check -o match:'"state":"disabled".*"default_et_open":true' "$JGC" -c "$SOCK" suricata rules sources=1
	atf_check -o match:'done' "$JGC" -c "$SOCK" suricata source-enable name=et/pro
	atf_check -o match:'S3CRET' cat update/sources/et-pro.yaml
	atf_check -o match:'done' "$JGC" -c "$SOCK" suricata source-add name=lab/local url=https://rules.example.org/local.rules
	atf_check -o match:'\{"name":"lab/local","url":"https://rules.example.org/local.rules","state":"enabled"\}' \
	    "$JGC" -c "$SOCK" suricata rules sources=1
	atf_check -o match:'done' "$JGC" -c "$SOCK" suricata source-remove name=lab/local
	test ! -f update/sources/lab-local.yaml || atf_fail "lab/local stayed"
	atf_check -s exit:1 -e match:"a source's name is" "$JGC" -c "$SOCK" suricata source-enable name=../x
	atf_check -s exit:1 -e match:"are source-enable's" "$JGC" -c "$SOCK" suricata source-disable name=et/pro secret-code=x
	atf_check -s exit:1 -e match:'needs its url=' "$JGC" -c "$SOCK" suricata source-add name=x
	atf_check -s exit:1 -o match:'failed.*is not enabled' "$JGC" -c "$SOCK" suricata source-disable name=oisf/trafficid
	atf_check -o match:"^  - $(pwd)/rules/suricata.rules\$" cat "$(dirname "$f")/sdwan-ids-sw1.yaml"
	atf_check -o match:'"ids_ruleset":\{"path":"[^"]*/rules/suricata.rules","at":[0-9]+,"size":[0-9]+\}' \
	    "$JGC" -c "$SOCK" sdwan
	sleep 2
	atf_check -o match:'^usr2$' cat suricata.log
	# A rule of the ruleset that negates a HOME_NET of any is left out,
	# as Suricata does running; one of the instance's own is refused.
	echo 'alert tcp !$HOME_NET any -> any 25 (msg:"NEGATED"; sid:2000002;)' > rules/suricata.rules
	rs2=$(echo "$rs" | sed 's/sid:1000001;/sid:1000002;/')
	atf_check -o match:'1 rule of the ruleset left out, as Suricata does when it runs: detect: Complete IP space negated' \
	    "$JGC" -t -c "$SOCK" sdwan ids "$rs2"
	# Interface any: FreeBSD's libpcap has none, so each interface up
	# but the loopback, pflog, pfsync and enc.
	rs3='{"instances":[{"name":"sw1","interfaces":["any"],"conf":"default-log-dir: @LOGDIR@\npcap:\n  - interface: any\nrule-files:\n  - @RULES@\n","rules":"alert tcp any any -> any 80 (sid:1000001;)\n"}]}'
	atf_check -o empty "$JGC" -c "$SOCK" sdwan ids "$rs3"
	atf_check -o not-match:'interface: any' -o not-match:'interface: lo[0-9]' \
	    -o match:'^  - interface: [a-z]+[0-9]+$' cat "$(dirname "$f")/sdwan-ids-sw1.yaml"
	# A pid file left by a start that failed or a crash: taken away, the
	# instance started; and why a start fails is what that start
	# logged, not an older error of the log.
	kill "$(cat "$(dirname "$f")/sdwan-ids-sw1.pid")"
	sleep 1
	echo 99999 > "$(dirname "$f")/sdwan-ids-sw1.pid"
	rs4=$(echo "$rs3" | sed 's/sid:1000001;/sid:1000004;/')
	atf_check -o match:'suricata sw1 on [0-9]+ interfaces?, detects: started' \
	    "$JGC" -t -c "$SOCK" sdwan ids "$rs4"
	atf_check -s exit:0 kill -0 "$(cat "$(dirname "$f")/sdwan-ids-sw1.pid")"
	echo "[1 - Main] 2026-10-18 Error: an old one" >> "$(dirname "$f")/sdwan-ids-sw1.d/suricata.log"
	rs5=$(echo "$rs3" | sed 's/rule-files:/# FAILSTART\\nrule-files:/')
	# Its thresholds and suppressions: its own file, where the
	# configuration says; changed, it starts again; not a string,
	# refused.
	rs7=$(echo "$rs4" | sed 's|rule-files:|threshold-file: @THRESHOLD@\\nrule-files:|; s|"rules":|"thresholds":"suppress gen_id 1, sig_id 1000004, track by_src, ip 10.0.0.9\\n","rules":|')
	atf_check -o match:'suricata sw1 on [0-9]+ interfaces?, detects: started' \
	    "$JGC" -t -c "$SOCK" sdwan ids "$rs7"
	atf_check -o inline:'suppress gen_id 1, sig_id 1000004, track by_src, ip 10.0.0.9\n' \
	    cat "$(dirname "$f")/sdwan-ids-sw1.threshold"
	atf_check -o match:"^threshold-file: /.*/sdwan-ids-sw1.threshold\$" \
	    cat "$(dirname "$f")/sdwan-ids-sw1.yaml"
	atf_check -o match:'detects: as it was' "$JGC" -t -c "$SOCK" sdwan ids "$rs7"
	atf_check -o match:'detects: started' "$JGC" -t -c "$SOCK" sdwan ids \
	    "$(echo "$rs7" | sed 's/ip 10.0.0.9/ip 10.0.0.8/')"
	atf_check -s exit:1 -e match:'an instance is a name' -o ignore "$JGC" -c "$SOCK" sdwan ids \
	    "$(echo "$rs4" | sed 's|"rules":|"thresholds":5,"rules":|')"
	# By netmap(4), not pcap(3); its interfaces' offloading turned off
	# as it starts, em0^ (a host stack, netmap's alone) being em0's.
	printf '#!/bin/sh\necho "ifconfig $*" >> %s/ifconfig.log\n' "$(pwd)" > fake-ifconfig
	chmod +x fake-ifconfig
	rs8=$(echo "$rs4" | sed 's/"interfaces":\["any"\]/"interfaces":["wg5","wg5^"],"capture":"netmap","offload":false/')
	atf_check -o match:'suricata sw1 on 2 interfaces, detects: started' \
	    -o match:'wg5: checksum, TSO and LRO offloading off' \
	    "$JGC" -t -c "$SOCK" sdwan ids "$rs8"
	atf_check -o match:'suricata -c .*sdwan-ids-sw1.yaml --pidfile .* --netmap -D$' tail -1 suricata.log
	atf_check -o inline:'ifconfig wg5 -rxcsum -txcsum -rxcsum6 -txcsum6 -tso -lro -vlanhwtso\nifconfig wg5 -rxcsum -txcsum -rxcsum6 -txcsum6 -tso -lro -vlanhwtso\n' \
	    cat ifconfig.log
	atf_check -o match:'"name":"sw1",[^]]*\],"mode":"detect",.*"capture":"netmap"' \
	    -o match:'"ids_host":\{"ncpu":[1-9][0-9]*,"ndomains":[1-9]' \
	    "$JGC" -c "$SOCK" sdwan
	atf_check -s exit:1 -e match:"netmap's alone" -o ignore "$JGC" -c "$SOCK" sdwan ids \
	    "$(echo "$rs4" | sed 's/"interfaces":\["any"\]/"interfaces":["wg5^"]/')"
	atf_check -s exit:1 -e match:'capture is pcap or netmap' -o ignore "$JGC" -c "$SOCK" sdwan ids \
	    "$(echo "$rs4" | sed 's/"interfaces":/"capture":"bpf","interfaces":/')"
	# What its Suricata is built with; and Suricata's own answers, by
	# the instance's command socket, those that read alone.
	atf_check -o match:'"ids_build":\{"version":"8.0.7","lua":true,"ipfw":true,"netmap":true,"hyperscan":false,"profiling":false,"profiling_rules":false,"plugins":true\}' \
	    "$JGC" -c "$SOCK" sdwan
	if [ -x /usr/local/bin/python3 ]; then
		rs9=$(echo "$rs4" | sed 's|rule-files:|unix-command:\\n  enabled: yes\\n  filename: @SOCKET@\\nrule-files:|; s/sid:1000004;/sid:1000009;/')
		atf_check -o match:'detects: started' "$JGC" -t -c "$SOCK" sdwan ids "$rs9"
		atf_check -o match:"^  filename: /.*/sdwan-ids-sw1.sock\$" cat "$(dirname "$f")/sdwan-ids-sw1.yaml"
		for i in $(seq 1 50); do [ -S sdwan-ids-sw1.sock ] && break; sleep 0.1; done
		atf_check -o inline:'{"message":[{"name": "flow", "value": "32mb"}],"return":"OK"}\n' \
		    sh -c "\"$JGC\" -c \"$SOCK\" suricata rules instance=sw1 command=memcap-list | sed 's/\"message\": /\"message\":/; s/, \"return\": /,\"return\":/'"
		atf_check -o match:'"iface": "wg5"' "$JGC" -c "$SOCK" suricata rules instance=sw1 command=iface-stat iface=wg5
		atf_check -o match:'"rules_failed": 1' "$JGC" -c "$SOCK" suricata rules instance=sw1 command=ruleset-stats
		atf_check -s exit:1 -e match:'a command is one that reads' "$JGC" -c "$SOCK" suricata rules instance=sw1 command=shutdown
		atf_check -s exit:1 -e match:'it alone, names an iface' "$JGC" -c "$SOCK" suricata rules instance=sw1 command=iface-stat
		atf_check -s exit:1 -e match:'does not answer' "$JGC" -c "$SOCK" suricata rules instance=nosuch command=uptime
	fi
	# Its Lua scripts: written to its own directory, which its
	# configuration names; the same, left running; changed, started
	# again; gone, taken away.  A name not NAME.lua refused.
	rs10=$(echo "$rs4" | sed 's|rule-files:|default-rule-path: @LUADIR@\\nrule-files:|; s|"rules":|"lua":{"ua.lua":"-- one\\n"},"rules":|')
	atf_check -o match:'detects: started' "$JGC" -t -c "$SOCK" sdwan ids "$rs10"
	atf_check -o inline:'-- one\n' cat sdwan-ids-sw1.lua/ua.lua
	atf_check -o match:"^default-rule-path: /.*/sdwan-ids-sw1.lua\$" cat sdwan-ids-sw1.yaml
	atf_check -o match:'detects: as it was' "$JGC" -t -c "$SOCK" sdwan ids "$rs10"
	atf_check -o match:'detects: started' "$JGC" -t -c "$SOCK" sdwan ids "$(echo "$rs10" | sed 's/-- one/-- two/')"
	atf_check -o inline:'-- two\n' cat sdwan-ids-sw1.lua/ua.lua
	atf_check -o match:'detects: started' "$JGC" -t -c "$SOCK" sdwan ids "$rs4"
	test ! -f sdwan-ids-sw1.lua/ua.lua || atf_fail "a script not named stayed"
	atf_check -s exit:1 -e match:'NAME.lua of letters' -o ignore "$JGC" -c "$SOCK" sdwan ids \
	    "$(echo "$rs4" | sed 's|"rules":|"lua":{"../x.lua":"x"},"rules":|')"
	# Its plugins: under /usr/local/lib, there and root's alone.
	atf_check -s exit:1 -e match:'is not there, or not root' -o ignore "$JGC" -c "$SOCK" sdwan ids \
	    "$(echo "$rs4" | sed 's|"rules":|"plugins":["/usr/local/lib/nosuch.so"],"rules":|')"
	atf_check -s exit:1 -e match:'a .so under /usr/local/lib' -o ignore "$JGC" -c "$SOCK" sdwan ids \
	    "$(echo "$rs4" | sed 's|"rules":|"plugins":["/tmp/x.so"],"rules":|')"
	if [ -f /usr/local/lib/libucl.so ] && [ "$(stat -f %u /usr/local/lib/libucl.so)" = 0 ]; then
		atf_check -o ignore "$JGC" -c "$SOCK" sdwan ids \
		    "$(echo "$rs4" | sed 's|"rules":|"plugins":["/usr/local/lib/libucl.so"],"rules":|')"
	fi
	# A capture replayed through it, offline: its alerts kept for the
	# read; a link, a path not whole, an instance not here, refused.
	printf 'PCAP' > lab.pcap
	ln -sf lab.pcap link.pcap
	atf_check -o match:'done +suricata replays .*/lab.pcap through sw1' \
	    "$JGC" -c "$SOCK" suricata pcap instance=sw1 file="$(pwd)/lab.pcap"
	atf_check -o match:'"replay":\{"file":"[^"]*/lab.pcap","at":[0-9]+,"seconds":[0-9]+,"status":0,"alerts_total":1,"alerts":\[\{"name":"sw1",[^}]*"sid":2000009,' \
	    "$JGC" -c "$SOCK" sdwan
	atf_check -s exit:1 -o match:'not a file the host has' "$JGC" -c "$SOCK" suricata pcap instance=sw1 file="$(pwd)/link.pcap"
	atf_check -s exit:1 -e match:'by its whole path' "$JGC" -c "$SOCK" suricata pcap instance=sw1 file=lab.pcap
	atf_check -s exit:1 -o match:'no instance nosuch here' "$JGC" -c "$SOCK" suricata pcap instance=nosuch file="$(pwd)/lab.pcap"
	# The packets of its alerts it keeps (pcap-log), listed.
	printf 'PCAPLOG' > sdwan-ids-sw1.d/log.pcap.1792400000
	atf_check -o match:'"pcaps":\[\{"path":"[^"]*/sdwan-ids-sw1.d/log.pcap.1792400000","size":7,' \
	    "$JGC" -c "$SOCK" sdwan
	# Stopped by the admin: not run, its files and its place kept;
	# started again as it was.
	atf_check -o ignore "$JGC" -c "$SOCK" sdwan ids "$rs4"
	pid=$(cat "$(dirname "$f")/sdwan-ids-sw1.pid")
	rs6=$(echo "$rs4" | sed 's/"name":"sw1",/"name":"sw1","stopped":true,/')
	atf_check -o match:'suricata sw1 stopped, kept' \
	    "$JGC" -t -c "$SOCK" sdwan ids "$rs6"
	kill -0 "$pid" 2>/dev/null && atf_fail "a stopped suricata still runs"
	test -f "$(dirname "$f")/sdwan-ids-sw1.yaml" || atf_fail "a stopped suricata lost its file"
	atf_check -o match:'"name":"sw1","interfaces":\[[^]]*\],"mode":"detect","running":false,"stopped":true' \
	    "$JGC" -c "$SOCK" sdwan
	atf_check -o match:'"stopped":true' cat "$(dirname "$f")/sdwan-ids.json"
	atf_check -o match:'suricata sw1 on [0-9]+ interfaces?, detects: started' \
	    "$JGC" -t -c "$SOCK" sdwan ids "$rs4"
	atf_check -s exit:0 kill -0 "$(cat "$(dirname "$f")/sdwan-ids-sw1.pid")"
	atf_check -s exit:1 -e match:'stopped is true or false' -o ignore \
	    "$JGC" -c "$SOCK" sdwan ids "$(echo "$rs4" | sed 's/"name":"sw1",/"name":"sw1","stopped":1,/')"
	# Rendered here from its settings (the console's way): SD-WAN's
	# shape, and the Security section's, each checked and started.
	atf_check -o match:'suricata sw1 on 1 interface, detects: started' \
	    "$JGC" -t -c "$SOCK" sdwan ids '{"instances":[{"name":"sw1","host":"edge-a","interfaces":["lo0"],"spec":{"flavor":"sdwan","service":"acme","home":["10.1.0.0/24"],"interfaces":["lo0"],"ruleset":false,"oneside":true},"rules":"alert tcp any any -> any 23 (sid:1000001;)\n"}]}'
	atf_check -o match:'^# Written by arcana-agent for the Arcana console: SD-WAN service acme at edge-a\.$' \
	    -o match:'^    HOME_NET: "\[10.1.0.0/24\]"$' -o match:'^  - interface: lo0$' \
	    -o match:'^  async-oneside: true$' -o not-match:'@RULESET@' cat "$(dirname "$f")/sdwan-ids-sw1.yaml"
	atf_check -s exit:1 -e match:'sw1: home .*: nonsense is not one' -o ignore "$JGC" -c "$SOCK" sdwan ids \
	    '{"instances":[{"name":"sw1","interfaces":["lo0"],"spec":{"flavor":"sdwan","home":["nonsense"],"interfaces":["lo0"]},"rules":"x"}]}'
	atf_check -o match:'suricata sec-x on 1 interface, detects: started' "$JGC" -t -c "$SOCK" sdwan ids \
	    '{"group":"security","instances":[{"name":"sec-x","host":"edge-a","interfaces":["lo0"],"spec":{"interfaces":["lo0"],"home":["any"],"preset":"small","eve":["http"],"reassembly_depth":"1mb","yaml":"# mine\n"},"rules":"alert tcp any any -> any 23 (sid:1000001;)\n"}]}'
	atf_check -o match:'^    HOME_NET: "any"$' -o match:'^runmode: autofp$' -o match:'^    depth: 1mb$' \
	    -o match:'^        - http$' -o match:'^# mine$' -o match:'^unix-command:$' cat "$(dirname "$f")/sdwan-ids-sec-x.yaml"
	atf_check -s exit:1 -e match:'sec-x: its own YAML may not set plugins' -o ignore "$JGC" -c "$SOCK" sdwan ids \
	    '{"group":"security","instances":[{"name":"sec-x","interfaces":["lo0"],"spec":{"interfaces":["lo0"],"yaml":"plugins:\n  - /tmp/x.so\n"},"rules":"x"}]}'
	atf_check -o ignore "$JGC" -c "$SOCK" sdwan ids '{"group":"security","instances":[]}'
	# Many placeholders: the configuration comes out whole, as long as
	# it is (the buffer was once a fixed size, and the loop hung).
	many=$(printf '%s' "$rs4" | sed "s|rule-files:|$(printf '# @PID@%.0s' $(seq 1 400))\\\\nrule-files:|")
	atf_check -o match:'detects: started' "$JGC" -t -c "$SOCK" sdwan ids "$many"
	atf_check -o match:'^# /.*/sdwan-ids-sw1\.pid# /.*/sdwan-ids-sw1\.pid# ' cat "$(dirname "$f")/sdwan-ids-sw1.yaml"
	atf_check -s exit:1 -e match:'did not start: Error: suricata: this start fails$' \
	    -e not-match:'an old one' -o ignore "$JGC" -c "$SOCK" sdwan ids "$rs5"
	atf_check -o empty "$JGC" -c "$SOCK" sdwan ids '{"instances":[]}'
}
sdwan_cleanup()
{
	stop_daemon
}

atf_test_case smtpd cleanup
smtpd_head()
{
	atf_set "descr" "OpenSMTPD: read whole (status, counters, queue, the file, the form, the tables); smtpd.conf rendered from the form and checked by smtpd -n; tables written, passwords hashed; the queue's commands"
}
smtpd_body()
{
	mkdir -p tools smtpd.d
	cat > tools/smtpd <<EOS
#!/bin/sh
echo "smtpd \$*" >> $(pwd)/smtpd.log
[ "\$1" = -n ] && { grep -q BROKEN "\$3" && { echo "smtpd: invalid virtual ip or interface: bogus0" >&2; exit 1; }; echo "configuration OK"; exit 0; }
exit 0
EOS
	cat > tools/smtpctl <<EOS
#!/bin/sh
echo "smtpctl \$*" >> $(pwd)/smtpctl.log
# The nice value a read's program gets, a job's not: set by the agent
# just after the spawn, so a moment is given.
sleep 0.2
echo "nice \$(ps -o nice= -p \$\$ | tr -d ' ') \$*" >> $(pwd)/nice.log
case "\$*" in
"show status") printf 'MDA running\\nMTA paused\\nSMTP running\\n' ;;
"show stats") printf 'control.session=1\\nscheduler.delivery.ok=2\\nscheduler.delivery.permfail=4\\nuptime=44\\nuptime.human=44s\\n' ;;
"show queue") printf '6022923fc9341b9d|local|mta|auth|root@edge-a.example|nobody@example.invalid|nobody@example.invalid|1792491081|1792491081|3|1792491200|pending|-2|(TempFail) no route\\n' ;;
"update table "*) echo "command succeeded" ;;
pause*|resume*) echo "command succeeded" ;;
schedule*) echo "1 envelope scheduled" ;;
remove*) echo "1 envelope removed" ;;
esac
exit 0
EOS
	cat > tools/encrypt <<EOS
#!/bin/sh
read -r p; echo "encrypt \$* <\$p" >> $(pwd)/encrypt.log
echo '\$6\$fake\$hashOf\$1'
EOS
	chmod +x tools/smtpd tools/smtpctl tools/encrypt
	DAEMON_ARGS="-2 $(pwd)/tools --smtpd-conf $(pwd)/smtpd.conf --smtpd-dir $(pwd)/smtpd.d"
	start_daemon
	printf '#!/bin/sh\n' > rc.d/smtpd
	chmod +x rc.d/smtpd
	# Not running: installed, enabled or not, no status asked of it.
	atf_check -o match:'"installed":true' -o match:'"running":false' -o not-match:'"status"' \
	    -o match:'"filters":\[' -o match:'"pki":false' "$JGC" -c "$SOCK" smtpd
	# The form rendered, checked by smtpd -n, written and kept beside.
	cat > form.json <<'EOF'
{"listeners":[{"on":"localhost"},{"on":"em0","port":587,"tls":"tls","pki":"mail","auth":true,"hostname":"mail.example.org"}],
 "domains":["example.org","example.net"],
 "delivery":{"kind":"maildir","path":"~/Maildir","aliases":true,"virtual":true},
 "relay":{"host":"smtp.example.net","port":587,"proto":"smtp+tls","auth":true,"mail_from":"@example.org"},
 "policy":{"max_size":"35M","check_rdns":true,"queue_compression":true,"bounce_warn":"4h","max_rcpt":100},
 "own":"mta max-deferred 50\n"}
EOF
	atf_check -o match:'done +smtpd conf' "$JGC" -c "$SOCK" smtpd conf form.json
	atf_check -o match:'^smtpd -n -f .*smtpd.conf.arcana-new$' cat smtpd.log
	atf_check -o match:'^table aliases file:.*/smtpd.d/aliases$' -o match:'^table credentials file:' \
	    -o match:'^table secrets file:' -o match:'^table domains file:' \
	    -o match:'^filter check_rdns phase connect match !rdns disconnect "550 no rDNS"$' \
	    -o match:'^listen on localhost$' \
	    -o match:'^listen on em0 port 587 tls pki mail auth <credentials> hostname mail.example.org$' \
	    -o match:'^action "local" maildir "~/Maildir" alias <aliases> virtual <virtuals>$' \
	    -o match:'^action "relay" relay host smtp\+tls://relay@smtp.example.net:587 auth <secrets> mail-from "@example.org"$' \
	    -o match:'^match from any for domain <domains> action "local"$' \
	    -o match:'^match auth from any for any action "relay"$' \
	    -o match:'^smtp max-message-size 35M$' -o match:'^queue compression$' \
	    -o match:'^bounce warn-interval 4h$' -o match:'^smtp max-rcpt 100$' \
	    -o match:'^mta max-deferred 50$' cat smtpd.conf
	atf_check -o match:'"spec":\{"listeners":\[\{"on":"localhost"\}' "$JGC" -c "$SOCK" smtpd
	# What the form may not say: a listener nowhere, a pki Arcana's with
	# no certificate here, own lines that listen, a filter not installed.
	printf '{"listeners":[]}' > f2.json
	atf_check -s exit:1 -e match:'a listener at least' -o ignore "$JGC" -c "$SOCK" smtpd conf f2.json
	printf '{"listeners":[{"on":"localhost","tls":"tls","pki":"arcana"}]}' > f3.json
	atf_check -s exit:1 -e match:'without a certificate' -o ignore "$JGC" -c "$SOCK" smtpd conf f3.json
	printf '{"listeners":[{"on":"localhost"}],"own":"listen on 0.0.0.0\\n"}' > f4.json
	atf_check -s exit:1 -e match:'may not listen' -o ignore "$JGC" -c "$SOCK" smtpd conf f4.json
	printf '{"listeners":[{"on":"localhost"}],"filters":[{"name":"nosuch"}]}' > f5.json
	atf_check -s exit:1 -e match:'filter nosuch is not installed' -o ignore "$JGC" -c "$SOCK" smtpd conf f5.json
	# What smtpd itself refuses is not put in place.
	printf '{"listeners":[{"on":"localhost"}],"own":"# BROKEN\\n"}' > f6.json
	atf_check -s exit:1 -o match:'failed.*smtpd does not take it: smtpd -n exited with status 1: smtpd: invalid virtual ip' \
	    "$JGC" -c "$SOCK" smtpd conf f6.json
	atf_check -o not-match:'BROKEN' cat smtpd.conf
	atf_check -s exit:1 test -e smtpd.conf.arcana-new
	# Tables: aliases as given; credentials' passwords hashed, the file
	# root's alone, the clear password in no log; secrets root's alone.
	printf 'root: admin@example.org\n' > aliases.txt
	atf_check -o match:'done +smtpd table aliases' "$JGC" -c "$SOCK" smtpd table aliases aliases.txt
	atf_check -o inline:'root: admin@example.org\n' cat smtpd.d/aliases
	printf 'alice hunter2\nbob $6$kept$already\n' > creds.txt
	atf_check -o match:'done +smtpd table credentials' -o not-match:'hunter2' "$JGC" -t -c "$SOCK" smtpd table credentials creds.txt
	atf_check -o inline:'alice\t$6$fake$hashOf$1\nbob\t$6$kept$already\n' cat smtpd.d/credentials
	atf_check -o match:'^-rw-------' ls -l smtpd.d/credentials
	atf_check -o match:'^encrypt  <hunter2$' -o not-match:'already' cat encrypt.log
	atf_check -o match:'"credentials":\["alice","bob"\]' -o not-match:'hunter2' -o not-match:'hashOf' "$JGC" -c "$SOCK" smtpd
	# One entry at a time: a user added, another's password changed,
	# the rest kept; one taken out; a key not there refused.
	printf 'carol pw3\nalice newpass\n' > c2.txt
	atf_check -o match:'done +smtpd entry credentials' -o not-match:'pw3' "$JGC" -t -c "$SOCK" smtpd entry credentials c2.txt
	atf_check -o inline:'bob\t$6$kept$already\ncarol\t$6$fake$hashOf$1\nalice\t$6$fake$hashOf$1\n' cat smtpd.d/credentials
	atf_check -o match:'^-rw-------' ls -l smtpd.d/credentials
	atf_check -o match:'done +smtpd unentry credentials' "$JGC" -c "$SOCK" smtpd unentry credentials bob
	atf_check -o inline:'carol\t$6$fake$hashOf$1\nalice\t$6$fake$hashOf$1\n' cat smtpd.d/credentials
	atf_check -s exit:1 -o match:'credentials has no entry nosuch' "$JGC" -c "$SOCK" smtpd unentry credentials nosuch
	printf 'postmaster: root\n' > a2.txt
	atf_check -o match:'done' "$JGC" -c "$SOCK" smtpd entry aliases a2.txt
	atf_check -o inline:'root: admin@example.org\npostmaster: root\n' cat smtpd.d/aliases
	atf_check -o match:'done' "$JGC" -c "$SOCK" smtpd unentry aliases root
	atf_check -o inline:'postmaster: root\n' cat smtpd.d/aliases
	printf 'root: admin@example.org\n' > smtpd.d/aliases
	printf 'relay user@example.net:s3cret\n' > secrets.txt
	atf_check -o match:'done' "$JGC" -c "$SOCK" smtpd table secrets secrets.txt
	atf_check -o match:'^-rw-------' ls -l smtpd.d/secrets
	atf_check -o match:'"secrets":\["relay"\]' -o not-match:'s3cret' "$JGC" -c "$SOCK" smtpd
	atf_check -s exit:1 -e match:'one of aliases' -o ignore "$JGC" -c "$SOCK" smtpd table nosuch aliases.txt
	# Enabled and started; then the read asks smtpd itself: its status,
	# counters and queue, as smtpctl prints them.
	atf_check -o match:'done +smtpd enable' "$JGC" -c "$SOCK" smtpd enable yes
	atf_check -o match:'^smtpd_enable="YES"$' cat rc.conf
	test -f running.smtpd || atf_fail "smtpd was not started"
	atf_check -o match:'"running":true' -o match:'"status":\{"mda":"running","mta":"paused","smtp":"running"\}' \
	    -o match:'"stats":\{"control.session":1,"scheduler.delivery.ok":2,"scheduler.delivery.permfail":4,"uptime":44,"uptime.human":"44s"\}' \
	    -o match:'"queue":\[\{"evpid":"6022923fc9341b9d","source":"local","type":"mta","flags":"auth","from":"root@edge-a.example","to":"nobody@example.invalid","dest":"nobody@example.invalid","created":1792491081,"expires":1792491081,"retries":3,"lasttry":1792491200,"state":"pending","next":-2,"error":"\(TempFail\) no route"\}\]' \
	    -o match:'"queued":1' "$JGC" -c "$SOCK" smtpd
	# A table written while it runs is read again; the queue's commands.
	atf_check -o match:'done' "$JGC" -c "$SOCK" smtpd table aliases aliases.txt
	atf_check -o match:'^smtpctl update table aliases$' cat smtpctl.log
	atf_check -o match:'done +smtpd pause mta' "$JGC" -c "$SOCK" smtpd pause mta
	atf_check -o match:'done +smtpd resume mta' "$JGC" -c "$SOCK" smtpd resume mta
	atf_check -o match:'done +smtpd schedule 6022923fc9341b9d' "$JGC" -c "$SOCK" smtpd schedule 6022923fc9341b9d
	atf_check -o match:'done +smtpd remove all' "$JGC" -c "$SOCK" smtpd remove all
	atf_check -o match:'^smtpctl pause mta$' -o match:'^smtpctl resume mta$' -o match:'^smtpctl schedule 6022923fc9341b9d$' \
	    -o match:'^smtpctl remove all$' cat smtpctl.log
	# A read's programs at nice 10, a job's at the agent's own.
	atf_check -o match:'^nice 10 show status$' -o match:'^nice 0 pause mta$' cat nice.log
	atf_check -s exit:1 -e match:'mta, mda or smtp' -o ignore "$JGC" -c "$SOCK" smtpd pause all
	atf_check -s exit:1 -e match:"envelope's or a message's id" -o ignore "$JGC" -c "$SOCK" smtpd remove '../x'
	# The form again while it runs: smtpd started again.
	atf_check -o match:'done +smtpd conf' "$JGC" -c "$SOCK" smtpd conf form.json
	atf_check -o match:'done +smtpd enable' "$JGC" -c "$SOCK" smtpd enable no
	atf_check -o match:'^smtpd_enable="NO"$' cat rc.conf
	test -f running.smtpd && atf_fail "smtpd was not stopped"
	# A jail's, with or without a network of its own: entered first
	# (none runs here); never safe.
	atf_check -s exit:1 -e match:'the jail web is not running' -o ignore "$JGC" -j web -c "$SOCK" smtpd
	atf_check -s exit:1 -e match:'not in safe mode' -o ignore "$JGC" -s -c "$SOCK" smtpd pause mta
}
smtpd_cleanup()
{
	stop_daemon
}

atf_test_case netstore cleanup
netstore_head()
{
	atf_set "descr" "the NFS server, the iSCSI target and HAST: read, and changed by jobs"
}
netstore_body()
{
	mkdir -p tools
	printf '#!/bin/sh\necho "ctladm $*" >> %s/ctladm.log\ncase "$1" in\ndevlist) echo "LUN Backend Size (Blocks) BS Serial Number Device ID"; echo "  0 block 2048 512 MYSERIAL0 MYDEVID0" ;;\nislist) echo "ID Portal Initiator name Target name" ;;\nportlist) echo "Port Online Frontend Name pp vp" ;;\nesac\n' "$(pwd)" > tools/ctladm
	printf '#!/bin/sh\necho "hastctl $*" >> %s/hastctl.log\ncase "$1" in\nstatus) printf "Name\\tStatus\\tRole\\tComponents\\nshared\\tcomplete\\tprimary\\t/dev/ada1\\tb.example.org\\n" ;;\nlist) echo "shared:" ;;\nesac\n' "$(pwd)" > tools/hastctl
	printf '#!/bin/sh\necho "Exports list on localhost:"\necho "/export 10.0.0.0"\n' > tools/showmount
	printf '#!/bin/sh\necho "sysctl $*" >> %s/sysctl.log\n' "$(pwd)" > fake-sysctl
	printf '#!/bin/sh\necho "zfs $*" >> %s/zfs.log\ncase "$1" in\nlist) printf "zroot/export\\t/export\\t-maproot=root\\nzroot/home\\t/home\\toff\\n" ;;\nesac\n' "$(pwd)" > fake-zfs
	chmod +x tools/ctladm tools/hastctl tools/showmount fake-sysctl fake-zfs
	printf '/export -network 10.0.0.0/24\n' > exports
	DAEMON_ARGS="-2 $(pwd)/tools -z $(pwd)/fake-zfs --exports $(pwd)/exports --ctl-conf $(pwd)/ctl.conf --hast-conf $(pwd)/hast.conf -Q $(pwd)/fake-sysctl -O $(pwd)/sysctl.conf"
	start_daemon
	for d in nfsd mountd ctld hastd; do
		printf '#!/bin/sh\n' > rc.d/$d
		chmod +x rc.d/$d
	done
	# Read whole, or one of them.
	atf_check -o match:'"nfs":\{.*"exports_path":"[^"]*/exports","exports":"/export -network 10.0.0.0/24\\n",.*"shares":\[\{"dataset":"zroot/export","mountpoint":"/export","sharenfs":"-maproot=root"\}\],"exported":"Exports list on localhost:' \
	    -o not-match:'"v4root"' \
	    -o match:'"iscsi":\{.*"luns":"LUN Backend[^"]*MYSERIAL0' \
	    -o match:'"hast":\{.*"status":"Name\\tStatus\\tRole\\tComponents\\nshared\\tcomplete\\tprimary' \
	    "$JGC" -c "$SOCK" netstore
	atf_check -o match:'^\{"iscsi":' -o not-match:'"nfs"' "$JGC" -c "$SOCK" netstore iscsi
	atf_check -s exit:1 -e match:'netstore reads nfs, iscsi and hast' "$JGC" -c "$SOCK" netstore smb
	# NFS, v4 alone: exports(5) written, mountd told, once its V4: root
	# is a directory on ZFS; a text that exports needs the root; a
	# root elsewhere (devfs), or nowhere, is refused.
	printf 'V4: /dev -sec=sys\n' > exports.dev
	atf_check -s exit:1 -o match:'failed.*V4: root /dev is not on ZFS \(devfs\)' "$JGC" -c "$SOCK" nfs exports exports.dev
	printf 'V4: /nonesuch\n' > exports.none
	atf_check -s exit:1 -o match:'failed.*V4: root /nonesuch: No such file' "$JGC" -c "$SOCK" nfs exports exports.none
	printf '/export -network 10.0.0.0/24\n' > exports.nov4
	atf_check -s exit:1 -o match:'failed.*exports needs a V4: line' "$JGC" -c "$SOCK" nfs exports exports.nov4
	printf '# nothing yet\n' > exports.empty
	atf_check -o match:'done +nfs exports' "$JGC" -c "$SOCK" nfs exports exports.empty
	printf '/export -network 10.0.0.0/24\nV4: %s -sec=sys\n' "$(pwd)" > exports.new
	fs=$(df -T . | awk 'NR==2{print $2}')
	if [ "$fs" = zfs ]; then
		atf_check -o match:'done +nfs exports' "$JGC" -c "$SOCK" nfs exports exports.new
		atf_check -o inline:"/export -network 10.0.0.0/24\nV4: $(pwd) -sec=sys\n" cat exports
		atf_check -o match:"\"v4root\":\"$(pwd)\",\"v4root_zfs\":true" "$JGC" -c "$SOCK" netstore nfs
	else
		atf_check -s exit:1 -o match:"failed.*V4: root $(pwd) is not on ZFS \($fs\)" "$JGC" -c "$SOCK" nfs exports exports.new
	fi
	# A dataset shared by its sharenfs: zfs set, which tells mountd.
	atf_check -o match:'done +nfs share' "$JGC" -c "$SOCK" nfs share dataset=zroot/export 'sharenfs=-maproot=root -network 10.0.0.0/24'
	atf_check -o match:'^zfs set sharenfs=-maproot=root -network 10.0.0.0/24 zroot/export$' cat zfs.log
	atf_check -o match:'done +nfs share' "$JGC" -c "$SOCK" nfs share dataset=zroot/export sharenfs=off
	atf_check -s exit:1 -e match:"share takes dataset=" "$JGC" -c "$SOCK" nfs share dataset=../x sharenfs=on
	atf_check -s exit:1 -e match:"share takes dataset=" "$JGC" -c "$SOCK" nfs share dataset=/zroot sharenfs=on
	# The server's settings: NFSv4 alone, up to 4.2, nfsd's threads,
	# pNFS's data servers and mirrors.
	atf_check -o match:'done +nfs server' "$JGC" -c "$SOCK" nfs server enable=yes \
	    minor=2 threads=8 pnfs=ds1.example.org:/ds0,ds2.example.org:/ds1 mirror=2
	atf_check -o match:'^nfs_server_flags="-u -t -n 8 -p ds1.example.org:/ds0,ds2.example.org:/ds1 -m 2"$' \
	    -o match:'^nfsv4_server_enable="YES"$' -o match:'^nfsv4_server_only="YES"$' \
	    -o not-match:'^rpcbind_enable' -o match:'^mountd_enable="YES"$' cat rc.conf
	atf_check -s exit:1 -e match:'server takes enable=' "$JGC" -c "$SOCK" nfs server v4only=no
	# The flags merged: threads alone keeps pNFS's -p and -m; mirror
	# without data servers is refused.
	atf_check -o match:'done +nfs server' "$JGC" -c "$SOCK" nfs server threads=16
	atf_check -o match:'^nfs_server_flags="-u -t -p ds1.example.org:/ds0,ds2.example.org:/ds1 -m 2 -n 16"$' cat rc.conf
	atf_check -o match:'done' "$JGC" -c "$SOCK" nfs server pnfs=
	atf_check -o match:'^nfs_server_flags="-u -t -n 16"$' cat rc.conf
	atf_check -s exit:1 -o match:'failed.*mirror needs pNFS' "$JGC" -c "$SOCK" nfs server mirror=2
	atf_check -o match:'vfs.nfsd.server_max_minorversion=2' cat sysctl.log
	atf_check -o match:'^vfs.nfsd.server_max_minorversion=2$' cat sysctl.conf
	test -f running.nfsd || atf_fail "nfsd is not started"
	atf_check -s exit:1 -e match:"minor is NFSv4's 0, 1 or 2" "$JGC" -c "$SOCK" nfs server minor=3
	atf_check -s exit:1 -e match:'pnfs is the data servers' "$JGC" -c "$SOCK" nfs server 'pnfs=a b'
	atf_check -s exit:1 -e match:'threads is 1 to 256' "$JGC" -c "$SOCK" nfs server threads=0
	atf_check -s exit:1 -e match:'server takes enable=' "$JGC" -c "$SOCK" nfs server color=red
	# iSCSI: ctl.conf root's alone; ctld on.
	printf 'portal-group pg0 {\n\tlisten 0.0.0.0\n}\n' > ctl.new
	atf_check -o match:'done +iscsi conf' "$JGC" -c "$SOCK" iscsi conf ctl.new
	atf_check -o match:'^-rw-------' ls -l ctl.conf
	atf_check -o match:'done +iscsi enable' "$JGC" -c "$SOCK" iscsi enable yes
	test -f running.ctld || atf_fail "ctld is not started"
	# HAST: hast.conf; a resource made, its role set.
	printf 'resource shared {\n\ton a { local /dev/ada1\n\t\tremote 10.0.0.2 }\n}\n' > hast.new
	atf_check -o match:'done +hast conf' "$JGC" -c "$SOCK" hast conf hast.new
	atf_check -o match:'resource shared' cat hast.conf
	atf_check -o match:'done +hast create shared' "$JGC" -c "$SOCK" hast create shared
	atf_check -o match:'done +hast role shared' "$JGC" -c "$SOCK" hast role primary shared
	atf_check -o match:'^hastctl create shared$' -o match:'^hastctl role primary shared$' cat hastctl.log
	atf_check -s exit:1 -e match:'role is init, primary or secondary' "$JGC" -c "$SOCK" hast role leader shared
	atf_check -s exit:1 -e match:'a hast resource is named' "$JGC" -c "$SOCK" hast create '../x'
	# The host's alone.
	atf_check -s exit:1 -e match:"the host's storage services are the host's" \
	    "$JGC" -j web -c "$SOCK" iscsi enable yes
}
netstore_cleanup()
{
	stop_daemon
}

atf_test_case sysfiles cleanup
sysfiles_head()
{
	atf_set "descr" "the system's own files, read and written by sysfile jobs, and the host's settings beside them"
}
sysfiles_body()
{
	mkdir -p tools root/etc/defaults root/etc/security
	printf '#!/bin/sh\necho "0 devfsrules_hide_all"\n' > tools/devfs
	printf '#!/bin/sh\necho "10.0.0.1 10.0.0.2 any"\necho "\tout ipsec esp/transport//require"\n' > tools/setkey
	printf '#!/bin/sh\necho "jail:www:memoryuse:deny=1g"\n' > tools/rctl
	cat > tools/geom <<EOS
#!/bin/sh
[ "\$1" = -t ] && { echo "Geom   Class   Provider"; echo "ada0   DISK    ada0"; exit 0; }
[ "\$2" = status ] && { [ "\$1" = mirror ] && { echo "Name Status Components"; echo "mirror/gm0 COMPLETE md1"; exit 0; }; exit 1; }
echo "geom \$*" >> $(pwd)/geom.log
# A passphrase file: what it holds kept, to be looked at.
while [ \$# -gt 0 ]; do [ "\$1" = -J ] || [ "\$1" = -j ] && cat "\$2" > $(pwd)/geom.pass; shift; done
exit 0
EOS
	printf '#!/bin/sh\necho "Geom name: ada1p1.eli"\n' > tools/geli
	printf '#!/bin/sh\necho "     remote  refid st t when poll reach delay offset jitter"\n' > tools/ntpq
	chmod +x tools/*
	printf '# defaults\ndaily_clean_tmps_enable="NO"\t\t# Delete stuff daily\ndaily_status_disks_enable="YES"\nsecurity_status_chksetuid_enable="YES"\n' > root/etc/defaults/periodic.conf
	DAEMON_ARGS="-2 $(pwd)/tools --root $(pwd)/root"
	start_daemon
	for d in syslogd devfs devd auditd ipsec rctl ntpd linux; do
		printf '#!/bin/sh\n' > rc.d/$d
		chmod +x rc.d/$d
	done
	echo 'sshd_svcj="YES"' >> rc.conf
	echo 'sshd_svcj_options="net_basic"' >> rc.conf
	# Read whole: its files (none there yet), and the host beside.
	atf_check -o match:'"files":\{"devfs.rules":\{"path":"/etc/devfs.rules","service":"devfs","enabled":false,"running":false,"shows":"0 devfsrules_hide_all\\n"\}' \
	    -o match:'"ipsec.conf":\{"path":"/etc/ipsec.conf","service":"ipsec",[^}]*"shows":"10.0.0.1 10.0.0.2 any\\n' \
	    -o match:'"rctl.conf":\{[^}]*"shows":"jail:www:memoryuse:deny=1g\\n"' \
	    -o match:'"securelevel":\{"now":-?[0-9]+' -o match:'"mac":\{"mac_bsdextended":(true|false),' \
	    -o match:'"geom":"Geom   Class   Provider\\nada0   DISK    ada0\\n"' -o match:'"geli":"Geom name: ada1p1.eli\\n"' \
	    -o match:'"periodic":\[\{"name":"daily_clean_tmps_enable","default":"NO"\},\{"name":"daily_status_disks_enable","default":"YES"\},' \
	    -o match:'"svcj":\{"sshd_svcj":"YES","sshd_svcj_options":"net_basic"\}' \
	    "$JGC" -c "$SOCK" system
	# The hardening sysctls this kernel has, and racct.
	atf_check -o match:'"racct":[01],"hardening":\{"security.bsd.see_other_uids":[01],' \
	    -o match:'"kern.elf64.aslr.enable":[01]' "$JGC" -c "$SOCK" system host
	atf_check -o match:'^\{"files":\{"krb5.conf":\{"path":"/etc/krb5.conf"\}\}\}$' "$JGC" -c "$SOCK" system krb5.conf
	atf_check -s exit:1 -e match:'system reads its files by name' "$JGC" -c "$SOCK" system passwd
	# Written whole, each where the table says, its daemon told.
	printf '*.err\t/var/log/errors\n' > syslog.new
	touch running.syslogd
	atf_check -o match:'done +syslog.conf written' "$JGC" -t -c "$SOCK" sysfile syslog.conf syslog.new
	atf_check -o inline:'*.err\t/var/log/errors\n' cat root/etc/syslog.conf
	printf 'flush\nspdflush\n' > ipsec.new
	atf_check -o match:'done' "$JGC" -c "$SOCK" sysfile ipsec.conf ipsec.new
	atf_check -o match:'^-rw-------' ls -l root/etc/ipsec.conf
	printf 'notify 0 { match "system" "IFNET"; action "logger $subsystem"; };\n' > devd.new
	atf_check -o match:'done' "$JGC" -c "$SOCK" sysfile devd devd.new
	atf_check -o match:'IFNET' cat root/usr/local/etc/devd/arcana.conf
	printf 'kern.racct.enable=1\n' > loader.new
	atf_check -o match:'done' "$JGC" -c "$SOCK" sysfile loader.conf.d loader.new
	atf_check -o inline:'kern.racct.enable=1\n' cat root/boot/loader.conf.d/arcana.conf
	# periodic.conf's variables, the rest kept.
	atf_check -o match:'done +periodic.conf.s variables written' "$JGC" -c "$SOCK" sysfile periodic \
	    daily_clean_tmps_enable=YES security_status_chksetuid_enable=NO
	atf_check -o match:'\{"name":"daily_clean_tmps_enable","default":"NO","value":"YES"\}' \
	    -o match:'\{"name":"security_status_chksetuid_enable","default":"YES","value":"NO"\}' \
	    "$JGC" -c "$SOCK" system host
	# securelevel at boot, rc.conf's, those two alone.
	atf_check -o match:'done +securelevel at boot written' "$JGC" -c "$SOCK" sysfile rc \
	    kern_securelevel_enable=YES kern_securelevel=2
	atf_check -o match:'^kern_securelevel="2"$' -o match:'^kern_securelevel_enable="YES"$' cat rc.conf
	atf_check -s exit:1 -e match:'rc sets kern_securelevel_enable' "$JGC" -c "$SOCK" sysfile rc sshd_enable=YES
	atf_check -s exit:1 -e match:'kern_securelevel=-1 to 3' "$JGC" -c "$SOCK" sysfile rc kern_securelevel=7
	# GEOM's classes loaded, their status; a class's command; GELI's
	# passphrase by a file of its own, gone after.
	atf_check -o match:'"geom_classes":\{"mirror":"Name Status Components\\nmirror/gm0 COMPLETE md1\\n"\}' \
	    "$JGC" -c "$SOCK" system host
	atf_check -o match:'done +geom mirror label /dev/md2' \
	    "$JGC" -c "$SOCK" geom mirror label -v -b round-robin gm0 /dev/md1 /dev/md2
	atf_check -o inline:'geom mirror label -v -b round-robin gm0 /dev/md1 /dev/md2\n' cat geom.log
	printf 'correct horse' > pass.txt
	atf_check -o match:'done +geom eli init /dev/md3' \
	    "$JGC" -t -c "$SOCK" geom eli init -s 4096 /dev/md3 -P pass.txt
	atf_check -o match:'^geom eli init -J .*/arcana-geli\.[0-9]+ -s 4096 /dev/md3$' tail -1 geom.log
	atf_check -o inline:'correct horse' cat geom.pass
	test -z "$(ls root | grep arcana-geli)" || atf_fail "the passphrase file stayed"
	atf_check -s exit:1 -e match:"a geom job's verb is its class" "$JGC" -c "$SOCK" geom gpart add x
	atf_check -s exit:1 -e match:'not a subcommand of the class' "$JGC" -c "$SOCK" geom mirror rm gm0
	atf_check -s exit:1 -e match:'a word is a flag or a name' "$JGC" -c "$SOCK" geom mirror label 'gm0;reboot' /dev/md1
	atf_check -s exit:1 -e match:"a passphrase is geli init's" "$JGC" -c "$SOCK" geom mirror label gm0 /dev/md1 -P pass.txt
	# What it does not write, and what it does not take.
	atf_check -s exit:1 -e match:"a sysfile job's verb names its file" "$JGC" -c "$SOCK" sysfile passwd syslog.new
	printf 'bad\001\n' > ctl.new
	atf_check -s exit:1 -e match:'lines of printable characters' "$JGC" -c "$SOCK" sysfile krb5.conf ctl.new
	atf_check -s exit:1 -e match:'name_enable=YES or NO' "$JGC" -c "$SOCK" sysfile periodic daily_x=1
	atf_check -s exit:1 -e match:"the system's files are the host's" "$JGC" -j web -c "$SOCK" sysfile krb5.conf syslog.new
	# Never safe: a file written whole has no undo kept.
	atf_check -s exit:1 -e match:'not undone: not in safe mode' "$JGC" -s -c "$SOCK" sysfile krb5.conf syslog.new
}
sysfiles_cleanup()
{
	stop_daemon
}

atf_test_case agent_build cleanup
agent_build_head()
{
	atf_set "descr" "arcana-agent is built from a repository and sent back"
}
agent_build_body()
{
	programs
	# git clone makes the tree; make "builds" by copying the agent.
	cat > fake-git <<EOS
#!/bin/sh
[ "\$1" = -c ] && shift 2
# The commit a clone is at, and the head of the repository's branch.
[ "\$1" = -C ] && [ "\$3" = rev-parse ] && { echo 1111111111111111111111111111111111111111; exit 0; }
# The log clone: made bare, fetched, read; what ./log and ./tags hold.
[ "\$1" = -C ] && [ "\$3" = config ] && { echo "\$5" > "\$2/ORIGIN"; exit 0; }
[ "\$1" = -C ] && [ "\$3" = fetch ] && exit 0
[ "\$1" = -C ] && [ "\$3" = log ] && { cat $(pwd)/log 2>/dev/null; exit 0; }
[ "\$1" = -C ] && [ "\$3" = for-each-ref ] && { cat $(pwd)/tags 2>/dev/null; exit 0; }
[ "\$1" = clone ] && [ "\$2" = --bare ] && { for a; do last=\$a; done; mkdir -p "\$last"; echo "\$*" > "\$last/HEAD"; exit 0; }
if [ "\$1" = ls-remote ]; then
	case "\$4" in nope) exit 2 ;; esac
	printf '%s\trefs/heads/%s\n' "\$(cat $(pwd)/head 2>/dev/null || echo 2222222222222222222222222222222222222222)" "\$4"
	exit 0
fi
[ "\$1" = clone ] || exit 2
for a; do last=\$a; done
case " \$* " in *" --branch chatty "*) jot 400 | sed 's/^/remote: line /' >&2; exit 128 ;; esac
case " \$* " in *" --branch nope "*) printf "Cloning into 'x'...\nfatal: no such branch\nfatal: Could not read from remote repository.\n\nPlease make sure you have the correct access rights\nand the repository exists.\n" >&2; exit 128 ;; esac
mkdir -p "\$last/lib/libjailconf" "\$last/lib/libvarconf" "\$last/usr.sbin/arcana-agent" "\$last/cblink/share/cblink"
touch "\$last/cblink/share/cblink/cblink.mk"
echo "\$*" > "\$last/CLONED"
EOS
	cat > fake-make <<EOS
#!/bin/sh
dir=\$2
echo "\$*" >> $(pwd)/made
echo "HOME=\$HOME" >> $(pwd)/made
[ -f $(pwd)/make-fails ] && exit 1
case " \$* " in
*" -V .OBJDIR "*) echo "\$dir/obj" ;;
*/usr.sbin/arcana-agent*) mkdir -p "\$dir/obj" && cp "$JGD" "\$dir/obj/arcana-agent" ;;
esac
EOS
	# The server's host key is a real one, so that ssh-keygen(1) can
	# fingerprint it and find it; only the scan is a stand-in.
	ssh-keygen -q -t ed25519 -N '' -C server -f hostkey
	cat > fake-keyscan <<EOS
#!/bin/sh
port=
for a; do [ "\$prev" = -p ] && port=\$a; prev=\$a; last=\$a; done
[ -n "\$port" ] && last="[\$last]:\$port"
# As newer ssh-keyscan(1) does: the banner, as a comment, with the keys.
echo "# \$last SSH-2.0-OpenSSH_10.0 ''"
echo "\$last \$(cut -d' ' -f1,2 $(pwd)/hostkey.pub)"
EOS
	chmod +x fake-git fake-make fake-keyscan
	echo 'CBLINK_PREFIX= /opt/cblink' > build.mk
	start_daemon

	atf_check -o match:'^Built: +[0-9]+\.[0-9]+' \
	    -o match:'git clone --depth 1 --recurse-submodules --shallow-submodules --branch main -- https://example.org/arcana.git' \
	    "$JGC" -t -c "$SOCK" agent-build -o built https://example.org/arcana.git main
	atf_check cmp -s "$JGD" built
	atf_check test -x built
	# cblink (the submodule: cblink-gen makes arcana.h) and the
	# libraries the agent links, before it, in that order.
	atf_check -o inline:'cblink-build\nlibjailconf\nlibvarconf\narcana-agent\n' \
	    sh -c "grep -v -e '^HOME=' -e '-V .OBJDIR' made | sed -n \
	    -e 's,.* cblink-build\$,cblink-build,p' -e 's,.*/lib/\\(lib[a-z]*\\) .*,\\1,p' \
	    -e 's,.*/usr.sbin/arcana-agent .*,arcana-agent,p'"
	# What was built is said by its commit, and the head of the
	# repository is asked without cloning or building anything.
	atf_check -o match:'^Commit: +1111111111111111111111111111111111111111$' \
	    "$JGC" -c "$SOCK" agent-build -o built https://example.org/arcana.git main
	rm made
	echo 3333333333333333333333333333333333333333 > head
	atf_check -o match:'^Commit: +3333333333333333333333333333333333333333$' \
	    "$JGC" -c "$SOCK" source-head https://example.org/arcana.git main
	atf_check test ! -e made
	# What is new: the latest commits and the tags, by a bare clone
	# without the files kept in the build directory, fetched again.
	printf 'aaaa\037100\037agent 0.2.0: two\037the body\036bbbb\03790\037agent 0.1.0: one\037\036' > log
	printf 'v0.2.0\037100\037Release two\036' > tags
	atf_check -o match:'^Commit: +1111111111111111111111111111111111111111$' \
	    -o match:'^Commits: +\[\{"commit":"aaaa","time":100,"subject":"agent 0.2.0: two","body":"the body"\},\{"commit":"bbbb","time":90,"subject":"agent 0.1.0: one","body":""\}\]$' \
	    -o match:'^Tags: +\[\{"name":"v0.2.0","time":100,"message":"Release two"\}\]$' \
	    "$JGC" -c "$SOCK" source-log -n 2 https://example.org/arcana.git main
	atf_check -o match:'clone --bare --filter=blob:none --single-branch --branch main -- https://example.org/arcana.git' cat build/log.git/HEAD
	atf_check -o inline:'https://example.org/arcana.git\n' cat build/log.git/ORIGIN
	# Another repository named: the clone kept, fetched from it.
	atf_check -o match:'^Commit: ' \
	    "$JGC" -c "$SOCK" source-log -n 2 https://example.org/moved.git main
	atf_check -o match:'-- https://example.org/arcana.git' cat build/log.git/HEAD
	atf_check -o inline:'https://example.org/moved.git\n' cat build/log.git/ORIGIN
	atf_check -s exit:1 -e match:'git failed' -o ignore \
	    "$JGC" -c "$SOCK" source-head https://example.org/arcana.git nope
	# Over SSH as a build is: the host key is not taken on trust.
	atf_check -s exit:1 -o match:'Host key: ' \
	    -e match:'does not know the SSH host key of git.example.org' \
	    "$JGC" -c "$SOCK" source-head git@git.example.org:me/arcana.git
	# The host's own settings went into the tree.
	atf_check -o match:'CBLINK_PREFIX' cat build/src/config.mk
	# A build that fails says why, and nothing is written.
	atf_check -s exit:1 -e match:'status 128.*no such branch.*Could not read' \
	    -e not-match:'repository exists' -o ignore \
	    "$JGC" -c "$SOCK" agent-build -o other https://example.org/arcana.git nope
	atf_check test ! -e other
	# Over SSH the server's host key is not taken on trust: the first
	# try hands back what was found, with fingerprints and this host's
	# deploy key, and builds nothing.
	atf_check -s exit:1 -o match:'Host key: +256 SHA256:' \
	    -o match:'Deploy key: +ssh-ed25519 ' \
	    -e match:'does not know the SSH host key of git.example.org' \
	    "$JGC" -c "$SOCK" agent-build -o viassh git@git.example.org:me/arcana.git
	atf_check test ! -e viassh -a ! -e build/known_hosts
	atf_check test -f build/id_ed25519
	# Confirmed, the key is kept and git is told to check against it.
	atf_check -o match:'^Built: ' -o match:'StrictHostKeyChecking=yes' \
	    -o match:'UserKnownHostsFile=.*/build/known_hosts' \
	    "$JGC" -t -c "$SOCK" agent-build -y -o viassh \
	    git@git.example.org:me/arcana.git
	atf_check -o match:'^git.example.org ssh-ed25519 ' cat build/known_hosts
	# Known from then on, also on a port of its own only when asked.
	atf_check -o match:'^Built: ' \
	    "$JGC" -c "$SOCK" agent-build -o viassh git@git.example.org:me/arcana.git
	atf_check -s exit:1 -o match:'Host key: ' -e match:'\[git.example.org\]:2222' \
	    "$JGC" -c "$SOCK" agent-build -o other \
	    ssh://git@git.example.org:2222/me/arcana.git
	# A key of the administrator's own, by its path on the host.
	atf_check -s exit:1 -e match:'missing-key is not there' -o ignore \
	    "$JGC" -c "$SOCK" agent-build -i "$(pwd)/missing-key" -o other \
	    git@git.example.org:me/arcana.git
	atf_check -o match:"ssh -i $(pwd)/hostkey " \
	    "$JGC" -t -c "$SOCK" agent-build -i "$(pwd)/hostkey" -o viassh \
	    git@git.example.org:me/arcana.git
	# The console's update: the whole tree is built and installed,
	# and the console's service restarted after the answer.
	atf_check -o match:'^Console: +installed, restarting' \
	    -o match:'fake-make -C .*/build/src MK_TESTS=no install' \
	    "$JGC" -t -c "$SOCK" console-update https://example.org/arcana.git
	atf_check -o match:'build/src MK_TESTS=no$' \
	    -o match:'build/src MK_TESTS=no install$' cat made
	# A build's programs have a home: emcc will not run without one.
	atf_check -o match:"^HOME=$(pwd)/build\$" cat made
	for i in $(seq 1 60); do
		[ -e running.arcana_console ] && break
		sleep 0.1
	done
	atf_check test -e running.arcana_console
	# The agent was installed with it: it is restarted too, or the new
	# console would talk to the agent of the version before.
	for i in $(seq 1 60); do
		[ -e running.arcana_agent ] && break
		sleep 0.1
	done
	atf_check test -e running.arcana_agent
	# A build that fails installs nothing and restarts nothing.
	rm running.arcana_console running.arcana_agent made
	touch make-fails
	atf_check -s exit:1 -e match:'make exited with status 1' -o ignore \
	    "$JGC" -c "$SOCK" console-update https://example.org/arcana.git
	atf_check -o not-match:'install' cat made
	sleep 1.5
	atf_check test ! -e running.arcana_console
	atf_check test ! -e running.arcana_agent
	rm make-fails
	# What git would take as an option is not a repository.
	atf_check -s exit:1 -e match:'not a repository' -o ignore \
	    "$JGC" -c "$SOCK" agent-build -- --upload-pack=x
	# A server that has much to say: all of it is told, and the daemon
	# is there afterwards.
	atf_check -s exit:1 -e match:'remote: line 1: remote: line 2' \
	    -e match:'remote: line 400' -o ignore \
	    "$JGC" -c "$SOCK" agent-build https://example.org/arcana.git chatty
	atf_check -o match:'^Host:' "$JGC" -c "$SOCK" hello
	# A key's path goes into a command the shell reads.
	atf_check -s exit:1 -e match:'letters, digits and' -o ignore \
	    "$JGC" -c "$SOCK" agent-build -i '/tmp/k;id' \
	    git@git.example.org:me/arcana.git
}
agent_build_cleanup()
{
	stop_daemon
}

atf_test_case stop cleanup
stop_head()
{
	atf_set "descr" "A stop waits for the change under way and logs it"
}
stop_body()
{
	start_daemon
	pid=$(cat daemon.pid)
	# Idle, it stops at once.
	kill "$pid"
	for i in $(seq 1 40); do
		kill -0 "$pid" 2>/dev/null || break
		sleep 0.1
	done
	atf_check -s exit:1 -e ignore kill -0 "$pid"
	atf_check -o match:'signal 15, stopping' cat daemon.out

	# In the middle of a change, with more queued: the change ends
	# first, and the log says what it is and what will not run.
	start_daemon
	pid=$(cat daemon.pid)
	# Under way until the test lets it end, however loaded the machine.
	touch slow hold
	"$JGC" -c "$SOCK" service sshd restart > change.out 2>&1 &
	change=$!
	# Once the change is under way, not at a guess of when.
	for i in $(seq 1 150); do
		"$JGC" -c "$SOCK" jobs 2>/dev/null | grep -q 'Under way' && break
		sleep 0.1
	done
	# What is under way and is not a job is said with the jobs.
	atf_check -o match:'Under way: +service sshd restart' \
	    -o not-match:'Stopping' "$JGC" -c "$SOCK" jobs
	atf_check -o ignore "$JGC" -q -c "$SOCK" start web
	kill "$pid"
	for i in $(seq 1 100); do
		"$JGC" -c "$SOCK" jobs 2>/dev/null | grep -q 'Stopping' && break
		sleep 0.1
	done
	atf_check -s exit:0 kill -0 "$pid"
	atf_check -o match:'Under way: +service sshd restart' \
	    -o match:'Stopping: +when what is under way ends' \
	    "$JGC" -c "$SOCK" jobs
	atf_check -o match:'a change is under way' \
	    -o match:'under way: service sshd restart' \
	    -o match:'queued, will not run: job 1: start web' cat daemon.out
	rm hold
	wait $change
	atf_check -o match:'sshd' cat change.out
	for i in $(seq 1 60); do
		kill -0 "$pid" 2>/dev/null || break
		sleep 0.1
	done
	atf_check -s exit:1 -e ignore kill -0 "$pid"
	atf_check test -e running.sshd
	# The queued job did not start behind the change.
	atf_check -o not-match:'job 1: start web: ok' cat daemon.out

	# Signalled twice, it does not wait.
	start_daemon
	pid=$(cat daemon.pid)
	touch slow hold
	"$JGC" -c "$SOCK" service sshd restart > /dev/null 2>&1 &
	# Under way before the signals, however loaded the machine is.
	for i in $(seq 1 150); do
		"$JGC" -c "$SOCK" jobs 2>/dev/null | grep -q 'Under way' && break
		sleep 0.1
	done
	atf_check -o match:'Under way' "$JGC" -c "$SOCK" jobs
	kill "$pid"
	sleep 0.3
	kill "$pid"
	for i in $(seq 1 15); do
		kill -0 "$pid" 2>/dev/null || break
		sleep 0.1
	done
	atf_check -s exit:1 -e ignore kill -0 "$pid"
	atf_check -o match:'signalled again' cat daemon.out
	rm hold
	wait
}
stop_cleanup()
{
	stop_daemon
}

atf_test_case agent_update cleanup
agent_update_head()
{
	atf_set "descr" "A new agent is checked, put in place, and restarted"
}
agent_update_body()
{
	start_daemon
	echo old > installed-agent
	# Something that is not arcana-agent never replaces the program.
	printf '#!/bin/sh\necho hello\n' > bogus
	atf_check -s exit:1 -e match:'does not run on this host' -o ignore \
	    "$JGC" -c "$SOCK" agent-update bogus
	atf_check -o inline:'old\n' cat installed-agent
	atf_check test ! -e installed-agent.new
	# The real one does, and the one before is kept.
	atf_check -o match:'^Agent: +[0-9]+\.[0-9]+.* in place' \
	    "$JGC" -c "$SOCK" agent-update "$JGD"
	atf_check cmp -s "$JGD" installed-agent
	atf_check -o inline:'old\n' cat installed-agent.old
	atf_check test ! -e running.arcana_agent
	# With -r the service is restarted, after the reply.
	atf_check -o match:'"restarting":"true"' -o match:'replace' \
	    "$JGC" --libxo json -t -c "$SOCK" agent-update -r "$JGD"
	for i in $(seq 1 60); do
		[ -e running.arcana_agent ] && break
		sleep 0.1
	done
	atf_check test -e running.arcana_agent
}
agent_update_cleanup()
{
	stop_daemon
}

atf_test_case kernel cleanup
kernel_head()
{
	atf_set "descr" "The kernel's modules and memory; one loaded, one unloaded, kept in kld_list"
}
kernel_body()
{
	# kldload and kldunload, which take a name: one of them is in use.
	cat > fake-kldload <<EOS
#!/bin/sh
echo "kldload \$*" >> $(pwd)/kld.log
[ "\$2" = nosuch ] && { echo "kldload: can't load nosuch: No such file or directory" >&2; exit 1; }
exit 0
EOS
	cat > fake-kldunload <<EOS
#!/bin/sh
echo "kldunload \$*" >> $(pwd)/kld.log
[ "\$1" = zfs ] && { echo "kldunload: can't unload file: Device busy" >&2; exit 1; }
exit 0
EOS
	chmod +x fake-kldload fake-kldunload
	cat > fake-sysctl <<EOS
#!/bin/sh
echo "sysctl \$*" >> $(pwd)/kld.log
[ "\$1" = "kern.nosuch=1" ] && { echo "sysctl: unknown oid 'kern.nosuch'" >&2; exit 1; }
exit 0
EOS
	chmod +x fake-sysctl
	printf '# kept\nkern.ipc.somaxconn=1024\nnet.inet.ip.forwarding = 1 # routes\n' > sysctl.conf
	DAEMON_ARGS="-Q $(pwd)/fake-sysctl -O $(pwd)/sysctl.conf"
	start_daemon
	printf 'kld_list="if_bridge"\n' >> rc.conf

	# What is in the kernel is read from the kernel: the kernel itself
	# first, with the modules it holds; what its memory went to.
	atf_check -o save:k.json "$JGC" -c "$SOCK" kmod
	atf_check -o match:'"files":\[\{"id":1,"name":"kernel","path":"/boot/[^"]*kernel"' \
	    -o match:'"refs":[0-9]+,"size":[0-9]+' -o match:'"modules":\["' \
	    -o match:'"available":\[' -o match:'"kept":\["if_bridge"\]' \
	    -o match:'"memory":\{"files":[0-9]+' \
	    -o match:'"malloc_total":[0-9]+,"malloc":\[\{"name":"[^"]+","bytes":[0-9]+,"count":[0-9]+,"requests":[0-9]+\}' \
	    -o match:'"zones":\[\{"name":"[^"]+","bytes":[0-9]+,"count":[0-9]+,"requests":[0-9]+,"size":[0-9]+,"free":[0-9]+\}' \
	    cat k.json

	# Loaded: as kldload finds it, and one that is in already is no
	# failure.  Kept, it is in kld_list beside what was there.
	atf_check -o match:'done +kldload sctp$' -o match:'fake-kldload -n sctp' \
	    "$JGC" -c "$SOCK" kmod load sctp
	atf_check -o not-match:'sctp' cat rc.conf
	atf_check -o match:'done +kldload sctp \(kept\)' \
	    "$JGC" -p -c "$SOCK" kmod load sctp
	atf_check -o match:'^kld_list="if_bridge sctp"$' cat rc.conf
	# Unloaded, and out of the list; what the kernel refuses is said.
	atf_check -o match:'done +kldunload sctp \(kept\)' \
	    -o match:'fake-kldunload sctp' "$JGC" -p -c "$SOCK" kmod unload sctp
	atf_check -o match:'^kld_list="if_bridge"$' cat rc.conf
	# Kept at boot, and taken out, the kernel as it is: no kldload.
	: > kld.log
	atf_check -o match:'done +sctp into kld_list$' \
	    "$JGC" -c "$SOCK" kmod keep sctp
	atf_check -o match:'^kld_list="if_bridge sctp"$' cat rc.conf
	atf_check -o match:'done +sctp out of kld_list$' \
	    "$JGC" -c "$SOCK" kmod forget sctp
	atf_check -o match:'^kld_list="if_bridge"$' cat rc.conf
	atf_check -o empty cat kld.log
	atf_check -s exit:1 -o match:'Device busy' \
	    "$JGC" -c "$SOCK" kmod unload zfs
	atf_check -s exit:1 -o match:'No such file' \
	    "$JGC" -c "$SOCK" kmod load nosuch
	# A name is a name: no path to a file of somebody's, no option;
	# and the kernel itself stays.
	: > kld.log
	atf_check -s exit:1 -e match:'without a path' -o ignore \
	    "$JGC" -c "$SOCK" kmod load /tmp/evil.ko
	atf_check -s exit:1 -e match:'without a path' -o ignore \
	    "$JGC" -c "$SOCK" kmod load ../evil
	atf_check -s exit:1 -e match:'the kernel itself is not unloaded' \
	    -o ignore "$JGC" -c "$SOCK" kmod unload kernel
	atf_check -s exit:1 -e match:'a jail has no kernel' -o ignore \
	    "$JGC" -j web -c "$SOCK" kmod load sctp
	atf_check -o empty cat kld.log
	# In safe mode, unconfirmed, what was loaded is unloaded again;
	# one that was in already is left in.
	atf_check -o match:'queued' "$JGC" -q -s -c "$SOCK" kmod load sctp
	for i in $(seq 1 100); do
		"$JGC" -c "$SOCK" jobs | grep -q 'unconfirmed\|queued\|running' ||
		    break
		sleep 0.1
	done
	atf_check -o match:'^kldload -n sctp$' cat kld.log
	if kldstat -q -m sctp 2>/dev/null; then
		atf_check -o not-match:'kldunload' cat kld.log
	else
		atf_check -o match:'^kldunload sctp$' cat kld.log
	fi

	# The kernel's state: read from the kernel, a name or the start of
	# one; with what sysctl.conf sets at boot.
	atf_check -o save:s.json "$JGC" -c "$SOCK" sysctl kern.ostype
	atf_check -o match:'"values":\[\{"name":"kern.ostype","value":"FreeBSD","type":"string","rw":false' \
	    -o match:'"kept":\[\{"name":"kern.ipc.somaxconn","value":"1024"\},\{"name":"net.inet.ip.forwarding","value":"1"\}\]' \
	    cat s.json
	atf_check -o match:'"name":"kern.maxproc","value":"[0-9]+","type":"integer"' \
	    -o match:'"descr":"' "$JGC" -c "$SOCK" sysctl kern.maxproc
	atf_check -o match:'"name":"kern.ipc.somaxconn"' \
	    -o not-match:'"name":"vm\.' "$JGC" -c "$SOCK" sysctl kern.ipc.
	# All of it is more than a reply carries: the first, and counted.
	atf_check -o match:'"name":"kern.ostype"' -e match:'the first of [0-9]+' \
	    "$JGC" -c "$SOCK" sysctl
	# In parts, as a dump: the whole tree, nothing left out for size,
	# each part an array of its own; and a part of the tree the same.
	atf_check -o save:parts.json "$JGC" -c "$SOCK" sysctl parts
	atf_check -o match:'^[1-9][0-9]*$' sh -c 'wc -l < parts.json | tr -d " "'
	[ "$(wc -l < parts.json)" -gt 10 ] || atf_fail "the tree came in $(wc -l < parts.json) parts"
	atf_check -o match:'^\[\{"name":"kern.ostype","value":"FreeBSD"' head -1 parts.json
	atf_check -o match:'"name":"vm\.' -o match:'"name":"net\.' cat parts.json
	atf_check -o match:'^\[\{"name":"kern.ostype"[^]]*\]$' \
	    "$JGC" -c "$SOCK" sysctl parts kern.ostype
	atf_check -s exit:1 -e match:'Invalid argument' -o ignore \
	    "$JGC" -c "$SOCK" sysctl parts 'kern x'
	# Set with sysctl(8); kept, the line that set it before is replaced
	# and the rest of the file is as it was.
	: > kld.log
	atf_check -o match:'done +sysctl kern.ipc.somaxconn=2048$' \
	    "$JGC" -c "$SOCK" sysctl kern.ipc.somaxconn=2048
	atf_check -o match:'^sysctl kern.ipc.somaxconn=2048$' cat kld.log
	atf_check -o match:'^kern.ipc.somaxconn=1024$' cat sysctl.conf
	atf_check -o match:'done +sysctl kern.ipc.somaxconn=4096 \(kept\)' \
	    "$JGC" -p -c "$SOCK" sysctl kern.ipc.somaxconn=4096
	atf_check -o match:'^kern.ipc.somaxconn=4096$' -o not-match:'1024' \
	    -o match:'^# kept$' -o match:'^net.inet.ip.forwarding = 1 # routes$' \
	    cat sysctl.conf
	atf_check -o match:'done' "$JGC" -p -c "$SOCK" sysctl 'kern.corefile=/var/cores/%N core'
	atf_check -o match:'^kern.corefile="/var/cores/%N core"$' cat sysctl.conf
	atf_check -o match:'"kept":.*"name":"kern.corefile","value":"/var/cores/%N core"' \
	    -o match:'"values":\[\]' "$JGC" -c "$SOCK" sysctl kern.nothing-there
	# A name the kernel leaves out of its list is found by itself.
	if sysctl -n kern.ipc.somaxconn >/dev/null 2>&1; then
		atf_check -o match:'"values":\[\{"name":"kern.ipc.somaxconn","value":"[0-9]+"' \
		    "$JGC" -c "$SOCK" sysctl kern.ipc.somaxconn
	fi
	# What sysctl refuses is said, and is not kept.
	atf_check -s exit:1 -o match:'unknown oid' \
	    "$JGC" -p -c "$SOCK" sysctl kern.nosuch=1
	atf_check -o not-match:'nosuch' cat sysctl.conf
	# A name is a name, a value one line; no jail, no taking back.
	: > kld.log
	atf_check -s exit:1 -e match:'letters, digits' -o ignore \
	    "$JGC" -c "$SOCK" sysctl '.a=1'
	atf_check -s exit:1 -e match:'letters, digits' -o ignore \
	    "$JGC" -c "$SOCK" sysctl 'kern.x y=1'
	atf_check -s exit:1 -e match:'one line' -o ignore \
	    "$JGC" -c "$SOCK" sysctl "kern.hostname=a
b"
	atf_check -s exit:1 -e match:'not set from here' -o ignore \
	    "$JGC" -j web -c "$SOCK" sysctl kern.hostname=x
	atf_check -s exit:1 -e match:'not taken back by itself' -o ignore \
	    "$JGC" -s -c "$SOCK" sysctl kern.hostname=x
	atf_check -o empty cat kld.log

	# How the agent is reached: its listeners, and who is connected
	# now, which is at least who asks.
	atf_check -o match:'"listeners":\[\{"uri":"unix:[^"]*","transport":"unix","up":true\}\]' \
	    -o match:'"sessions":\[\{"transport":"unix"' \
	    -o match:'"seen":[0-9]+' "$JGC" -c "$SOCK" transport
	# SCTP is tried again only where the kernel has it.
	if kldstat -q -m sctp 2>/dev/null; then
		atf_check -o match:'"sctp":true' "$JGC" -c "$SOCK" transport retry
	else
		atf_check -s exit:1 -e match:'load the sctp module first' \
		    -o ignore "$JGC" -c "$SOCK" transport retry
	fi
}
kernel_cleanup()
{
	stop_daemon
}

atf_test_case l2 cleanup
l2_head()
{
	atf_set "descr" "Bridges with their spanning tree and VLANs, geneve tunnels; access and trunk ports, options, and no address on a member"
}
l2_body()
{
	# ifconfig(8): -a says what there is, the rest is logged.
	cat > fake-ifconfig <<EOS
#!/bin/sh
if [ "\$*" = "-av" ]; then cat $(pwd)/ifconfig.out; exit 0; fi
if [ "\$2" = addr ]; then
	[ "\$1" = bridge0 ] && printf '\t02:00:00:00:00:01 Vlan10 epair0a 1193 flags=0<>\n\t02:00:00:00:00:02 Vlan1 em1 0 flags=1<STATIC>\n'
	exit 0
fi
echo "\$*" >> $(pwd)/ifconfig.log
case " \$* " in *" nosuch0 "*) echo "ifconfig: BRDGADD nosuch0: No such file or directory" >&2; exit 1 ;; esac
exit 0
EOS
	chmod +x fake-ifconfig
	printf '%s\n' \
	    'bridge0: flags=1008843<UP,BROADCAST,RUNNING,SIMPLEX,MULTICAST,LOWER_UP> metric 0 mtu 1500' \
	    '	options=10<VLAN_HWTAGGING>' \
	    '	ether 58:9c:fc:10:ff:aa' \
	    '	inet 10.7.0.1 netmask 0xffffff00 broadcast 10.7.0.255' \
	    '	id 58:9c:fc:10:ff:aa priority 32768 hellotime 2 fwddelay 15' \
	    '	maxage 20 holdcnt 6 proto rstp maxaddr 2000 timeout 1200' \
	    '	root id 00:11:22:33:44:55 priority 4096 ifcost 2000 port 5' \
	    '	bridge flags=1<VLANFILTER> defuntagged=1' \
	    '	member: epair5a flags=1c7<LEARNING,DISCOVER,STP,AUTOEDGE,PTP,AUTOPTP>' \
	    '	        port 5 priority 128 path cost 2000 proto rstp' \
	    '	        role root state forwarding untagged 10' \
	    '	member: em1 flags=143<LEARNING,DISCOVER,AUTOEDGE,AUTOPTP>' \
	    '	        port 6 priority 128 path cost 20000 vlan protocol 802.1q untagged 1 tagged 10-20,30' \
	    '	member: tap3 flags=147<LEARNING,DISCOVER,STP,AUTOEDGE,AUTOPTP>' \
	    '	        port 7 priority 128 path cost 2000000 proto rstp' \
	    '	        role alternate state discarding' \
	    '	groups: bridge' \
	    '	nd6 options=9<PERFORMNUD,IFDISABLED>' \
	    'em1: flags=8863<UP,BROADCAST,RUNNING,SIMPLEX,MULTICAST> metric 0 mtu 1500' \
	    '	inet 192.0.2.7 netmask 0xffffff00 broadcast 192.0.2.255' \
	    '	inet6 fe80::1%em1 prefixlen 64 scopeid 0x2' \
	    'geneve0: flags=8843<UP,BROADCAST,RUNNING,SIMPLEX,MULTICAST> metric 0 mtu 1450' \
	    '	geneve mode: l2' \
	    '	geneve config:' \
	    '		virtual network identifier (vni): 100' \
	    '		local: 198.51.100.10:6081' \
	    '		remote: 203.0.113.1:6081' \
	    '		portrange: 49152-65535, ttl: 64, df: unset' \
	    '		ftable mode: learning, count: 2, max: 2000, timeout: 1200' \
	    'geneve1: flags=8051<UP,POINTOPOINT,RUNNING,MULTICAST> metric 0 mtu 1450' \
	    '	geneve mode: l3' \
	    '	geneve config:' \
	    '		virtual network identifier (vni): 42' \
	    '		local: [3fff::1]:6081' \
	    '		group: [ff08::db8:1]:6081, dev: em0' \
	    '		portrange: 49152-65535, ttl: inherit, dscp: inherit, df: inherit' \
	    > ifconfig.out
	start_daemon

	# A bridge: its spanning tree, and each member's place in it; who
	# is an access port and who a trunk; and a member's addresses.
	atf_check -o save:br.json "$JGC" -c "$SOCK" net bridges
	atf_check -o match:'"name":"bridge0","id":"58:9c:fc:10:ff:aa","priority":32768,"hellotime":2,"fwddelay":15' \
	    -o match:'"proto":"rstp"' -o match:'"maxage":20' \
	    -o match:'"root":"00:11:22:33:44:55","root_priority":4096,"root_cost":2000,"root_port":5' \
	    -o match:'"vlanfilter":true' -o match:'"defuntagged":1' \
	    -o match:'"is_root":false' cat br.json
	# The addresses it has learned, and behind which member each is.
	atf_check -o match:'"learned":\[\{"mac":"02:00:00:00:00:01","vlan":10,"member":"epair0a","expire":1193\},\{"mac":"02:00:00:00:00:02","vlan":1,"member":"em1","expire":0,"static":true\}\],"learned_total":2' \
	    cat br.json
	atf_check -o match:'"name":"epair5a","stp":true,"flags":\[[^]]*"stp"[^]]*\],"port":5,"priority":128,"cost":2000,"proto":"rstp","role":"root","state":"forwarding","untagged":10,"mode":"access"' \
	    -o match:'"name":"em1","stp":false,[^}]*"addresses":\["192.0.2.7"\],"port":6,[^}]*"vlanproto":"802.1q","untagged":1,"tagged":"10-20,30","mode":"trunk"' \
	    -o match:'"name":"tap3",[^}]*"role":"alternate","state":"discarding"\}' \
	    cat br.json
	# A geneve tunnel in each mode: one to a host, one to a group.
	atf_check -o save:gn.json "$JGC" -c "$SOCK" net geneve
	atf_check -o match:'"name":"geneve0","mode":"l2","id":100,"local":"198.51.100.10:6081","remote":"203.0.113.1:6081","portrange":"49152-65535","ttl":"64","df":"unset","dscpinherit":false,"external":false,"learn":true,"count":2,"maxaddr":2000,"timeout":1200,"up":true' \
	    -o match:'"name":"geneve1","mode":"l3","id":42,"local":"\[3fff::1\]:6081","group":"\[ff08::db8:1\]:6081","dev":"em0",[^}]*"ttl":"inherit","df":"inherit","dscpinherit":true' \
	    cat gn.json

	# An access port: in one VLAN untagged, and none tagged.
	atf_check -o match:'done +bridge0 access epair5a 20' \
	    "$JGC" -c "$SOCK" bridge bridge0 access epair5a 20
	atf_check -o match:'^bridge0 ifuntagged epair5a 20 iftagged epair5a none$' \
	    tail -1 ifconfig.log
	# A trunk: its VLANs tagged, with one untagged or none.
	atf_check -o ignore "$JGC" -c "$SOCK" bridge bridge0 trunk em1 10-20,30 1
	atf_check -o match:'^bridge0 iftagged em1 10-20,30 ifuntagged em1 1$' \
	    tail -1 ifconfig.log
	atf_check -o ignore "$JGC" -c "$SOCK" bridge bridge0 trunk em1 all
	atf_check -o match:'^bridge0 iftagged em1 all -ifuntagged em1$' \
	    tail -1 ifconfig.log
	atf_check -o ignore "$JGC" -c "$SOCK" bridge bridge0 vlanfilter on
	atf_check -o match:'^bridge0 vlanfilter$' tail -1 ifconfig.log
	atf_check -o ignore "$JGC" -c "$SOCK" bridge bridge0 flag tap3 -stp
	atf_check -o match:'^bridge0 -stp tap3$' tail -1 ifconfig.log
	atf_check -o ignore "$JGC" -c "$SOCK" bridge bridge0 set proto stp
	atf_check -o match:'^bridge0 proto stp$' tail -1 ifconfig.log
	atf_check -o ignore "$JGC" -c "$SOCK" bridge bridge0 ifset em1 ifpathcost 100
	atf_check -o match:'^bridge0 ifpathcost em1 100$' tail -1 ifconfig.log
	# A member taken in is brought up; what ifconfig refuses is said.
	atf_check -o ignore "$JGC" -c "$SOCK" bridge bridge0 addm tap9
	atf_check -o match:'^bridge0 addm tap9$' -o match:'^tap9 up$' \
	    tail -2 ifconfig.log
	atf_check -s exit:1 -o match:'No such file' \
	    "$JGC" -c "$SOCK" bridge bridge0 addm nosuch0
	# Kept: in rc.conf, in place of what set the same before.
	atf_check -o match:'\(kept\)' \
	    "$JGC" -p -c "$SOCK" bridge bridge0 access epair5a 20
	atf_check -o match:'^ifconfig_bridge0="ifuntagged epair5a 20 iftagged epair5a none"$' \
	    cat rc.conf
	atf_check -o ignore "$JGC" -p -c "$SOCK" bridge bridge0 vlanfilter on
	atf_check -o ignore "$JGC" -p -c "$SOCK" bridge bridge0 trunk epair5a 30-40
	atf_check -o match:'^ifconfig_bridge0="vlanfilter iftagged epair5a 30-40"$' \
	    cat rc.conf
	atf_check -o ignore "$JGC" -p -c "$SOCK" bridge bridge0 addm tap9
	atf_check -o ignore "$JGC" -p -c "$SOCK" bridge bridge0 flag tap9 stp
	atf_check -o match:'^ifconfig_bridge0="vlanfilter iftagged epair5a 30-40 addm tap9 stp tap9"$' \
	    cat rc.conf
	atf_check -o ignore "$JGC" -p -c "$SOCK" bridge bridge0 flag tap9 -stp
	atf_check -o ignore "$JGC" -p -c "$SOCK" bridge bridge0 vlanfilter off
	atf_check -o ignore "$JGC" -p -c "$SOCK" bridge bridge0 deletem tap9
	atf_check -o match:'^ifconfig_bridge0="iftagged epair5a 30-40"$' \
	    cat rc.conf
	# Addresses: one set behind a member, kept until it is set again or
	# taken away; one learned forgotten; what was learned flushed.
	atf_check -o ignore "$JGC" -p -c "$SOCK" bridge bridge0 static em1 02:00:00:00:00:aa
	atf_check -o ignore "$JGC" -p -c "$SOCK" bridge bridge0 static tap3 02:00:00:00:00:bb
	atf_check -o match:'^bridge0 static tap3 02:00:00:00:00:bb$' tail -1 ifconfig.log
	atf_check -o ignore "$JGC" -p -c "$SOCK" bridge bridge0 static epair5a 02:00:00:00:00:AA
	atf_check -o match:'^ifconfig_bridge0="iftagged epair5a 30-40 static tap3 02:00:00:00:00:bb static epair5a 02:00:00:00:00:AA"$' \
	    cat rc.conf
	atf_check -o ignore "$JGC" -p -c "$SOCK" bridge bridge0 deladdr 02:00:00:00:00:bb
	atf_check -o match:'^bridge0 deladdr 02:00:00:00:00:bb$' tail -1 ifconfig.log
	atf_check -o match:'^ifconfig_bridge0="iftagged epair5a 30-40 static epair5a 02:00:00:00:00:AA"$' \
	    cat rc.conf
	atf_check -o ignore "$JGC" -c "$SOCK" bridge bridge0 flush
	atf_check -o match:'^bridge0 flush$' tail -1 ifconfig.log
	atf_check -s exit:1 -e match:'six bytes of hex' -o ignore \
	    "$JGC" -c "$SOCK" bridge bridge0 static em1 02:00:00
	# Every word is checked before anything runs.
	: > ifconfig.log
	for bad in "access epair5a 5000" "access epair5a" "trunk em1 10-5" \
	    "trunk em1 1,2,x" "flag tap3 bogus" "set proto mstp" \
	    "set hellotime 9" "ifset em1 ifpathcost -1" "vlanfilter maybe" \
	    "addm -rf" "frobnicate em1"; do
		atf_check -s exit:1 -e not-empty -o ignore \
		    "$JGC" -c "$SOCK" bridge bridge0 $bad
	done
	atf_check -s exit:1 -e match:'not taken back by itself' -o ignore \
	    "$JGC" -s -c "$SOCK" bridge bridge0 vlanfilter on
	atf_check -o empty cat ifconfig.log

	# A member of a bridge takes no address: the bridge does.  One it
	# has may be taken away.
	atf_check -s exit:1 -o match:'em1 is a member of bridge0' \
	    "$JGC" -c "$SOCK" interface em1 add 10.1.1.1/24
	atf_check -o empty cat ifconfig.log

	# A geneve tunnel made, in the mode it will keep; its options set.
	atf_check -o match:'done +geneve5 create' "$JGC" -c "$SOCK" geneve \
	    geneve5 create mode l3 id 77 local 192.0.2.1 remote 192.0.2.2 \
	    ttl inherit df inherit
	atf_check -o match:'^geneve5 create genevemode l3 geneveid 77 genevelocal 192.0.2.1 geneveremote 192.0.2.2 genevettl inherit genevedf inherit$' \
	    tail -1 ifconfig.log
	atf_check -o ignore "$JGC" -c "$SOCK" geneve geneve0 set learn off \
	    portrange 5000-6000 group ff08::1 dev em0 dscpinherit on
	atf_check -o match:'^geneve0 -genevelearn geneveportrange 5000 6000 genevegroup ff08::1 genevedev em0 genevedscpinherit$' \
	    tail -1 ifconfig.log
	atf_check -o ignore "$JGC" -c "$SOCK" geneve geneve0 flush all
	atf_check -o match:'^geneve0 geneveflushall$' tail -1 ifconfig.log
	atf_check -o ignore "$JGC" -p -c "$SOCK" geneve geneve6 create mode l2 \
	    id 9 local 192.0.2.1 group 239.0.0.9 dev em0
	atf_check -o match:'^ifconfig_geneve6="genevemode l2 geneveid 9 genevelocal 192.0.2.1 genevegroup 239.0.0.9 genevedev em0"$' \
	    -o match:'^cloned_interfaces="geneve6"$' cat rc.conf
	atf_check -o ignore "$JGC" -p -c "$SOCK" geneve geneve6 set id 10
	atf_check -o match:'^ifconfig_geneve6="genevemode l2 genevelocal 192.0.2.1 genevegroup 239.0.0.9 genevedev em0 geneveid 10"$' \
	    cat rc.conf
	: > ifconfig.log
	for bad in "set mode l3" "create mode l4" "set id 99999999" \
	    "set ttl 300" "set df maybe" "set local nothing" "set learn" \
	    "set portrange 9" "set bogus 1"; do
		atf_check -s exit:1 -e not-empty -o ignore \
		    "$JGC" -c "$SOCK" geneve geneve0 $bad
	done
	atf_check -s exit:1 -e not-empty -o ignore \
	    "$JGC" -c "$SOCK" geneve em0 set id 5
	atf_check -o empty cat ifconfig.log
}
l2_cleanup()
{
	stop_daemon
}

atf_test_case observe cleanup
observe_head()
{
	atf_set "descr" "what runs, with what each uses; a process sent a signal and given a nice value, and which are left alone; a log read from its end, by text, and followed; the history the agent keeps by itself"
}
observe_body()
{
	mkdir log
	{
		printf 'Oct  5 12:00:01 web1 kernel: em0: link state changed to UP\n'
		printf 'Oct  5 12:00:02 web1 sshd[812]: Accepted publickey for root from 2001:db8::9 port 51234\n'
		printf '2026-10-05T12:00:03.123456+03:30 web1 cron 933 - - (root) CMD (/usr/libexec/atrun)\n'
		printf 'a line of no form\n'
		printf 'Oct  5 12:00:04 web1 syslogd: last message repeated 2 times\n'
	} > log/messages
	printf 'Oct  5 11:00:00 web1 su[77]: BAD SU alice to root on /dev/pts/1\n' > log/auth.log
	printf 'Oct  5 11:00:01 <auth.info> web1 sshd[80]: Connection closed\n' >> log/auth.log
	printf 'Sep 30 09:00:00 web1 kernel: an older day\n' | bzip2 > log/messages.0.bz2
	printf 'who\0was\0here\n' > log/utx.log
	printf 'not\0a\0text\n' > log/blob
	ln -s /etc/master.passwd log/linked
	# zpool(8): a pool 95% full, as the storage limit sees it.
	cat > fake-zpool <<'EOS'
#!/bin/sh
case "$*" in
*name,size,alloc,free,health*) printf 'tank\t1000\t950\t50\tONLINE\n' ;;
*name,size,alloc*) printf 'tank\t1000\t950\n' ;;
esac
EOS
	chmod +x fake-zpool
	DAEMON_ARGS="-v $(pwd)/log -Z $(pwd)/fake-zpool"
	start_daemon

	# What runs: this test's own sleep among it, with what top shows.
	sleep 300 &
	pid=$!
	atf_check -o save:ps.json "$JGC" -c "$SOCK" ps
	atf_check -o match:"\"pid\":$pid,\"ppid\":[0-9]+,\"user\":\"$(id -un)\",\"jid\":[0-9]+,\"state\":\"sleep\"" \
	    -o match:'"nice":0,"pri":-?[0-9]+,"threads":1,"rss":[0-9]+,"size":[0-9]+,"time":[0-9.]+,"wcpu":[0-9.]+,"cpu":[0-9.]+,"in":[0-9]+,"out":[0-9]+,"io":[0-9.]+,"start":[0-9]+' \
	    -o match:'"comm":"sleep","args":"sleep 300"' \
	    -o match:'"ncpu":[0-9]+,"elapsed":[0-9.]+' cat ps.json
	atf_check -s exit:1 -e match:'not running' -o ignore \
	    "$JGC" -j nosuchjail -c "$SOCK" ps
	# Each jail's share, added up; and one process with its files and
	# threads.
	atf_check -o match:'"jails":\[' cat ps.json
	atf_check -o save:one.json "$JGC" -c "$SOCK" ps $pid
	atf_check -o match:"^\{\"pid\":$pid,\"comm\":\"sleep\",\"files\":\[" \
	    -o match:'"threads":\[\{"tid":[0-9]+,"name":"sleep","state":"sleep","wait":"nanslp","pri":-?[0-9]+,"wcpu":[0-9.]+,"time":[0-9.]+,"cpu":[0-9]+\}\]' \
	    cat one.json
	atf_check -s exit:1 -e match:'no process 99998' -o ignore "$JGC" -c "$SOCK" ps 99998

	# A nice value, and a signal; with when it started, only that one.
	atf_check -o match:"done +renice 5 $pid\$" \
	    "$JGC" -c "$SOCK" renice $pid 5
	atf_check -o match:"\"pid\":$pid,[^}]*\"nice\":5," "$JGC" -c "$SOCK" ps
	atf_check -s exit:1 -o match:'not a process of jail' \
	    "$JGC" -j web -c "$SOCK" signal $pid
	atf_check -o match:"done +kill -STOP $pid\$" \
	    "$JGC" -c "$SOCK" signal $pid sigstop
	atf_check -o match:"\"pid\":$pid,[^}]*\"state\":\"stop\"" \
	    "$JGC" -c "$SOCK" ps
	atf_check -o match:"done +kill -CONT $pid\$" \
	    "$JGC" -c "$SOCK" signal $pid 19
	atf_check -o match:"done +kill -TERM $pid\$" \
	    "$JGC" -c "$SOCK" signal $pid
	wait $pid
	atf_check -s exit:1 -o match:"no process $pid" \
	    "$JGC" -c "$SOCK" signal $pid KILL
	# Not init, no group, not the agent, not the kernel's own; a signal
	# there is, a nice value there can be; nothing is taken back.
	for bad in 1 0 -1 x 100000; do
		atf_check -s exit:1 -e match:'by its number' -o ignore \
		    "$JGC" -c "$SOCK" signal $bad HUP
	done
	atf_check -s exit:1 -e match:'stopped as a service' -o ignore \
	    "$JGC" -c "$SOCK" signal "$(cat daemon.pid)" TERM
	atf_check -s exit:1 -e match:'no such signal' -o ignore \
	    "$JGC" -c "$SOCK" signal 4242 NOSUCH
	atf_check -s exit:1 -e match:'from -20 to 20' -o ignore \
	    "$JGC" -c "$SOCK" renice 4242 21
	atf_check -s exit:1 -e match:'not taken back' -o ignore \
	    "$JGC" -s -c "$SOCK" signal 4242 HUP
	kpid=$(ps -axo pid,flags,comm | awk '$3 == "idle" { print $1; exit }')
	if [ -n "$kpid" ] && [ "$kpid" -gt 1 ]; then
		atf_check -s exit:1 -o match:"the kernel's own" \
		    "$JGC" -c "$SOCK" signal "$kpid" CONT
	fi

	# A log: messages when none is named, each line taken apart; the
	# logs there are, without what is packed or is not a file.
	atf_check -o save:log.json "$JGC" -c "$SOCK" log
	atf_check -o match:'"name":"messages"' \
	    -o match:'"files":\[\{"name":"auth.log","size":[0-9]+,"mtime":[0-9]+\},\{"name":"blob",[^}]*\},\{"name":"messages",' \
	    -o not-match:'linked' -o not-match:'utx' \
	    -o match:'\{"time":"Oct  5 12:00:01","host":"web1","tag":"kernel","text":"em0: link state changed to UP"\}' \
	    -o match:'\{"time":"Oct  5 12:00:02","host":"web1","pid":"812","tag":"sshd","text":"Accepted publickey for root from 2001:db8::9 port 51234"\}' \
	    -o match:'\{"time":"2026-10-05T12:00:03.123456\+03:30","host":"web1","tag":"cron","pid":"933","text":"\(root\) CMD \(/usr/libexec/atrun\)"\}' \
	    -o match:'\{"text":"a line of no form"\}' \
	    -o match:'"tag":"syslogd","text":"last message repeated 2 times"' \
	    cat log.json
	size=$(wc -c < log/messages | tr -d ' ')
	atf_check -o match:"\"size\":$size,\"position\":$size" cat log.json
	# By text, in either case; the last of them only; another log.
	atf_check -o match:'"lines":\[\{[^}]*"tag":"sshd"[^}]*\}\]' \
	    "$JGC" -c "$SOCK" log messages PUBLICKEY
	atf_check -o match:'"lines":\[\{"text":"a line of no form"\},\{[^}]*syslogd[^}]*\}\]' \
	    "$JGC" -c "$SOCK" log -o 2
	atf_check -o match:'"name":"auth.log"' -o match:'"tag":"su","text":"BAD SU' \
	    -o match:'"time":"Oct  5 11:00:01","level":"auth.info","host":"web1","pid":"80","tag":"sshd"' \
	    "$JGC" -c "$SOCK" log auth.log
	# A packed log is unpacked to be read; the kernel's own messages.
	atf_check -o match:'"name":"messages.0.bz2","size":[0-9]+,"mtime":[0-9]+,"packed":true' \
	    -o match:'"tag":"kernel","text":"an older day"' \
	    "$JGC" -c "$SOCK" log messages.0.bz2
	if sysctl -n kern.msgbuf 2>/dev/null | grep -q .; then
		atf_check -o match:'"name":"@dmesg","lines":\[\{"text":"' "$JGC" -c "$SOCK" log @dmesg
	else
		atf_check -s exit:1 -e match:'kern.msgbuf' -o ignore "$JGC" -c "$SOCK" log @dmesg
	fi
	atf_check -s exit:1 -e match:'@dmesg or @audit' -o ignore "$JGC" -c "$SOCK" log @nosuch
	# Followed: only what was written since, a line half written not
	# yet; a file shorter than it was is read again from its start.
	atf_check -o match:'"lines":\[\]' -o match:"\"position\":$size" \
	    "$JGC" -c "$SOCK" log -f "$size"
	printf 'Oct  5 12:00:09 web1 ntpd[5]: time set\nOct  5 12:00:10 web1 half' >> log/messages
	atf_check -o match:'"lines":\[\{[^}]*"tag":"ntpd","text":"time set"\}\]' \
	    -o match:"\"position\":$((size + 39))" \
	    "$JGC" -c "$SOCK" log -f "$size"
	printf 'Oct  5 13:00:00 web1 newsyslog[9]: logfile turned over\n' > log/messages
	atf_check -o match:'"rotated":true' -o match:'"tag":"newsyslog"' \
	    "$JGC" -c "$SOCK" log -f "$size"
	# Only a file of the log directory, by its name, and not a packed one.
	for bad in ../rc.conf .hidden a/b; do
		atf_check -s exit:1 -e match:'named' -o ignore \
		    "$JGC" -c "$SOCK" log "$bad"
	done
	atf_check -s exit:1 -e match:'linked' -o ignore \
	    "$JGC" -c "$SOCK" log linked
	atf_check -s exit:1 -e match:'nosuch' -o ignore \
	    "$JGC" -c "$SOCK" log nosuch
	atf_check -s exit:1 -e match:'not a text' -o ignore \
	    "$JGC" -c "$SOCK" log blob

	# What happened: numbered from one, the last of them kept; none
	# after a number there is none after.
	atf_check -o match:'^\{"last":[0-9]+,"first":[0-9]+,"kept":512,"events":\[' \
	    "$JGC" -c "$SOCK" events
	atf_check -o match:'"events":\[\]' "$JGC" -c "$SOCK" events 99999999

	# The history is kept without being asked for: one sample after a
	# second, and none after the time of the last.
	sleep 2
	atf_check -o save:h.json "$JGC" -c "$SOCK" history
	atf_check -o match:'"step":5,"keep":720,"bytes":[1-9][0-9]+,"ncpu":[0-9]+,"mem_total":[1-9][0-9]+,"swap_total":[0-9]+' \
	    -o match:'"fields":\["t","cpu","load","mem","swap","rx","tx","read","write"\]' \
	    -o match:'"nets":\[("[A-Za-z0-9_.:-]+",?)*\],"disks":\[("[a-z0-9]+",?)*\]' \
	    -o match:'"samples":\[\[[0-9]+,[0-9.]+,[0-9.]+,[1-9][0-9]+,[0-9]+,[0-9]+,[0-9]+,[0-9]+,[0-9]+[],]' \
	    cat h.json
	# A sample is as wide as its fields, the interfaces and the disks.
	atf_check -o inline:'ok\n' awk '{
		nn = 0; nd = 0
		if (match($0, /"nets":\[[^]]*\]/)) { s = substr($0, RSTART, RLENGTH); nn = gsub(/"[^"]*"/, "", s) - 1 }
		if (match($0, /"disks":\[[^]]*\]/)) { s = substr($0, RSTART, RLENGTH); nd = gsub(/"[^"]*"/, "", s) - 1 }
		match($0, /"samples":\[\[[^]]*\]/); s = substr($0, RSTART, RLENGTH)
		print (gsub(/,/, "", s) + 1 == 9 + 2 * nn + 2 * nd) ? "ok" : "width " nn " " nd
	}' h.json
	last=$(sed -E 's/.*\[([0-9]+),[^]]*\]\]\}.*/\1/' h.json)
	# The sampler may have looked again since; what comes is only that.
	atf_check -o save:after.json "$JGC" -c "$SOCK" history "$last"
	atf_check -o inline:'ok\n' awk -v last="$last" '{
		match($0, /"samples":\[.*\]/); s = substr($0, RSTART + 11, RLENGTH - 12)
		n = split(s, a, /\],?\[?/); ok = 1
		for (i = 1; i <= n; i++) { sub(/^\[/, "", a[i]); split(a[i], f, ","); if (a[i] != "" && f[1] + 0 <= last) ok = 0 }
		print ok ? "ok" : "old " s
	}' after.json
	# How it samples is set, and written down for the next start: fewer
	# kept are the newest; none kept is no sampling and no memory.
	# A limit crossed is an event, once, until it is crossed back; told
	# to those who follow the events the moment it is made.
	"$JGC" -c "$SOCK" events -f > follow.out 2>&1 &
	echo $! > follow.pid
	sleep 0.5
	atf_check -o match:'"limits":\{"cpu":1,"mem":1,"swap":0,"storage":90\}' \
	    "$JGC" -c "$SOCK" history set 1 20 1 1 0
	sleep 3
	kill "$(cat follow.pid)"
	atf_check -o match:'^\{"n":[0-9]+,"t":[0-9]+,"kind":"threshold","data":\{"what":"mem","value":[0-9]+,"limit":1,"over":true\}\}$' \
	    cat follow.out
	atf_check -o match:'"kind":"threshold","data":\{"what":"mem","value":[0-9]+,"limit":1,"over":true\}' \
	    "$JGC" -c "$SOCK" events
	atf_check -o inline:'1\n' sh -c "$JGC -c $SOCK events | grep -o '\"what\":\"mem\"' | wc -l | tr -d ' '"
	atf_check -o match:'^cpu=1$' -o match:'^mem=1$' cat history.conf
	# A pool over the storage limit: an event and a storage fault
	# (Mplify 119's resource faults); none as the limit, cleared.
	atf_check -o match:'"kind":"threshold","data":\{"what":"storage","name":"tank","value":95,"limit":90,"over":true\}' \
	    "$JGC" -c "$SOCK" events
	atf_check -o match:'"type":"storage","severity":"Major","was":"Major","object":"tank","by":"sampler","description":"tank 95% full, over 90%","cleared":false' \
	    "$JGC" -c "$SOCK" sdwan
	atf_check -o match:'"limits":\{"cpu":90,"mem":90,"swap":50,"storage":0\}' \
	    "$JGC" -c "$SOCK" history set 1 20 90 90 50 0
	sleep 2
	atf_check -o match:'"what":"storage","name":"tank","limit":0,"over":false' \
	    "$JGC" -c "$SOCK" events
	atf_check -o match:'"object":"tank","by":"sampler",[^}]*"cleared":true' \
	    "$JGC" -c "$SOCK" sdwan
	atf_check -o match:'^storage=0$' cat history.conf
	atf_check -s exit:1 -e match:'a limit is 0 to 100' -o ignore \
	    "$JGC" -c "$SOCK" history set 1 20 90 90 50 101
	atf_check -o match:'"limits":\{"cpu":90,"mem":90,"swap":50,"storage":0\}' \
	    "$JGC" -c "$SOCK" history set 1 20 90 90 50
	atf_check -o match:'"step":1,"keep":2,"bytes":[1-9][0-9]*,' \
	    "$JGC" -c "$SOCK" history set 1 2
	atf_check -o match:'^step=1$' -o match:'^keep=2$' cat history.conf
	sleep 4
	atf_check -o save:h2.json "$JGC" -c "$SOCK" history
	atf_check -o inline:'2\n' sh -c "grep -o '\[[0-9][0-9,.]*\]' h2.json | wc -l | tr -d ' '"
	# The kernel's messages, refused to one not root, say what lets it.
	if [ "$(id -u)" != 0 ] && [ "$(sysctl -n security.bsd.unprivileged_read_msgbuf)" = 0 ]; then
		atf_check -s exit:1 -e match:'unprivileged_read_msgbuf=1' -o ignore \
		    "$JGC" -c "$SOCK" log @dmesg
	fi
	# All there: the older are thinned, not dropped; the newest half
	# keeps every look, the oldest are further apart.
	atf_check -o ignore "$JGC" -c "$SOCK" history set 1 8
	sleep 14
	atf_check -o save:h3.json "$JGC" -c "$SOCK" history
	grep -o '\[[0-9][0-9]*,' h3.json | tr -d '[,' > t3
	atf_check -o inline:'8\n' sh -c "wc -l < t3 | tr -d ' '"
	atf_check -o inline:'ok\n' awk 'NR > 1 { g[NR - 1] = $1 - p } { p = $1 }
	    END { print (g[1] >= 2 && g[7] <= 2 && g[1] > g[7]) ? "ok" : "gaps " g[1] " " g[7] }' t3
	atf_check -o match:'"step":60,"keep":0,"bytes":0,' -o match:'"samples":\[\]' \
	    "$JGC" -c "$SOCK" history set 60 0
	sleep 2
	atf_check -o match:'"samples":\[\]' "$JGC" -c "$SOCK" history
	atf_check -o match:'"step":2,"keep":10,' "$JGC" -c "$SOCK" history set 2 10
	# The limits of one device or jail each: kept, said, refused when
	# they are not one; an empty list takes them away.
	atf_check -o match:'"rules":\[\{"kind":"net","name":"lo1","limit":1000,"over":false\},\{"kind":"jail-cpu","name":"web","limit":80,"over":false\},\{"kind":"jail-mem","name":"web","limit":1073741824,"over":false\}\]' \
	    -o match:'"racct":(true|false)' -o match:'"jails":\[' \
	    "$JGC" -c "$SOCK" history set 2 10 rules 'net:lo1=1000,jail-cpu:web=80,jail-mem:web=1073741824'
	atf_check -o match:'^rule=net:lo1=1000$' -o match:'^rule=jail-mem:web=1073741824$' \
	    cat history.conf
	atf_check -s exit:1 -e match:'net:, disk:, jail-cpu: or jail-mem:' -o ignore \
	    "$JGC" -c "$SOCK" history set 2 10 rules 'cpu:all=5'
	atf_check -s exit:1 -e match:'a rule is' -o ignore \
	    "$JGC" -c "$SOCK" history set 2 10 rules 'net:lo1=-3'
	atf_check -o match:'^rule=net:lo1=1000$' cat history.conf
	atf_check -o match:'"rules":\[\]' "$JGC" -c "$SOCK" history set 2 10 rules ''
	atf_check -o not-match:'^rule=' cat history.conf
	sleep 3
	atf_check -o match:'"samples":\[\[' "$JGC" -c "$SOCK" history
	atf_check -s exit:1 -e ignore -o ignore "$JGC" -c "$SOCK" history set 3601 10
	atf_check -s exit:1 -e ignore -o ignore "$JGC" -c "$SOCK" history set 5 5001
	atf_check -s exit:1 -e ignore -o ignore "$JGC" -c "$SOCK" history set 0 10
	# At its next start the agent samples as it was told.
	sleep 3
	stop_daemon
	sleep 1
	# The samples were written down when it stopped, and are back.
	atf_check -o match:'^# arcana-agent samples' cat history.conf.samples
	start_daemon
	atf_check -o match:'"step":2,"keep":10,' -o match:'"samples":\[\[' \
	    "$JGC" -c "$SOCK" history
}
observe_cleanup()
{
	stop_daemon
}

atf_test_case fw_trace cleanup
fw_trace_head()
{
	atf_set "descr" "packets followed through the firewall by the kernel: dtrace(1) asked for ipfw:::rule-matched of one address, and what it tells read"
}
fw_trace_body()
{
	# dtrace(1): the script it is given is kept, two packets told.
	mkdir tools
	cat > tools/dtrace <<EOS
#!/bin/sh
cat "\$3" > $(pwd)/script.d
echo 'P 12 0 192.0.2.7 198.51.100.1 6 40000 443 100 em0 0'
echo 'P 13 1 198.51.100.1 192.0.2.7 6 443 40000 65535 em0 1'
EOS
	chmod +x tools/dtrace
	DAEMON_ARGS="-2 $(pwd)/tools"
	start_daemon
	atf_check -o match:'"packets":\[\{"ms":12,"verdict":"pass","family":"inet","source":"192.0.2.7","destination":"198.51.100.1","proto":6,"sport":40000,"dport":443,"rule":100,"interface":"em0","direction":"out"\},\{"ms":13,"verdict":"deny",[^}]*"rule":65535,[^}]*"direction":"in"\}\],"seconds":5,"limit":100' \
	    "$JGC" -c "$SOCK" ipfw trace 192.0.2.7 5
	# Of that address only, as the kernel holds it, and no longer.
	atf_check -o match:'^ipfw:::rule-matched$' -o match:'arg1 == 2 && \(\(\(\(uint32_t \*\)arg2\)\[0\] == [0-9]+U\) \|\| \(\(\(uint32_t \*\)arg3\)\[0\] == [0-9]+U\)\)' \
	    -o match:'^tick-5s$' -o match:'^/n >= 100/$' cat script.d
	atf_check -o ignore "$JGC" -c "$SOCK" ipfw trace 2001:db8::7 1 3
	atf_check -o match:'arg1 == 28 && \(\(\(\(uint32_t \*\)arg2\)\[0\] == [0-9]+U && .*\[3\] == [0-9]+U\)' \
	    -o match:'^tick-1s$' -o match:'^/n >= 3/$' -o match:'inet_ntoa6' cat script.d
	atf_check -s exit:1 -e match:'IPv4 or IPv6 address' "$JGC" -c "$SOCK" ipfw trace nonsense
	atf_check -s exit:1 -e ignore "$JGC" -c "$SOCK" ipfw trace 192.0.2.7 61
}
fw_trace_cleanup()
{
	stop_daemon
}

atf_test_case firewall_aliases cleanup
firewall_aliases_head()
{
	atf_set "descr" "ipfw aliases: an address list made a table, a port" \
	    "list and a value written into the rules that name them; a" \
	    "rule kept with its own words, written again when an alias it" \
	    "names changes; the kept file loadable as it is"
}
firewall_aliases_body()
{
	# Rule 1000 is in the kernel's set 0; scripts are logged.
	cat > fake-ipfw <<EOS
#!/bin/sh
echo "ipfw \$*" >> $(pwd)/ipfw.log
case "\$*" in
"-S list 1000") echo "01000 set 0 allow tcp from table(lan) to me 80,443 in via vtnet0" ;;
"-S list "*) echo "ipfw: rule \$3 does not exist" >&2 ;;
"-n /dev/stdin") sed -e 's/^add //' ;;
"-q /dev/stdin") cat >> $(pwd)/ipfw.log ;;
esac
exit 0
EOS
	chmod +x fake-ipfw
	mkdir fw
	DAEMON_ARGS="-h $(pwd)/fake-ipfw -J $(pwd)/fw/ipfw.rules"
	start_daemon

	# An address list: a table of its name, now and kept.
	atf_check -o match:'done' "$JGC" -c "$SOCK" ipfw alias lan addr \
	    10.0.0.0/8 192.168.1.0/24
	atf_check -o match:'^ipfw -q table lan flush$' \
	    -o match:'^ipfw -q table lan add 10.0.0.0/8$' \
	    -o match:'^ipfw -q table lan add 192.168.1.0/24$' cat ipfw.log
	atf_check -o match:'done' "$JGC" -c "$SOCK" ipfw alias web ports 80,443
	atf_check -o match:'done' "$JGC" -c "$SOCK" ipfw alias wan value vtnet0
	# A rule by its aliases: the table named, the others written in.
	: > ipfw.log
	atf_check -o match:'done' "$JGC" -c "$SOCK" -p ipfw add 1000 allow \
	    tcp from '$lan' to me '$web' in via '$wan'
	# Added now, then kept: the kernel asked first for set 0's rules, to
	# keep them too when none is kept yet (none here).
	atf_check -o inline:'ipfw -q add 1000 allow tcp from table(lan) to me 80,443 in via vtnet0\nipfw -S list\n' \
	    cat ipfw.log
	atf_check -o match:'^#arcana alias lan addr$' \
	    -o match:'^table lan create type addr$' \
	    -o match:'^table lan add 10.0.0.0/8$' \
	    -o match:'^#arcana alias web ports 80,443$' \
	    -o match:'^#arcana alias wan value vtnet0$' \
	    -o match:'^#arcana add 01000 allow tcp from \$lan to me \$web in via \$wan$' \
	    -o match:'^add 01000 allow tcp from table\(lan\) to me 80,443 in via vtnet0$' \
	    cat fw/ipfw.rules
	# Read back: the aliases, and the rule's own words beside it.
	atf_check -o match:'"aliases":\[' \
	    -o match:'\{"name":"lan","kind":"addr","value":"10.0.0.0/8 192.168.1.0/24"\}' \
	    -o match:'\{"name":"web","kind":"ports","value":"80,443"\}' \
	    -o match:'"num":1000,"text":"allow tcp from table\(lan\) to me 80,443 in via vtnet0","source":"allow tcp from \$lan to me \$web in via \$wan"' \
	    "$JGC" -c "$SOCK" net ipfw
	# A port list changed: the rule written again, kept and now.
	: > ipfw.log
	atf_check -o match:'done' "$JGC" -c "$SOCK" ipfw alias web ports 8080
	atf_check -o match:'^add 01000 allow tcp from table\(lan\) to me 8080 in via vtnet0$' \
	    -o not-match:'80,443' cat fw/ipfw.rules
	# The kernel's rule 1000, told by its words as put in before, changed
	# by one checked script of ipfw's.
	atf_check -o match:'^ipfw -S list 1000$' -o match:'^ipfw -n /dev/stdin$' \
	    -o match:'^set 0 delete 1000$' \
	    -o match:'^add 1000 allow tcp from table\(lan\) to me 8080 in via vtnet0$' \
	    -o not-match:'^ipfw -q delete' cat ipfw.log
	# The address list changed: its table, no rule.
	: > ipfw.log
	atf_check -o match:'done' "$JGC" -c "$SOCK" ipfw alias lan addr 10.1.0.0/16
	atf_check -o not-match:'add 1000' -o match:'table lan add 10.1.0.0/16' cat ipfw.log
	atf_check -o match:'^table lan add 10.1.0.0/16$' -o not-match:'192.168' \
	    cat fw/ipfw.rules
	# What a rule names is not deleted; one there is not is said.
	atf_check -s exit:1 -o match:'rule 1000 names \$web' \
	    sh -c '"$0" -c "$1" ipfw alias web delete 2>&1' "$JGC" "$SOCK"
	atf_check -s exit:1 -o match:'\$nope: there is no such alias' \
	    sh -c '"$0" -c "$1" ipfw add 1001 allow ip from \$nope to any 2>&1' \
	    "$JGC" "$SOCK"
	atf_check -s exit:1 -o match:'a port list is ports' \
	    sh -c '"$0" -c "$1" ipfw alias web ports http 2>&1' "$JGC" "$SOCK"
	# The kept rules as text: a rule written with aliases by hand is
	# kept with its own words and as ipfw reads it.
	"$JGC" -c "$SOCK" ipfw rules > text
	echo 'add 02000 deny ip from $lan to any via $wan' >> text
	atf_check -o ignore "$JGC" -c "$SOCK" ipfw rules -w text
	atf_check -o match:'^#arcana add 02000 deny ip from \$lan to any via \$wan$' \
	    -o match:'^add 02000 deny ip from table\(lan\) to any via vtnet0$' \
	    cat fw/ipfw.rules
	# Deleted kept: the rule and its own words.
	atf_check -o match:'done' "$JGC" -c "$SOCK" -p ipfw delete 1000
	atf_check -o not-match:'01000' cat fw/ipfw.rules
	atf_check -o match:'done' "$JGC" -c "$SOCK" ipfw keep delete 2000
	atf_check -o match:'done' "$JGC" -c "$SOCK" ipfw alias web delete
	atf_check -o not-match:'alias web' cat fw/ipfw.rules
}
firewall_aliases_cleanup()
{
	[ -f daemon.pid ] && kill "$(cat daemon.pid)" 2>/dev/null
	true
}

atf_test_case firewall cleanup
firewall_head()
{
	atf_set "descr" "ipfw: rules read with sets and counters; a rule added and deleted, now and kept; the kept rules applied through set 1, and taken back unconfirmed"
}
firewall_body()
{
	# ipfw(8): what it has is canned, what it is told is logged; a file
	# it is given is read, and refused when it has the word bogus.
	cat > fake-ipfw <<EOS
#!/bin/sh
echo "ipfw \$*" >> $(pwd)/ipfw.log
case "\$*" in
"-S show")
	printf '00005     12      900 set 0 skipto 500 ip from any to any out\n'
	printf '00200      0        0 set 0 check-state :default\n'
	printf '01001      3      180 set 0 allow tcp from any to me6 22 in\n'
	printf '# DISABLED 01001      0        0 set 1 allow tcp from any to me6 2222 in\n'
	printf '65535     99     9999 set 31 deny ip from any to any\n' ;;
"table all info") printf -- '--- table(T46), set(0) ---\n kindex: 1, type: addr\n references: 2, valtype: legacy\n' ;;
"table T46 list") printf -- '--- table(T46), set(0) ---\n10.0.0.0/8 0\n2001:db8::/32 0\n' ;;
"pipe show") printf '00001:  10.000 Mbit/s    0 ms burst 0\n' ;;
"-q table T46 add 10.9.9.9") echo "ipfw: Adding record failed: record already exists" >&2; exit 1 ;;
"-D show")
	printf '## Dynamic rules (2 136):\n'
	printf '01001      7      560 (298s) STATE tcp 2001:db8::9 51234 <-> 2001:db8::1 22 :default\n'
	printf '06101     12     1440 (3s) STATE udp 10.0.0.5 5353 <-> 10.0.0.1 53 :default\n' ;;
"-n -q "*) grep -q bogus "\$3" && { echo "ipfw: line 2: bad command bogus" >&2; exit 1; } ;;
"-q add "*" refuse "*) echo "ipfw: unrecognised option refuse" >&2; exit 1 ;;
"-q add "*) n="\${*#-q add }"; printf '%05d set 0 %s\n' "\${n%% *}" "\${n#* }" >> $(pwd)/live.rules ;;
"list 1001") printf '01001 allow tcp from any to me6 22 in\n' ;;
# set 0's rules, as they are now: live.rules.
"-S list") [ -f $(pwd)/live.rules ] && cat $(pwd)/live.rules ;;
"-S list "*) if [ -f $(pwd)/live.rules ] && grep -qE "^0*\$3 " $(pwd)/live.rules; then grep -E "^0*\$3 " $(pwd)/live.rules; else echo "ipfw: rule \$3 does not exist" >&2; fi ;;
# The words as ipfw writes them back (all is ip), a line out for each
# line in, as ipfw does: it writes while it reads.
"-n /dev/stdin") tee $(pwd)/n.in | sed -e '/bogus/q' -e 's/^add \([0-9]*\) /\1 /' -e 's/ all / ip /g' -e 's/^\([0-9]*\) all /\1 ip /' | grep -v bogus
	! grep -q bogus $(pwd)/n.in || { echo "Line 1: invalid action bogus" >&2; exit 65; } ;;
# A script, a line at a time as ipfw does: stopped at what it refuses.
"-q /dev/stdin") cat > $(pwd)/script.in; cat $(pwd)/script.in >> $(pwd)/script.log; touch $(pwd)/live.rules
	while IFS= read -r l; do
		case "\$l" in
		*refuse*) echo "ipfw: unrecognised option refuse" >&2; exit 1 ;;
		"set 0 delete "*) grep -vE "^0*\${l#set 0 delete } set 0 " $(pwd)/live.rules > $(pwd)/live.tmp; mv $(pwd)/live.tmp $(pwd)/live.rules ;;
		"add "*) n="\${l#add }"; printf '%05d set 0 %s\n' "\${n%% *}" "\${n#* }" >> $(pwd)/live.rules ;;
		esac
	done < $(pwd)/script.in
	sort -n -o $(pwd)/live.rules $(pwd)/live.rules ;;
"-q "*.arcana-load) cat "\$2" > $(pwd)/loaded.rules; grep -q fails "\$2" && { echo "ipfw: line 1: getsockopt(IP_FW_XADD): Invalid argument" >&2; exit 1; } ;;
esac
exit 0
EOS
	chmod +x fake-ipfw
	DAEMON_ARGS="-h $(pwd)/fake-ipfw -J $(pwd)/fw/ipfw.rules"
	start_daemon

	# What the firewall has: each rule with its set and counters, one
	# of a disabled set marked so; no kept rules yet.
	atf_check -o save:fw.json "$JGC" -c "$SOCK" net ipfw
	atf_check -o match:'"loaded":true' \
	    -o match:'\{"num":5,"pkts":12,"bytes":900,"set":0,"text":"skipto 500 ip from any to any out"\}' \
	    -o match:'\{"num":1001,"pkts":0,"bytes":0,"set":1,"text":"allow tcp from any to me6 2222 in","disabled":true\}' \
	    -o match:'"tables":\[\{"name":"T46","type":"addr","entries":\[\{"key":"10.0.0.0/8","value":"0"\},\{"key":"2001:db8::/32","value":"0"\}\],"count":2\}\]' \
	    -o match:'"pipes":\["00001:  10.000 Mbit/s    0 ms burst 0"\]' \
	    -o match:'"kept":\[\]' \
	    -o match:'"file":false' cat fw.json
	# The dynamic rules: the connections let through, each with its
	# rule, its counters and how long it still lives.
	atf_check -o match:'"dynamic_total":2,"dynamic":\[\{"num":1001,"pkts":7,"bytes":560,"ttl":298,"kind":"STATE","flow":"tcp 2001:db8::9 51234 <-> 2001:db8::1 22 :default"\}' \
	    -o match:'\{"num":6101,"pkts":12,"bytes":1440,"ttl":3,"kind":"STATE","flow":"udp 10.0.0.5 5353 <-> 10.0.0.1 53 :default"\}' \
	    cat fw.json

	# A rule added now, and deleted now.
	atf_check -o match:'done +ipfw add 1002 allow tcp from any to me6 80 in \(now\)' \
	    "$JGC" -c "$SOCK" ipfw add 1002 allow tcp from any to me6 80 in
	atf_check -o match:'^ipfw -q add 1002 allow tcp from any to me6 80 in$' \
	    tail -1 ipfw.log
	atf_check test ! -e fw/ipfw.rules
	atf_check -o inline:'01002 set 0 allow tcp from any to me6 80 in\n' cat live.rules
	# Deleted by a script of ipfw's, set 0's alone.
	atf_check -o ignore "$JGC" -c "$SOCK" ipfw delete 1002
	atf_check -o match:'^ipfw -q /dev/stdin$' tail -1 ipfw.log
	atf_check -o inline:'set 0 delete 1002\n' cat script.log
	atf_check -o empty cat live.rules
	# A rule changed as one: ipfw reads the new one first, then one
	# script deletes the number and adds the new rule; one the kernel
	# does not take after all leaves the number as it was listed.
	printf '01001 set 0 allow tcp from any to me6 22 in\n' > live.rules
	: > ipfw.log
	: > script.log
	atf_check -s exit:1 -o match:'did not take it: .*refuse; rule 1001 was put back as it was' \
	    "$JGC" -c "$SOCK" ipfw replace 1001 1001 allow tcp from any to me6 22 refuse in
	atf_check -o inline:'ipfw -S list 1001
ipfw -n /dev/stdin
ipfw -q /dev/stdin
ipfw -q /dev/stdin
' cat ipfw.log
	atf_check -o inline:'set 0 delete 1001
add 1001 allow tcp from any to me6 22 refuse in
set 0 delete 1001
add 1001 allow tcp from any to me6 22 in
' cat script.log
	atf_check -o inline:'01001 set 0 allow tcp from any to me6 22 in\n' cat live.rules
	atf_check -s exit:1 -e match:'with no quotes' -o ignore \
	    "$JGC" -c "$SOCK" ipfw replace 1001 1001 allow ip from any to any via '"wg[0-1]"'
	: > ipfw.log
	atf_check -o match:'done +ipfw replace 1001 1001 allow ip from any to any via wg\[0-1\]' \
	    "$JGC" -c "$SOCK" ipfw replace 1001 1001 allow ip from any to any via 'wg[0-1]'
	atf_check -o inline:'01001 set 0 allow ip from any to any via wg[0-1]\n' cat live.rules
	# Words ipfw reads that are not the rule's: refused, though it is
	# the number's only one.
	atf_check -s exit:1 -o match:'rule 1001 now is "allow ip from any to any via wg\[0-1\]", not these words' \
	    "$JGC" -c "$SOCK" ipfw delete 1001 deny ip from any to any
	atf_check -o inline:'01001 set 0 allow ip from any to any via wg[0-1]\n' cat live.rules

	# Two rules of one number: one deleted by its words, the other
	# staying; the number alone refused, nothing touched.  Set 0's are
	# the rules Arcana changes: SD-WAN's set 30 rule of the same number
	# stays, as ipfw is told "set 0 delete".
	printf '00700 set 0 allow tcp from any to me 80 in\n00700 set 0 allow tcp from any to me 443 in\n00700 set 30 count ip from any to any\n' > live.rules
	: > script.log
	atf_check -s exit:1 -o match:'2 rules 700 now: say which, by its words; nothing was changed' \
	    "$JGC" -c "$SOCK" ipfw delete 700
	atf_check -o empty cat script.log
	atf_check -o match:'done +ipfw delete 700 allow tcp from any to me 80 in' \
	    "$JGC" -c "$SOCK" ipfw delete 700 allow tcp from any to me 80 in
	atf_check -o inline:'set 0 delete 700\nadd 700 allow tcp from any to me 443 in\n' cat script.log
	atf_check -o inline:'00700 set 0 allow tcp from any to me 443 in\n00700 set 30 count ip from any to any\n' cat live.rules
	# One of two replaced, told by its words (--was): the other stays;
	# with neither words nor a single rule, refused.
	printf '00900 set 0 allow tcp from any to me 80 in\n00900 set 0 allow tcp from any to me 443 in\n' > live.rules
	atf_check -s exit:1 -o match:'2 rules 900 now: say which' \
	    "$JGC" -c "$SOCK" ipfw replace 900 900 deny ip from any to any
	atf_check -o match:'done +ipfw replace 900 901 allow tcp from any to me 8443 in' \
	    "$JGC" -c "$SOCK" ipfw replace 900 901 allow tcp from any to me 8443 in --was allow tcp from any to me 443 in
	atf_check -o inline:'00900 set 0 allow tcp from any to me 80 in\n00901 set 0 allow tcp from any to me 8443 in\n' cat live.rules
	# Rules moved on by one to make room, the farthest first; refused
	# whole when a number is not free by the time it is reached.
	printf '00800 set 0 count ip from any to any\n00801 set 0 count tcp from any to any\n00802 set 0 count udp from any to any\n' > live.rules
	: > script.log
	atf_check -s exit:1 -o match:'802 has a rule by the time 801 is moved there: nothing was changed' \
	    "$JGC" -c "$SOCK" ipfw renumber 801 802 802 803
	atf_check -o empty cat script.log
	atf_check -o match:'done +ipfw renumber 802 803 801 802 800 801' \
	    "$JGC" -c "$SOCK" ipfw renumber 802 803 801 802 800 801
	atf_check -o inline:'00801 set 0 count ip from any to any\n00802 set 0 count tcp from any to any\n00803 set 0 count udp from any to any\n' cat live.rules
	atf_check -o inline:'add 803 count udp from any to any\nset 0 delete 802\nadd 802 count tcp from any to any\nset 0 delete 801\nadd 801 count ip from any to any\nset 0 delete 800\n' cat script.log
	rm live.rules
	# Kept only: into the file, in the order of the numbers.
	: > ipfw.log
	atf_check -o match:'\(kept\)' \
	    "$JGC" -c "$SOCK" ipfw keep add 1001 allow tcp from any to me6 22 in
	atf_check -o ignore "$JGC" -c "$SOCK" ipfw keep add 5 skipto 500 all from any to any out
	atf_check -o ignore "$JGC" -c "$SOCK" ipfw keep add 999 deny log all from any to any
	atf_check -o ignore "$JGC" -c "$SOCK" ipfw keep add 200 check-state
	atf_check -o inline:'add 00005 skipto 500 all from any to any out
add 00200 check-state
add 00999 deny log all from any to any
add 01001 allow tcp from any to me6 22 in
' cat fw/ipfw.rules
	atf_check -o not-match:'ipfw -q add' cat ipfw.log
	# Both: now, and kept.
	atf_check -o match:'\(now, and kept\)' \
	    "$JGC" -p -c "$SOCK" ipfw add 1002 allow tcp from any to me6 443 in
	atf_check -o match:'^ipfw -q add 1002 allow' tail -1 ipfw.log
	atf_check -o match:'^add 01002 allow tcp from any to me6 443 in$' cat fw/ipfw.rules
	atf_check -o ignore "$JGC" -p -c "$SOCK" ipfw delete 1002
	atf_check -o not-match:'01002' cat fw/ipfw.rules
	# Each kept rule with ipfw's own wording beside, as the kernel's
	# listing of it would say (all is ip).
	atf_check -o match:'"kept":\[\{"num":5,"text":"skipto 500 all from any to any out","norm":"skipto 500 ip from any to any out"\},\{"num":200' \
	    -o match:'"file":true' "$JGC" -c "$SOCK" net ipfw
	# Kept rules renumbered with their place in the file.
	atf_check -o ignore "$JGC" -c "$SOCK" ipfw keep renumber 999 998
	atf_check -o match:'^add 00998 deny log all from any to any$' -o not-match:'00999' cat fw/ipfw.rules
	atf_check -o ignore "$JGC" -c "$SOCK" ipfw keep renumber 998 999
	atf_check -o match:'^add 00999 deny log all from any to any$' cat fw/ipfw.rules

	# Applied: the kept rules into set 1 while it is off, swapped with
	# set 0, and the old ones deleted.
	: > ipfw.log
	atf_check -o match:'done +ipfw apply' "$JGC" -c "$SOCK" ipfw apply
	atf_check -o inline:'ipfw -q set disable 1
ipfw -q -f set 1 flush
ipfw -q set 1 table all destroy
' sh -c 'head -3 ipfw.log'
	atf_check -o match:'^ipfw -q .*/ipfw.rules.arcana-load$' \
	    -o match:'^ipfw -q set swap 0 1$' \
	    -o match:'^ipfw -q -f delete set 1$' cat ipfw.log
	atf_check -o inline:'add 00005 set 1 skipto 500 all from any to any out
add 00200 set 1 check-state
add 00999 set 1 deny log all from any to any
add 01001 set 1 allow tcp from any to me6 22 in
' cat loaded.rules
	# In safe mode, unconfirmed: the old rules, which waited in set 1,
	# are swapped back in.
	: > ipfw.log
	atf_check -o match:'queued' "$JGC" -q -s -c "$SOCK" ipfw apply
	for i in $(seq 1 100); do
		"$JGC" -c "$SOCK" jobs | grep -q 'unconfirmed\|queued\|running' ||
		    break
		sleep 0.1
	done
	atf_check -o match:'not confirmed' "$JGC" -c "$SOCK" jobs
	atf_check -o inline:'ipfw -q set swap 0 1
ipfw -q set swap 0 1
ipfw -q -f delete set 1
' sh -c 'grep -E "swap|delete set" ipfw.log'

	# The kept file as a whole: read; replaced once ipfw has nothing
	# against it, and not when it has.
	atf_check -o match:'^add 00005 skipto' "$JGC" -c "$SOCK" ipfw rules
	printf 'table T46 create type addr\nadd 00010 allow ip from table(T46) to any\n' > new.rules
	atf_check -o match:'in place' "$JGC" -c "$SOCK" ipfw rules -w new.rules
	atf_check -o file:new.rules cat fw/ipfw.rules
	atf_check -o match:'^add 00005' cat fw/ipfw.rules.arcana-old
	: > ipfw.log
	atf_check -o ignore "$JGC" -c "$SOCK" ipfw apply
	atf_check -o inline:'set 1 table T46 create type addr
add 00010 set 1 allow ip from table(T46) to any
' cat loaded.rules
	printf 'add 00010 allow ip from any to any\nbogus\n' > bad.rules
	atf_check -s exit:1 -e match:'bad command bogus' -o ignore \
	    "$JGC" -c "$SOCK" ipfw rules -w bad.rules
	printf 'add 00010 allow ip from any to any\nset swap 0 1\n' > bad.rules
	atf_check -s exit:1 -e match:'line 2: the kept rules are what there is to be' \
	    -o ignore "$JGC" -c "$SOCK" ipfw rules -w bad.rules
	atf_check -o file:new.rules cat fw/ipfw.rules
	# What ipfw refuses of the load leaves set 0 alone.
	printf 'add 00010 allow ip from any to fails\n' > f.rules
	atf_check -o ignore "$JGC" -c "$SOCK" ipfw rules -w f.rules
	: > ipfw.log
	atf_check -s exit:1 -o match:'Invalid argument' "$JGC" -c "$SOCK" ipfw apply
	atf_check -o not-match:'swap' cat ipfw.log

	# The file the host loads now, as rc.conf names it, made into kept
	# rules and not written: what applying does left as comments, the
	# options before a command taken off.
	atf_check -s exit:1 -e match:'sets no firewall_script of its own nor a firewall_type file' -o ignore \
	    "$JGC" -c "$SOCK" ipfw rules -r
	printf 'firewall_type="open"\n' >> rc.conf
	atf_check -s exit:1 -e match:"one of rc.firewall's own" -o ignore \
	    "$JGC" -c "$SOCK" ipfw rules -r
	printf '# the host'"'"'s own\n-f flush\nadd 100 allow ip from any to any via lo0\n-q add 200 deny ip from any to 127.0.0.0/8\ntable T9 create type addr\nset disable 3\n' > host.rules
	sed -i '' -e '/^firewall_type=/d' rc.conf
	printf 'firewall_type="%s/host.rules"\n' "$(pwd)" >> rc.conf
	atf_check -o inline:"# from $(pwd)/host.rules
# the host's own
# left out, applying does it: -f flush
add 100 allow ip from any to any via lo0
add 200 deny ip from any to 127.0.0.0/8
table T9 create type addr
# left out, applying does it: set disable 3
" "$JGC" -c "$SOCK" ipfw rules -r
	atf_check -o file:f.rules cat fw/ipfw.rules
	sed -i '' -e '/^firewall_type=/d' rc.conf
	# A script of the host's own, as firewall_script names it: its ipfw
	# commands (ipfw, its path, a variable holding it) taken out, a
	# line continued joined, the shell's quoting taken off, the shell's
	# own lines left in as comments.  It is read first.
	cat > fw.sh <<'EOS'
#!/bin/sh
fwcmd="/sbin/ipfw -q"
${fwcmd} -f flush
${fwcmd} add 100 allow ip from any to any via lo0
ipfw -q add 200 deny tcp from any to me 22 \
    in via em0
/sbin/ipfw add 300 allow ip from \( 10.0.0.0/8 or 192.168.0.0/16 \) to any
if [ -n "$x" ]; then
	$fwcmd add 400 count ip from any to any
fi
cmd="ipfw -q add"
pif="em0"
ks="keep-state"
$cmd 00500 check-state
$cmd 00502 allow tcp from me to any out via $pif setup $ks
$cmd 00504 allow ip from any to any via $nosuch
echo add this is not a rule
EOS
	printf 'firewall_type="open"\nfirewall_script="%s/fw.sh"\n' "$(pwd)" >> rc.conf
	atf_check -o inline:"# from $(pwd)/fw.sh
# left out, the script's own: fwcmd=\"/sbin/ipfw -q\"
# left out, applying does it: \${fwcmd} -f flush
add 100 allow ip from any to any via lo0
add 200 deny tcp from any to me 22 in via em0
add 300 allow ip from ( 10.0.0.0/8 or 192.168.0.0/16 ) to any
# left out, the script's own: if [ -n \"\$x\" ]; then
# taken from inside the script's if, case or loop above: it may add these only at times
add 400 count ip from any to any
# left out, the script's own: fi
# left out, the script's own: cmd=\"ipfw -q add\"
# left out, the script's own: pif=\"em0\"
# left out, the script's own: ks=\"keep-state\"
add 00500 check-state
add 00502 allow tcp from me to any out via em0 setup keep-state
# left out, a variable not known here: \$cmd 00504 allow ip from any to any via \$nosuch
# left out, the script's own: echo add this is not a rule
" "$JGC" -c "$SOCK" ipfw rules -r
	sed -i '' -e '/^firewall_type=/d' -e '/^firewall_script=/d' rc.conf

	# On and off, kept in rc.conf with where the rules are.
	atf_check -o ignore "$JGC" -p -c "$SOCK" ipfw enable
	atf_check -o match:'^ipfw -q enable firewall$' tail -1 ipfw.log
	atf_check -o match:'^firewall_enable="YES"$' \
	    -o match:'^firewall_type=".*/fw/ipfw.rules"$' cat rc.conf
	atf_check -s exit:1 -e match:'already: the kept rules are what the firewall loads' \
	    -o ignore "$JGC" -c "$SOCK" ipfw rules -r
	atf_check -o ignore "$JGC" -c "$SOCK" ipfw zero 5
	atf_check -o match:'^ipfw -q zero 5$' tail -1 ipfw.log
	# What a rule names and is not one: a table's entry, a NAT
	# instance, a pipe; kept, a line at the head of the kept file,
	# once; what ipfw refuses said; not all at once, no shell's words.
	atf_check -o match:'done +ipfw table T46 add 192.0.2.0/24$' \
	    "$JGC" -c "$SOCK" ipfw table T46 add 192.0.2.0/24
	atf_check -o match:'^ipfw -q table T46 add 192.0.2.0/24$' cat ipfw.log
	atf_check -o match:'done +ipfw nat 1 config if em0 same_ports \(kept\)$' \
	    "$JGC" -p -c "$SOCK" ipfw nat 1 config if em0 same_ports
	atf_check -o ignore "$JGC" -p -c "$SOCK" ipfw nat 1 config if em0 same_ports
	atf_check -o inline:'1\n' sh -c "grep -c '^nat 1 config if em0 same_ports\$' fw/ipfw.rules"
	atf_check -o match:'^nat 1 config if em0 same_ports$' sed -n 1p fw/ipfw.rules
	atf_check -o match:'done' "$JGC" -c "$SOCK" ipfw pipe 1 config bw 10Mbit/s
	# Undone, kept: so are the lines it had made, and no others.
	atf_check -o ignore "$JGC" -p -c "$SOCK" ipfw table T9 create type addr
	atf_check -o ignore "$JGC" -p -c "$SOCK" ipfw table T9 add 10.1.0.1
	atf_check -o ignore "$JGC" -p -c "$SOCK" ipfw table T9 add 10.1.0.10
	atf_check -o ignore "$JGC" -p -c "$SOCK" ipfw table T9 delete 10.1.0.1
	atf_check -o match:'^table T9 add 10.1.0.10$' -o not-match:'^table T9 add 10.1.0.1$' \
	    -o match:'^table T9 create type addr$' cat fw/ipfw.rules
	atf_check -o ignore "$JGC" -p -c "$SOCK" ipfw table T9 flush
	atf_check -o not-match:'^table T9 add' -o match:'^table T9 create type addr$' \
	    cat fw/ipfw.rules
	atf_check -o ignore "$JGC" -p -c "$SOCK" ipfw table T9 destroy
	atf_check -o not-match:'T9' cat fw/ipfw.rules
	atf_check -o match:'^ipfw -q table T9 destroy$' cat ipfw.log
	atf_check -o ignore "$JGC" -p -c "$SOCK" ipfw nat 1 delete
	atf_check -o not-match:'^nat 1 ' -o match:'^add ' cat fw/ipfw.rules
	atf_check -s exit:1 -o match:'record already exists' \
	    "$JGC" -c "$SOCK" ipfw table T46 add 10.9.9.9
	atf_check -s exit:1 -e match:'not all of them at once' -o ignore \
	    "$JGC" -c "$SOCK" ipfw table all flush
	atf_check -s exit:1 -e match:'the words are ipfw' -o ignore \
	    "$JGC" -c "$SOCK" ipfw table T46 add '10.0.0.1;id'
	atf_check -s exit:1 -e match:'not taken back' -o ignore \
	    "$JGC" -s -c "$SOCK" ipfw table T46 flush x

	# A large kept file read through ipfw -n, which writes while it
	# reads: the agent feeds it as it reads back, and does not wait.
	awk 'BEGIN { for (i = 1; i <= 6000; i++) printf "add %05d allow tcp from any to me %d in // a rule long enough to fill the pipes\n", i + 10000, i }' > big.rules
	atf_check -o ignore "$JGC" -c "$SOCK" ipfw rules -w big.rules
	atf_check -o match:'"num":16000,"text":"allow tcp from any to me 6000 in // a rule long enough to fill the pipes","norm":"allow tcp from any to me 6000 in' \
	    timeout 60 "$JGC" -c "$SOCK" net ipfw

	# The first rule kept, no rule being kept yet: set 0's rules are
	# kept first (not SD-WAN's set 30, not the rule itself twice), so
	# that applying does not take them away.
	printf 'table T1 create type addr\n' > tbl.rules
	atf_check -o ignore "$JGC" -c "$SOCK" ipfw rules -w tbl.rules
	printf '00010 set 0 allow ip from any to any via lo0\n00500 set 30 count ip from any to any\n00600 set 0 allow tcp from any to me 22 in\n' > live.rules
	atf_check -o match:'now, and kept' "$JGC" -p -c "$SOCK" ipfw add 700 deny ip from any to any
	atf_check -o inline:"table T1 create type addr
# The kernel's rules when the first rule was kept, by Arcana: the kept rules are the whole ruleset once applied.
add 00010 allow ip from any to any via lo0
add 00600 allow tcp from any to me 22 in
add 00700 deny ip from any to any
" cat fw/ipfw.rules
	rm live.rules

	# A rule's words are ipfw's own; a number is a number; the sets
	# are not a rule's to name; what ipfw refuses is said.
	: > ipfw.log
	atf_check -s exit:1 -e match:'no quotes and nothing a shell would read' \
	    -o ignore "$JGC" -c "$SOCK" ipfw add 10 allow ip from any to 'any;reboot'
	atf_check -s exit:1 -e match:'no quotes' -o ignore \
	    "$JGC" -c "$SOCK" ipfw add 10 allow ip from any to '$(id)'
	atf_check -s exit:1 -e match:'its number, 1 to 65534' -o ignore \
	    "$JGC" -c "$SOCK" ipfw add 65535 allow ip from any to any
	atf_check -s exit:1 -e match:'not given a set here' -o ignore \
	    "$JGC" -c "$SOCK" ipfw add 10 set 1 allow ip from any to any
	atf_check -s exit:1 -e match:'not put back by itself' -o ignore \
	    "$JGC" -s -c "$SOCK" ipfw delete 5
	atf_check -s exit:1 -e match:'is add, delete, renumber, alias, apply' -o ignore \
	    "$JGC" -c "$SOCK" ipfw flush
	atf_check -o empty cat ipfw.log
	atf_check -s exit:1 -o match:'unrecognised option refuse' \
	    "$JGC" -c "$SOCK" ipfw add 10 allow refuse from any to any
}
firewall_cleanup()
{
	stop_daemon
}

atf_test_case storage cleanup
storage_head()
{
	atf_set "descr" "Disks, pools, datasets, snapshots, mounts and fstab; zfs, zpool, mount and gpart jobs, each word checked"
}
storage_body()
{
	# zfs(8) and zpool(8): what they list is canned, what they are told
	# to do is logged.
	cat > fake-zfs <<EOS
#!/bin/sh
echo "zfs \$*" >> $(pwd)/storage.log
case "\$*" in
"list -j -p -t filesystem,volume"*)
	printf '%s\n' '{"output_version":{"command":"zfs list","vers_major":0,"vers_minor":1},"datasets":{"tank":{"name":"tank","type":"FILESYSTEM","pool":"tank","properties":{"type":{"value":"filesystem"},"used":{"value":"5000"},"available":{"value":"9000"},"referenced":{"value":"96"},"mountpoint":{"value":"/tank"},"compression":{"value":"lz4"},"compressratio":{"value":"1.50"},"quota":{"value":"0"},"reservation":{"value":"0"},"mounted":{"value":"yes"},"canmount":{"value":"on"},"origin":{"value":"-"},"volsize":{"value":"-"},"readonly":{"value":"off"},"encryption":{"value":"off"},"keystatus":{"value":"-"},"keylocation":{"value":"none"},"jailed":{"value":"off"}}},"tank/data":{"name":"tank/data","type":"FILESYSTEM","pool":"tank","properties":{"type":{"value":"filesystem"},"used":{"value":"4000"},"available":{"value":"9000"},"referenced":{"value":"4000"},"mountpoint":{"value":"/tank/data"},"compression":{"value":"lz4"},"compressratio":{"value":"2.00"},"quota":{"value":"8000"},"reservation":{"value":"0"},"mounted":{"value":"yes"},"canmount":{"value":"on"},"origin":{"value":"-"},"volsize":{"value":"-"},"readonly":{"value":"off"},"encryption":{"value":"aes-256-gcm"},"keystatus":{"value":"unavailable"},"keylocation":{"value":"file:///k"},"jailed":{"value":"on"}}},"tank/vol":{"name":"tank/vol","type":"VOLUME","pool":"tank","properties":{"type":{"value":"volume"},"used":{"value":"100"},"available":{"value":"9000"},"referenced":{"value":"100"},"mountpoint":{"value":"-"},"compression":{"value":"off"},"compressratio":{"value":"1.00"},"quota":{"value":"-"},"reservation":{"value":"0"},"mounted":{"value":"-"},"canmount":{"value":"-"},"origin":{"value":"tank/data@a"},"volsize":{"value":"1048576"},"readonly":{"value":"off"},"encryption":{"value":"off"},"keystatus":{"value":"-"},"keylocation":{"value":"none"},"jailed":{"value":"off"}}}}}' ;;
"list -j -p -t snapshot"*)
	printf '%s\n' '{"output_version":{"command":"zfs list","vers_major":0,"vers_minor":1},"datasets":{"tank/data@b":{"name":"tank/data@b","type":"SNAPSHOT","pool":"tank","properties":{"used":{"value":"10"},"referenced":{"value":"4000"},"creation":{"value":"1759500000"}}},"tank/data@a":{"name":"tank/data@a","type":"SNAPSHOT","pool":"tank","properties":{"used":{"value":"20"},"referenced":{"value":"3000"},"creation":{"value":"1759400000"}}}}}' ;;
"destroy tank/busy") echo "cannot destroy 'tank/busy': dataset is busy" >&2; exit 1 ;;
"list -H -o name -s createtxg -t snapshot -d 1 tank/data") printf 'tank/data@a\ntank/data@b\n' ;;
"destroy tank/data@b") [ -f $(pwd)/held ] && { echo "cannot destroy snapshot tank/data@b: dataset is busy" >&2; exit 1; } ;;
esac
exit 0
EOS
	cat > fake-zpool <<EOS
#!/bin/sh
echo "zpool \$*" >> $(pwd)/storage.log
case "\$*" in
"list -Hp -o name,size,alloc,free,health") printf 'tank\t14000\t5000\t9000\tONLINE\n' ;;
"list -j -p -o name,size,allocated"*) printf '%s\n' '{"output_version":{"command":"zpool list","vers_major":0,"vers_minor":1},"pools":{"tank":{"name":"tank","type":"POOL","state":"DEGRADED","properties":{"size":{"value":"14000"},"allocated":{"value":"5000"},"free":{"value":"9000"},"fragmentation":{"value":"12"},"capacity":{"value":"35"},"dedupratio":{"value":"1.00"},"health":{"value":"DEGRADED"}}}}}' ;;
import) printf '   pool: spare\n     id: 1234567890\n  state: ONLINE\n action: The pool can be imported using its name or numeric identifier.\n config:\n\n\tspare       ONLINE\n\t  ada7p1    ONLINE\n' ;;
"status -j") printf '%s\n' '{"output_version":{"command":"zpool status","vers_major":0,"vers_minor":1},"pools":{"tank":{"name":"tank","state":"DEGRADED","pool_guid":"1","txg":"1","spa_version":"5000","zpl_version":"5","status":"One or more devices has been taken offline by the administrator. Sufficient replicas exist for the pool to continue functioning.","action":"Online the device using '\''zpool online'\''.","msgid":"ZFS-8000-2Q","moreinfo":"https://openzfs.github.io/openzfs-docs/msg/ZFS-8000-2Q","scan_stats":{"function":"SCRUB","state":"FINISHED","start_time":"Sun Oct  4 02:49:49 2026","end_time":"Sun Oct  4 03:00:00 2026","errors":"0"},"vdevs":{"tank":{"name":"tank","vdev_type":"root","guid":"1","class":"normal","state":"DEGRADED","read_errors":"0","write_errors":"0","checksum_errors":"0","vdevs":{"mirror-0":{"name":"mirror-0","vdev_type":"mirror","guid":"2","class":"normal","state":"DEGRADED","read_errors":"0","write_errors":"0","checksum_errors":"0","vdevs":{"ada1p1":{"name":"ada1p1","vdev_type":"disk","guid":"3","path":"/dev/ada1p1","class":"normal","state":"ONLINE","read_errors":"0","write_errors":"0","checksum_errors":"0"},"ada2p1":{"name":"ada2p1","vdev_type":"disk","guid":"4","path":"/dev/ada2p1","class":"normal","state":"OFFLINE","read_errors":"0","write_errors":"0","checksum_errors":"0"}}}}}},"error_count":"0","errlist":[]}}}' ;;
esac
exit 0
EOS
	for p in gpart mount umount camcontrol; do
		printf '#!/bin/sh\necho "%s $*" >> %s/storage.log\n[ "$1 $2" = "destroy ada9" ] && { echo "gpart: Device busy" >&2; exit 1; }\n[ "$1" = devlist ] && echo "<FAKE DISK 1.0>   at scbus0 target 0 lun 0 (pass0,ada0)"\nexit 0\n' "$p" "$(pwd)" > fake-$p
	done
	chmod +x fake-zfs fake-zpool fake-gpart fake-mount fake-umount fake-camcontrol
	# The programs the daemon has no option for, in a directory of
	# their own: what they are told is logged, what they say is canned.
	mkdir tools
	for p in newfs newfs_msdos growfs swapon swapoff; do
		printf '#!/bin/sh\necho "%s $*" >> %s/storage.log\nexit 0\n' "$p" "$(pwd)" > tools/$p
	done
	printf '#!/bin/sh\n[ "$1" = /dev/ada0p3 ] && echo ufs && exit 0\nexit 1\n' > tools/fstyp
	cat > tools/nvmecontrol <<'EOS'
#!/bin/sh
cat <<EOP
SMART/Health Information Log
============================
Critical Warning State:         0x00
 Available spare:               0
 Temperature:                   0
Temperature:                    312 K, 38.85 C, 101.93 F
Available spare:                100
Available spare threshold:      10
Percentage used:                3
Power cycles:                   120
Power on hours:                 4567
Unsafe shutdowns:               12
Media errors:                   0
EOP
EOS
	cat > tools/smartctl <<'EOS'
#!/bin/sh
case "$4" in
/dev/da0) echo '{"smart_status":{"passed":false},"temperature":{"current":51},"power_on_time":{"hours":40000},"ata_smart_attributes":{"table":[{"id":5,"name":"Reallocated_Sector_Ct","raw":{"value":88}},{"id":197,"name":"Current_Pending_Sector","raw":{"value":3}}]}}'; exit 8 ;;
*) echo '{"smart_status":{"passed":true},"temperature":{"current":34},"power_on_time":{"hours":1200},"power_cycle_count":40,"ata_smart_attributes":{"table":[{"id":5,"name":"Reallocated_Sector_Ct","raw":{"value":0}},{"id":231,"name":"SSD_Life_Left","raw":{"value":97}}]}}' ;;
esac
EOS
	chmod +x tools/*
	printf '# Device\tMountpoint\tFStype\tOptions\tDump\tPass#\n/dev/ada0p2\t/\tufs\trw\t1\t1\n/dev/ada0p3\t/mnt/data\tufs\trw,noatime\t2\t2\nproc\t/proc\tprocfs\trw\t0\t0\n' > fstab
	DAEMON_ARGS="-z $(pwd)/fake-zfs -Z $(pwd)/fake-zpool -q $(pwd)/fake-gpart -m $(pwd)/fake-mount -u $(pwd)/fake-umount -i $(pwd)/fake-camcontrol -S $(pwd)/fstab -2 $(pwd)/tools"
	start_daemon

	# A dataset's encryption and whether a jail has it; its key loaded
	# from where it is kept, and forgotten; given to a jail, taken back.
	atf_check -o match:'"name":"tank/data",[^}]*"encryption":"aes-256-gcm","keystatus":"unavailable","keylocation":"file:///k","jailed":"on"' \
	    "$JGC" -c "$SOCK" storage datasets
	atf_check -o match:'done +zfs load-key tank/data$' "$JGC" -c "$SOCK" zfs load-key tank/data
	atf_check -o match:'done +zfs unload-key -r tank/data$' "$JGC" -c "$SOCK" zfs unload-key -r tank/data
	atf_check -o match:'done +zfs jail web tank/data$' "$JGC" -c "$SOCK" zfs jail tank/data web
	atf_check -o match:'done +zfs unjail web tank/data$' "$JGC" -c "$SOCK" zfs unjail tank/data web
	atf_check -s exit:1 -e match:'a jail is named' -o ignore "$JGC" -c "$SOCK" zfs jail tank/data 'a b'
	atf_check -s exit:1 -e match:'a dataset is pool/name' -o ignore "$JGC" -c "$SOCK" zfs jail tank web
	# A snapshot sent into a new dataset: the helper pipes zfs send
	# into zfs receive, of all or of what changed since another.
	atf_check -o match:'done' "$JGC" -c "$SOCK" zfs replicate tank/data@b backup/data
	atf_check -o match:"^0 zfs-pipe $(pwd)/fake-zfs tank/data@b backup/data - -\$" cat helper.log
	atf_check -s exit:1 -e match:'a dataset is pool/name' -o ignore "$JGC" -c "$SOCK" zfs replicate tank/data backup/data
	atf_check "$JGD" --scope-helper 0 zfs-pipe "$(pwd)/fake-zfs" tank/data@b backup/data tank/data@a r
	atf_check -o match:'^zfs send -R -i tank/data@a tank/data@b$' \
	    -o match:'^zfs receive -u backup/data$' cat storage.log
	# A file system made on a partition: not on one that has one, is
	# a pool's, or is not a device; and one grown.
	atf_check -o match:'done +newfs -U -L data /dev/ada0p4$' "$JGC" -c "$SOCK" gpart newfs ada0p4 data
	# FAT, its label in capitals, eleven at most; refused as newfs is.
	atf_check -o match:'done +newfs_msdos -L USB_KEY /dev/ada0p4$' "$JGC" -c "$SOCK" gpart newfs-msdos ada0p4 usb_key
	atf_check -s exit:1 -e match:'FAT label is 11' -o ignore "$JGC" -c "$SOCK" gpart newfs-msdos ada0p4 far_too_long_label
	atf_check -s exit:1 -o match:'has a file system on it \(ufs\)' "$JGC" -c "$SOCK" gpart newfs-msdos ada0p3
	atf_check -s exit:1 -o match:'has a file system on it \(ufs\)' "$JGC" -c "$SOCK" gpart newfs ada0p3
	atf_check -o match:'done +newfs -U /dev/ada0p3$' "$JGC" -c "$SOCK" gpart newfs -f ada0p3
	atf_check -s exit:1 -o match:'ada1p1 is a device of a pool' "$JGC" -c "$SOCK" gpart newfs -f ada1p1
	atf_check -s exit:1 -e match:'named as GEOM names it' -o ignore "$JGC" -c "$SOCK" gpart newfs ../etc
	atf_check -o match:'done +growfs -y /dev/ada0p3$' "$JGC" -c "$SOCK" gpart growfs ada0p3
	atf_check -o not-match:'ada1p1$' -o not-match:'etc' cat storage.log
	# Swap, on a device and off it.
	atf_check -o match:'done +swapon /dev/ada0p9$' "$JGC" -c "$SOCK" swapon /dev/ada0p9
	atf_check -o match:'done +swapoff /dev/ada0p9$' "$JGC" -c "$SOCK" swapoff /dev/ada0p9
	atf_check -s exit:1 -e match:'swap is on a device' -o ignore "$JGC" -c "$SOCK" swapon /etc/passwd
	atf_check -o match:'"swap":\[' "$JGC" -c "$SOCK" storage mounts
	# How the disks say they are: an NVMe disk by nvmecontrol, the
	# others by smartctl, one of them failing.
	atf_check -o save:health.json "$JGC" -c "$SOCK" storage health
	atf_check -o match:'\{"name":"nda0","by":"nvmecontrol","ok":true,"temperature":39,"spare_pct":100,"used_pct":3,"power_on_hours":4567,"unsafe_shutdowns":12,"media_errors":0,"power_cycles":120\}' \
	    -o match:'\{"name":"ada0","by":"smartctl","ok":true,"temperature":34,"power_on_hours":1200,"power_cycles":40,"reallocated":0,"life_left":97\}' \
	    -o match:'\{"name":"da0","by":"smartctl","ok":false,"temperature":51,"power_on_hours":40000,"reallocated":88,"pending":3\}' \
	    cat health.json
	: > storage.log

	# The disks are GEOM's own, read from the kernel: sizes in bytes,
	# partitions with their sectors.
	atf_check -o save:d.json "$JGC" -c "$SOCK" storage disks
	atf_check -o match:'^\{"disks":\[' cat d.json
	if [ -n "$(sysctl -n kern.disks)" ]; then
		atf_check -o match:'"name":"[a-z]+[0-9]+","size":[0-9]+,"sectorsize":[0-9]+' \
		    -o match:'"parts":\[' cat d.json
	fi
	# The pools, with what zpool status says of each and its devices
	# as they are nested.
	atf_check -o save:p.json "$JGC" -c "$SOCK" storage pools
	atf_check -o match:'"name":"tank","size":14000,"alloc":5000,"free":9000,"frag":12,"cap":35,"dedup":"1.00","health":"DEGRADED"' \
	    -o match:'"state":"DEGRADED"' \
	    -o match:'"status":"One or more devices has been taken offline by the administrator. Sufficient replicas exist' \
	    -o match:'"scan":"scrub finished with 0 errors on Sun Oct  4 03:00:00 2026"' -o match:'"errors":"No known data errors"' \
	    -o match:'"see":"https://openzfs.github.io/openzfs-docs/msg/ZFS-8000-2Q"' \
	    -o match:'\{"name":"mirror-0","depth":1,"state":"DEGRADED","read":"0","write":"0","cksum":"0"\}' \
	    -o match:'\{"name":"ada2p1","depth":2,"state":"OFFLINE","read":"0","write":"0","cksum":"0"\}' \
	    cat p.json
	# Datasets and snapshots: sizes are numbers, "-" is nothing.
	atf_check -o match:'\{"name":"tank/data","type":"filesystem","used":4000,"avail":9000,"refer":4000,"mountpoint":"/tank/data","compression":"lz4","ratio":"2.00","quota":8000,"reservation":0,"mounted":"yes","canmount":"on","readonly":"off",' \
	    -o match:'"name":"tank/vol","type":"volume".*"origin":"tank/data@a","volsize":1048576' \
	    "$JGC" -c "$SOCK" storage datasets
	atf_check -o match:'\{"snapshots":\[\{"name":"tank/data@b","used":10,"refer":4000,"creation":1759500000\}' \
	    "$JGC" -c "$SOCK" storage snapshots tank/data
	atf_check -o match:'^zfs list -j -p -t snapshot -o name,used,referenced,creation -S creation -r tank/data$' \
	    cat storage.log
	atf_check -s exit:1 -e match:'a dataset is named' -o ignore \
	    "$JGC" -c "$SOCK" storage snapshots '-r'
	# What is mounted is the kernel's word; what should be, fstab's.
	atf_check -o save:m.json "$JGC" -c "$SOCK" storage mounts
	atf_check -o match:'"mounts":\[\{"from":"[^"]+","on":"/","type":"[a-z]+","options":"[^"]*","size":[0-9]+,"used":[0-9]+,"avail":[0-9]+\}' \
	    -o match:'\{"spec":"/dev/ada0p2","file":"/","vfstype":"ufs","mntops":"rw","type":"rw","freq":1,"passno":1,"mounted":true\}' \
	    -o match:'"file":"/mnt/data","vfstype":"ufs","mntops":"rw,noatime".*"mounted":false' \
	    cat m.json

	# zfs: a snapshot, with those under it; rolled back; destroyed.
	: > storage.log
	atf_check -o match:'done +zfs snapshot -r tank/data@c$' \
	    "$JGC" -c "$SOCK" zfs snapshot -r tank/data@c
	atf_check -o match:'done +zfs rollback tank/data@c' \
	    "$JGC" -c "$SOCK" zfs rollback tank/data@c
	atf_check -o match:'done +zfs destroy tank/data@c' \
	    "$JGC" -c "$SOCK" zfs destroy tank/data@c
	# The newest snapshot made again under its name: a snapshot there
	# all along; not one that is not the newest; one held kept.
	n=$(wc -l < storage.log)
	atf_check -o match:'done +zfs resnapshot tank/data@b$' \
	    "$JGC" -c "$SOCK" zfs resnapshot tank/data@b
	atf_check -o inline:'zfs list -H -o name -s createtxg -t snapshot -d 1 tank/data
zfs snapshot tank/data@b.resnap
zfs destroy tank/data@b
zfs rename tank/data@b.resnap tank/data@b
' tail -n +$((n + 1)) storage.log
	atf_check -s exit:1 -o match:'tank/data@a is not the newest snapshot of tank/data: tank/data@b is' \
	    "$JGC" -c "$SOCK" zfs resnapshot tank/data@a
	touch held
	n=$(wc -l < storage.log)
	atf_check -s exit:1 -o match:'tank/data@b is kept as it was: .*busy' \
	    "$JGC" -c "$SOCK" zfs resnapshot tank/data@b
	atf_check -o match:'^zfs destroy tank/data@b.resnap$' -o not-match:'rename' \
	    tail -n +$((n + 1)) storage.log
	rm held
	atf_check -o match:'^zfs snapshot -r tank/data@b.resnap$' \
	    -o match:'^zfs rename -r tank/data@b.resnap tank/data@b$' \
	    sh -c "\"$JGC\" -c $SOCK zfs resnapshot -r tank/data@b >/dev/null; cat storage.log"
	atf_check -o match:'done +zfs create -o compression=zstd -o quota=10G tank/new' \
	    "$JGC" -c "$SOCK" zfs create tank/new compression=zstd quota=10G
	atf_check -o match:'done +zfs create -V 2G -o volblocksize=16k tank/zvol' \
	    "$JGC" -c "$SOCK" zfs create tank/zvol volsize=2G volblocksize=16k
	atf_check -o match:'done +zfs set mountpoint=/srv/data atime=off tank/data' \
	    "$JGC" -c "$SOCK" zfs set tank/data mountpoint=/srv/data atime=off
	atf_check -o match:'done +zfs set org.example:owner=me tank/data' \
	    "$JGC" -c "$SOCK" zfs set tank/data org.example:owner=me
	atf_check -o match:'done +zfs inherit quota tank/data' \
	    "$JGC" -c "$SOCK" zfs inherit tank/data quota
	atf_check -o match:'done +zfs clone tank/data@a tank/copy' \
	    "$JGC" -c "$SOCK" zfs clone tank/data@a tank/copy
	atf_check -o match:'done +zfs unmount -f tank/data' \
	    "$JGC" -c "$SOCK" zfs unmount -f tank/data
	atf_check -o match:'done +zfs rename tank/a tank/b' \
	    "$JGC" -c "$SOCK" zfs rename tank/a tank/b
	# What zfs refuses is said as it said it.
	atf_check -s exit:1 -o match:'dataset is busy' \
	    "$JGC" -c "$SOCK" zfs destroy tank/busy
	atf_check -o match:'^zfs snapshot -r tank/data@c$' \
	    -o match:'^zfs create -V 2G -o volblocksize=16k tank/zvol$' \
	    cat storage.log
	# No word is an option, a pool is not destroyed by its name, a
	# property is one zfs has, and nothing here is undone: not in
	# safe mode.
	: > storage.log
	for bad in 'destroy tank' 'destroy -R' 'destroy tank/x;reboot' \
	    'snapshot tank/data' 'snapshot tank/data@a@b' 'rollback tank/data' \
	    'create tank' 'create tank/x mountpoint' 'create tank/x evil=1' \
	    'set tank/data -o=x' 'create tank/x volsize=lots' 'send tank/data' \
	    'rename tank/a tank/b@c' 'destroy /etc/passwd'; do
		atf_check -s exit:1 -o ignore -e not-empty \
		    "$JGC" -c "$SOCK" zfs $bad
	done
	atf_check -s exit:1 -e match:'not in safe mode' -o ignore \
	    "$JGC" -s -c "$SOCK" zfs snapshot tank/data@s
	atf_check -s exit:1 -e match:"storage is the host's" -o ignore \
	    "$JGC" -j web -c "$SOCK" zfs snapshot tank/data@s
	atf_check -o empty cat storage.log

	# zpool: a scrub started and stopped, a device taken off and on.
	atf_check -o match:'done +zpool scrub tank' "$JGC" -c "$SOCK" zpool scrub tank
	atf_check -o match:'done +zpool scrub -s tank' \
	    "$JGC" -c "$SOCK" zpool scrub-stop tank
	atf_check -o match:'done +zpool offline tank ada2p1' \
	    "$JGC" -c "$SOCK" zpool offline tank ada2p1
	atf_check -o match:'done +zpool online tank gpt/disk2' \
	    "$JGC" -c "$SOCK" zpool online tank gpt/disk2
	atf_check -o match:'done +zpool clear tank' "$JGC" -c "$SOCK" zpool clear tank
	# A pool made, of devices put together as zpool has it; given more
	# devices; a device mirrored, taken out, replaced; exported,
	# imported, destroyed.
	atf_check -o match:'done +zpool create -m /srv/tank -o ashift=12 tank mirror ada1p1 ada2p1 log gpt/slog' \
	    "$JGC" -c "$SOCK" zpool create tank mirror ada1p1 ada2p1 log gpt/slog mountpoint=/srv/tank ashift=12
	atf_check -o match:'done +zpool create -f lab ada3' \
	    "$JGC" -c "$SOCK" zpool create -f lab ada3
	atf_check -o match:'done +zpool add tank cache ada4p1' \
	    "$JGC" -c "$SOCK" zpool add tank cache ada4p1
	atf_check -o match:'done +zpool attach tank ada1p1 ada5p1' \
	    "$JGC" -c "$SOCK" zpool attach tank ada1p1 ada5p1
	atf_check -o match:'done +zpool detach tank ada5p1' \
	    "$JGC" -c "$SOCK" zpool detach tank ada5p1
	atf_check -o match:'done +zpool replace tank ada2p1 ada6p1' \
	    "$JGC" -c "$SOCK" zpool replace tank ada2p1 ada6p1
	atf_check -o match:'done +zpool remove tank ada4p1' \
	    "$JGC" -c "$SOCK" zpool remove tank ada4p1
	atf_check -o match:'done +zpool export tank' "$JGC" -c "$SOCK" zpool export tank
	atf_check -o match:'done +zpool import -R /mnt tank' \
	    "$JGC" -c "$SOCK" zpool import tank altroot=/mnt
	atf_check -o match:'done +zpool destroy tank' \
	    "$JGC" -c "$SOCK" zpool destroy tank
	# Never by force: that unmounts what is in use.
	atf_check -s exit:1 -e match:'not destroyed or exported by force' \
	    -o ignore "$JGC" -c "$SOCK" zpool destroy -f tank
	atf_check -s exit:1 -e match:'not destroyed or exported by force' \
	    -o ignore "$JGC" -c "$SOCK" zpool export -f tank
	: > storage.log
	for bad in 'scrub -s' 'offline tank ../x' 'create tank' \
	    'create tank mirror' 'create tank ada1 evil=1' \
	    'create tank ada1 mountpoint=srv' 'create tank ada1 ashift=x' \
	    'add tank ada1 mountpoint=/x' 'add tank log' \
	    'import tank altroot=etc' 'attach tank ada1' 'detach tank' \
	    'replace tank' 'destroy' 'create tank ada1;reboot' 'split tank x'; do
		atf_check -s exit:1 -o ignore -e not-empty \
		    "$JGC" -c "$SOCK" zpool $bad
	done
	atf_check -o empty cat storage.log
	# Never a pool the system lives on: any with a dataset mounted on
	# the root or under /usr, /var, /home and the like.  (zpool here
	# is the stand-in: nothing real is asked of a real pool.)
	for pool in $(mount -t zfs | awk '$3 == "/" || $3 ~ "^/(usr|var|home|tmp|compat)(/|$)" { split($1, a, "/"); print a[1] }' | sort -u); do
		atf_check -s exit:1 -e match:'where the system lives' \
		    -o ignore "$JGC" -c "$SOCK" zpool destroy "$pool"
		atf_check -s exit:1 -e match:'where the system lives' \
		    -o ignore "$JGC" -c "$SOCK" zpool export "$pool"
		atf_check -s exit:1 -e match:'where the system lives' \
		    -o ignore "$JGC" -c "$SOCK" zfs unmount -f "$pool/x"
		atf_check -o empty cat storage.log
	done
	atf_check -s exit:1 -e match:'where the system lives' -o ignore \
	    "$JGC" -c "$SOCK" umount -f /dev
	atf_check -o empty cat storage.log
	# The pools that could be imported.
	atf_check -o match:'\{"importable":\[\{"name":"spare","id":"1234567890","state":"ONLINE"\}\]\}' \
	    "$JGC" -c "$SOCK" storage importable

	# mount: what fstab describes; unmount: what is mounted, never /.
	atf_check -o match:'done +mount -F .*/fstab /mnt/data' \
	    "$JGC" -c "$SOCK" mount /mnt/data
	atf_check -s exit:1 -e match:'/mnt/other is not in fstab' -o ignore \
	    "$JGC" -c "$SOCK" mount /mnt/other
	atf_check -s exit:1 -e match:'the root is not unmounted' -o ignore \
	    "$JGC" -c "$SOCK" umount /
	atf_check -s exit:1 -e match:'nothing is mounted on /mnt/data' -o ignore \
	    "$JGC" -c "$SOCK" umount /mnt/data
	atf_check -o match:'done +umount /dev' "$JGC" -c "$SOCK" umount /dev
	atf_check -s exit:1 -e match:'a mount point is a whole path' -o ignore \
	    "$JGC" -c "$SOCK" mount '/mnt/../etc'

	# gpart: a table made, a partition added, labelled, resized,
	# deleted; a table destroyed only as gpart lets it be.
	atf_check -o match:'done +gpart create -s gpt ada9' \
	    "$JGC" -c "$SOCK" gpart create ada9 gpt
	atf_check -o match:'done +gpart add -t freebsd-zfs -a 1m -s 10G -l tank0 ada9' \
	    "$JGC" -c "$SOCK" gpart add ada9 freebsd-zfs 10G tank0
	atf_check -o match:'done +gpart add -t freebsd-swap -a 1m ada9' \
	    "$JGC" -c "$SOCK" gpart add ada9 freebsd-swap
	atf_check -o match:'done +gpart modify -i 1 -l tank1 ada9' \
	    "$JGC" -c "$SOCK" gpart modify ada9 1 tank1
	atf_check -o match:'done +gpart resize -i 1 -a 1m -s 20G ada9' \
	    "$JGC" -c "$SOCK" gpart resize ada9 1 20G
	atf_check -o match:'done +gpart delete -i 2 ada9' \
	    "$JGC" -c "$SOCK" gpart delete ada9 2
	atf_check -s exit:1 -o match:'Device busy' \
	    "$JGC" -c "$SOCK" gpart destroy ada9
	: > storage.log
	for bad in 'create ada9 zfs' 'add ada9 -F' 'add ada9 freebsd-zfs big' \
	    'delete ada9 one' 'destroy -F ada9' 'destroy ada9 -F' \
	    'modify ada9 1 a;b' 'bootcode ada9' 'add /dev/ada9 freebsd-zfs'; do
		atf_check -s exit:1 -o ignore -e not-empty \
		    "$JGC" -c "$SOCK" gpart $bad
	done
	atf_check -o empty cat storage.log
	atf_check -o match:'done +camcontrol rescan all' "$JGC" -c "$SOCK" cam rescan

	# fstab: read whole, put back whole once it is an fstab, the one
	# before kept beside it; not over somebody else's change.
	atf_check -o match:'^/dev/ada0p3	/mnt/data	ufs	rw,noatime	2	2$' \
	    "$JGC" -c "$SOCK" fstab
	cp fstab new.fstab
	printf '/dev/ada0p4\t/mnt/more\tufs\trw\t2\t2\n' >> new.fstab
	atf_check -o match:'it is an fstab; left as it was' \
	    "$JGC" -c "$SOCK" fstab -n -w new.fstab
	atf_check -o not-match:'/mnt/more' cat fstab
	atf_check -o match:'in place' "$JGC" -c "$SOCK" fstab -w new.fstab
	atf_check -o match:'/mnt/more' cat fstab
	atf_check -o not-match:'/mnt/more' cat fstab.arcana-old
	# And what it now describes can be mounted.
	atf_check -o match:'done +mount -F .*/fstab /mnt/more' \
	    "$JGC" -c "$SOCK" mount /mnt/more
	printf '/dev/ada0p5 /mnt/x\n' > bad.fstab
	atf_check -s exit:1 -e match:'line 1: an entry is a device' -o ignore \
	    "$JGC" -c "$SOCK" fstab -w bad.fstab
	printf '/dev/ada0p5 mnt ufs rw 0 0\n' > bad.fstab
	atf_check -s exit:1 -e match:'line 1: mnt is no mount point' -o ignore \
	    "$JGC" -c "$SOCK" fstab -w bad.fstab
	printf '/dev/ada0p5 /mnt/x ufs rw 0 0' > bad.fstab
	atf_check -s exit:1 -e match:'the last line has to end' -o ignore \
	    "$JGC" -c "$SOCK" fstab -w bad.fstab
	atf_check -o match:'/mnt/more' -o not-match:'ada0p5' cat fstab
}
storage_cleanup()
{
	stop_daemon
}

atf_test_case ntp cleanup
ntp_head()
{
	atf_set "descr" "The NTP servers: ntp.conf between arcana's marks, ntpd enabled and restarted; taken away again"
}
ntp_body()
{
	write_rc
	printf 'driftfile /var/db/ntpd.drift\nserver 0.freebsd.pool.ntp.org iburst\n' > ntp.conf
	start_daemon
	atf_check -s exit:1 -e match:'a server is a name' -o ignore "$JGC" -c "$SOCK" ntp 'bad host'
	atf_check -o match:'ntp servers ntp.example.org and more \(kept\)' "$JGC" -c "$SOCK" -p ntp ntp.example.org 10.99.0.9
	atf_check -o match:'^server 0.freebsd.pool.ntp.org iburst$' \
	    -o match:'^# arcana: the NTP servers, set by the console; begin$' \
	    -o match:'^server ntp.example.org iburst$' \
	    -o match:'^server 10.99.0.9 iburst$' \
	    -o match:'^# arcana: end$' cat ntp.conf
	atf_check -o match:'^ntpd_enable="YES"$' cat rc.conf
	test -f running.ntpd || atf_fail "ntpd was not restarted"
	# Set again: one block, the new servers only.
	atf_check -o ignore "$JGC" -c "$SOCK" -p ntp 10.99.0.10
	atf_check -o inline:'1\n' sh -c "grep -c '^# arcana: end' ntp.conf"
	atf_check -o not-match:'ntp.example.org' -o match:'^server 10.99.0.10 iburst$' cat ntp.conf
	# Taken away: the block goes, the line before stays.
	atf_check -o match:'ntp servers removed' "$JGC" -c "$SOCK" ntp remove
	atf_check -o not-match:'arcana' -o not-match:'10.99.0.10' -o match:'^server 0.freebsd.pool.ntp.org iburst$' cat ntp.conf
}
ntp_cleanup()
{
	stop_daemon
}

atf_test_case ipsec_sa cleanup
ipsec_sa_head()
{
	atf_set "descr" "Manually keyed SAs of an ipsec(4) interface by setkey(8) from a file; the keys never in the trace; cleared again"
}
ipsec_sa_body()
{
	write_rc
	cat > fake-setkey <<EOS
#!/bin/sh
echo "setkey \$*" >> $(pwd)/setkey.log
[ "\$1" = -f ] && { stat -f %Lp "\$2" >> $(pwd)/setkey.log; cat "\$2" >> $(pwd)/setkey.conf; }
exit 0
EOS
	chmod +x fake-setkey
	start_daemon
	K=00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff
	A=0011223344556677889900112233445566778899
	atf_check -s exit:1 -e match:'an ipsec\(4\) one' -o ignore "$JGC" -c "$SOCK" ipsec-sa set gre0 100 10.202.0.1 10.202.0.2 spi-in 0x1001 spi-out 0x1002
	atf_check -s exit:1 -e match:'from 256' -o ignore "$JGC" -c "$SOCK" ipsec-sa set ipsec0 100 10.202.0.1 10.202.0.2 spi-in 10 spi-out 0x1002 enc aes-cbc auth hmac-sha1 key-in $K key-out $K akey-in $A akey-out $A
	atf_check -s exit:1 -e match:'32, 48 or 64' -o ignore "$JGC" -c "$SOCK" ipsec-sa set ipsec0 100 10.202.0.1 10.202.0.2 spi-in 0x1001 spi-out 0x1002 enc aes-cbc auth hmac-sha1 key-in 0011 key-out $K akey-in $A akey-out $A
	atf_check -s exit:1 -e match:'authenticates by itself' -o ignore "$JGC" -c "$SOCK" ipsec-sa set ipsec0 100 10.202.0.1 10.202.0.2 spi-in 0x1001 spi-out 0x1002 enc aes-gcm-16 auth hmac-sha1 key-in ${K}00112233 key-out ${K}00112233
	atf_check -s exit:1 -e match:'of one family' -o ignore "$JGC" -c "$SOCK" ipsec-sa set ipsec0 100 10.202.0.1 fd00::2 spi-in 0x1001 spi-out 0x1002 enc aes-cbc auth hmac-sha1 key-in $K key-out $K akey-in $A akey-out $A
	# Set: the two SAs, out then in, on the reqid, ESN and ESP in UDP;
	# the file 0600; the trace without the keys, the title too.
	atf_check -o save:sa.out "$JGC" -t -c "$SOCK" ipsec-sa set ipsec0 100 10.202.0.1 10.202.0.2 spi-in 0x1001 spi-out 0x1002 enc aes-cbc auth hmac-sha1 key-in $K key-out $K akey-in $A akey-out $A encap esn
	atf_check -o match:'ipsec sa set ipsec0 reqid 100' -o not-match:"$K" -o not-match:"$A" -o match:'not kept: it has keys' cat sa.out
	atf_check -o match:'^600$' -o match:'^setkey -f /tmp/arcana-sa\.' cat setkey.log
	atf_check -o match:"^add 10.202.0.1 10.202.0.2 esp 0x1002 -m tunnel -u 100 -r 128 -esn -natt 10.202.0.1\[4500\] 10.202.0.2\[4500\] -E aes-cbc 0x$K -A hmac-sha1 0x$A ;\$" \
	    -o match:"^add 10.202.0.2 10.202.0.1 esp 0x1001 -m tunnel -u 100 -r 128 -esn -natt 10.202.0.2\[4500\] 10.202.0.1\[4500\] -E aes-cbc 0x$K -A hmac-sha1 0x$A ;\$" cat setkey.conf
	test ! -e /tmp/arcana-sa.* 2>/dev/null || true
	# GCM: no auth; neither flag.
	atf_check -o ignore "$JGC" -c "$SOCK" ipsec-sa set ipsec1 101 10.202.0.1 10.202.0.2 spi-in 0x2001 spi-out 0x2002 enc aes-gcm-16 key-in ${K}00112233 key-out ${K}00112233
	atf_check -o match:"^add 10.202.0.1 10.202.0.2 esp 0x2002 -m tunnel -u 101 -r 128 -E aes-gcm-16 0x${K}00112233 ;\$" cat setkey.conf
	# Cleared: every SA between the two, both ways.
	atf_check -o match:'ipsec sa clear ipsec0 reqid 100' "$JGC" -c "$SOCK" ipsec-sa clear ipsec0 100 10.202.0.1 10.202.0.2
	atf_check -o match:'^deleteall 10.202.0.1 10.202.0.2 esp ;$' -o match:'^deleteall 10.202.0.2 10.202.0.1 esp ;$' cat setkey.conf
	# A key pair an interface's own, 0600, made once; its public half
	# in the sdwan read; derived SAs: the two ends (two interfaces of
	# this one host standing for them) each take the other's public
	# half and come out with the same SAs, mirrored.
	atf_check -s exit:1 -o match:'no key pair yet' -e ignore "$JGC" -c "$SOCK" ipsec-sa derive ipsec0 100 10.202.0.1 10.202.0.2 peer AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA= enc aes-cbc auth hmac-sha2-256
	atf_check -o match:'ipsec sa key ipsec0' -o match:'public [A-Za-z0-9+/]{43}=' "$JGC" -t -c "$SOCK" ipsec-sa key ipsec0
	atf_check -o match:'^600$' stat -f %Lp "$(dirname "$f")/sdwan-key-ipsec0.pem"
	atf_check -o match:'BEGIN PRIVATE KEY' cat "$(dirname "$f")/sdwan-key-ipsec0.pem"
	atf_check -o ignore "$JGC" -c "$SOCK" ipsec-sa key ipsec1
	P0=$("$JGC" -c "$SOCK" sdwan | sed -E 's/.*"keys":\[//' | tr '}' '\n' | grep '"interface":"ipsec0"' | sed -E 's/.*"public":"([^"]*)".*/\1/')
	P1=$("$JGC" -c "$SOCK" sdwan | sed -E 's/.*"keys":\[//' | tr '}' '\n' | grep '"interface":"ipsec1"' | sed -E 's/.*"public":"([^"]*)".*/\1/')
	test ${#P0} -eq 44 -a ${#P1} -eq 44 -a "$P0" != "$P1" || atf_fail "the public halves: $P0 $P1"
	# Made again: the same pair.
	atf_check -o ignore "$JGC" -c "$SOCK" ipsec-sa key ipsec0
	atf_check -o match:"\"public\":\"$(echo "$P0" | sed 's|/|\\/|g; s|+|\\+|g')\"" "$JGC" -c "$SOCK" sdwan
	atf_check -s exit:1 -o match:'own public half' -e ignore "$JGC" -c "$SOCK" ipsec-sa derive ipsec0 100 10.202.0.1 10.202.0.2 peer "$P0" enc aes-cbc auth hmac-sha2-256
	atf_check -s exit:1 -e match:'no SPIs or keys' -o ignore "$JGC" -c "$SOCK" ipsec-sa derive ipsec0 100 10.202.0.1 10.202.0.2 peer "$P1" enc aes-cbc auth hmac-sha2-256 spi-in 0x1001
	rm -f setkey.conf
	atf_check -o not-match:'0x[0-9a-f]{40}' "$JGC" -t -c "$SOCK" ipsec-sa derive ipsec0 100 10.202.0.1 10.202.0.2 peer "$P1" enc aes-cbc auth hmac-sha2-256 encap esn
	atf_check -o ignore "$JGC" -c "$SOCK" ipsec-sa derive ipsec1 101 10.202.0.2 10.202.0.1 peer "$P0" enc aes-cbc auth hmac-sha2-256 encap esn
	atf_check -o inline:'4\n' sh -c "grep -c '^add ' setkey.conf"
	# The SA from .1 to .2 as ipsec0 set it out and as ipsec1 set it in:
	# one and the same but for the reqid; the other way too.
	atf_check -o inline:'1\n' sh -c "grep '^add 10.202.0.1 10.202.0.2 ' setkey.conf | sed 's/-u 10[01]/-u N/' | sort -u | wc -l | tr -d ' '"
	atf_check -o inline:'1\n' sh -c "grep '^add 10.202.0.2 10.202.0.1 ' setkey.conf | sed 's/-u 10[01]/-u N/' | sort -u | wc -l | tr -d ' '"
	atf_check -o match:'^add 10.202.0.1 10.202.0.2 esp 0x[0-9a-f]+ -m tunnel -u 100 -r 128 -esn -natt 10.202.0.1\[4500\] 10.202.0.2\[4500\] -E aes-cbc 0x[0-9a-f]{64} -A hmac-sha2-256 0x[0-9a-f]{64} ;$' cat setkey.conf
	# Another epoch: other keys; the SAs set before taken out first.
	S_IN=$(grep '^add 10.202.0.2 10.202.0.1 .* -u 100 ' setkey.conf | sed -E 's/.*esp (0x[0-9a-f]+).*/\1/')
	S_OUT=$(grep '^add 10.202.0.1 10.202.0.2 .* -u 100 ' setkey.conf | sed -E 's/.*esp (0x[0-9a-f]+).*/\1/')
	rm -f setkey.conf
	atf_check -o ignore "$JGC" -c "$SOCK" ipsec-sa derive ipsec0 100 10.202.0.1 10.202.0.2 peer "$P1" enc aes-gcm-16 epoch 1 lifetime 3600
	atf_check -o match:"^delete 10.202.0.2 10.202.0.1 esp $S_IN ;\$" -o match:"^delete 10.202.0.1 10.202.0.2 esp $S_OUT ;\$" -o match:'^add 10.202.0.1 10.202.0.2 esp 0x[0-9a-f]+ -m tunnel -u 100 -r 128 -E aes-gcm-16 0x[0-9a-f]{72} ;$' cat setkey.conf
	# What was set, kept and told: the SPIs, when, the lifetime.
	atf_check -o match:'"interface":"ipsec0","public":"[^"]*","keyed_at":[0-9]{10},"lifetime":3600,"spi_in":[0-9]+,"spi_out":[0-9]+,"pending":false' "$JGC" -c "$SOCK" sdwan
	# A rotation (R110, R112): the next pair on each end, its public
	# half told; the new SAs from the next pairs put in inbound on
	# both ends, then outbound, beside the old; then committed: the
	# old taken out, the next pair the pair.
	atf_check -s exit:1 -e match:'next at most' -o ignore "$JGC" -c "$SOCK" ipsec-sa key ipsec0 soon
	atf_check -s exit:1 -e match:"next is derive's" -o ignore "$JGC" -c "$SOCK" ipsec-sa set ipsec0 100 10.202.0.1 10.202.0.2 spi-in 0x1001 spi-out 0x1002 enc aes-gcm-16 key-in ${K}00112233 key-out ${K}00112233 next
	atf_check -s exit:1 -o match:'nothing to commit' -e ignore "$JGC" -c "$SOCK" ipsec-sa commit ipsec0 100 10.202.0.1 10.202.0.2
	atf_check -s exit:1 -o match:'no next pair yet' -e ignore "$JGC" -c "$SOCK" ipsec-sa derive ipsec0 100 10.202.0.1 10.202.0.2 peer "$P1" enc aes-gcm-16 next install in
	atf_check -o match:'"type":"key-rotation"' -o match:'"object":"ipsec0"' "$JGC" -c "$SOCK" sdwan
	atf_check -o match:'sdwan-key-ipsec0-next.pem' "$JGC" -t -c "$SOCK" ipsec-sa key ipsec0 next
	atf_check -o ignore "$JGC" -c "$SOCK" ipsec-sa key ipsec1 next
	atf_check -o match:'^600$' stat -f %Lp "$(dirname "$f")/sdwan-key-ipsec0-next.pem"
	N0=$("$JGC" -c "$SOCK" sdwan | sed -E 's/.*"keys":\[//' | tr '}' '\n' | grep '"interface":"ipsec0"' | sed -E 's/.*"next":"([^"]*)".*/\1/')
	N1=$("$JGC" -c "$SOCK" sdwan | sed -E 's/.*"keys":\[//' | tr '}' '\n' | grep '"interface":"ipsec1"' | sed -E 's/.*"next":"([^"]*)".*/\1/')
	test ${#N0} -eq 44 -a ${#N1} -eq 44 -a "$N0" != "$P0" -a "$N0" != "$N1" || atf_fail "the next halves: $N0 $N1"
	# ipsec1's SAs, derived plainly, as the ones to turn.
	atf_check -o ignore "$JGC" -c "$SOCK" ipsec-sa derive ipsec1 101 10.202.0.2 10.202.0.1 peer "$P0" enc aes-gcm-16 epoch 1
	rm -f setkey.conf
	atf_check -o ignore "$JGC" -c "$SOCK" ipsec-sa derive ipsec0 100 10.202.0.1 10.202.0.2 peer "$N1" enc aes-gcm-16 next install in
	atf_check -o ignore "$JGC" -c "$SOCK" ipsec-sa derive ipsec1 101 10.202.0.2 10.202.0.1 peer "$N0" enc aes-gcm-16 next install in
	# Inbound only: on ipsec0 the SA from .2, on ipsec1 the one from .1.
	atf_check -o inline:'2\n' sh -c "grep -c '^add ' setkey.conf"
	atf_check -o match:'^add 10.202.0.2 10.202.0.1 esp 0x[0-9a-f]+ -m tunnel -u 100 ' -o match:'^add 10.202.0.1 10.202.0.2 esp 0x[0-9a-f]+ -m tunnel -u 101 ' -o not-match:'^delete ' cat setkey.conf
	atf_check -o match:'"interface":"ipsec0",.*"pending":true' "$JGC" -c "$SOCK" sdwan
	# Run again, the same inbound SA: taken out and put in again.
	atf_check -o ignore "$JGC" -c "$SOCK" ipsec-sa derive ipsec0 100 10.202.0.1 10.202.0.2 peer "$N1" enc aes-gcm-16 next install in
	atf_check -o match:'^delete 10.202.0.2 10.202.0.1 esp 0x[0-9a-f]+ ;$' cat setkey.conf
	# Outbound: the new SA in, and the old outbound one out with it.
	O_OUT=$("$JGC" -c "$SOCK" sdwan | sed -E 's/.*"keys":\[//' | tr '}' '\n' | grep '"interface":"ipsec0"' | sed -E 's/.*"spi_out":([0-9]+).*/\1/')
	rm -f setkey.conf
	atf_check -o ignore "$JGC" -c "$SOCK" ipsec-sa derive ipsec0 100 10.202.0.1 10.202.0.2 peer "$N1" enc aes-gcm-16 next install out
	atf_check -o ignore "$JGC" -c "$SOCK" ipsec-sa derive ipsec1 101 10.202.0.2 10.202.0.1 peer "$N0" enc aes-gcm-16 next install out
	atf_check -o inline:'2\n' sh -c "grep -c '^add ' setkey.conf"
	atf_check -o inline:'2\n' sh -c "grep -c '^delete ' setkey.conf"
	atf_check -o match:'^add 10.202.0.1 10.202.0.2 esp 0x[0-9a-f]+ -m tunnel -u 100 ' -o match:'^add 10.202.0.2 10.202.0.1 esp 0x[0-9a-f]+ -m tunnel -u 101 ' -o match:"^delete 10.202.0.1 10.202.0.2 esp $(printf '0x%x' "$O_OUT") ;\$" cat setkey.conf
	# The new SAs the same on both, mirrored, and not the old ones.
	atf_check -o inline:'1\n' sh -c "grep '^add 10.202.0.1 10.202.0.2 ' setkey.conf | sed 's/-u 10[01]/-u N/' | sort -u | wc -l | tr -d ' '"
	# Committed: the old inbound SPI out, the next pair the pair, the
	# fault cleared.
	O_IN=$("$JGC" -c "$SOCK" sdwan | sed -E 's/.*"keys":\[//' | tr '}' '\n' | grep '"interface":"ipsec0"' | sed -E 's/.*"spi_in":([0-9]+).*/\1/')
	rm -f setkey.conf
	atf_check -o match:'ipsec sa commit ipsec0 reqid 100' -o match:'spi in 0x' "$JGC" -t -c "$SOCK" ipsec-sa commit ipsec0 100 10.202.0.1 10.202.0.2
	atf_check -o inline:'1\n' sh -c "grep -c '^delete ' setkey.conf"
	atf_check -o match:"^delete 10.202.0.2 10.202.0.1 esp $(printf '0x%x' "$O_IN") ;\$" -o not-match:'^add ' cat setkey.conf
	test ! -e "$(dirname "$f")/sdwan-key-ipsec0-next.pem" || atf_fail "the next pair still there"
	atf_check -o match:"\"interface\":\"ipsec0\",\"public\":\"$(echo "$N0" | sed 's|/|\\/|g; s|+|\\+|g')\"" -o match:'"interface":"ipsec0",.*"pending":false' -o match:'"type":"key-rotation",.*"cleared":true' "$JGC" -c "$SOCK" sdwan
	atf_check -s exit:1 -o match:'nothing to commit' -e ignore "$JGC" -c "$SOCK" ipsec-sa commit ipsec0 100 10.202.0.1 10.202.0.2
	# Cleared: the next pair and what was kept go with the SAs.
	atf_check -o ignore "$JGC" -c "$SOCK" ipsec-sa key ipsec1 next
	atf_check -o ignore "$JGC" -c "$SOCK" ipsec-sa clear ipsec1 101 10.202.0.2 10.202.0.1
	test ! -e "$(dirname "$f")/sdwan-key-ipsec1-next.pem" -a ! -e "$(dirname "$f")/sdwan-sa-ipsec1.json" || atf_fail "ipsec1 not cleared"
}
ipsec_sa_cleanup()
{
	stop_daemon
}

atf_test_case rtadvd cleanup
rtadvd_head()
{
	atf_set "descr" "Router advertisements on an interface: an entry in rtadvd.conf between arcana's marks, the interface on rtadvd_interfaces, rtadvd enabled and restarted; taken away again"
}
rtadvd_body()
{
	write_rc
	printf 'em0:\\\n\t:addr="2001:db8:9::":prefixlen#64:\n' > rtadvd.conf
	start_daemon
	atf_check -s exit:1 -e match:'length 64' -o ignore "$JGC" -c "$SOCK" rtadvd gre100 2001:db8:1::/48
	atf_check -s exit:1 -e match:'not an IPv6 address' -o ignore "$JGC" -c "$SOCK" rtadvd gre100 2001:db8:1::/64 8.8.8.8
	atf_check -o match:'rtadvd on gre100 2001:db8:1::/64' "$JGC" -c "$SOCK" -p rtadvd gre100 2001:db8:1::/64 2001:db8::53 2001:db8::54
	atf_check -o match:'^em0:' \
	    -o match:'^# arcana: the UNIs. router advertisements, set by the console; begin$' \
	    -o match:'^gre100:\\$' \
	    -o match:'^	:addr="2001:db8:1::":prefixlen#64:rdnss="2001:db8::53,2001:db8::54":$' \
	    -o match:'^# arcana: end$' cat rtadvd.conf
	atf_check -o match:'^rtadvd_enable="YES"$' -o match:'^rtadvd_interfaces="gre100"$' cat rc.conf
	test -f running.rtadvd || atf_fail "rtadvd was not restarted"
	# A second interface: two entries in the one block; the first set
	# again: its entry once, the new prefix.
	atf_check -o ignore "$JGC" -c "$SOCK" -p rtadvd vlan100 2001:db8:2::/64
	atf_check -o ignore "$JGC" -c "$SOCK" -p rtadvd gre100 2001:db8:3::/64
	atf_check -o inline:'1\n' sh -c "grep -c '^# arcana: end' rtadvd.conf"
	atf_check -o inline:'1\n' sh -c "grep -c '^gre100:' rtadvd.conf"
	atf_check -o match:'addr="2001:db8:3::"' -o not-match:'2001:db8:1::' -o match:'^vlan100:' cat rtadvd.conf
	atf_check -o match:'^rtadvd_interfaces="gre100 vlan100"$' cat rc.conf
	# Taken away one by one: the other stays; the last takes the block
	# and rtadvd with it.
	atf_check -o match:'rtadvd off gre100' "$JGC" -c "$SOCK" -p rtadvd gre100 remove
	atf_check -o not-match:'gre100' -o match:'^vlan100:' -o match:'arcana' cat rtadvd.conf
	atf_check -o match:'^rtadvd_enable="YES"$' -o match:'^rtadvd_interfaces="vlan100"$' cat rc.conf
	atf_check -o ignore "$JGC" -c "$SOCK" -p rtadvd vlan100 remove
	atf_check -o not-match:'arcana' -o not-match:'vlan100' -o match:'^em0:' cat rtadvd.conf
	atf_check -o match:'^rtadvd_enable="NO"$' cat rc.conf
}
rtadvd_cleanup()
{
	stop_daemon
}

atf_test_case jail_conf cleanup
jail_conf_head()
{
	atf_set "descr" "jail-conf: the jails' defaults, a template, a jail made from a base snapshot with its file, and taken away"
}
jail_conf_body()
{
	# zfs(8): a dataset there or not by a marker, its mountpoint, what
	# it is told logged; send writes a stream, recv reads it.
	cat > fake-zfs <<EOS
#!/bin/sh
echo "zfs \$*" >> $(pwd)/zfs.log
case "\$1" in
list) [ -e "$(pwd)/ds.\$(echo "\$5" | tr / _)" ] ;;
get) cat "$(pwd)/mp.\$(echo "\$6" | tr / _)" 2>/dev/null || exit 1 ;;
clone) touch "$(pwd)/ds.\$(echo "\$5" | tr / _)"; echo "\$3" | sed 's/^mountpoint=//' > "$(pwd)/mp.\$(echo "\$5" | tr / _)" ;;
send) echo "stream of \$2" ;;
recv) cat > "$(pwd)/recv.in"; [ -e $(pwd)/recv.fail ] && exit 1; touch "$(pwd)/ds.\$(echo "\$4" | tr / _)" ;;
destroy) rm -f "$(pwd)/ds.\$(echo "\$3" | tr / _)" ;;
esac
EOS
	chmod +x fake-zfs
	touch ds.tank ds.tank_jails
	DAEMON_ARGS="-z $(pwd)/fake-zfs"
	start_daemon
	d=$(pwd)/etc
	# The defaults every jail file includes, the file before kept; one
	# jail(8) does not take is refused and the one before put back.
	printf 'path = "/usr/jails/${name}";\nhost.hostname = "${name}.example.org";\nexec.start = "/bin/sh /etc/rc";\nmount.devfs;\n' > defaults.conf
	atf_check -o match:'done +jail defaults' "$JGC" -c "$SOCK" jailconf defaults defaults.conf
	atf_check cmp -s defaults.conf "$d/jail.conf"
	test -f "$d/jail.conf.arcana.bak" || atf_fail "the jail.conf before was not kept"
	printf 'path = "/usr/jails/${name}";\nbroken {\n' > bad.conf
	atf_check -s exit:1 -o match:'jail\(8\) does not take it.*the one before put back' "$JGC" -c "$SOCK" jailconf defaults bad.conf
	atf_check cmp -s defaults.conf "$d/jail.conf"
	# A template, kept beside the jails, outside rc.d/jail's *.conf.
	printf 'exec.created += "mkdir -p /usr/jails/${name}/x";\nallow.raw_sockets;\n' > certbot.inc
	atf_check -o match:'done +jail template certbot' "$JGC" -c "$SOCK" jailconf template certbot certbot.inc
	atf_check cmp -s certbot.inc "$d/jail.conf.d/certbot.inc"
	# A jail: its dataset cloned from the base's snapshot at its path,
	# its file read back by jail(8) and put in place, then started.
	printf '.include "%s/jail.conf";\nwww {\n\tdevfs_ruleset = 4;\n\tip4.addr = "lo0|127.0.0.9";\n\t.include "%s/jail.conf.d/certbot.inc";\n}\n' "$d" "$d" > www.conf
	atf_check -o match:'done +jail make www from tank/jails/base@15.0' \
	    -o match:'fake-jail -f [^ ]+ -c www: exit status 0' \
	    "$JGC" -t -c "$SOCK" jailconf make www www.conf tank/jails/www tank/jails/base@15.0 clone /usr/jails/www start
	atf_check -o match:'^zfs clone -o mountpoint=/usr/jails/www tank/jails/base@15.0 tank/jails/www$' cat zfs.log
	atf_check cmp -s www.conf "$d/jail.conf.d/www.conf"
	# Not twice; not a file of another jail, nor of two; not where the
	# path is not the dataset's: nothing made, the dataset taken back.
	atf_check -s exit:1 -o match:'is there already' "$JGC" -c "$SOCK" jailconf make www www.conf
	printf '.include "%s/jail.conf";\nmail {\n}\n' "$d" > mail.conf
	atf_check -s exit:1 -o match:'the file defines mail, not the one jail web2' "$JGC" -c "$SOCK" jailconf make web2 mail.conf tank/jails/web2 tank/jails/base@15.0 send /usr/jails/web2
	test -e ds.tank_jails_web2 && atf_fail "the dataset made for a refused jail stayed"
	test -e "$d/jail.conf.d/web2.conf" && atf_fail "a refused jail's file stayed"
	printf '.include "%s/jail.conf";\nweb2 {\n\tpath = /elsewhere;\n}\n' "$d" > web2.conf
	atf_check -s exit:1 -o match:'path is /elsewhere, not /usr/jails/web2' "$JGC" -c "$SOCK" jailconf make web2 web2.conf tank/jails/web2 tank/jails/base@15.0 send /usr/jails/web2
	# A copy of its own: zfs send into zfs recv, mounted at its path.
	printf '.include "%s/jail.conf";\nweb2 {\n}\n' "$d" > web2.conf
	atf_check -o match:'done +jail make web2' "$JGC" -c "$SOCK" jailconf make web2 web2.conf tank/jails/web2 tank/jails/base@15.0 send /usr/jails/web2
	atf_check -o match:'^zfs send tank/jails/base@15.0$' -o match:'^zfs recv -o mountpoint=/usr/jails/web2 tank/jails/web2$' cat zfs.log
	atf_check -o inline:'stream of tank/jails/base@15.0\n' cat recv.in
	# A pool that is not there is not one to make anything in.
	atf_check -s exit:1 -o match:'there is no pool nopool' "$JGC" -c "$SOCK" jailconf make web3 web2.conf nopool/jails/web3 tank/jails/base@15.0 clone /usr/jails/web3
	atf_check -o not-match:'destroy -r nopool' -o not-match:'create' cat zfs.log
	# A made jail's file changed: read back first, the one before kept;
	# one of another jail refused, the file left; none is no jail made.
	printf '.include "%s/jail.conf";\nwww {\n\tdevfs_ruleset = 5;\n\tip4.addr = "lo0|127.0.0.9";\n\t.include "%s/jail.conf.d/certbot.inc";\n}\n' "$d" "$d" > www2.conf
	atf_check -o match:'done +jail edit www$' "$JGC" -c "$SOCK" jailconf edit www www2.conf
	atf_check cmp -s www2.conf "$d/jail.conf.d/www.conf"
	atf_check cmp -s www.conf "$d/jail.conf.d/www.conf.arcana.bak"
	atf_check -s exit:1 -o match:'the file defines mail, not the one jail www' "$JGC" -c "$SOCK" jailconf edit www mail.conf
	atf_check cmp -s www2.conf "$d/jail.conf.d/www.conf"
	atf_check -s exit:1 -o match:'nosuch.conf: No such file' "$JGC" -c "$SOCK" jailconf edit nosuch www2.conf
	test -e "$d/jail.conf.d/nosuch.conf" && atf_fail "edit made a jail"
	# The template kept while a jail includes it.
	atf_check -s exit:1 -o match:'certbot.inc is included by www.conf: kept' "$JGC" -c "$SOCK" jailconf untemplate certbot
	# Checked before queued: names, datasets, the copy, the path.
	atf_check -s exit:1 -e match:'invalid jail name' -o ignore "$JGC" -c "$SOCK" jailconf make 'a b' www.conf
	atf_check -s exit:1 -e match:'under a pool' -o ignore "$JGC" -c "$SOCK" jailconf make x www.conf tank tank/jails/base@15.0 clone /usr/jails/x
	atf_check -s exit:1 -e match:'clone or send' -o ignore "$JGC" -c "$SOCK" jailconf make x www.conf tank/jails/x tank/jails/base@15.0 copy /usr/jails/x
	atf_check -s exit:1 -e match:'an absolute one' -o ignore "$JGC" -c "$SOCK" jailconf make x www.conf tank/jails/x tank/jails/base@15.0 clone usr/jails/x
	# Taken away: its dataset only where it is mounted at its path.
	atf_check -s exit:1 -o match:'tank/jails/web2 is not mounted at the jail' "$JGC" -c "$SOCK" jailconf remove www tank/jails/web2
	test -f "$d/jail.conf.d/www.conf" || atf_fail "a jail was taken away when its dataset was not its"
	atf_check -o match:'done +jail remove www' "$JGC" -c "$SOCK" jailconf remove www tank/jails/www
	test -e "$d/jail.conf.d/www.conf" && atf_fail "the jail's file stayed"
	atf_check -o match:'^zfs destroy -r tank/jails/www$' cat zfs.log
	atf_check -o match:'done +jail untemplate certbot' "$JGC" -c "$SOCK" jailconf untemplate certbot
}
jail_conf_cleanup()
{
	stop_daemon
}

atf_test_case carp cleanup
carp_head()
{
	atf_set "descr" "A carp(4) address: its vhid set by the helper with the key on its input, the address under it, kept in rc.conf with carp in kld_list; changed there; taken away; what is not one refused"
}
carp_body()
{
	cat > fake-ifconfig <<EOS
#!/bin/sh
echo "\$*" >> $(pwd)/ifconfig.log
exit 0
EOS
	chmod +x fake-ifconfig
	start_daemon
	echo 'sekrit' | atf_check -o match:'done +lo0: carp add vhid 3 10.0.0.100/24$' \
	    -o not-match:'sekrit' "$JGC" -t -p -c "$SOCK" carp add lo0 10.0.0.100/24 vhid=3 advskew=20 key
	atf_check -o inline:'carp-set lo0 3 advskew=20 key=sekrit\n' cat carp.log
	atf_check -o match:'^lo0 inet 10.0.0.100/24 vhid 3 alias$' cat ifconfig.log
	atf_check -o match:'^ifconfig_lo0_alias0="inet vhid 3 advskew 20 pass sekrit 10.0.0.100/24"$' \
	    -o match:'^kld_list="carp"$' cat rc.conf
	# Changed: kept as it is now, the key as it was.
	atf_check -o match:'done +lo0: carp set vhid 3$' \
	    "$JGC" -p -c "$SOCK" carp set lo0 vhid=3 advskew=40 state=backup
	atf_check -o match:'^carp-set lo0 3 advskew=40 state=backup key=$' tail -1 carp.log
	atf_check -o match:'^ifconfig_lo0_alias0="inet vhid 3 advskew 40 pass sekrit 10.0.0.100/24"$' cat rc.conf
	# Taken away, from rc.conf too.
	atf_check -o match:'done +lo0: carp remove vhid 3 10.0.0.100' \
	    "$JGC" -p -c "$SOCK" carp remove lo0 10.0.0.100 vhid=3
	atf_check -o match:'^lo0 inet 10.0.0.100 -alias$' tail -1 ifconfig.log
	atf_check -o not-match:'ifconfig_lo0_alias' cat rc.conf
	# What is not one.
	atf_check -s exit:1 -e match:'a vhid, 1 to 255' -o ignore \
	    "$JGC" -c "$SOCK" carp add lo0 10.0.0.100/24 vhid=0
	atf_check -s exit:1 -e match:'the words are vhid' -o ignore \
	    "$JGC" -c "$SOCK" carp add lo0 10.0.0.100/24 vhid=3 peer=10.0.0.9
	echo 'a key with spaces' | atf_check -s exit:1 -e match:'19 characters at most' -o ignore \
	    "$JGC" -c "$SOCK" carp add lo0 10.0.0.100/24 vhid=3 key
	atf_check -s exit:1 -e match:'not in safe mode' -o ignore \
	    "$JGC" -s -c "$SOCK" carp set lo0 vhid=3 advskew=1
	atf_check -s exit:1 -e match:'state master or backup' -o ignore \
	    "$JGC" -c "$SOCK" carp set lo0 vhid=3 state=init
}
carp_cleanup()
{
	stop_daemon
}

atf_test_case clamav cleanup
clamav_head()
{
	atf_set "descr" "freshclam's mirrors written into freshclam.conf, made from the port's sample when there is none"
}
clamav_body()
{
	d=$(pwd)
	mkdir fc
	printf '# Comment\nExample\nDatabaseOwner clamav\nDatabaseMirror database.clamav.net\nNotifyClamd /usr/local/etc/clamd.conf\n' \
	    > fc/freshclam.conf.sample
	DAEMON_ARGS="--freshclam-conf $d/fc/freshclam.conf"
	start_daemon
	# None there: made from the sample, without its Example line, the
	# mirrors in the order given where the sample's was.
	atf_check -o match:'done' "$JGC" -c "$SOCK" clamav mirrors \
	    database.clamav.net https://packages.microsoft.com/clam
	atf_check -o inline:'# Comment\nDatabaseOwner clamav\nDatabaseMirror database.clamav.net\nDatabaseMirror https://packages.microsoft.com/clam\nNotifyClamd /usr/local/etc/clamd.conf\n' \
	    cat fc/freshclam.conf
	# There: its mirrors replaced, the rest as it was.
	atf_check -o match:'done' "$JGC" -c "$SOCK" clamav mirrors \
	    https://mirror.example.org/clamav
	atf_check -o inline:'# Comment\nDatabaseOwner clamav\nDatabaseMirror https://mirror.example.org/clamav\nNotifyClamd /usr/local/etc/clamd.conf\n' \
	    cat fc/freshclam.conf
	# What is not a mirror, none, a jail's: refused.
	atf_check -s exit:1 -e match:'host name, or an http or https' \
	    -o ignore "$JGC" -c "$SOCK" clamav mirrors 'ftp://x/y'
	atf_check -s exit:1 -e match:'host name, or an http or https' \
	    -o ignore "$JGC" -c "$SOCK" clamav mirrors 'a b'
	atf_check -s exit:1 -e match:"freshclam is the host's" -o ignore \
	    "$JGC" -c "$SOCK" -j web clamav mirrors database.clamav.net
	# Neither the file nor its sample: ClamAV is not there.
	rm fc/freshclam.conf fc/freshclam.conf.sample
	atf_check -s exit:1 -o match:'pkg install clamav' -e ignore \
	    "$JGC" -c "$SOCK" clamav mirrors database.clamav.net
}
clamav_cleanup()
{
	stop_daemon
}

atf_test_case multicast cleanup
multicast_head()
{
	atf_set "descr" "IGMP's and MLD's state as ifmcstat(8) prints it:" \
	    "each interface's version and timers, the groups joined with" \
	    "their mode, link-level address and sources; and the kernel's" \
	    "settings by sysctl(8)"
}
multicast_body()
{
	# ifmcstat(8) as FreeBSD prints it (tabs, a source under a group).
	printf '#!/bin/sh\nprintf "%s"\n' 'vtnet0:\n\tinet 192.0.2.5\n\tigmpv3 rv 2 qi 125 qri 100 uri 3\n\t\tgroup 224.0.0.1 mode exclude\n\t\t\tmcast-macaddr 01:00:5e:00:00:01\n\t\tgroup 232.1.1.1 mode include\n\t\t\tsource 192.0.2.9\n\t\t\tmcast-macaddr 01:00:5e:01:01:01\n\tinet6 fe80::1%%vtnet0 scopeid 0x1\n\tmldv2 flags=2<USEALLOW> rv 2 qi 125 qri 10000 uri 3\n\t\tgroup ff02::1%%vtnet0 scopeid 0x1 mode exclude\n\t\t\tmcast-macaddr 33:33:00:00:00:01\nlo0:\n\tinet 127.0.0.1\n\tigmpv2 rv 2 qi 125 qri 10 uri 3\n\t\tgroup 224.0.0.1 mode exclude\n' > fake-ifmcstat
	chmod +x fake-ifmcstat
	DAEMON_ARGS="--ifmcstat $(pwd)/fake-ifmcstat"
	start_daemon
	atf_check -o save:m.json "$JGC" -c "$SOCK" net multicast
	atf_check -o match:'"name":"vtnet0","groups":\[\{"family":"inet","group":"224.0.0.1","mode":"exclude","sources":\[\],"lladdr":"01:00:5e:00:00:01"\},\{"family":"inet","group":"232.1.1.1","mode":"include","sources":\["192.0.2.9"\],"lladdr":"01:00:5e:01:01:01"\},\{"family":"inet6","group":"ff02::1","mode":"exclude"' \
	    -o match:'"igmp":\{"version":3,"rv":2,"qi":125,"qri":100,"uri":3\}' \
	    -o match:'"mld":\{"version":2,"flags":"USEALLOW","rv":2,"qi":125,"qri":10000,"uri":3\}' \
	    -o match:'"name":"lo0",.*"igmp":\{"version":2,' \
	    -o match:'"settings":\[\{"name":"net.inet.igmp.default_version","value":"[123]"\}' \
	    cat m.json
	# And the host's own, as its ifmcstat says it.
	stop_daemon
	if [ -x /usr/sbin/ifmcstat ]; then
		DAEMON_ARGS=""
		start_daemon
		atf_check -o match:'"interfaces":\[\{"name":"[a-z]+[0-9]*",' \
		    -o match:'"group":"224.0.0.1"' "$JGC" -c "$SOCK" net multicast
	fi
}
multicast_cleanup()
{
	stop_daemon
}

atf_test_case neighbours cleanup
neighbours_head()
{
	atf_set "descr" "ARP and NDP neighbours set by hand, permanent or aging out, kept in rc.conf's static pairs, and deleted"
}
neighbours_body()
{
	mkdir -p tools
	for p in arp ndp; do
		printf '#!/bin/sh\necho "%s $*" >> %s/neigh.log\n' "$p" "$(pwd)" > tools/$p
		chmod +x tools/$p
	done
	DAEMON_ARGS="-2 $(pwd)/tools"
	start_daemon
	atf_check -o match:'done +neighbour add 192.0.2.5 00:11:22:33:44:55$' \
	    "$JGC" -c "$SOCK" neigh add 192.0.2.5 00:11:22:33:44:55
	atf_check -o match:'done +neighbour add 192.0.2.6 00:11:22:33:44:66 \(ages out\)$' \
	    "$JGC" -c "$SOCK" neigh add 192.0.2.6 00:11:22:33:44:66 temp
	# Kept for a boot: a pair of static_ndp_pairs, named by the address.
	atf_check -o match:'done +neighbour add fe80::1%em0 00:11:22:33:44:77 \(now, and kept\)$' \
	    "$JGC" -p -c "$SOCK" neigh add 'fe80::1%em0' 00:11:22:33:44:77
	atf_check -o inline:'arp -s 192.0.2.5 00:11:22:33:44:55
arp -s 192.0.2.6 00:11:22:33:44:66 temp
ndp -s fe80::1%em0 00:11:22:33:44:77
' cat neigh.log
	atf_check -o match:'^static_ndp_pairs="arcana_fe80__1_em0"$' \
	    -o match:'^static_ndp_arcana_fe80__1_em0="fe80::1%em0 00:11:22:33:44:77"$' cat rc.conf
	atf_check -o match:'done +neighbour delete fe80::1%em0' \
	    "$JGC" -p -c "$SOCK" neigh delete 'fe80::1%em0'
	atf_check -o match:'^ndp -d fe80::1%em0$' tail -1 neigh.log
	atf_check -o not-match:'arcana_fe80' cat rc.conf
	# What is not a neighbour, nor one that ages out kept for a boot.
	atf_check -s exit:1 -e match:'six bytes of hex' -o ignore \
	    "$JGC" -c "$SOCK" neigh add 192.0.2.7 00:11:22
	atf_check -s exit:1 -e match:'an IPv4 or IPv6 address' -o ignore \
	    "$JGC" -c "$SOCK" neigh add host.example 00:11:22:33:44:55
	# A zone is an interface's name: nothing for sh to read in rc.conf.
	atf_check -s exit:1 -e match:'an IPv4 or IPv6 address' -o ignore \
	    "$JGC" -p -c "$SOCK" neigh add 'fe80::1%";id>x;"' 00:11:22:33:44:55
	test -e x && atf_fail "ran"
	atf_check -s exit:1 -e match:'not kept for a boot' -o ignore \
	    "$JGC" -p -c "$SOCK" neigh add 192.0.2.8 00:11:22:33:44:88 temp
}
neighbours_cleanup()
{
	stop_daemon
}

atf_test_case certs cleanup
certs_head()
{
	atf_set "descr" "The certificates OpenSSL trusts, read with OpenSSL; added, distrusted and trusted again where certctl rehash keeps them"
}
certs_body()
{
	R=$(pwd)/tools/certroot
	mkdir -p tools $R/usr/share/certs/trusted
	# certctl rehash as it is: the store made again from FreeBSD's own,
	# those given, and those not to be trusted, by fingerprint.
	cat > tools/certctl <<EOT
#!/bin/sh
echo "certctl \$*" >> $(pwd)/certctl.log
R=\$2
fp() { openssl x509 -noout -fingerprint -sha256 -in "\$1" | tr -d ' '; }
rm -rf \$R/etc/ssl/certs \$R/etc/ssl/untrusted
mkdir -p \$R/etc/ssl/certs \$R/etc/ssl/untrusted
bad=
for f in \$R/usr/local/share/certs/untrusted/*; do
	[ -f "\$f" ] || continue
	bad="\$bad \$(fp \$f)"
	cp \$f \$R/etc/ssl/untrusted/\$(basename \$f .pem)
done
for f in \$R/usr/share/certs/trusted/* \$R/usr/local/share/certs/trusted/*; do
	[ -f "\$f" ] || continue
	case "\$bad" in *\$(fp \$f)*) continue ;; esac
	cp \$f \$R/etc/ssl/certs/\$(basename \$f .pem).0
done
EOT
	chmod +x tools/certctl
	for n in root added; do
		openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 \
		    -nodes -keyout $n.key -out $n.pem -days 30 \
		    -subj "/O=Arcana/CN=Arcana $n CA" 2>/dev/null ||
		    atf_fail "openssl req"
	done
	cp root.pem $R/usr/share/certs/trusted/root.pem
	DAEMON_ARGS="-2 $(pwd)/tools"
	start_daemon
	atf_check -o match:'done +certificate rehash$' "$JGC" -c "$SOCK" cert rehash
	atf_check -o inline:"certctl -D $R rehash\n" cat certctl.log
	# Read with OpenSSL: who, its key, when it ends; FreeBSD's own.
	atf_check -o save:list "$JGC" -c "$SOCK" cert
	atf_check -o match:'"file":"root.0"' -o match:'"cn":"Arcana root CA"' \
	    -o match:'"org":"Arcana"' -o match:'"key":"EC prime256v1"' \
	    -o match:'"self_signed":true' -o match:'"not_after":[0-9]{10}' \
	    -o match:'"untrusted":\[\]' -o not-match:'"local"' cat list
	# Given one: kept where rehash finds it, the certificate alone.
	cat added.key >> added.pem
	atf_check -s exit:1 -e match:'no key with it' -o ignore \
	    "$JGC" -c "$SOCK" cert add added added.pem
	openssl x509 -in added.pem -out added.pem
	atf_check -o match:'done +certificate add added$' \
	    "$JGC" -c "$SOCK" cert add added added.pem
	atf_check -o match:'BEGIN CERTIFICATE' -o not-match:'PRIVATE' \
	    cat $R/usr/local/share/certs/trusted/added.pem
	atf_check -o match:'"cn":"Arcana added CA"[^}]*"local":"/usr/local/share/certs/trusted/added.pem"' \
	    "$JGC" -c "$SOCK" cert
	# FreeBSD's own not trusted: a copy among the untrusted.
	atf_check -o match:'done +certificate untrust root.0$' \
	    "$JGC" -c "$SOCK" cert untrust root.0
	test -f $R/usr/local/share/certs/untrusted/root.0.pem || atf_fail "no copy"
	atf_check -o match:'"untrusted":\[\{"file":"root.0"[^]]*"local":"/usr/local/share/certs/untrusted/root.0.pem"' \
	    -o not-match:'"trusted":\[[^]]*Arcana root' "$JGC" -c "$SOCK" cert
	# Trusted again: the copy taken away.
	atf_check -o match:'done +certificate trust root.0$' \
	    "$JGC" -c "$SOCK" cert trust root.0
	test -f $R/usr/local/share/certs/untrusted/root.0.pem && atf_fail "copy kept"
	atf_check -o match:'"untrusted":\[\]' -o match:'"cn":"Arcana root CA"' \
	    "$JGC" -c "$SOCK" cert
	# One FreeBSD itself does not trust is not trusted again here.
	cp root.pem $R/etc/ssl/untrusted/other.0
	atf_check -s exit:1 -o match:'failed +certificate trust other.0: other.0 is untrusted by FreeBSD itself' \
	    "$JGC" -c "$SOCK" cert trust other.0
	atf_check -o match:'done +certificate remove added.pem$' \
	    "$JGC" -c "$SOCK" cert remove added.pem
	atf_check -o not-match:'Arcana added' "$JGC" -c "$SOCK" cert
	atf_check -s exit:1 -o match:'was not given to this host' \
	    "$JGC" -c "$SOCK" cert remove added.pem
	atf_check -s exit:1 -e match:'letters, digits' -o ignore \
	    "$JGC" -c "$SOCK" cert untrust ../root.0
	echo nothing > junk.pem
	atf_check -s exit:1 -e match:'no PEM certificate' -o ignore \
	    "$JGC" -c "$SOCK" cert add junk junk.pem
}
certs_cleanup()
{
	stop_daemon
}

atf_test_case sshd cleanup
sshd_head()
{
	atf_set "descr" "The base system's sshd: its settings, banner, host keys and their certificates, and the keys users sign in with"
}
sshd_body()
{
	R=$(pwd)/tools/sshroot
	mkdir -p tools $R/etc/ssh $R/root $R/home/alice
	# sshd -t refuses what says BAD; -T is the file's settings.
	cat > tools/sshd <<'EOT'
#!/bin/sh
case "$1" in
-t)	if grep -q BAD "$3"; then
		echo "$3 line 1: Bad configuration option: BAD" >&2
		exit 255
	fi
	exit 0 ;;
-T)	awk '!/^[ \t]*#/ && NF > 1 { if (tolower($1) == "match") exit;
	    k = tolower($1); $1 = ""; sub(/^ /, ""); print k, $0 }' "$3"
	grep -qi '^hostkey' "$3" ||
	    echo "hostkey /etc/ssh/ssh_host_ed25519_key"
	exit 0 ;;
esac
exit 1
EOT
	chmod +x tools/sshd
	ln -s "$(which ssh-keygen)" tools/ssh-keygen
	ln -s "$(which ssh-agent)" tools/ssh-agent
	ln -s "$(which ssh-add)" tools/ssh-add
	printf 'PermitRootLogin no\nPasswordAuthentication yes\nMatch User nobody\n\tPasswordAuthentication no\n' \
	    > $R/etc/ssh/sshd_config
	printf 'root:*:0:0:Charlie &:/root:/bin/sh\nalice:*:%d:%d:Alice:/home/alice:/bin/sh\ndaemon:*:1:1::/root:/usr/sbin/nologin\n' \
	    "$(id -u)" "$(id -g)" > $R/etc/passwd
	ssh-keygen -q -t ed25519 -N '' -C host -f $R/etc/ssh/ssh_host_ed25519_key
	ssh-keygen -q -t ed25519 -N '' -C alice@lab -f alice_key
	ssh-keygen -q -t ed25519 -N '' -C lab-ca -f ca
	hostfp=$(ssh-keygen -lf $R/etc/ssh/ssh_host_ed25519_key.pub | awk '{print $2}')
	alicefp=$(ssh-keygen -lf alice_key.pub | awk '{print $2}')
	cafp=$(ssh-keygen -lf ca.pub | awk '{print $2}')
	DAEMON_ARGS="-2 $(pwd)/tools -w 2"
	start_daemon
	# Read: its settings, its host key's fingerprint, who signs in.
	atf_check -o save:list "$JGC" -c "$SOCK" sshd
	atf_check -o match:'"permitrootlogin":\["no"\]' -o match:'"bits":256' \
	    -o match:'"name":"alice"' -o match:'"name":"root"' \
	    -o not-match:'"name":"daemon"' cat list
	grep -qF "\"fingerprint\":\"$hostfp\"" list || atf_fail "host key"
	# A setting: read by sshd -t, before the first Match, the file kept.
	atf_check -o match:'done +sshd set PermitRootLogin$' \
	    "$JGC" -c "$SOCK" sshd set PermitRootLogin prohibit-password
	atf_check -o inline:'PermitRootLogin prohibit-password\nPasswordAuthentication yes\nMatch User nobody\n\tPasswordAuthentication no\n' \
	    cat $R/etc/ssh/sshd_config
	test -f $R/etc/ssh/sshd_config.arcana-before || atf_fail "not kept"
	atf_check -o match:'done' "$JGC" -c "$SOCK" sshd set AllowUsers alice 'bob@10.*'
	atf_check -o match:'^AllowUsers alice bob@10\.\*$' cat $R/etc/ssh/sshd_config
	atf_check -o match:'done' "$JGC" -c "$SOCK" sshd set AllowUsers
	atf_check -o not-match:'AllowUsers' cat $R/etc/ssh/sshd_config
	atf_check -s exit:1 -e match:'a value it takes' -o ignore \
	    "$JGC" -c "$SOCK" sshd set PermitRootLogin maybe
	atf_check -s exit:1 -e match:'set is of AllowUsers' -o ignore \
	    "$JGC" -c "$SOCK" sshd set ForceCommand /bin/sh
	# What sshd -t refuses is not put in place.
	atf_check -s exit:1 -o match:'sshd -t: .*Bad configuration option: BAD' \
	    "$JGC" -c "$SOCK" sshd set AllowUsers BAD
	atf_check -o not-match:'BAD' cat $R/etc/ssh/sshd_config
	# The banner.
	echo 'Authorised use only.' > banner.txt
	atf_check -o match:'done +sshd banner$' "$JGC" -c "$SOCK" sshd banner banner.txt
	atf_check -o inline:'Authorised use only.\n' cat $R/etc/ssh/banner
	atf_check -o match:'^Banner /etc/ssh/banner$' cat $R/etc/ssh/sshd_config
	atf_check -o match:'"banner_text":"Authorised use only.\\n"' \
	    "$JGC" -c "$SOCK" sshd
	# A key of alice's: her own .ssh, hers alone.
	atf_check -o match:'done +sshd authorize of alice$' \
	    "$JGC" -c "$SOCK" sshd authorize alice alice_key.pub
	atf_check -o match:'^-rw------- ' ls -l $R/home/alice/.ssh/authorized_keys
	atf_check -o match:'^drwx------ ' ls -ld $R/home/alice/.ssh
	atf_check -o save:list "$JGC" -c "$SOCK" sshd
	grep -qF "\"keys\":[{\"type\":\"ssh-ed25519\",\"fingerprint\":\"$alicefp\",\"comment\":\"alice@lab\"" list ||
	    atf_fail "alice's key"
	atf_check -s exit:1 -o match:'has that key already' \
	    "$JGC" -c "$SOCK" sshd authorize alice alice_key.pub
	# Its options changed in place, the key and its comment as they
	# were; options that make no key sshd reads are refused.
	atf_check -o match:'done +sshd options of alice$' \
	    "$JGC" -c "$SOCK" sshd options alice "$alicefp" \
	    'principals="alice,admin",no-pty'
	atf_check -o inline:"principals=\"alice,admin\",no-pty $(cut -d' ' -f1-2 alice_key.pub) alice@lab\n" \
	    cat $R/home/alice/.ssh/authorized_keys
	atf_check -o save:list "$JGC" -c "$SOCK" sshd
	grep -qF '"options":"principals=\"alice,admin\",no-pty"' list ||
	    atf_fail "the options listed"
	atf_check -s exit:1 -o match:"a value's quote is not closed" \
	    "$JGC" -c "$SOCK" sshd options alice "$alicefp" 'from="10.0.0.0/8'
	# Options sshd does not know, or a flag given a value: refused,
	# the key line as it was.
	atf_check -s exit:1 -o match:'not an option sshd knows' \
	    "$JGC" -c "$SOCK" sshd options alice "$alicefp" 'frm="10.0.0.0/8"'
	atf_check -s exit:1 -o match:'that option takes no value' \
	    "$JGC" -c "$SOCK" sshd options alice "$alicefp" 'no-pty="x"'
	atf_check -o match:'done +sshd options of alice$' \
	    "$JGC" -c "$SOCK" sshd options alice "$alicefp"
	atf_check -o inline:"$(cut -d' ' -f1-2 alice_key.pub) alice@lab\n" \
	    cat $R/home/alice/.ssh/authorized_keys
	atf_check -s exit:1 -o match:'daemon is no user who signs in here' \
	    "$JGC" -c "$SOCK" sshd authorize daemon alice_key.pub
	atf_check -o match:'done +sshd unauthorize of alice$' \
	    "$JGC" -c "$SOCK" sshd unauthorize alice "$alicefp"
	atf_check -o empty cat $R/home/alice/.ssh/authorized_keys
	atf_check -s exit:1 -o match:'has no key' \
	    "$JGC" -c "$SOCK" sshd unauthorize alice "$alicefp"
	# A link where .ssh is: not followed.
	mkdir -p $R/home/eve elsewhere
	printf 'eve:*:%d:%d:Eve:/home/eve:/bin/sh\n' "$(id -u)" "$(id -g)" >> $R/etc/passwd
	ln -s $(pwd)/elsewhere $R/home/eve/.ssh
	atf_check -s exit:1 -o match:'sshd authorize of eve: ' \
	    "$JGC" -c "$SOCK" sshd authorize eve alice_key.pub
	test -e elsewhere/authorized_keys && atf_fail "written through a link"
	# The host key signed by the CA: its certificate, and sshd told.
	atf_check -o match:'done +sshd sign$' "$JGC" -c "$SOCK" sshd sign ca lab.example
	test -f $R/etc/ssh/ssh_host_ed25519_key-cert.pub || atf_fail "no certificate"
	atf_check -o match:'^HostCertificate /etc/ssh/ssh_host_ed25519_key-cert.pub$' \
	    cat $R/etc/ssh/sshd_config
	ls -a $R/etc/ssh | grep -q arcana-ca && atf_fail "the CA key was left"
	test -z "$(ls -A tools/tmp 2>/dev/null)" || atf_fail "the signing left $(ls -A tools/tmp)"
	atf_check -o save:list -o match:'"principals":\["lab.example"\]' \
	    -o match:'"kind":"host"' -o match:'"certificate_used":true' \
	    "$JGC" -c "$SOCK" sshd
	grep -qF "\"ca\":\"$cafp\"" list || atf_fail "the CA"
	atf_check -s exit:1 -e match:"the CA's private key" -o ignore \
	    "$JGC" -c "$SOCK" sshd sign ca.pub
	atf_check -s exit:1 -e match:'good for any' -o ignore \
	    "$JGC" -c "$SOCK" sshd sign ca
	# In safe mode, unconfirmed: the file before it back.
	cp $R/etc/ssh/sshd_config before
	atf_check -o match:'queued' "$JGC" -q -s -c "$SOCK" sshd set PasswordAuthentication no
	sleep 1
	for i in $(seq 1 100); do
		"$JGC" -c "$SOCK" jobs | grep -q 'unconfirmed\|queued\|running' ||
		    break
		sleep 0.1
	done
	# The newest job, whatever its number.
	jid=$("$JGC" -c "$SOCK" jobs | awk '$1 ~ /^[0-9]+$/ {print $1}' |
	    sort -n | tail -1)
	atf_check -o match:'not confirmed within 2 s: undone' -s exit:1 \
	    "$JGC" -c "$SOCK" job "$jid"
	atf_check -o file:before cat $R/etc/ssh/sshd_config
	# What passwd and sshd say is the host's or a jail's, not the
	# agent's to trust: a long home in a keys file of %h four times
	# read without harm; a keys file outside the home by .. refused;
	# a keys file of another name too (a hard link) left alone.
	c=$(printf '%0200d' 0)
	long=/home/$c/$c/$c/$c
	mkdir -p "$R$long"
	printf 'mallory:*:%d:%d:M:%s:/bin/sh\nroot2:*:%d:%d:R:/:/bin/sh\n' \
	    "$(id -u)" "$(id -g)" "$long" "$(id -u)" "$(id -g)" >> $R/etc/passwd
	# Before any Match, where sshd -T reads it.
	{ printf 'AuthorizedKeysFile %%h%%h%%h%%h\n'; cat $R/etc/ssh/sshd_config; } > c.tmp
	mv c.tmp $R/etc/ssh/sshd_config
	atf_check -o match:'"name":"mallory"' "$JGC" -c "$SOCK" sshd
	atf_check -o match:'"name":"alice"' "$JGC" -c "$SOCK" sshd
	sed -i '' '/^AuthorizedKeysFile/d' $R/etc/ssh/sshd_config
	{ printf 'AuthorizedKeysFile ../authorized_keys\n'; cat $R/etc/ssh/sshd_config; } > c.tmp
	mv c.tmp $R/etc/ssh/sshd_config
	atf_check -s exit:1 -o match:'not a path in their home' \
	    "$JGC" -c "$SOCK" sshd authorize root2 alice_key.pub
	sed -i '' '/^AuthorizedKeysFile/d' $R/etc/ssh/sshd_config
	echo 'secret of another' > secret
	rm -f $R/home/alice/.ssh/authorized_keys
	ln secret $R/home/alice/.ssh/authorized_keys
	atf_check -s exit:1 -o match:'not a file of alice.s alone' \
	    "$JGC" -c "$SOCK" sshd authorize alice alice_key.pub
	atf_check -o inline:'secret of another\n' cat secret
	# The CAs whose user certificates sshd takes.
	{ echo '# the lab CA'; cat ca.pub; } > cas.txt
	atf_check -o match:'done +sshd user-cas$' \
	    "$JGC" -c "$SOCK" sshd user-cas cas.txt
	atf_check -o file:cas.txt cat $R/etc/ssh/trusted_user_ca_keys
	atf_check -o match:'^TrustedUserCAKeys /etc/ssh/trusted_user_ca_keys$' \
	    cat $R/etc/ssh/sshd_config
	atf_check -o save:list "$JGC" -c "$SOCK" sshd
	grep -qF "\"user_cas\":[{\"type\":\"ssh-ed25519\",\"fingerprint\":\"$cafp\"" list ||
	    atf_fail "the user CA"
	grep -qF '"user_cas_text":"# the lab CA' list || atf_fail "its text"
	# A certificate is not a CA's key, nor is a private one.
	atf_check -s exit:1 -o match:"not a CA's public key" "$JGC" -c "$SOCK" \
	    sshd user-cas $R/etc/ssh/ssh_host_ed25519_key-cert.pub
	atf_check -s exit:1 -e match:'not a private one' -o ignore \
	    "$JGC" -c "$SOCK" sshd user-cas ca
	atf_check -o file:cas.txt cat $R/etc/ssh/trusted_user_ca_keys
	# None: the line goes.
	atf_check -o match:'done' "$JGC" -c "$SOCK" sshd user-cas -
	atf_check -o not-match:'TrustedUserCAKeys' cat $R/etc/ssh/sshd_config
}
sshd_cleanup()
{
	stop_daemon
}

atf_test_case capture cleanup
capture_head()
{
	atf_set "descr" "Packets taken with tcpdump off an interface or a tap: the sources, the lines and the pcap, nothing left behind"
}
capture_body()
{
	mkdir -p tools/tmp
	printf '#!/bin/sh\nshift\nexec "$@"\n' > tools/timeout
	cat > tools/tcpdump <<'EOT'
#!/bin/sh
echo "tcpdump $*" >> tcpdump.log
case "$1" in
-D)	printf '1.em0 [Up, Running]\n2.ipfw150 [Up]\n' ;;
-n)	if [ "$2" = -tttt ]; then
		printf '2026-10-12 10:00:00.000001 IP 10.0.0.2 > 10.0.0.1: ICMP echo request\n'
		exit 0
	fi
	while [ $# -gt 0 ]; do
		[ "$1" = -w ] && printf PCAPDATA > "$2"
		[ "$1" = -i ] && [ "$2" = gone0 ] && { echo "tcpdump: gone0: No such device exists" >&2; exit 1; }
		shift
	done ;;
esac
EOT
	chmod +x tools/timeout tools/tcpdump
	DAEMON_ARGS="-2 $(pwd)/tools"
	start_daemon
	atf_check -o inline:'{"sources":["em0","ipfw150"]}\n' "$JGC" -c "$SOCK" capture
	atf_check -o match:'"source":"ipfw150","filter":"icmp and host 10.0.0.2","packets":1,"limit":5,"seconds":3' \
	    -o match:'"pcap":"UENBUERBVEE="' -o match:'"bytes":8' -o match:'ICMP echo request' \
	    "$JGC" -c "$SOCK" capture ipfw150 5 3 icmp and host 10.0.0.2
	atf_check -o match:'^tcpdump -n -U -i ipfw150 -c 5 -w .*/tmp/\.arcana-capture\.[0-9a-f]*/c\.pcap -- icmp and host 10\.0\.0\.2$' \
	    cat tcpdump.log
	# No word of the filter is an option of tcpdump's, which runs as
	# root: -w a file, -z a command.
	: > tcpdump.log
	atf_check -o ignore "$JGC" -c "$SOCK" capture em0 1 1 -w /etc/owned -z /bin/sh
	atf_check -o match:' -w .*/c\.pcap -- -w /etc/owned -z /bin/sh$' cat tcpdump.log
	atf_check -s exit:1 -e match:"an interface or a tap's name" -o ignore \
	    "$JGC" -c "$SOCK" capture -z 1 1
	test -z "$(ls -A tools/tmp)" || atf_fail "left behind: $(ls -A tools/tmp)"
	atf_check -s exit:1 -e match:'No such device exists' -o ignore \
	    "$JGC" -c "$SOCK" capture gone0 5 3
	test -z "$(ls -A tools/tmp)" || atf_fail "left behind after a failure"
	atf_check -s exit:1 -e match:"an interface or a tap's name" -o ignore \
	    "$JGC" -c "$SOCK" capture 'em0;x' 5 3
}
capture_cleanup()
{
	stop_daemon
}

atf_test_case config_bundle cleanup
config_bundle_head()
{
	atf_set "descr" "the host as a bundle (config-export) and a bundle" \
	    "made the host (config-apply): the files Arcana manages, secrets" \
	    "only when asked, the agent's identity never; the hardware" \
	    "checked, a diff, the files before kept, no path but those a" \
	    "bundle may carry"
}
config_bundle_body()
{
	local r="$(pwd)/root"

	mkdir -p "$r/etc/rc.conf.d" "$r/boot" arcana wg
	printf 'hostname="lab"\nsshd_enable="YES"\n' > "$r/etc/rc.conf"
	echo 'ntpd_flags="-g"' > "$r/etc/rc.conf.d/ntpd"
	echo 'hidden' > "$r/etc/rc.conf.d/.hidden"
	echo '127.0.0.1 localhost' > "$r/etc/hosts"
	echo 'kern.ipc.maxsockbuf=4194304' > "$r/boot/loader.conf"
	printf '[Interface]\nPrivateKey = c2VjcmV0\n' > wg/wg0.conf
	chmod 600 wg/wg0.conf
	echo 'every 10' > arcana/history.conf
	echo 'id' > arcana/id_ed25519
	DAEMON_ARGS="--root $r -1 $(pwd)/arcana/history.conf"
	start_daemon

	# Without secrets: WireGuard's file said, its text not there; a
	# hidden file and the agent's SSH key not at all.
	atf_check -o save:b.json "$JGC" -c "$SOCK" config-export
	atf_check -o match:'"arcana":"host","format":1' \
	    -o match:'"path":"/etc/rc.conf","mode":"0644",' \
	    -o match:'"text":"hostname=\\"lab\\"\\nsshd_enable=\\"YES\\"\\n"' \
	    -o match:'"path":"/etc/rc.conf.d/ntpd"' \
	    -o match:'"path":"/boot/loader.conf"' \
	    -o match:'"path":"/usr/local/etc/wireguard/wg0.conf","mode":"0600","owner":"[a-z0-9]+","group":"[a-z0-9]+","secret":true\}' \
	    -o match:'"path":"/usr/local/etc/arcana/history.conf"' \
	    -o match:'"facts":\{"arch":"[a-z0-9_]+"' -o match:'"interfaces":\[' \
	    -o not-match:'hidden' -o not-match:'id_ed25519' \
	    -o not-match:'c2VjcmV0' cat b.json
	# With them, the key's text too.
	atf_check -o match:'"path":"/usr/local/etc/wireguard/wg0.conf".*"text":"\[Interface\]\\nPrivateKey = c2VjcmV0\\n","secret":true' \
	    "$JGC" -c "$SOCK" config-export -s

	# Another host's state: rc.conf changed, ntpd's file gone, the key
	# another.  The report first: a diff, a new file, the key withheld.
	printf 'hostname="other"\n' > "$r/etc/rc.conf"
	rm "$r/etc/rc.conf.d/ntpd"
	printf '[Interface]\nPrivateKey = b3RoZXI=\n' > wg/wg0.conf
	atf_check -o save:n.json "$JGC" -c "$SOCK" config-apply -n b.json
	atf_check -o match:'"path":"/etc/rc.conf","state":"changed","diff":"[^"]*-hostname=\\"other\\"\\n\+hostname=\\"lab\\"\\n\+sshd_enable=\\"YES\\"' \
	    -o match:'"path":"/etc/rc.conf.d/ntpd","state":"new"' \
	    -o match:'"path":"/etc/hosts","state":"same"' \
	    -o match:'"path":"/usr/local/etc/wireguard/wg0.conf","state":"withheld"' \
	    -o match:'"mismatches":\[\]' -o not-match:'"applied"' cat n.json
	atf_check -o inline:'hostname="other"\n' cat "$r/etc/rc.conf"
	# Done: in place, the ones before kept, the key as it was, a
	# reboot said; another host name asked for.
	atf_check -o save:a.json "$JGC" -c "$SOCK" config-apply -H lab2 b.json
	atf_check -o match:'"applied":true' -o match:'"reboot":true' \
	    -o match:"\"backup\":\"$r/var/backups/arcana/config-[0-9]{8}-[0-9]{6}\"" \
	    cat a.json
	atf_check -o inline:'sshd_enable="YES"\nhostname="lab2"\n' \
	    cat "$r/etc/rc.conf"
	atf_check -o inline:'ntpd_flags="-g"\n' cat "$r/etc/rc.conf.d/ntpd"
	atf_check -o match:'b3RoZXI=' cat wg/wg0.conf
	atf_check -o inline:'hostname="other"\n' \
	    sh -c "cat $r/var/backups/arcana/config-*/etc/rc.conf"
	# Again: nothing to change, nothing written; without the other
	# name, rc.conf's would be.
	atf_check -o not-match:'"state":"changed"' -o not-match:'"state":"new"' \
	    -o not-match:'"applied"' "$JGC" -c "$SOCK" config-apply -H lab2 \
	    b.json
	atf_check -o match:'"path":"/etc/rc.conf","state":"changed"' \
	    "$JGC" -c "$SOCK" config-apply -n b.json

	# Hardware not the bundle's: refused unless anyway.
	sed 's/"interfaces":\[/"interfaces":[{"name":"nosuch0","driver":"nosuch"},/' \
	    b.json > hw.json
	atf_check -s exit:1 -o match:'"mismatches":\["no interface nosuch0 here"\]' \
	    -e match:'not the bundle.s \(1 differences\): nothing was done' \
	    "$JGC" -c "$SOCK" config-apply hw.json
	atf_check -o match:'"mismatches":\["no interface nosuch0 here"\]' \
	    -o match:'"applied":true' "$JGC" -c "$SOCK" config-apply -a hw.json

	# A path no bundle carries: refused, nothing written.
	for p in /root/.ssh/authorized_keys /etc/rc.conf.d/../passwd \
	    /usr/local/etc/arcana/id_ed25519 /etc/rc.conf.d/.hidden; do
		sed "s|\"files\":\[|\"files\":[{\"path\":\"$p\",\"text\":\"x\"},|" \
		    b.json > bad.json
		atf_check -s exit:1 -e match:"$p: not a file a bundle may carry" \
		    -o empty "$JGC" -c "$SOCK" config-apply bad.json
	done
	atf_check -o inline:'id\n' cat arcana/id_ed25519
	atf_check -o inline:'hidden\n' cat "$r/etc/rc.conf.d/.hidden"
	echo '{"arcana":"tab"}' > tab.json
	atf_check -s exit:1 -e match:'not a host.s bundle' -o empty \
	    "$JGC" -c "$SOCK" config-apply tab.json
}
config_bundle_cleanup()
{
	[ -f daemon.pid ] && kill "$(cat daemon.pid)" 2>/dev/null
	true
}

atf_test_case crash_fault
crash_fault_head()
{
	atf_set "descr" "the kernel's line for a program that died of a" \
	    "signal (kmsg.c): the crash event with the kernel's reason for" \
	    "no core, the crash fault of the program with the signal's name" \
	    "and the day's count, said anew at each crash, cleared after an" \
	    "hour without one"
}
crash_fault_body()
{
	local f="$(atf_get_srcdir)/kmsg"

	cat > lines <<'EOF'
100 pid 13939 (bird), jid 0, uid 0: exited on signal 10 (no core dump - sugid process denied by kern.sugid_coredump)
200 pid 14000 (bird), jid 0, uid 0: exited on signal 10 (no core dump - sugid process denied by kern.sugid_coredump)
250 pid 812 (nginx), jid 7, uid 80: exited on signal 11 (core dumped)
300 em0: link state changed to UP
86500 pid 14100 (bird), jid 0, uid 0: exited on signal 6 (no core dump - bad address)
sweep 90000
sweep 90101
sweep 90151
EOF
	atf_check -o save:out "$f" < lines
	# The event, with the reason; the fault, by the kernel.
	atf_check -o match:'^event crash \{"pid":13939,"process":"bird","jid":0,"jail":"","uid":0,"signal":10,"core":false,"reason":"sugid process denied by kern.sugid_coredump"\}$' \
	    cat out
	atf_check -o match:'^set crash Major host:bird kernel: bird died of SIGBUS \(pid 13939\), 1 time in 24 h; no core: sugid process denied by kern.sugid_coredump$' \
	    cat out
	# The second crash: the same fault, its line said anew.
	atf_check -o match:'^update crash host:bird: bird died of SIGBUS \(pid 14000\), 2 times in 24 h; no core: sugid' \
	    cat out
	atf_check -o not-match:'set again' cat out
	# A jail's, by its id when it has no name any more; a core dumped.
	atf_check -o match:'^event crash \{"pid":812,"process":"nginx","jid":7,"jail":"","uid":80,"signal":11,"core":true\}$' \
	    cat out
	atf_check -o match:'^set crash Major jail:7/nginx kernel: nginx died of SIGSEGV \(pid 812\), 1 time in 24 h; a core was dumped$' \
	    cat out
	atf_check -o match:'^not a crash: em0: link state changed to UP$' cat out
	# A day on: the crash of a day ago no longer counts.
	atf_check -o match:'^update crash host:bird: bird died of SIGABRT \(pid 14100\), 2 times in 24 h; no core: bad address$' \
	    cat out
	# An hour without one, each: nginx's at the first sweep, its last
	# crash a day before it; bird's at the second, an hour and a
	# second after its last; the third clears none.
	atf_check -o inline:'clear crash jail:7/nginx: nginx ran an hour without crashing\nclear crash host:bird: bird ran an hour without crashing\n' \
	    grep '^clear' out
	atf_check -o inline:'2\n' sh -c "grep -c '^set' out"
}

atf_test_case fw_walk
fw_walk_head()
{
	atf_set "descr" "ipfw's ruleset walked for a packet (fwmatch.c), as" \
	    "path-check does: skipto, uRPF, a table, setup and keep-state," \
	    "a reply let in by its state, a socket's rule for a packet" \
	    "passing through, fwd by a table's value, what is not known"
}
fw_walk_body()
{
	local f="$(atf_get_srcdir)/fwmatch" l

	cat > list <<'EOF'
00100 allow ip from any to any via lo0
00200 deny ip from any to 127.0.0.0/8
00300 deny ip from any to any not verrevpath in
00400 check-state :default
00500 count ip from any to any in recv vtnet0
00600 skipto 1000 ip from 10.0.0.0/8 to any
00700 deny log ip from table(bad) to any in
00800 allow tcp from any to me 22 in recv vtnet0 setup keep-state :default
00900 deny ip from any to any in recv vtnet0
01000 setfib 1 ip from 10.1.0.0/16 to any in
01100 allow udp from any to any 53,123 out keep-state :default
01200 allow ip from { 10.0.0.1 or 10.0.0.2 } to any
01300 allow tcp from any to any established
01400 deny ip from any to any uid 1001
01500 nat 1 ip from 10.2.0.0/16 to any out xmit vtnet0
01600 allow icmp from any to any icmptypes 0,8
01700 fwd 192.0.2.1 ip from 10.3.0.0/16 to any in recv em*
65535 deny ip from any to any
65535 count ip from any to any not // orphaned dynamic states counter
00012 fwd tablearg ip4 from any to table(swt)
EOF
	cat > tables <<'EOF'
--- table(bad), set(0) ---
198.51.100.0/24 0
--- table(swt), set(0) ---
10.20.0.0/24 100.64.0.9
EOF
	l="local=192.0.2.10@vtnet0 local=10.0.0.10@em0"
	t() { "$f" list tables $l "$@"; }
	atf_check -o inline:'allow 800 keep-state\n' "$f" list tables $l in \
	    rcv=vtnet0 src=203.0.113.5 dst=192.0.2.10 proto=tcp sport=40000 \
	    dport=22 syn rpf reach
	# The rules met, in order, with what each did.
	atf_check -o inline:'allow 800 keep-state\n  400 check-state :default: no state of it yet, on\n  500 met, on\n  800 decides\n' \
	    "$f" list tables $l in rcv=vtnet0 src=203.0.113.5 dst=192.0.2.10 \
	    proto=tcp sport=40000 dport=22 syn rpf reach walk
	# call and return as the kernel's O_CALLRETURN: into the block
	# called, back to the rule numbered after the call (next-rulenum);
	# a return with nothing called goes on; reass goes on; a rule of
	# options alone (return via any) names no protocol.
	cat > chain <<'EOT'
00001 call 9000 ip6 from any to any
00020 call 9100 ip from any to any in
00099 reass ip from any to any in
00200 check-state :default
00300 call 9200 ip from any to any in
00999 deny ip from any to any
09000 allow icmp6 from fe80::/10 to fe80::/10
09099 return via any
09100 deny udp from any to 255.255.255.255 1900 in
09199 return via any
09200 allow tcp from any to me 22 in
09299 return next-rule via any
65535 deny ip from any to any
EOT
	atf_check -o inline:'deny 9100\n  20 call 9100\n  9100 decides\n' "$f" chain tables $l \
	    in rcv=em0 src=10.0.0.5 dst=255.255.255.255 proto=udp sport=1900 \
	    dport=1900 rpf reach walk
	atf_check -o inline:'allow 9200\n  20 call 9100\n  9199 return, after 20\n  99 met, on\n  200 check-state :default: no state of it yet, on\n  300 call 9200\n  9200 decides\n' \
	    "$f" chain tables $l in rcv=em0 src=10.0.0.5 dst=10.0.0.10 \
	    proto=tcp sport=4000 dport=22 syn rpf reach walk
	atf_check -o inline:'deny 999\n  20 call 9100\n  9199 return, after 20\n  99 met, on\n  200 check-state :default: no state of it yet, on\n  300 call 9200\n  9299 return, after 300\n  999 decides\n' \
	    "$f" chain tables $l in rcv=em0 src=10.0.0.5 dst=10.0.0.10 \
	    proto=tcp sport=4000 dport=80 syn rpf reach walk
	# As edge-a's ruleset writes them: a return of no addresses
	# (return next-rulenum proto ip) returns; tcpflags and ipoptions
	# are judged of the packet modelled (a SYN, no IP option); a long
	# { a or b } list is read whole.
	{
		echo '00020 call 9100 ip from any to any in'
		echo '00030 call 9200 ip from any to any in'
		echo '00099 allow tcp from any to any 443 in'
		echo '09100 deny udp from any to any 1900 in'
		echo '09199 return next-rulenum proto ip'
		echo '09251 deny log logamount 500 tcp from any to any tcpflags fin,psh,urg in'
		echo '09252 deny log logamount 500 tcp from any to any tcpflags !syn,!fin,!ack,!psh,!rst,!urg in'
		echo '09253 deny log logamount 500 tcp from any to any tcpflags syn,fin in'
		echo '09255 deny log logamount 500 ip from any to any ipoptions ssrr,lsrr,rr,ts in'
		printf '09301 deny ip4 from { '
		n=0; while [ $n -lt 60 ]; do printf '198.18.%d.0/24 or ' $n; n=$((n + 1)); done
		echo '198.19.0.1 } to any in'
		echo '09999 return next-rulenum proto ip'
		echo '65535 deny ip from any to any'
	} > edge-a
	atf_check -o inline:'allow 99\n  20 call 9100\n  9199 return, after 20\n  30 call 9200\n  9999 return, after 30\n  99 decides\n' \
	    "$f" edge-a tables $l in rcv=em0 src=203.0.113.9 dst=10.0.0.10 \
	    proto=tcp sport=40000 dport=443 syn rpf reach walk
	atf_check -o inline:'deny 9301\n  20 call 9100\n  9199 return, after 20\n  30 call 9200\n  9301 decides\n' \
	    "$f" edge-a tables $l in rcv=em0 src=198.18.59.7 dst=10.0.0.10 \
	    proto=tcp sport=40000 dport=443 syn rpf reach walk
	# A segment of no flags at all: 9252 drops it.
	atf_check -o inline:'deny 9252\n  20 call 9100\n  9199 return, after 20\n  30 call 9200\n  9252 decides\n' \
	    "$f" edge-a tables $l in rcv=em0 src=203.0.113.9 dst=10.0.0.10 \
	    proto=tcp sport=40000 dport=443 rpf reach walk
	# record-state with defer-immediate-action, as edge-a's outgoing
	# rules: the state made, the packet on, and a check-state of the
	# same flow decides by it (of another flow, not).
	{
		echo '00001 call 9000 ip6 from any to any'
		echo '00005 skipto 500 ip from any to any out'
		echo '00200 check-state :default'
		echo '00510 call 5000 ip6 from me6 to any out'
		echo '00700 check-state :default'
		echo '00999 deny log logamount 500 ip from any to any'
		echo '05012 allow ip6 from me6 to any out record-state :default defer-immediate-action'
		echo '05999 return next-rulenum proto ip'
		echo '09000 allow icmp6 from fe80::/10 to fe80::/10'
		echo '09099 return next-rulenum proto ip'
		echo '65535 deny ip from any to any'
	} > defer
	atf_check -o inline:'allow 700 by-state keep-state\n  1 call 9000\n  9099 return, after 1\n  5 skipto 500\n  510 call 5000\n  5012 makes a state :default, its allow deferred: on\n  5999 return, after 510\n  700 decides: the state 5012 made (:default)\n' \
	    "$f" defer tables local=2001:db8::10@em0 out xmit=wg0 \
	    src=2001:db8::10 dst=2001:db8:99::1 proto=tcp sport=40000 \
	    dport=4310 syn reach walk
	sed 's/:default defer/:other defer/' defer > defer2
	atf_check -o match:'^deny 999' -o match:'700 check-state :default: no state of it yet, on' \
	    "$f" defer2 tables local=2001:db8::10@em0 out xmit=wg0 \
	    src=2001:db8::10 dst=2001:db8:99::1 proto=tcp sport=40000 \
	    dport=4310 syn reach walk
	# A reply with its state: check-state decides.
	atf_check -o inline:'allow 200 by-state\n  20 call 9100\n  9199 return, after 20\n  99 met, on\n  200 decides: its state lets it by\n' \
	    "$f" chain tables $l in rcv=em0 src=10.0.0.5 dst=10.0.0.10 \
	    proto=tcp sport=4000 dport=80 ack state rpf reach walk
	atf_check -o inline:'deny 900\n' "$f" list tables $l in rcv=vtnet0 \
	    src=203.0.113.5 dst=192.0.2.10 proto=tcp sport=40000 dport=80 syn \
	    rpf reach
	# The route back is another way: uRPF.
	atf_check -o inline:'deny 300\n' "$f" list tables $l in rcv=vtnet0 \
	    src=203.0.113.5 dst=192.0.2.10 proto=tcp sport=40000 dport=22 syn \
	    reach
	atf_check -o inline:'deny 700\n' "$f" list tables $l in rcv=vtnet0 \
	    src=198.51.100.9 dst=192.0.2.10 proto=tcp sport=1 dport=22 syn \
	    rpf reach
	# The reply, by the state its request made.
	atf_check -o inline:'allow 400 by-state\n' "$f" list tables $l in \
	    rcv=vtnet0 src=203.0.113.5 dst=192.0.2.10 proto=tcp sport=40000 \
	    dport=22 ack state rpf reach
	# Passing through: no socket, so no uid rule.
	atf_check -o inline:'deny 65535 setfib=1\n' "$f" list tables $l in \
	    rcv=em0 src=10.1.2.3 dst=8.8.8.8 proto=udp sport=5353 dport=53 \
	    rpf reach
	# Made here: the uid rule cannot be judged.
	atf_check -o inline:'allow 1100 keep-state\n' "$f" list tables $l out \
	    xmit=vtnet0 src=192.0.2.10 dst=8.8.8.8 proto=udp sport=5353 \
	    dport=53 srclocal
	atf_check -o inline:'deny 65535 uncertain=1400(uid)\n' "$f" list \
	    tables $l out xmit=vtnet0 src=192.0.2.10 dst=8.8.4.4 proto=tcp \
	    sport=1 dport=443 syn srclocal
	atf_check -o inline:'allow 1200\n' "$f" list tables $l in rcv=em0 \
	    src=10.0.0.1 dst=8.8.4.4 proto=tcp sport=1 dport=443 syn rpf reach
	atf_check -o inline:'allow 100\n' "$f" list tables $l in rcv=lo0 \
	    src=127.0.0.1 dst=127.0.0.1 proto=tcp sport=1 dport=443 syn
	atf_check -o inline:'allow 1600\n' "$f" list tables $l in rcv=em1 \
	    src=10.3.0.4 dst=8.8.8.8 proto=icmp icmp=8 rpf reach
	# fwd by a table: to the table's value.
	atf_check -o inline:'fwd 12 fwd=100.64.0.9\n' "$f" list tables $l in \
	    rcv=em0 src=10.0.0.5 dst=10.20.0.7 proto=icmp icmp=8 rpf reach
}

atf_test_case host_watch cleanup
host_watch_head()
{
	atf_set "descr" "what changes on the host, told as the kernel tells" \
	    "it: a configuration file written or replaced (EVFILT_VNODE)," \
	    "processes started and gone (EVFILT_PROC), each kind once a second"
}
host_watch_body()
{
	# jail.conf in a directory of its own, where nothing else changes.
	mkdir q
	echo '# jails' > q/jail.conf
	DAEMON_ARGS="-f $(pwd)/q/jail.conf"
	start_daemon
	"$JGC" -c "$SOCK" events -f > follow.out 2>&1 &
	echo $! > follow.pid
	sleep 1.2
	# Written in place, then replaced as sysrc(8) and editors do.
	echo '# one' >> q/jail.conf
	sleep 1.5
	cp q/jail.conf jail.conf.new
	echo '# two' >> jail.conf.new
	mv jail.conf.new q/jail.conf
	sleep 1.5
	pat="\"kind\":\"conf\",\"data\":{\"file\":\"$(pwd)/q/jail.conf\"}"
	n=$(grep -c "$pat" follow.out)
	[ "$n" -ge 2 ] || atf_fail "$n events of jail.conf written and replaced"
	# And grown again, by truncate -c, which leaves the directory as
	# it is (no O_CREAT): the new file is the one watched.
	truncate -c -s +1 q/jail.conf
	sleep 1.5
	kill "$(cat follow.pid)"
	[ "$(grep -c "$pat" follow.out)" -gt "$n" ] ||
	    atf_fail "the file put in its place is not watched"
	# The sleeps and cp above are this shell's, not the agent's.
	atf_check -o match:'"kind":"procs","data":\{"started":[1-9][0-9]*,"exited":[0-9]+\}' \
	    cat follow.out
}
host_watch_cleanup()
{
	[ -f follow.pid ] && kill "$(cat follow.pid)" 2>/dev/null
	stop_daemon
}

atf_test_case poudriere cleanup
poudriere_head()
{
	atf_set "descr" "poudriere(8) as a plugin: its jails, ports trees," \
	    "make.conf files, repositories and builds read; a jail, a" \
	    "tree and a build started as runs that go on after the job," \
	    "one stopped; a make.conf for debug symbols; poudriere.conf's" \
	    "variables; what is refused"
}
poudriere_body()
{
	local d="$(pwd)" n

	mkdir -p pe/poudriere.d data/packages/FreeBSD:16:amd64-default-debug/All \
	    bl/logs/errors
	# The build's log directory: a port failed in build, without a
	# reason found, and one skipped for it.
	printf 'devel/broken broken-1.0 build  42\n' > bl/.poudriere.ports.failed
	printf 'net/needs needs-2.0 broken-1.0\n' > bl/.poudriere.ports.skipped
	printf '===> Building for broken-1.0\ncc: error: no such file\n*** Error code 1\n' \
	    > bl/logs/errors/broken-1.0.log
	touch data/packages/FreeBSD:16:amd64-default-debug/All/bird3-3.4.0.pkg
	# poudriere(8): jset and pset as it keeps them, a bulk that says
	# what it builds; test/sleepy builds until it is interrupted,
	# test/broken fails.
	cat > fake-poudriere <<EOS
#!/bin/sh
echo "poudriere \$*" >> $d/poudriere.log
e=$d/pe/poudriere.d
v=; a=amd64; m=http; n=; br=
cmd=\$1; shift
case "\$cmd" in
jail|ports)
	verb=\$1; shift
	opts=yj:p:v:a:m:B:U:M:; [ \$cmd = jail ] && opts=yj:v:a:m:K:bBt:
	while getopts \$opts o; do
		case \$o in j|p) n=\$OPTARG;; v) v=\$OPTARG;; a) a=\$OPTARG;; m) m=\$OPTARG;; B) br=\$OPTARG;; esac
	done
	k=jails; [ \$cmd = ports ] && k=ports
	case "\$verb" in
	-c)	echo "[00:00:01] Creating \$n fs"
		mkdir -p \$e/\$k/\$n
		[ \$cmd = jail ] && { echo \$v > \$e/\$k/\$n/version; echo \$a > \$e/\$k/\$n/arch; }
		echo \$m > \$e/\$k/\$n/method
		echo /poudriere/\$k/\$n > \$e/\$k/\$n/mnt
		echo 1792200000 > \$e/\$k/\$n/timestamp
		echo "[00:00:02] Done" ;;
	-u)	echo "[00:00:01] Updating \$n"; echo 1792209999 > \$e/\$k/\$n/timestamp ;;
	-d)	[ -d \$e/\$k/\$n ] || { echo "Error: No such \$k \$n" >&2; exit 1; }
		rm -rf \$e/\$k/\$n ;;
	esac ;;
bulk)
	echo "[00:00:00] Building: \$*"
	case " \$* " in *" test/broken "*) echo "Error: test/broken failed" >&2; exit 1 ;; esac
	case " \$* " in *" test/sleepy "*) sleep 60 ;; esac
	echo "[00:00:03] Built 1 packages" ;;
status)
	printf 'debug\tdefault\tFreeBSD:16:amd64\t2026-10-17_09h00m00s\tdone:\t3\t0\t0\t1\t1\t1\t0\t0\t00:03:10\t$d/bl\n' ;;
esac
EOS
	chmod +x fake-poudriere
	# A ports tree, opt, whose one port answers as the ports framework
	# would: showconfig, and its variables; make(1) is the real one.
	mkdir -p tree/net/bird3 pe/poudriere.d/ports/opt
	echo "$d/tree" > pe/poudriere.d/ports/opt/mnt
	cat > tree/net/bird3/Makefile <<'EOF'
PKGNAME=	bird3-3.4.0
COMPLETE_OPTIONS_LIST=	BFD BGP MRT
OPTIONS_FILE=	${PORT_DBDIR}/net_bird3/options
showconfig:
	@echo "===> The following configuration options are available for ${PKGNAME}:"
	@echo "     BFD=on: Bidirectional Forwarding Detection"
	@echo "====> Routing Protocols"
	@echo "     BGP=on: Border Gateway Protocol"
	@echo "     MRT=off: Dumping Routing Information in MRT Format"
	@echo "===> Use 'make config' to modify these settings"
EOF
	printf '#!/bin/sh\nexec /usr/bin/make "$@"\n' > fake-make
	chmod +x fake-make
	DAEMON_ARGS="--poudriere $d/fake-poudriere --poudriere-etc $d/pe"
	start_daemon

	# Nothing yet: installed, without poudriere.conf.
	atf_check -o match:'"installed":true' -o match:'"configured":false' \
	    -o match:'"jails":\[\]' -o match:'"runs":\[\]' \
	    "$JGC" -c "$SOCK" poudriere

	# poudriere.conf: ZPOOL and BASEFS, by sysrc -f; the data directory
	# under BASEFS unless said, ${BASEFS} put in.
	atf_check -o match:'done +poudriere.conf: ZPOOL=tank and more$' \
	    "$JGC" -c "$SOCK" poudriere conf ZPOOL=tank BASEFS=/poudriere
	echo 'POUDRIERE_DATA=${BASEFS}/../'"$d"'/data' >> pe/poudriere.conf
	atf_check -o match:"-f $d/pe/poudriere.conf ZPOOL=tank" cat sysrc.log
	atf_check -o match:'"configured":true' \
	    -o match:'"conf":\{"ZPOOL":"tank","BASEFS":"/poudriere","POUDRIERE_DATA":"/poudriere/../' \
	    "$JGC" -c "$SOCK" poudriere
	atf_check -s exit:1 -e match:"variables set from here" -o ignore \
	    "$JGC" -c "$SOCK" poudriere conf PATH=/tmp
	atf_check -o match:'done' "$JGC" -c "$SOCK" poudriere conf BASEFS=
	atf_check -o not-match:'^BASEFS=' cat pe/poudriere.conf

	# A jail, named as an ABI, and a ports tree: runs; the job ends at
	# once, the run when poudriere does.
	atf_check -o match:'done +poudriere jail-create FreeBSD:16:amd64$' \
	    "$JGC" -c "$SOCK" poudriere jail-create name=FreeBSD:16:amd64 \
	    version=16.0-CURRENT method=pkgbase
	atf_check -o match:'done +poudriere ports-create default$' \
	    "$JGC" -c "$SOCK" poudriere ports-create name=default \
	    method=git+https branch=main
	for i in $(seq 1 50); do
		[ $("$JGC" -c "$SOCK" poudriere | grep -o '"state":"done"' |
		    wc -l) -ge 2 ] && break
		sleep 0.1
	done
	atf_check -o match:'"jails":\[\{"name":"FreeBSD:16:amd64",[^]]*"version":"16.0-CURRENT"' \
	    -o match:'"method":"pkgbase"' -o match:'"timestamp":1792200000' \
	    -o match:'"ports":\[[^]]*\{"name":"default",' \
	    -o match:'"id":1,"title":"poudriere jail-create FreeBSD:16:amd64","started":[0-9]+,"argv":\["[^"]*fake-poudriere","jail","-c","-j","FreeBSD:16:amd64","-v","16.0-CURRENT","-m","pkgbase"\],"state":"done","exit":0' \
	    -o match:'"log":"\[00:00:01\] Creating FreeBSD:16:amd64 fs\\n\[00:00:02\] Done\\n"' \
	    "$JGC" -c "$SOCK" poudriere
	atf_check -o match:'^poudriere ports -c -p default -m git\+https -B main$' \
	    cat poudriere.log

	# Debug symbols for BIRD: a set's make.conf, then its build.
	printf 'WITH_DEBUG_PORTS+= net/bird3\n' > debug.conf
	atf_check -o match:'done +poudriere debug-make.conf written$' \
	    "$JGC" -c "$SOCK" poudriere make-conf debug debug.conf
	atf_check -o inline:'WITH_DEBUG_PORTS+= net/bird3\n' \
	    cat pe/poudriere.d/debug-make.conf
	atf_check -o match:'done +poudriere bulk net/bird3 in FreeBSD:16:amd64 with default, set debug$' \
	    "$JGC" -c "$SOCK" poudriere bulk jail=FreeBSD:16:amd64 \
	    ports=default set=debug jobs=4 origin=net/bird3
	for i in $(seq 1 50); do
		[ $("$JGC" -c "$SOCK" poudriere | grep -o '"state":"done"' |
		    wc -l) -ge 3 ] && break
		sleep 0.1
	done
	atf_check -o match:'^poudriere bulk -j FreeBSD:16:amd64 -p default -z debug -J 4 net/bird3$' \
	    cat poudriere.log
	atf_check -o match:'"makeconf":\[\{"name":"debug","file":"[^"]*/debug-make.conf","text":"WITH_DEBUG_PORTS\+= net/bird3\\n"\}\]' \
	    -o match:'"repos":\[\{"name":"FreeBSD:16:amd64-default-debug","path":"[^"]*","packages":1\}\]' \
	    -o match:'"builds":\[\{"set":"debug","ports":"default","jail":"FreeBSD:16:amd64","build":"2026-10-17_09h00m00s","status":"done:","queued":3,"inspected":0,"ignored":0,"built":1,"failed":1,"skipped":1,"fetched":0,"remaining":0,"time":"00:03:10","logs":"[^"]*/bl"' \
	    -o match:'"failed_ports":\[\{"origin":"devel/broken","package":"broken-1.0","phase":"build","elapsed":42,"log_file":"[^"]*/bl/logs/errors/broken-1.0.log","log":"===> Building for broken-1.0\\ncc: error: no such file\\n\*\*\* Error code 1\\n"\}\]' \
	    -o match:'"skipped_ports":\[\{"origin":"net/needs","package":"needs-2.0","because":"broken-1.0"\}\]' \
	    -o match:'"id":3,"title":"poudriere bulk net/bird3 in FreeBSD:16:amd64 with default, set debug"' \
	    "$JGC" -c "$SOCK" poudriere
	# make.conf itself, and taken away.
	atf_check -o match:'done +poudriere make.conf written$' \
	    "$JGC" -c "$SOCK" poudriere make-conf - debug.conf
	atf_check -o match:'done +poudriere make.conf taken away$' \
	    "$JGC" -c "$SOCK" poudriere make-conf - -
	atf_check -s exit:1 -e ignore cat pe/poudriere.d/make.conf

	# A port's options, as a build of the jail, opt and debug takes
	# them: no options directory yet, the build's own would be made.
	atf_check -o match:'"pkgname":"bird3-3.4.0","options_dir":"[^"]*/pe/poudriere.d/FreeBSD:16:amd64-opt-debug-options","options_dir_exists":false,"options_file":"[^"]*/FreeBSD:16:amd64-opt-debug-options/net_bird3/options","configured":false' \
	    -o match:'"sections":\[\{"title":"","options":\[\{"name":"BFD","on":true,"description":"Bidirectional Forwarding Detection"\}\]\},\{"title":"Routing Protocols","options":\[\{"name":"BGP","on":true,"description":"Border Gateway Protocol"\},\{"name":"MRT","on":false,' \
	    "$JGC" -c "$SOCK" poudriere show-options jail=FreeBSD:16:amd64 \
	    ports=opt set=debug origin=net/bird3
	# With the tree's directory there, it is the one the build copies,
	# as poudriere bulk looks: written there.
	mkdir pe/poudriere.d/opt-options
	atf_check -o match:'done +poudriere options of net/bird3$' \
	    "$JGC" -c "$SOCK" poudriere options jail=FreeBSD:16:amd64 \
	    ports=opt set=debug origin=net/bird3 on=BFD on=MRT off=BGP
	atf_check -o inline:"# This file is auto-generated by 'make config'.\n# Options for bird3-3.4.0, set by Arcana\n_OPTIONS_READ=bird3-3.4.0\n_FILE_COMPLETE_OPTIONS_LIST=BFD BGP MRT\nOPTIONS_FILE_SET+=BFD\nOPTIONS_FILE_SET+=MRT\nOPTIONS_FILE_UNSET+=BGP\n" \
	    cat pe/poudriere.d/opt-options/net_bird3/options
	atf_check -o match:'"options":\[\{"name":"opt","dir":"[^"]*/opt-options","ports":\[\{"name":"net_bird3","pkgname":"bird3-3.4.0","set":\["BFD","MRT"\],"unset":\["BGP"\]\}\]\}\]' \
	    "$JGC" -c "$SOCK" poudriere
	atf_check -o match:'"options_dir_exists":true,[^}]*"configured":true' \
	    "$JGC" -c "$SOCK" poudriere show-options jail=FreeBSD:16:amd64 \
	    ports=opt set=debug origin=net/bird3
	# The read and a port's options as arcana-builder has them, and
	# notify's request as arcana-notify: through YANG-CBOR and back.
	"$JGC" -c "$SOCK" poudriere > builder.json
	"$JGC" -c "$SOCK" poudriere show-options jail=FreeBSD:16:amd64 \
	    ports=opt set=debug origin=net/bird3 > options.json
	# One the port has not, refused; one that is no option's name, too.
	atf_check -s exit:1 -o match:'bird3-3.4.0 has no option NOPE' -e ignore \
	    "$JGC" -c "$SOCK" poudriere options jail=FreeBSD:16:amd64 \
	    ports=opt origin=net/bird3 on=NOPE
	atf_check -s exit:1 -e match:'capitals, digits and _' -o ignore \
	    "$JGC" -c "$SOCK" poudriere options jail=FreeBSD:16:amd64 \
	    ports=opt origin=net/bird3 'on=a b'
	atf_check -s exit:1 -e match:'no port net/nosuch' -o ignore \
	    "$JGC" -c "$SOCK" poudriere show-options jail=FreeBSD:16:amd64 \
	    ports=opt origin=net/nosuch
	# Back to the port's defaults.
	atf_check -o match:"done +poudriere options of net/bird3: the port's defaults$" \
	    "$JGC" -c "$SOCK" poudriere options jail=FreeBSD:16:amd64 \
	    ports=opt set=debug origin=net/bird3 reset=yes
	atf_check -s exit:1 test -e pe/poudriere.d/opt-options/net_bird3

	# A build that fails is a run that failed: the job itself was
	# done, starting it.
	atf_check -o match:done "$JGC" -c "$SOCK" poudriere bulk \
	    jail=FreeBSD:16:amd64 origin=test/broken
	for i in $(seq 1 50); do
		"$JGC" -c "$SOCK" poudriere | grep -q '"state":"failed","exit":1' &&
		    break
		sleep 0.1
	done
	atf_check -o match:'"id":4,[^}]*"state":"failed","exit":1,[^}]*"log":"\[00:00:00\] Building: -j FreeBSD:16:amd64 test/broken\\nError: test/broken failed\\n"' \
	    "$JGC" -c "$SOCK" poudriere

	# One that goes on until it is stopped: SIGINT, as a terminal's.
	atf_check -o match:done "$JGC" -c "$SOCK" poudriere bulk \
	    jail=FreeBSD:16:amd64 origin=test/sleepy
	for i in $(seq 1 50); do
		"$JGC" -c "$SOCK" poudriere | grep -q '"id":5,[^}]*"state":"running","pid":[0-9]*' &&
		    break
		sleep 0.1
	done
	atf_check -o match:'"id":5,[^}]*"state":"running","pid":[0-9]+' \
	    "$JGC" -c "$SOCK" poudriere
	# Its waiter, not the agent's child, holds none of the agent's
	# descriptors: only poudriere's standard input, output and error.
	n=$(ps -o ppid= -p "$(cat builder/5.pid)" | tr -d ' ')
	atf_check test "$(ps -o ppid= -p "$n" | tr -d ' ')" != "$(cat daemon.pid)"
	# procstat(1) sees another's descriptors as root, or when the host
	# lets anyone debug their own (security.bsd.unprivileged_proc_debug).
	if [ "$(id -u)" = 0 ] || [ "$(sysctl -n \
	    security.bsd.unprivileged_proc_debug 2>/dev/null)" = 1 ]; then
		atf_check -o inline:'0\n1\n2\n' sh -c "procstat -f $n | awk 'NR > 1 && \$3 ~ /^[0-9]+\$/ { print \$3 }'"
	fi
	atf_check -o match:'done +poudriere run 5 stopped$' \
	    "$JGC" -c "$SOCK" poudriere stop run=5
	for i in $(seq 1 50); do
		"$JGC" -c "$SOCK" poudriere | grep -q '"id":5,[^}]*"state":"failed","exit":130' &&
		    break
		sleep 0.1
	done
	atf_check -o match:'"id":5,[^}]*"state":"failed","exit":130' \
	    "$JGC" -c "$SOCK" poudriere
	atf_check -s exit:1 -o match:'failed +poudriere run 5 stopped: run 5 has ended already \(exit 130\)' \
	    -e ignore "$JGC" -c "$SOCK" poudriere stop run=5
	atf_check -s exit:1 -o match:'run 99 is not running' -e ignore \
	    "$JGC" -c "$SOCK" poudriere stop run=99

	# Refused: a port's path out of the tree, a set with a -, a jail's
	# name with a dot, a word that is no key=value, a jail scope.
	atf_check -s exit:1 -e match:'category and name' -o ignore \
	    "$JGC" -c "$SOCK" poudriere bulk jail=j origin=../etc
	atf_check -s exit:1 -e match:"a set's name" -o ignore \
	    "$JGC" -c "$SOCK" poudriere bulk jail=j set=a-b origin=net/bird3
	atf_check -s exit:1 -e match:"a jail's name" -o ignore \
	    "$JGC" -c "$SOCK" poudriere jail-create name=a.b version=15.0-RELEASE
	# -K, -b, -B and -m as poudriere-jail(8) has them: -b for a src=
	# tree, -B for what is built here, a method's path absolute.
	atf_check -s exit:1 -e match:'build is for method src=' -o ignore \
	    "$JGC" -c "$SOCK" poudriere jail-create name=j version=15.0-RELEASE build=yes
	atf_check -s exit:1 -e match:'pkgbase-set is built from source' -o ignore \
	    "$JGC" -c "$SOCK" poudriere jail-create name=j version=15.0-RELEASE \
	    method=src=/usr/src pkgbase-set=yes
	atf_check -s exit:1 -e match:'a method is http' -o ignore \
	    "$JGC" -c "$SOCK" poudriere jail-create name=j version=15.0-RELEASE method=src=usr/src
	atf_check -s exit:1 -e match:'a method is http' -o ignore \
	    "$JGC" -c "$SOCK" poudriere jail-create name=j version=15.0-RELEASE method=rsync
	atf_check -s exit:1 -e match:"a kernel's name" -o ignore \
	    "$JGC" -c "$SOCK" poudriere jail-create name=j version=15.0-RELEASE kernel=a/b
	atf_check -o match:'done +poudriere jail-create src15' \
	    "$JGC" -c "$SOCK" poudriere jail-create name=src15 version=15.0-STABLE \
	    method=src=/usr/src kernel=GENERIC build=yes pkgbase-set=yes
	atf_check -o match:'"argv":\["[^"]*fake-poudriere","jail","-c","-j","src15","-v","15.0-STABLE","-m","src=/usr/src","-K","GENERIC","-b","-B"\]' \
	    "$JGC" -c "$SOCK" poudriere
	atf_check -o match:'done +poudriere jail-create git15' \
	    "$JGC" -c "$SOCK" poudriere jail-create name=git15 version=15.0-STABLE \
	    method=git+https kernel= pkgbase-set=yes
	atf_check -o match:'"argv":\["[^"]*fake-poudriere","jail","-c","-j","git15","-v","15.0-STABLE","-m","git\+https","-K","","-B"\]' \
	    "$JGC" -c "$SOCK" poudriere
	# Updated: to a version (-t), with a kernel (-K), its source built
	# (-b) where it was made from src= or a checkout; its method is the
	# one it was made with.
	for i in $(seq 1 50); do
		[ -f pe/poudriere.d/jails/src15/method ] && break
		sleep 0.1
	done
	atf_check -o match:'done +poudriere jail-update src15' \
	    "$JGC" -c "$SOCK" poudriere jail-update name=src15 version=15-STABLE \
	    kernel=GENERIC build=yes
	atf_check -o match:'"argv":\["[^"]*fake-poudriere","jail","-u","-j","src15","-t","15-STABLE","-K","GENERIC","-b"\]' \
	    "$JGC" -c "$SOCK" poudriere
	atf_check -s exit:1 -o match:'made by pkgbase: build is for one made from src=' \
	    -e ignore "$JGC" -c "$SOCK" poudriere jail-update name=FreeBSD:16:amd64 build=yes
	atf_check -s exit:1 -e match:'updated by the method it was made with' -o ignore \
	    "$JGC" -c "$SOCK" poudriere jail-update name=src15 method=http
	atf_check -s exit:1 -e match:'key=value' -o ignore \
	    "$JGC" -c "$SOCK" poudriere bulk net/bird3
	atf_check -s exit:1 -e match:"the host's" -o ignore \
	    "$JGC" -c "$SOCK" -j web poudriere jail-update name=x
	atf_check -s exit:1 -e match:'URL is one word' -o ignore \
	    "$JGC" -c "$SOCK" poudriere ports-create name=p 'url=http://x/ y'

	# Deleted: poudriere -y, to its end in the job.
	atf_check -o match:'done +poudriere jail-delete FreeBSD:16:amd64$' \
	    "$JGC" -c "$SOCK" poudriere jail-delete name=FreeBSD:16:amd64
	atf_check -o match:'^poudriere jail -d -y -j FreeBSD:16:amd64$' \
	    cat poudriere.log
	for j in src15 git15; do
		atf_check -o match:"done +poudriere jail-delete $j\$" \
		    "$JGC" -c "$SOCK" poudriere jail-delete name=$j
	done
	atf_check -o match:'"jails":\[\]' "$JGC" -c "$SOCK" poudriere
	atf_check -s exit:1 -o match:'failed +poudriere ports-delete nosuch: .*No such ports nosuch' \
	    -e ignore "$JGC" -c "$SOCK" poudriere ports-delete name=nosuch
}
poudriere_cleanup()
{
	[ -f builder/5.pid ] && kill -INT -"$(cat builder/5.pid)" 2>/dev/null
	stop_daemon
}

atf_test_case bird_watch cleanup
bird_watch_head()
{
	atf_set "descr" "BIRD's sessions watched: a BGP session, an OSPF neighbour and a BFD session that go down are faults, cleared when they are up again"
}
bird_watch_body()
{
	# birdc(8): what each session is, from files the test changes.
	cat > fake-birdc <<EOS
#!/bin/sh
[ "\$1" = -r ] && shift
d=$(pwd)
case "\$*" in
'show status') printf 'BIRD 2.15.1 ready.\\nRouter ID is 192.0.2.1\\n' ;;
'show protocols all')
	st=up; info=Established; bs=Established; err=
	[ -e \$d/bgp.down ] && { st=start; info=Active; bs=Active; err='    Last error:       Socket: Connection refused'; }
	printf 'BIRD 2.15.1 ready.\\nName Proto Table State Since Info\\n'
	printf 'bgp1 BGP --- %s 12:00:00 %s\\n  BGP state:          %s\\n    Neighbor address: 192.0.2.7\\n    Neighbor AS:      65001\\n%s\\n' \$st \$info \$bs "\$err"
	printf 'off1 BGP --- down 12:00:00\\n  BGP state:          Down\\n' ;;
'show ospf neighbors')
	printf 'ospf1:\\nRouter ID Pri State DTime Interface Router IP\\n'
	[ -e \$d/ospf.gone ] || printf '10.0.0.2 1 Full/PtP 00:00:35 gif0 10.255.0.2\\n' ;;
'show bfd sessions')
	s=Up; [ -e \$d/bfd.down ] && s=Down
	printf 'bfd1:\\nIP address Interface State Since Interval Timeout\\nfe80::2 gif0 %s 13:01:27 0.200 1.000\\n' \$s ;;
*) printf 'BIRD 2.15.1 ready.\\n' ;;
esac
EOS
	chmod +x fake-birdc
	DAEMON_ARGS="--bird-watch 1"
	start_daemon
	# All well: no fault, but the session turned off is none either.
	sleep 2.5
	atf_check -o not-match:'sdwan-fault' "$JGC" -c "$SOCK" events
	touch bgp.down ospf.gone bfd.down
	for i in $(seq 1 40); do
		[ $("$JGC" -c "$SOCK" events | grep -o '"state":"set"' | wc -l) -ge 3 ] && break
		sleep 0.2
	done
	atf_check -o match:'"type":"bgp-neighbor","severity":"Major","object":"host:bgp1","by":"bird","description":"BGP bgp1 to 192.0.2.7 is Active: Socket: Connection refused","state":"set"' \
	    -o match:'"type":"ospf-neighbor","severity":"Major","object":"host:ospf1/10.0.0.2@gif0","by":"bird","description":"OSPF neighbour ospf1/10.0.0.2@gif0 is gone from BIRD.s list","state":"set"' \
	    -o match:'"type":"bfd","severity":"Major","object":"host:bfd1/fe80::2@gif0","by":"bird","description":"BFD to fe80::2 on gif0 is Down","state":"set"' \
	    -o not-match:'"object":"off1"' \
	    "$JGC" -c "$SOCK" events
	# Well again: each cleared.
	rm -f bgp.down ospf.gone bfd.down
	for i in $(seq 1 40); do
		[ $("$JGC" -c "$SOCK" events | grep -o '"state":"cleared"' | wc -l) -ge 3 ] && break
		sleep 0.2
	done
	atf_check -o match:'"type":"bgp-neighbor","severity":"Cleared","object":"host:bgp1","description":"BGP bgp1 is established","state":"cleared"' \
	    -o match:'"type":"ospf-neighbor","severity":"Cleared","object":"host:ospf1/10.0.0.2@gif0"' \
	    -o match:'"type":"bfd","severity":"Cleared","object":"host:bfd1/fe80::2@gif0"' \
	    "$JGC" -c "$SOCK" events
}
bird_watch_cleanup()
{
	stop_daemon
}

atf_init_test_cases()
{
	atf_add_test_case bird_watch
	atf_add_test_case poudriere
	atf_add_test_case host_watch
	atf_add_test_case fw_walk
	atf_add_test_case crash_fault
	atf_add_test_case firewall_aliases
	atf_add_test_case config_bundle
	atf_add_test_case ntp
	atf_add_test_case rtadvd
	atf_add_test_case ipsec_sa
	atf_add_test_case interfaces
	atf_add_test_case network_more
	atf_add_test_case sdwan
	atf_add_test_case netstore
	atf_add_test_case smtpd
	atf_add_test_case sysfiles
	atf_add_test_case sdwan_jail
	atf_add_test_case jail_conf
	atf_add_test_case carp
	atf_add_test_case neighbours
	atf_add_test_case multicast
	atf_add_test_case clamav
	atf_add_test_case certs
	atf_add_test_case sshd
	atf_add_test_case capture
	atf_add_test_case vpn
	atf_add_test_case vnet
	atf_add_test_case traceroute
	atf_add_test_case kernel
	atf_add_test_case l2
	atf_add_test_case fw_trace
	atf_add_test_case firewall
	atf_add_test_case observe
	atf_add_test_case storage
	atf_add_test_case notify
	atf_add_test_case safe_mode
	atf_add_test_case agent_update
	atf_add_test_case agent_restart
	atf_add_test_case agent_build
	atf_add_test_case stop
	atf_add_test_case hello
	atf_add_test_case socket_mode
	atf_add_test_case list
	atf_add_test_case conf_errors
	atf_add_test_case trace
	atf_add_test_case start
	atf_add_test_case failures
	atf_add_test_case address_dry_run
	atf_add_test_case address_persist
	atf_add_test_case address_refused
	atf_add_test_case many_jails
	atf_add_test_case services
	atf_add_test_case service_actions
	atf_add_test_case service_config
	atf_add_test_case network
	atf_add_test_case ipsec
	atf_add_test_case packages
	atf_add_test_case jobs
}
