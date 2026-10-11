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
	put "\$key" "\${old:+\$old }\$val"; echo "\$key: \$old -> \$val" ;;
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
		touch "running.\$name"; echo "Restarting \$name." ;;
reload)		echo "Reloading \$name." ;;
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
[ "$1" = -o ] && shift 2
[ "$1" = -j ] && shift 2
case "$1" in
update)	exit 0 ;;
query)	printf 'aria2\t1.37.0_1\t0\t5242880\twww/aria2\tDownload utility\npimd\t3.1.0\t1\t102400\tnet/pimd\tPIM-SM daemon\n' ;;
clean)	echo "$*" >> clean.log ;;
install) echo "$*" >> install.log ;;
version)
	[ -s pending ] || exit 1
	while read nv remote; do
		printf '%-30s <   needs updating (remote has %s)
' "$nv" "$remote"
	done < pending ;;
upgrade)
	shift; dry=no; [ "$1" = -n ] && dry=yes; shift
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
	    -X "$(pwd)/fake-traceroute" \
	    $DAEMON_ARGS \
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
	[ -f daemon.pid ] && kill "$(cat daemon.pid)" 2>/dev/null
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
	atf_check -o match:'fake-helper -Q 0 routes 6 0 - -:' \
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
	atf_check -o match:'fake-helper -Q 0 pcb-conns 4' \
	    -o match:'"statistics":\{"socket":\[\{"protocol":"tcp4"' \
	    "$JGC" -t -c "$SOCK" net connections -4
	atf_check -o save:so.out "$JGC" -t -c "$SOCK" net sockets
	atf_check -o match:'fake-helper -Q 0 pcb-socks 0' \
	    -o match:'"sockstat":\{"socket":\[\{"user":"root","command":"sshd"' cat so.out
	# The nexthop groups, what a route of several next hops points to.
	atf_check -o match:'"nhgrp-index":1,"nhg-refcnt":1,"nhop-weights":\[\{"nh-index":5,"nh-weight":2' \
	    -o match:'fake-netstat --libxo json -OnW -f inet$' \
	    "$JGC" -t -c "$SOCK" net nhgroups
	# The neighbours, of ARP and NDP, asked of the kernel.
	atf_check -o match:'fake-helper -Q 0 route-neighs 0 -' \
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
	# The installed, from the host's own database: no repository.
	atf_check -o match:'^aria2 +1\.37\.0_1 +by hand +5242880 Download utility' \
	    -o match:'^pimd +3\.1\.0 +automatic' -o match:'fake-pkg query' \
	    -o not-match:'fake-pkg (version|update)' \
	    "$JGC" -t -c "$SOCK" packages -i
	# Over IPv6 only; past OSVERSION.
	atf_check -o match:'fake-pkg -6 version -vRl <' "$JGC" -t -c "$SOCK" packages -6
	atf_check -o match:'fake-pkg -4 -o IGNORE_OSVERSION=yes upgrade -n' \
	    "$JGC" -t -c "$SOCK" pkg-upgrade -n -O -4
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
	    -o match:'fake-helper -Q 0 route-add 10.77.0.0/16 10.0.0.1 - 0 0 0 -' \
	    "$JGC" -c "$SOCK" route add 10.77.0.0/16 10.0.0.1
	# With its cost, its share among those of one cost, and the address
	# sent from; kept, they are in rc.conf's route too.
	atf_check -o match:'route add 10.81.0.0/16 via 10.0.0.1 \(metric\) \(weight\) \(kept\)' \
	    -o match:'fake-helper -Q 0 route-add 10.81.0.0/16 10.0.0.1 - 0 5 20 10.0.0.9' \
	    "$JGC" -p -c "$SOCK" route add 10.81.0.0/16 10.0.0.1 metric 5 weight 20 source 10.0.0.9
	atf_check -o match:'^route_[a-z0-9_]*="10.81.0.0/16 10.0.0.1 -ifa 10.0.0.9 -metric 5 -weight 20"$' \
	    cat rc.conf
	atf_check -o match:'fake-helper -Q 0 route-del 10.81.0.0/16 10.0.0.1 - 0 5' \
	    "$JGC" -p -c "$SOCK" route delete 10.81.0.0/16 10.0.0.1 metric 5
	atf_check -o not-match:'10.81.0.0' cat rc.conf
	atf_check -s exit:1 -o match:'no address of the route.s family' \
	    "$JGC" -c "$SOCK" route add 10.82.0.0/16 10.0.0.1 source 2001:db8::9
	atf_check -s exit:1 -e match:'the address to send from is an address' -o ignore \
	    "$JGC" -c "$SOCK" route add 10.82.0.0/16 10.0.0.1 source '-x'
	atf_check -o match:'fake-helper -Q 0 route-add 2001:db8:7::/48 2001:db8::1 - 0 0 0 -' \
	    "$JGC" -c "$SOCK" route add 2001:db8:7::/48 2001:db8::1
	atf_check -o match:'fake-helper -Q 0 route-add 10.78.0.0/16 - lo0 0 0 0 -' \
	    "$JGC" -c "$SOCK" route add 10.78.0.0/16 lo0
	atf_check -o match:'fake-helper -Q 0 route-add ::/0 2001:db8::1 - 0 0 0 -' \
	    "$JGC" -c "$SOCK" route add ::/0 2001:db8::1
	atf_check -o match:'fake-helper -Q 0 route-del 10.77.0.0/16 - - 0 0' \
	    "$JGC" -c "$SOCK" route delete 10.77.0.0/16
	atf_check -o match:'^ +[0-9]+ queued +route delete default via 10.0.0.1' \
	    "$JGC" -q -c "$SOCK" route delete default 10.0.0.1
	# Several gateways: one route of as many next hops, each with its
	# share; not kept, not deleted as one, and each an address.
	atf_check -o match:'fake-helper -Q 0 route-add 10.83.0.0/16 10.0.0.1@2,10.0.0.2 - 0 0 0 -' \
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
	atf_check -o match:'fake-helper -Q 0 route-add 10.77.0.0/16 10.0.0.1 - 2 0 0 -' \
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
	atf_check -o match:'fake-helper -Q 0 routes 4 2 - -' \
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
	atf_check -o match:'fake-helper -Q 0 route-get 10.77.5.5 4' \
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
	atf_check -o match:'Plugins: bird wireguard' "$JGC" -c "$SOCK" hello
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
	atf_check -o match:'^-Q 4 interfaces - 0$' cat helper.log
	atf_check -o match:'"name":"lo0"' -o not-match:'epair91b' \
	    "$JGC" -c "$SOCK" net interfaces
	# Its bridges and geneve tunnels: ifconfig told the jail once.
	atf_check -o ignore "$JGC" -j gateway -c "$SOCK" net bridges
	atf_check -o match:'^-j 4 -av$' cat ifconfig.log
	# Its routes and its route to an address: the host's programs,
	# told which jail.
	atf_check -o match:'fake-helper -Q 4 routes 4 0 - -' \
	    "$JGC" -t -j gateway -c "$SOCK" net routes -4
	atf_check -o match:'"gateway":"10.99.0.1","fib":"0","interface":"epair91b"' \
	    "$JGC" -j gateway -c "$SOCK" route get 192.0.2.9
	atf_check -o match:'^-Q 4 route-get 192.0.2.9 0$' cat helper.log

	# A change there: ifconfig and route with the jail, the job named
	# after it, what is kept kept in the jail's own rc.conf.
	atf_check -o match:'gateway: epair91b: add 10.99.0.5/24' \
	    -o match:'fake-ifconfig -j 4 epair91b inet 10.99.0.5/24 alias' \
	    "$JGC" -p -j gateway -c "$SOCK" interface epair91b add 10.99.0.5/24
	atf_check -o match:'^ifconfig_epair91b_alias0="inet 10.99.0.5/24"$' \
	    cat "$R/etc/rc.conf"
	atf_check -o not-match:'10.99.0.5' cat rc.conf
	atf_check -o match:'fake-helper -Q 4 route-add 10.77.0.0/16 10.99.0.1 - 0 0 0 -' \
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
	    "$JGC" -c "$SOCK" job 2
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
exit 0
EOS
	chmod +x fake-ipfw
	printf '#!/bin/sh\necho "kldload $*" >> %s/kldload.log\nexit 0\n' "$(pwd)" > fake-kldload
	chmod +x fake-kldload
	DAEMON_ARGS="-h $(pwd)/fake-ipfw -3 $(pwd)/fake-setfib"
	start_daemon
	atf_check -o match:'"targets":\[\]' -o match:'"probing":true' \
	    -o match:'"rules":\{"set":0,"rules":0,"tables":\[\],"objects":0\}' \
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
	    -o match:'^table sw1_zone add 10.1.0.0/16 12$' \
	    -o match:'^table sw1_zone add 0.0.0.0/0 13$' \
	    -o match:'^table sw1_z0p0_4 create type addr valtype ipv4$' \
	    -o match:'^add 10 set 30 skipto tablearg ip from table\(sw1_zone\) to any in recv lo1$' \
	    -o match:'^add 12 set 30 deny ip from any to any$' \
	    -o match:'^ipfw -q set enable 30$' cat ipfw.log
	# Disabled, loaded, enabled: in that order.
	atf_check -o inline:'1\n' sh -c "grep -n 'set disable 30' ipfw.log | cut -d: -f1 | head -1"
	atf_check -o match:'"rules":\{"set":30,"rules":4,"tables":\["sw1_zone","sw1_z0p0_4"\],"objects":0\}' \
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
	    -o match:'^table sw1_known create type addr valtype legacy$' \
	    -o match:'^add 12 set 30 queue 3001 ip from any to any$' cat ipfw.log
	atf_check -o inline:'yes\n' sh -c "test \$(grep -n '^pipe 3000' ipfw.log | cut -d: -f1 | head -1) -lt \$(grep -n '^add 12' ipfw.log | cut -d: -f1 | head -1) && echo yes"
	atf_check -o match:'dummynet' -o match:'ipfw_nat' cat kldload.log
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
# bird -c conf -s sock -P pid: started, says the socket.
shift 3; shift 2; touch "\$2"
exit 0
EOS
	chmod +x fake-bird fake-birdc fake-setfib
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
	    "$JGC" -c "$SOCK" events
	rm -f bfd.down
	for i in $(seq 1 30); do
		"$JGC" -c "$SOCK" sdwan | grep -q '"chosen":0' && break
		sleep 0.2
	done
	atf_check -o match:'"chosen":0' "$JGC" -c "$SOCK" sdwan
	atf_check -o empty "$JGC" -c "$SOCK" sdwan bird \
	    '{"instances":[{"name":"sw1","fib":1,"conf":"router id 100.64.0.0;\nprotocol device {}\nprotocol static {}\n"}]}'
	atf_check -o match:'configure$' cat birdc.log
	atf_check -o inline:'1\n' sh -c "grep -c '^setfib' setfib.log"
	atf_check -o empty "$JGC" -c "$SOCK" sdwan bird '{"instances":[]}'
	atf_check -o match:'down$' cat birdc.log
	test ! -f "$(dirname "$f")/sdwan-bird-sw1.conf" || atf_fail "the instance's file stayed"
	atf_check -o match:'"bird":\[\]' "$JGC" -c "$SOCK" sdwan
	# No rules: the set emptied, the tables gone, the objects deleted.
	: > ipfw.log
	atf_check -o empty "$JGC" -c "$SOCK" sdwan rules '{"set":30,"tables":[],"rules":[]}'
	atf_check -o match:'^ipfw -q table sw1_known destroy$' \
	    -o match:'^ipfw -q nat 3001 delete$' \
	    -o match:'^ipfw -q queue 3001 delete$' \
	    -o match:'^ipfw -q pipe 3000 delete$' cat ipfw.log
	atf_check -o inline:'yes\n' sh -c "test \$(grep -n '^ipfw -q queue 3001 delete' ipfw.log | cut -d: -f1 | head -1) -lt \$(grep -n '^ipfw -q pipe 3000 delete' ipfw.log | cut -d: -f1 | head -1) && echo yes"
	atf_check -o match:'"rules":\{"set":0,' "$JGC" -c "$SOCK" sdwan
}
sdwan_cleanup()
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
if [ "\$1" = ls-remote ]; then
	case "\$4" in nope) exit 2 ;; esac
	printf '%s\trefs/heads/%s\n' "\$(cat $(pwd)/head 2>/dev/null || echo 2222222222222222222222222222222222222222)" "\$4"
	exit 0
fi
[ "\$1" = clone ] || exit 2
for a; do last=\$a; done
case " \$* " in *" --branch chatty "*) jot 400 | sed 's/^/remote: line /' >&2; exit 128 ;; esac
case " \$* " in *" --branch nope "*) printf "Cloning into 'x'...\nfatal: no such branch\nfatal: Could not read from remote repository.\n\nPlease make sure you have the correct access rights\nand the repository exists.\n" >&2; exit 128 ;; esac
mkdir -p "\$last/lib/libjailconf" "\$last/usr.sbin/arcana-agent"
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
	    -o match:'git clone --depth 1 --branch main -- https://example.org/arcana.git' \
	    "$JGC" -t -c "$SOCK" agent-build -o built https://example.org/arcana.git main
	atf_check cmp -s "$JGD" built
	atf_check test -x built
	# What was built is said by its commit, and the head of the
	# repository is asked without cloning or building anything.
	atf_check -o match:'^Commit: +1111111111111111111111111111111111111111$' \
	    "$JGC" -c "$SOCK" agent-build -o built https://example.org/arcana.git main
	rm made
	echo 3333333333333333333333333333333333333333 > head
	atf_check -o match:'^Commit: +3333333333333333333333333333333333333333$' \
	    "$JGC" -c "$SOCK" source-head https://example.org/arcana.git main
	atf_check test ! -e made
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
	touch slow
	"$JGC" -c "$SOCK" service sshd restart > change.out 2>&1 &
	change=$!
	sleep 0.5
	# What is under way and is not a job is said with the jobs.
	atf_check -o match:'Under way: +service sshd restart' \
	    -o not-match:'Stopping' "$JGC" -c "$SOCK" jobs
	atf_check -o ignore "$JGC" -q -c "$SOCK" start web
	kill "$pid"
	sleep 0.5
	atf_check -s exit:0 kill -0 "$pid"
	atf_check -o match:'Under way: +service sshd restart' \
	    -o match:'Stopping: +when what is under way ends' \
	    "$JGC" -c "$SOCK" jobs
	atf_check -o match:'a change is under way' \
	    -o match:'under way: service sshd restart' \
	    -o match:'queued, will not run: job 1: start web' cat daemon.out
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
	"$JGC" -c "$SOCK" service sshd restart > /dev/null 2>&1 &
	sleep 0.5
	kill "$pid"
	sleep 0.3
	kill "$pid"
	for i in $(seq 1 15); do
		kill -0 "$pid" 2>/dev/null || break
		sleep 0.1
	done
	atf_check -s exit:1 -e ignore kill -0 "$pid"
	atf_check -o match:'signalled again' cat daemon.out
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
	DAEMON_ARGS="-v $(pwd)/log"
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
	atf_check -o match:'"samples":\[\]' "$JGC" -c "$SOCK" history "$last"
	# How it samples is set, and written down for the next start: fewer
	# kept are the newest; none kept is no sampling and no memory.
	# A limit crossed is an event, once, until it is crossed back; told
	# to those who follow the events the moment it is made.
	"$JGC" -c "$SOCK" events -f > follow.out 2>&1 &
	echo $! > follow.pid
	sleep 0.5
	atf_check -o match:'"limits":\{"cpu":1,"mem":1,"swap":0\}' \
	    "$JGC" -c "$SOCK" history set 1 20 1 1 0
	sleep 3
	kill "$(cat follow.pid)"
	atf_check -o match:'^\{"n":[0-9]+,"t":[0-9]+,"kind":"threshold","data":\{"what":"mem","value":[0-9]+,"limit":1,"over":true\}\}$' \
	    cat follow.out
	atf_check -o match:'"kind":"threshold","data":\{"what":"mem","value":[0-9]+,"limit":1,"over":true\}' \
	    "$JGC" -c "$SOCK" events
	atf_check -o inline:'1\n' sh -c "$JGC -c $SOCK events | grep -o '\"what\":\"mem\"' | wc -l | tr -d ' '"
	atf_check -o match:'^cpu=1$' -o match:'^mem=1$' cat history.conf
	atf_check -o match:'"limits":\{"cpu":90,"mem":90,"swap":50\}' \
	    "$JGC" -c "$SOCK" history set 1 20 90 90 50
	atf_check -o match:'"step":1,"keep":2,"bytes":[1-9][0-9]*,' \
	    "$JGC" -c "$SOCK" history set 1 2
	atf_check -o match:'^step=1$' -o match:'^keep=2$' cat history.conf
	sleep 4
	atf_check -o save:h2.json "$JGC" -c "$SOCK" history
	atf_check -o inline:'2\n' sh -c "grep -o '\[[0-9][0-9,.]*\]' h2.json | wc -l | tr -d ' '"
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
	atf_check -o ignore "$JGC" -c "$SOCK" ipfw delete 1002
	atf_check -o match:'^ipfw -q delete 1002$' tail -1 ipfw.log
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
	atf_check -o match:'"kept":\[\{"num":5,"text":"skipto 500 all from any to any out"\},\{"num":200' \
	    -o match:'"file":true' "$JGC" -c "$SOCK" net ipfw

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
	atf_check -s exit:1 -e match:'sets no firewall_type' -o ignore \
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
	atf_check -s exit:1 -e match:'is add, delete, apply' -o ignore \
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
"list -Hp -t filesystem,volume"*)
	printf 'tank\tfilesystem\t5000\t9000\t96\t/tank\tlz4\t1.50\t0\t0\tyes\ton\t-\t-\toff\toff\t-\tnone\toff\n'
	printf 'tank/data\tfilesystem\t4000\t9000\t4000\t/tank/data\tlz4\t2.00\t8000\t0\tyes\ton\t-\t-\toff\taes-256-gcm\tunavailable\tfile:///k\ton\n'
	printf 'tank/vol\tvolume\t100\t9000\t100\t-\toff\t1.00\t-\t0\t-\t-\ttank/data@a\t1048576\toff\toff\t-\tnone\toff\n' ;;
"list -Hp -t snapshot"*)
	printf 'tank/data@b\t10\t4000\t1759500000\n'
	printf 'tank/data@a\t20\t3000\t1759400000\n' ;;
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
"list -Hp -o name,size,allocated"*) printf 'tank\t14000\t5000\t9000\t12\t35\t1.00\tDEGRADED\n' ;;
import) printf '   pool: spare\n     id: 1234567890\n  state: ONLINE\n action: The pool can be imported using its name or numeric identifier.\n config:\n\n\tspare       ONLINE\n\t  ada7p1    ONLINE\n' ;;
status) cat <<EOP ;;
  pool: tank
 state: DEGRADED
status: One or more devices has been taken offline by the administrator.
	Sufficient replicas exist for the pool to continue functioning.
action: Online the device using 'zpool online'.
  scan: scrub repaired 0B in 00:10:11 with 0 errors on Sun Oct  4 03:00:00 2026
config:

	NAME        STATE     READ WRITE CKSUM
	tank        DEGRADED     0     0     0
	  mirror-0  DEGRADED     0     0     0
	    ada1p1  ONLINE       0     0     0
	    ada2p1  OFFLINE      0     0     0  was /dev/ada2p1

errors: No known data errors
EOP
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
	for p in newfs growfs swapon swapoff; do
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
	atf_check "$JGD" -Q 0 zfs-pipe "$(pwd)/fake-zfs" tank/data@b backup/data tank/data@a r
	atf_check -o match:'^zfs send -R -i tank/data@a tank/data@b$' \
	    -o match:'^zfs receive -u backup/data$' cat storage.log
	# A file system made on a partition: not on one that has one, is
	# a pool's, or is not a device; and one grown.
	atf_check -o match:'done +newfs -U -L data /dev/ada0p4$' "$JGC" -c "$SOCK" gpart newfs ada0p4 data
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
	    -o match:'"scan":"scrub repaired 0B' -o match:'"errors":"No known data errors"' \
	    -o match:'\{"name":"mirror-0","depth":1,"state":"DEGRADED","read":"0","write":"0","cksum":"0"\}' \
	    -o match:'\{"name":"ada2p1","depth":2,"state":"OFFLINE","read":"0","write":"0","cksum":"0","note":"was /dev/ada2p1"\}' \
	    cat p.json
	# Datasets and snapshots: sizes are numbers, "-" is nothing.
	atf_check -o match:'\{"name":"tank/data","type":"filesystem","used":4000,"avail":9000,"refer":4000,"mountpoint":"/tank/data","compression":"lz4","ratio":"2.00","quota":8000,"reservation":0,"mounted":"yes","canmount":"on","readonly":"off",' \
	    -o match:'"name":"tank/vol","type":"volume".*"origin":"tank/data@a","volsize":1048576' \
	    "$JGC" -c "$SOCK" storage datasets
	atf_check -o match:'\{"snapshots":\[\{"name":"tank/data@b","used":10,"refer":4000,"creation":1759500000\}' \
	    "$JGC" -c "$SOCK" storage snapshots tank/data
	atf_check -o match:'^zfs list -Hp -t snapshot -o name,used,referenced,creation -S creation -r tank/data$' \
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

atf_init_test_cases()
{
	atf_add_test_case interfaces
	atf_add_test_case network_more
	atf_add_test_case sdwan
	atf_add_test_case vpn
	atf_add_test_case vnet
	atf_add_test_case traceroute
	atf_add_test_case kernel
	atf_add_test_case l2
	atf_add_test_case fw_trace
	atf_add_test_case firewall
	atf_add_test_case observe
	atf_add_test_case storage
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
