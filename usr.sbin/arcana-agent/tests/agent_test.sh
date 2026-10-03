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
start)		touch "running.\$name"; echo "Starting \$name." ;;
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
# With ./huge, a table too large to hold: the libxo document is cut
# short, and the plain listing has 3000 routes to read line by line.
if [ -f huge ] && [ "$*" = "--libxo json -rnW -f inet" ]; then
	printf '{"statistics": {"route-information": {"route-table": {"rt-family": [{"address-family": "Internet", "rt-entry": ['
	head -c 5000000 /dev/zero | tr '\0' ' '
	exit 0
fi
if [ -f huge ] && [ "$*" = "-rnW -f inet" ]; then
	printf 'Routing tables\n\nInternet:\nDestination        Gateway            Flags   Nhop#    Mtu            Netif   Metric Expire\n'
	jot 3000 0 | awk '{ printf "10.%d.%d.0/24      192.0.2.1          UGS  %8d   1500              em0       1\n", int($1 / 250), $1 % 250, $1 }'
	exit 0
fi
# With ./big, an IPv4 routing table of 6000 routes: over a megabyte.
if [ -f big ] && [ "$*" = "--libxo json -rnW -f inet" ]; then
	printf '{"statistics": {"route-information": {"route-table": {"rt-family": [{"address-family": "Internet", "rt-entry": ['
	i=0
	while [ $i -lt 6000 ]; do
		printf '{"destination":"10.%d.%d.0/24","gateway":"192.0.2.1","flags":"UGS","flags_pretty":["up","gateway","static"],"nhop":%d,"mtu":1500,"interface-name":"em0"},' $((i / 250)) $((i % 250)) $i
		i=$((i + 1))
	done
	echo '{"destination":"10.99.99.99/32","gateway":"last-entry","flags":"UH","interface-name":"lo0"}]}]}}}}'
	exit 0
fi
case "$*" in
*-rnW*)	echo '{"statistics": {"route-information": {"route-table": {"rt-family": [{"address-family": "Internet6", "rt-entry": [{"destination": "::1", "gateway": "link#2", "flags": "UHS", "interface-name": "lo0"}]}]}}}}' ;;
*-onW*)	echo '{"statistics": {"route-nhop-information": {"nhop-table": {"rt-family": []}}}}' ;;
*)	echo '{"statistics": {"socket": [{"protocol": "tcp4", "local": {"address": "10.0.0.1", "port": "22"}, "remote": {"address": "10.0.0.2", "port": "4000"}, "tcp-state": "ESTABLISHED"}]}}' ;;
esac
EOS
	cat > fake-sockstat <<'EOS'
#!/bin/sh
echo "fake-sockstat $*" >&2
echo '{"__version": "1", "sockstat": {"socket": [{"user": "root", "command": "sshd", "pid": 1, "fd": 3, "proto": "tcp4", "local": {"address": "*", "port": 22}, "foreign": {"address": "*", "port": "*"}}]}}'
EOS
	chmod +x fake-netstat fake-sockstat
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
[ "$1" = -j ] && shift 2
case "$1" in
update)	exit 0 ;;
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
	    -X "$(pwd)/fake-sockstat" -P "$(pwd)/fake-pkg" \
	    -U "$(pwd)/installed-agent" -B "$(pwd)/build" \
	    -c "$(pwd)/build.mk" -G "$(pwd)/fake-git" -M "$(pwd)/fake-make" \
	    -Y "$(pwd)/fake-keyscan" -I "$(pwd)/fake-ifconfig" \
	    -r "$(pwd)/fake-route" -n "$(pwd)/fake-ngctl" -w 2 \
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
	atf_set "descr" "routes, nexthops, connections and sockets as the programs' libxo JSON"
}
network_body()
{
	start_daemon
	atf_check -o save:routes.out "$JGC" -c "$SOCK" net routes -6
	atf_check -o match:'"route-table"' cat routes.out
	atf_check -o match:'fake-netstat --libxo json -rnW -f inet6' \
	    "$JGC" -t -c "$SOCK" net routes -6
	# Both families: a run each, the entries joined.
	atf_check -o save:nh.out "$JGC" -t -c "$SOCK" net nexthops
	atf_check -o match:'fake-netstat --libxo json -onW -f inet$' cat nh.out
	atf_check -o match:'fake-netstat --libxo json -onW -f inet6$' cat nh.out
	atf_check -o match:'"rt-family"' cat nh.out
	atf_check -o match:'fake-netstat --libxo json -nW -f inet$' \
	    "$JGC" -t -c "$SOCK" net connections -4
	atf_check -o save:so.out "$JGC" -t -c "$SOCK" net sockets
	atf_check -o match:'fake-sockstat --libxo json -w -4$' cat so.out
	atf_check -o match:'fake-sockstat --libxo json -w -6$' cat so.out
	atf_check -o match:'"sshd".*"sshd"' cat so.out
	atf_check -s exit:2 -e ignore "$JGC" -c "$SOCK" net tables
	# A table far larger than what a trace step keeps arrives whole.
	touch big
	atf_check -o save:big.out "$JGC" -c "$SOCK" net routes -4
	atf_check -o match:'"destination":"10.99.99.99/32"' cat big.out
	atf_check -o match:'last-entry' cat big.out

	# A table too large to send whole: its first rows come, with how
	# many there are; and it can be searched on the host.
	rm big
	touch huge
	atf_check -o save:huge.out -e match:'the table has 3000 rows' \
	    "$JGC" -c "$SOCK" net routes -4
	atf_check -o match:'"destination":"10.0.0.0/24"' \
	    -o match:'"destination":"10.7.249.0/24"' \
	    -o not-match:'"destination":"10.8.0.0/24"' \
	    -o match:'"interface-name":"em0"' cat huge.out
	atf_check -o save:found.out "$JGC" -c "$SOCK" net routes -4 10.11.249.
	atf_check -o match:'"destination":"10.11.249.0/24"' \
	    -o not-match:'"destination":"10.0.0.0/24"' cat found.out
	atf_check -o match:'"total":3000' -o match:'"truncated":"false"' \
	    "$JGC" --libxo json -c "$SOCK" net routes -4 10.11.249.
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
	cat > fake-route <<EOS
#!/bin/sh
echo "\$*" >> $(pwd)/route.log
case " \$* " in *" 10.66.0.0/16 "*) echo "route: message indicates error: File exists" >&2; exit 1 ;; esac
echo "add net \$4: gateway \$5"
EOS
	chmod +x fake-ifconfig fake-route
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

	# Static routes: route(8) is run as one would run it.
	atf_check -o match:'route add 10.77.0.0/16 via 10.0.0.1' \
	    -o match:'fake-route -n add -inet 10.77.0.0/16 10.0.0.1' \
	    "$JGC" -c "$SOCK" route add 10.77.0.0/16 10.0.0.1
	atf_check -o match:'fake-route -n add -inet6 2001:db8:7::/48 2001:db8::1' \
	    "$JGC" -c "$SOCK" route add 2001:db8:7::/48 2001:db8::1
	atf_check -o match:'fake-route -n add -inet 10.78.0.0/16 -iface lo0' \
	    "$JGC" -c "$SOCK" route add 10.78.0.0/16 lo0
	atf_check -o match:'fake-route -n add -inet6 default 2001:db8::1' \
	    "$JGC" -c "$SOCK" route add ::/0 2001:db8::1
	atf_check -o match:'fake-route -n delete -inet 10.77.0.0/16:' \
	    "$JGC" -c "$SOCK" route delete 10.77.0.0/16
	atf_check -o match:'^ +[0-9]+ queued +route delete default via 10.0.0.1' \
	    "$JGC" -q -c "$SOCK" route delete default 10.0.0.1
	atf_check -s exit:1 -o match:'File exists' \
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
	cat > fake-route <<EOS
#!/bin/sh
echo "\$*" >> $(pwd)/route.log
if [ "\$2" = get ]; then
	case "\$*" in *203.0.113.*) echo "route: route has not been found" >&2; exit 1 ;; esac
	printf '   route to: %s\ndestination: 10.77.0.0\n       mask: 255.255.0.0\n    gateway: 10.0.0.1\n        fib: 0\n  interface: em0\n      flags: <UP,GATEWAY,DONE,STATIC>\n recvpipe  sendpipe\n       0         0\n' "\$4"
fi
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
	chmod +x fake-ifconfig fake-route fake-ngctl
	start_daemon
	# The plain routing table, for the routes that cover an address.
	cat > fake-netstat <<'EOS'
#!/bin/sh
echo "fake-netstat $*" >&2
case "$*" in
"-rnW -f inet"*)
	printf 'Routing tables\n\nInternet:\nDestination        Gateway            Flags   Nhop#    Mtu      Netif Expire\n'
	printf 'default            192.0.2.1          UGS         1   1500        em0\n'
	printf '10.77.0.0/16       10.0.0.1           UGS         2   1500        em0\n'
	printf '10.77.5.0/24       10.0.0.9           UGS         3   1500        em1\n'
	printf '10.78.0.0/16       10.0.0.1           UGS         4   1500        em0\n'
	printf '10.77.5.5          link#3             UH          5   1500        lo0\n' ;;
*)	echo '{"statistics": {"route-information": {"route-table": {"rt-family": []}}}}' ;;
esac
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
	atf_check -s exit:1 -o match:'without quotes' \
	    "$JGC" -c "$SOCK" interface lo0 description 'a"; reboot'

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
	    -o match:'fake-ifconfig gif7 tunnel 2001:db8::1 2001:db8::2' \
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
	atf_check -o match:'fake-route -n add -inet 10.77.0.0/16 10.0.0.1 -fib 2' \
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
	atf_check -o match:'fake-netstat --libxo json -rnW -f inet -F 2' \
	    "$JGC" -t -F 2 -c "$SOCK" net routes -4

	# The route to an address: the one taken, and those that cover it,
	# each with the length of its prefix.
	atf_check -o save:get.out "$JGC" -c "$SOCK" route get 10.77.5.5
	atf_check -o match:'"best":\{"to":"10.77.5.5","destination":"10.77.0.0","mask":"255.255.0.0","gateway":"10.0.0.1","fib":"0","interface":"em0"' \
	    -o match:'"destination":"default".*"prefixlen":0' \
	    -o match:'"destination":"10.77.0.0/16".*"prefixlen":16' \
	    -o match:'"destination":"10.77.5.0/24","gateway":"10.0.0.9".*"prefixlen":24' \
	    -o match:'"destination":"10.77.5.5".*"prefixlen":32' \
	    -o not-match:'10.78.0.0' cat get.out
	# No route is an answer: nothing is best, the default still covers.
	atf_check -o not-match:'"best"' -o match:'"destination":"default"' \
	    "$JGC" -c "$SOCK" route get 203.0.113.9
	atf_check -s exit:1 -e match:'not an IPv4 or IPv6 address' -o ignore \
	    "$JGC" -c "$SOCK" route get '10.0.0.1;id'
	atf_check -o match:'get -inet 10.77.5.5 -fib 4' \
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

atf_test_case safe_mode cleanup
safe_mode_head()
{
	atf_set "descr" "A safe change stays when confirmed, and is undone when not"
	atf_set "timeout" "60"
}
safe_mode_body()
{
	printf '#!/bin/sh\necho "$*" >> %s/ifconfig.log\n' "$(pwd)" > fake-ifconfig
	printf '#!/bin/sh\necho "$*" >> %s/route.log\n' "$(pwd)" > fake-route
	chmod +x fake-ifconfig fake-route
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
	atf_check -o match:'^-n add -inet 10.77.0.0/16 10.0.0.1$' \
	    -o match:'^-n delete -inet 10.77.0.0/16 10.0.0.1$' \
	    -o match:'^-n delete -inet 10.78.0.0/16 10.0.0.1$' \
	    -o match:'^-n add -inet 10.78.0.0/16 10.0.0.1$' cat route.log
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
[ "\$1" = clone ] || exit 2
for a; do last=\$a; done
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
	# A build that fails installs nothing and restarts nothing.
	rm running.arcana_console made
	touch make-fails
	atf_check -s exit:1 -e match:'make exited with status 1' -o ignore \
	    "$JGC" -c "$SOCK" console-update https://example.org/arcana.git
	atf_check -o not-match:'install' cat made
	sleep 1.5
	atf_check test ! -e running.arcana_console
	rm make-fails
	# What git would take as an option is not a repository.
	atf_check -s exit:1 -e match:'not a repository' -o ignore \
	    "$JGC" -c "$SOCK" agent-build -- --upload-pack=x
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

atf_init_test_cases()
{
	atf_add_test_case interfaces
	atf_add_test_case network_more
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
	atf_add_test_case packages
	atf_add_test_case jobs
}
