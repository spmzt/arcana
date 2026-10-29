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

# Whether a process is there and not a zombie: in a container no reaper
# may wait for one that ended, and kill -0 still finds it.
alive()
{
	ps -o state= -p "$1" 2>/dev/null | grep -qv Z
}

# Does the kernel have SCTP: compiled in (kern.features.sctp) or the
# module loaded.
has_sctp()
{
	[ "$(sysctl -n kern.features.sctp 2>/dev/null)" = 1 ] ||
	    kldstat -q -m sctp 2>/dev/null
}

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
	# libjail's jail_getv(3) answering from ./jails: built beside the
	# tests, or installed with them.
	FJL="$(atf_get_srcdir)/libfakejail/libfakejail.so"
	[ -f "$FJL" ] || FJL="$(atf_get_srcdir)/libfakejail.so"
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
# A third word: arcana_relay's, a relay's profile, run as rc.subr's
# arcana_relay_<profile> (its verbs noted); dhclient's, its interface,
# the same service.
name=\$1; verb=\$2; r=\$name
[ "\$name" = arcana_relay ] && r=\$name\${3:+_\$3} && echo "\$verb \$r" >> arcana_relay.verbs
case "\$verb" in
rcvar)		echo "# \$name"; echo "\${name}_enable=\"NO\""; echo '#   (default: "")' ;;
# rc.subr's answer: the last of rc.conf and Arcana's file (a case's
# root) that sets it.
enabled)	cat "\$conf" $(pwd)/root/usr/local/etc/rc.conf.d/arcana 2>/dev/null |
		grep "^\${name}_enable=" | tail -1 | grep -q '="YES"' ;;
status|onestatus)	[ -f "running.\$r" ] && { echo "\$r is running as pid 4242."; exit 0; }
		echo "\$r is not running."; exit 1 ;;
start|onestart)	touch "running.\$r"; echo "Starting \$r." ;;
stop|onestop)	rm -f "running.\$r"; echo "Stopping \$r." ;;
restart|onerestart)	[ -f slow ] && sleep 2
		# Held while the test wants it under way (it lets go by taking
		# hold away), five minutes at most: a loaded run is slow to
		# look.
		i=0; while [ -f hold ] && [ \$i -lt 3000 ]; do sleep 0.1; i=\$((i + 1)); done
		touch "running.\$r"; echo "Restarting \$r." ;;
reload|onereload)	[ -f "noreload.\$r" ] && { echo "\$r: not reloaded" >&2; exit 1; }
		echo reloaded >> "reloads.\$r"
		echo "Reloading \$name." ;;
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
	[ "\$1" != 6 ] && echo '{"destination":"10.0.0.0/24","gateway":"link#1","flags":"U","nhop":2,"mtu":16384,"interface-name":"lo0","metric":1,"weight":1,"fib":'\$2',"prefixlen":24}'
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
anyos=no
while [ "$1" = -o ]; do
	echo "opt $2" >> opts.log
	[ "$2" = IGNORE_OSVERSION=yes ] && anyos=yes
	shift 2
done
[ "$1" = -j ] && shift 2
case "$1" in
# pkgbase: FreeBSD-runtime is installed once the file pkgbase is there.
info)	[ -e pkgbase ] && exit 0 || exit 1 ;;
rquery)	printf 'FreeBSD-runtime\nFreeBSD-set-base-jail\nFreeBSD-set-base-jail-dbg\nFreeBSD-set-minimal-jail\n' ;;
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
	# What pkg does on a conversion: a file of stock/ that the jail
	# (its root in ./jroot) has otherwise is put aside as .pkgsave.
	if [ "$1" = install -a -d stock ]; then
		R=$(cat jroot)
		for f in stock/*; do
			n=${f#stock/}
			[ -e "$R/etc/$n" ] && ! cmp -s "$f" "$R/etc/$n" &&
			    mv "$R/etc/$n" "$R/etc/$n.pkgsave"
			cp "$f" "$R/etc/$n"
		done
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
	# Emptied here, before the daemon starts: its child empties it only
	# once it runs, and the "ready" of the one before would be read.
	: > daemon.out
	# The jails it finds by name are ./jails' (none until a case
	# writes it), never the host's.
	[ -f "$FJL" ] || atf_fail "no libfakejail.so at $FJL"
	FAKEJAIL="$(pwd)/jails" LD_PRELOAD="$FJL" \
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
	    -x "$(pwd)/fake-jexec" \
	    -H "$(pwd)/fake-helper" -T "$(pwd)/fake-kldload" \
	    -t "$(pwd)/fake-kldunload" -1 "$(pwd)/history.conf" -w 2 \
	    --jobs-conf "$(pwd)/jobs.conf" --nacm "$(pwd)/nacm.cbor" \
	    -X "$(pwd)/fake-traceroute" -4 "$(pwd)/ntp.conf" \
	    -6 "$(pwd)/rtadvd.conf" -7 "$(pwd)/fake-dnsmasq" -8 "$(pwd)/fake-rtsol" \
	    -9 "$(pwd)/fake-setkey" -0 "$(pwd)/fake-local-unbound" \
	    --rtadvctl "$(pwd)/fake-rtadvctl" \
	    --bird-watch 0 $DAEMON_ARGS \
	    > daemon.out 2>&1 &
	echo $! > daemon.pid
	# Ready a minute at most: the whole suite at once can make it slow,
	# and a case that went on before would find no socket.
	for i in $(seq 1 1200); do
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
	# away the socket the next one had made.  A minute on a busy host,
	# then for good.
	for i in $(seq 1 1200); do
		alive "$pid" || return 0
		sleep 0.05
	done
	kill -9 "$pid" 2>/dev/null
	for i in $(seq 1 100); do
		alive "$pid" || return 0
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


# The ietf-interfaces collector (yang/collect.h) beside what ifconfig(8)
# and netstat(1) -i say of the same interfaces.
atf_test_case yang_active_route
yang_active_route_head()
{
	atf_set "descr" "ietf-routing's active-route action:" \
	    "the route an address goes by, as route -n get finds it"
}
yang_active_route_body()
{
	# route -n get's answer as ycollect writes it: af, the destination
	# with its mask's length (none: a host's), the gateway (link#N,
	# none: -), the interface, the special next hop (-: none).
	cat > get.awk <<'EOF'
function hexv(s,    v, k) {
	v = 0
	for (k = 1; k <= length(s); k++)
		v = v * 16 + index("0123456789abcdef", substr(tolower(s), k, 1)) - 1
	return v
}
function bits(x,    n) {
	n = 0
	while (x > 0) { n += x % 2; x = int(x / 2) }
	return n
}
$1 == "destination:" { d = $2 }
$1 == "mask:" { m = $2 }
$1 == "gateway:" { g = $2 }
$1 == "interface:" { i = $2 }
$1 == "flags:" { f = $2 }
END {
	if (d == "") { print "none"; exit }
	af = d ~ /:/ ? "inet6" : "inet"
	sub(/%.*/, "", d)
	if (m == "")
		len = af == "inet" ? 32 : 128
	else {
		len = 0
		n = split(m, o, af == "inet" ? "." : ":")
		for (k = 1; k <= n; k++)
			if (o[k] != "")
				len += bits(af == "inet" ? o[k] + 0 : hexv(o[k]))
	}
	if (g == "" || g ~ /^link#/) g = "-"
	sp = "-"
	if (f ~ /BLACKHOLE/) sp = "blackhole"
	else if (f ~ /REJECT/) sp = "unreachable"
	else if (f ~ /HOST/ && f !~ /GATEWAY/ && i ~ /^lo/) sp = "receive"
	if (sp != "-") { i = "-"; g = "-" }
	print af, d "/" len, g, i, sp
}
EOF
	# Somewhere out, the loopback, and every address of the host's.
	{
		echo 127.0.0.1 ::1 192.0.2.77 2001:db8::77 198.51.100.1
		ifconfig -a | awk '$1 == "inet" || $1 == "inet6" { print $2 }'
	} | tr ' ' '\n' | sort -u > addrs
	while read -r x; do
		[ -z "$x" ] && continue
		fam=-inet; case "$x" in *:*) fam=-inet6;; esac
		route -n get "$fam" "$x" 2>/dev/null | awk -f get.awk > want
		atf_check -o save:got "$(atf_get_srcdir)/ycollect" active 0 "$x"
		atf_check -o match:'^yang-cbor [0-9]+ bytes, the same back$' \
		    tail -1 got
		head -1 got | awk '{ print $1, $2, $3, $4, $5 }' | \
		    sed 's/^none.*/none/' > got1
		cmp -s want got1 || { echo "$x:"; cat want got1; atf_fail \
		    "$x: the action and route -n get differ"; }
	done < addrs
}

atf_test_case yang_lne
yang_lne_head()
{
	atf_set "descr" "the vnet jails as RFC 8530's logical network" \
	    "elements: as jls(8) lists them"
}
yang_lne_body()
{
	jls -n name vnet | sed -n 's/^name=\(.*\) vnet=new$/\1 managed/p' \
	    > want
	echo "yang-cbor the same back" >> want
	atf_check -o file:want "$(atf_get_srcdir)/ycollect" lne
}

atf_test_case yang_ni_conf
yang_ni_conf_head()
{
	atf_set "descr" "FIBs as RFC 8529's network instances:" \
	    "one each from FIB 1 to net.fibs - 1, fibs.conf's names" \
	    "and descriptions read and written, what cannot be said"
}
yang_ni_conf_body()
{
	local y="$(atf_get_srcdir)/yni" n i

	# This host's: FIB 1 to net.fibs - 1, fibN each.
	n=$(sysctl -n net.fibs)
	: > want
	i=1
	while [ "$i" -lt "$n" ]; do
		echo "fib$i $i -" >> want
		i=$((i + 1))
	done
	echo "yang-cbor" >> want
	atf_check -o file:want sh -c "'$y' - | sed 's/^yang-cbor.*/yang-cbor/'"
	cat > fibs.conf <<'EOF'
# The names of the FIBs.
fib2_name="blue"
fib2_description="the blue customer's"
fib3_name="fib1"
fib1_name="$x"
fib9_name=far
fib0_name=host
EOF
	atf_check -o inline:"fib1 1 -
blue 2 the blue customer's
fib3 3 -
unread fib1_name: not settled by reading the file
unread fib3_name: another FIB's name
unread fib9_name: no such FIB: net.fibs is fewer
unread fib0_name: FIB 0 is the host's, not an instance
yang-cbor 66 bytes, the same back
" "$y" -n 4 fibs.conf
	# One name given two FIBs: the first's.
	printf 'fib1_name=blue\nfib2_name=blue\n' > two.conf
	atf_check -o inline:"blue 1 -
fib2 2 -
unread fib2_name: another FIB's name
yang-cbor 31 bytes, the same back
" "$y" -n 3 two.conf
	# Written: names and descriptions set, those of FIBs not given
	# taken out, the rest of the file as it was.
	printf '2 red\n3 green the green one\n' > in
	atf_check sh -c "'$y' -n 4 -w fibs.conf < in"
	atf_check -o inline:'# The names of the FIBs.
fib2_name="red"
fib3_name="green"
fib9_name=far
fib0_name=host
fib3_description="the green one"
' cat fibs.conf
	atf_check -o inline:"fib1 1 -
red 2 -
green 3 the green one
unread fib9_name: no such FIB: net.fibs is fewer
unread fib0_name: FIB 0 is the host's, not an instance
yang-cbor 60 bytes, the same back
" "$y" -n 4 fibs.conf
	# Refused, the file as it was: a FIB there is not, another's name,
	# one FIB twice.
	cp fibs.conf was
	printf '5 red\n' > in
	atf_check -s exit:1 -e inline:"yni: red: FIB 5, net.fibs is 4\n" \
	    sh -c "'$y' -n 4 -w fibs.conf < in"
	printf '2 fib3\n' > in
	atf_check -s exit:1 -e inline:"yni: fib3: another FIB's name\n" \
	    sh -c "'$y' -n 4 -w fibs.conf < in"
	printf '2 red\n2 blue\n' > in
	atf_check -s exit:1 -e inline:"yni: red, blue: FIB 2 twice\n" \
	    sh -c "'$y' -n 4 -w fibs.conf < in"
	atf_check cmp was fibs.conf
}

atf_test_case yang_ni_grow
yang_ni_grow_head()
{
	atf_set "descr" "an instance past the last FIB:" \
	    "net.fibs kept in loader.conf; not raised live, unprivileged," \
	    "so a reboot required"
	# Never root: a live raise of the host's net.fibs is for good.
	atf_set "require.user" "unprivileged"
}
yang_ni_grow_body()
{
	local y="$(atf_get_srcdir)/yni"

	cat > loader.conf <<'EOF'
# The kernel's tables.
net.fibs="2"
EOF
	: > fibs.conf
	printf '1 blue\n5 far\n' > in
	atf_check -o inline:"net.fibs 6 reboot required\n" \
	    sh -c "'$y' -n 3 -w -l loader.conf fibs.conf < in"
	atf_check -o inline:'# The kernel'"'"'s tables.
net.fibs="6"
' cat loader.conf
	atf_check -o inline:'fib1_name="blue"
fib5_name="far"
' cat fibs.conf
	# As many already: loader.conf as it was.
	printf '2 red\n' > in
	atf_check -o inline:"net.fibs 3 live\n" \
	    sh -c "'$y' -n 3 -w -l loader.conf fibs.conf < in"
	atf_check -o match:'^net.fibs="6"$' cat loader.conf
	# Refused, nothing grown: one FIB twice, past the kernel's.
	cp loader.conf was
	printf '7 red\n7 blue\n' > in
	atf_check -s exit:1 -e inline:"yni: red, blue: FIB 7 twice\n" \
	    sh -c "'$y' -n 3 -w -l loader.conf fibs.conf < in"
	printf '65535 top\n' > in
	atf_check -s exit:1 \
	    -e inline:"yni: top: FIB 65535, the kernel has at most 65535\n" \
	    sh -c "'$y' -n 3 -w -l loader.conf fibs.conf < in"
	atf_check cmp was loader.conf
}

atf_test_case yang_ni_rc
yang_ni_rc_head()
{
	atf_set "descr" "bind-ni-name kept in rc.conf:" \
	    "the fib words of ifconfig_<if> set, replaced, taken out"
}
yang_ni_rc_body()
{
	local y="$(atf_get_srcdir)/yni"

	cat > rc.conf <<'EOF'
ifconfig_em0="inet 192.0.2.1/24 fib 2 up"
ifconfig_lo1="fib 3"
ifconfig_vlan0_10="inet 198.51.100.1/24"
ifconfig_em1="$x"
EOF
	atf_check "$y" -r em0 3 rc.conf
	atf_check "$y" -r lo1 0 rc.conf
	atf_check "$y" -r vlan0.10 2 rc.conf
	atf_check "$y" -r igb0 0 rc.conf
	atf_check "$y" -r igb1 5 rc.conf
	atf_check -s exit:1 -e inline:"yni: ifconfig_em1: not settled by reading the file\n" \
	    "$y" -r em1 2 rc.conf
	atf_check -o inline:'ifconfig_em0="inet 192.0.2.1/24 fib 3 up"
ifconfig_vlan0_10="inet 198.51.100.1/24 fib 2"
ifconfig_em1="$x"
ifconfig_igb1="fib 5"
' cat rc.conf
}

atf_test_case yang_rtadv_conf
yang_rtadv_conf_head()
{
	atf_set "descr" "rtadvd.conf as RFC 8349's router advertisement" \
	    "submodule and arcana-ra: read through tc=, an edit" \
	    "of one leaf alone, every capability written and" \
	    "read back byte for byte, other capabilities kept"
}
yang_rtadv_conf_body()
{
	local y="$(atf_get_srcdir)/yrtadv"

	# rtadvd.conf(5)'s examples.
	cat > rtadvd.conf <<'EOF'
ne0:\
	:rltime#0:
default:\
	:chlim#64:raflags#0:rltime#1800:rtime#0:retrans#0:\
	:pinfoflags="la":vltime#2592000:pltime#604800:mtu#0:
ef1:\
	:addr="2001:db8:ffff:1000::":prefixlen#64:tc=default:
wlan0:\
	:addr="2001:db8:ffff:1000::":prefixlen#48:pinfoflags="l":\
	:addr0="2001:db8:1::":vltime0#3600:pltime0#1800:raflags="mo":
EOF
	atf_check -o inline:"managed-flag=0
other-config-flag=0
link-mtu=0
reachable-time=0
retrans-timer=0
cur-hop-limit=64
default-lifetime=1800
router-preference=medium
prefix 2001:db8:ffff:1000::/64 1 1 2592000 604800 0 0
other tc=default
" "$y" rtadvd.conf ef1
	atf_check -o inline:"managed-flag=1
other-config-flag=1
router-preference=medium
prefix 2001:db8:ffff:1000::/48 1 0 2592000 604800 0 0
prefix 2001:db8:1::/64 1 1 3600 1800 0 0
" "$y" rtadvd.conf wlan0
	atf_check -o inline:"default-lifetime=0\n" "$y" rtadvd.conf ne0
	atf_check -o inline:"none\n" "$y" rtadvd.conf nothere
	# One leaf edited: the record written whole, in rtadvd.conf(5)'s
	# order, nothing else of the file touched.
	cp rtadvd.conf was
	atf_check "$y" -m rtadvd.conf wlan0 300
	atf_check -s exit:1 -o inline:"9,10c9,11
< 	:addr=\"2001:db8:ffff:1000::\":prefixlen#48:pinfoflags=\"l\":\\
< 	:addr0=\"2001:db8:1::\":vltime0#3600:pltime0#1800:raflags=\"mo\":
---
> 	:maxinterval#300:raflags=\"mo\":addr=\"2001:db8:ffff:1000::\":\\
> 	:prefixlen#48:pinfoflags=\"l\":addr0=\"2001:db8:1::\":prefixlen0#64:\\
> 	:vltime0#3600:pltime0#1800:
" diff was rtadvd.conf
	atf_check -o match:'^max-rtr-adv-interval=300$' "$y" rtadvd.conf wlan0
	# A record with tc=: what default brings and the edit does not
	# change stays default's; its own prefix is written whole.
	cp rtadvd.conf was2
	atf_check "$y" -m rtadvd.conf ef1 450
	atf_check -s exit:1 -o inline:"7c7,8
< 	:addr=\"2001:db8:ffff:1000::\":prefixlen#64:tc=default:
---
> 	:maxinterval#450:addr=\"2001:db8:ffff:1000::\":prefixlen#64:\\
> 	:pinfoflags=\"la\":vltime#2592000:pltime#604800:tc=default:
" diff was2 rtadvd.conf
	atf_check -o match:'^cur-hop-limit=64$' -o match:'^other tc=default$' \
	    "$y" rtadvd.conf ef1
	# Written to another file and read back: the same.
	"$y" was wlan0 > want
	atf_check -o file:want "$y" -w was wlan0 out
	# Every capability of rtadvd.conf(5), as Arcana writes it: read,
	# written to another file, the bytes the same; and read back the
	# same.  hapref and hatime, which rtadvd(8) refuses, and a field it
	# never heard of are kept as written, a cancelled mtu too.
	cat > full.conf <<'EOF'
# The lab's advertisements.
base:\
	:chlim#64:mtu#01500:
em0:\
	:maxinterval#600:mininterval#200:chlim#32:raflags="moh":\
	:rltime#1800:rtime#30000:retrans#1000:noifprefix:clockskew#10:\
	:addr="2001:db8:1::":prefixlen#64:addr0="2001:db8:2::":\
	:prefixlen0#56:pinfoflags0="l":vltime0#3600:vltimedecr0:\
	:pltime0#1800:pltimedecr0:mtu#1280:nolladdr:\
	:rtprefix="2001:db8:100::":rtplen#48:rtflags="h":rtltime#900:\
	:rtprefix0="2001:db8:200::":rtplen0#64:rtflags0="l":\
	:rdnss="2001:db8::53,2001:db8::54":rdnssltime#900:\
	:rdnss0="2001:db8::55":dnssl="example.com,lab.example.com":\
	:dnsslltime#700:dnssl0="corp.example":pref64="64:ff9b::":\
	:pref640="2001:db8:64::":pref64len0#48:pref64lifetime0#3600:\
	:hapref#10:hatime#100:unheardof="x":mtu@:tc=base:
em1:\
	:raflags="l":addr="2001:db8:3::":prefixlen#64:mtu="auto":
EOF
	cat > want.em0 <<'EOF'
max-rtr-adv-interval=600
min-rtr-adv-interval=200
managed-flag=1
other-config-flag=1
link-mtu=1280
reachable-time=30000
retrans-timer=1000
cur-hop-limit=32
default-lifetime=1800
router-preference=high
interface-prefixes=0
source-link-layer-address=0
clock-skew=10
prefix 2001:db8:1::/64 1 1 2592000 604800 0 0
prefix 2001:db8:2::/56 1 0 3600 1800 1 1
route 2001:db8:100::/48 high 900
route 2001:db8:200::/64 low -
rdnss 2001:db8::53 900
rdnss 2001:db8::54 900
rdnss 2001:db8::55 -
dnssl example.com 700
dnssl lab.example.com 700
dnssl corp.example -
pref64 64:ff9b::/96 -
pref64 2001:db8:64::/48 3600
other hapref#10
other hatime#100
other unheardof="x"
other mtu@
other tc=base
EOF
	atf_check -o file:want.em0 "$y" full.conf em0
	atf_check -o inline:"managed-flag=0
other-config-flag=0
router-preference=low
link-mtu-auto=1
prefix 2001:db8:3::/64 1 1 2592000 604800 0 0
" "$y" full.conf em1
	cp full.conf again.conf
	atf_check -o file:want.em0 "$y" -w full.conf em0 again.conf
	atf_check -o ignore "$y" -w full.conf em1 again.conf
	atf_check cmp full.conf again.conf
	# A record of another interface is not touched by a write of one.
	printf 'em9:\\\n\t:rltime#0:\n' > one.conf
	atf_check -o ignore "$y" -w full.conf em1 one.conf
	atf_check -o inline:"em9:\\\\
	:rltime#0:
em1:\\\\
	:raflags=\"l\":addr=\"2001:db8:3::\":prefixlen#64:mtu=\"auto\":
" cat one.conf
}

atf_test_case yang_rc_routes
yang_rc_routes_head()
{
	atf_set "descr" "rc.conf's static routes as ietf-routing's static" \
	    "control-plane-protocol, read and written" \
	    "back to a fragment"
}
yang_rc_routes_body()
{
	local y="$(atf_get_srcdir)/yrcroutes"

	# Every form rc.d/routing takes; what the model cannot hold, or
	# reading not tell, unread.
	cat > rc.conf <<'EOF'
hostname="gw"
defaultrouter="192.0.2.254"
ipv6_defaultrouter="fe80::1%em0"
defaultrouter_fib1="198.51.100.1"
static_routes="lan2 lan3 tun:wg0 ecmp1 ecmp2 bh rej mtu calc dup1 dup2 missing fib1 cls"
route_lan2="-net 10.2.0.0/16 192.0.2.10"
route_lan3="-net 10.3.0.0 -netmask 255.255.0.0 192.0.2.11"
route_tun="-net 10.9.0.0/24 -iface wg0"
route_ecmp1="-net 10.8.0.0/24 192.0.2.21"
route_ecmp2="-net 10.8.0.0/24 192.0.2.22 -ifp em1"
route_bh="-net 203.0.113.0/24 127.0.0.1 -blackhole"
route_rej="-host 203.0.113.9 127.0.0.1 -reject"
route_mtu="-net 10.7.0.0/24 192.0.2.1 -mtu 1400"
route_calc="-net ${x} 192.0.2.1"
route_dup1="-host 10.6.0.1 192.0.2.30"
route_dup2="10.6.0.1 192.0.2.30"
route_fib1="-net 10.5.0.0/24 192.0.2.40 -fib 1"
route_cls="-net 10.4.0.0 192.0.2.2"
ipv6_static_routes="v6a v6b"
ipv6_route_v6a="2001:db8:1::/48 2001:db8::1"
ipv6_route_v6b="-net 2001:db8:2:: -prefixlen 64 -iface em1"
EOF
	# A later file's wins: rc.conf.local's.
	printf 'ipv6_route_v6a="2001:db8:1::/48 2001:db8::2"\n' > rc.conf.local
	cat > want0 <<'EOF'
inet 10.2.0.0/16 192.0.2.10 - - -
inet 10.3.0.0/16 192.0.2.11 - - -
inet 10.9.0.0/24 - wg0 - rc.conf: only with wg0
inet 10.8.0.0/24 192.0.2.21 - - -
inet 10.8.0.0/24 192.0.2.22 em1 - -
inet 203.0.113.0/24 - - blackhole -
inet 203.0.113.9/32 - - unreachable -
inet 10.6.0.1/32 192.0.2.30 - - -
inet 0.0.0.0/0 192.0.2.254 - - -
inet6 2001:db8:1::/48 2001:db8::2 - - -
inet6 2001:db8:2::/64 - em1 - -
inet6 ::/0 fe80::1%em0 - - -
EOF
	cat > unread0 <<'EOF'
unread route_mtu: a route(8) option the model has no leaf for
unread route_calc: not a value reading tells
unread route_missing: not set
unread route_cls: a network without its length
unread route_dup2: the same prefix and gateway as another
EOF
	cat want0 unread0 > all0
	atf_check -o file:all0 "$y" 0 rc.conf rc.conf.local
	# FIB 1's: its own route, its default router.
	atf_check -o match:'^inet 10\.5\.0\.0/24 192\.0\.2\.40 - - -$' \
	    -o match:'^inet 0\.0\.0\.0/0 198\.51\.100\.1 - - -$' \
	    -o not-match:'10\.2\.0\.0' "$y" 1 rc.conf rc.conf.local
	# Written to a fragment and read back from it: the same routes,
	# nothing unread; and sh(1) reads the fragment.
	atf_check -o file:want0 "$y" -w 0 frag rc.conf rc.conf.local
	atf_check -o match:'^static_routes=".*arc_10_9_0_0_24:wg0' cat frag
	atf_check -o match:'^-net 10\.8\.0\.0/24 192\.0\.2\.22 -ifp em1$' \
	    sh -c '. ./frag; echo "$route_arc_10_8_0_0_24_2"'
	atf_check -o inline:"192.0.2.254 fe80::1%em0\n" \
	    sh -c '. ./frag; echo "$defaultrouter $ipv6_defaultrouter"'
	# Written again, the same: what was there replaced, not added to.
	cp frag frag1
	atf_check -o file:want0 "$y" -w 0 frag rc.conf rc.conf.local
	atf_check cmp frag frag1
}

atf_test_case yang_pmd
yang_pmd_head()
{
	atf_set "descr" "a medium's IEEE 802.3 PMD type, by the name" \
	    "<net/if_media.h> gives it: IEEE's, none where IEEE names none"
}
yang_pmd_body()
{
	cat > want <<'EOF'
1000baseT pmd-type-1000BASE-T
10Gbase-SR pmd-type-10GBASE-SR
25GBase-CR1 pmd-type-25GBASE-CR
5000Base-T pmd-type-5GBASE-T
2500Base-T -
10base5/AUI -
10baseT/UTP pmd-type-10BASE-T
100GBase-SR4 pmd-type-100GBASE-SR4
10BASE-T1S pmd-type-10BASE-T1S
autoselect -
EOF
	atf_check -o file:want "$(atf_get_srcdir)/ycollect" pmd 1000baseT \
	    10Gbase-SR 25GBase-CR1 5000Base-T 2500Base-T 10base5/AUI \
	    10baseT/UTP 100GBase-SR4 10BASE-T1S autoselect
}

atf_test_case yang_origins
yang_origins_head()
{
	atf_set "descr" "a route's source-protocol by its netlink(4) origin:" \
	    "RFC 8349's static and direct, a routing protocol's own" \
	    "module's identity (OSPF and RIP by the family), else" \
	    "arcana-routing's"
}
yang_origins_body()
{
	cat > want <<'EOF'
0 - arcana-routing:other arcana-routing:other
0 gw arcana-routing:other arcana-routing:other
1 - arcana-routing:redirect arcana-routing:redirect
1 gw arcana-routing:redirect arcana-routing:redirect
2 - ietf-routing:direct ietf-routing:direct
2 gw arcana-routing:kernel arcana-routing:kernel
3 - ietf-routing:static ietf-routing:static
3 gw ietf-routing:static ietf-routing:static
4 - ietf-routing:static ietf-routing:static
4 gw ietf-routing:static ietf-routing:static
9 - arcana-routing:router-advertisement arcana-routing:router-advertisement
9 gw arcana-routing:router-advertisement arcana-routing:router-advertisement
11 - arcana-routing:zebra arcana-routing:zebra
11 gw arcana-routing:zebra arcana-routing:zebra
12 - arcana-routing:bird arcana-routing:bird
12 gw arcana-routing:bird arcana-routing:bird
16 - arcana-routing:dhcp arcana-routing:dhcp
16 gw arcana-routing:dhcp arcana-routing:dhcp
42 - ietf-babel:babel ietf-babel:babel
42 gw ietf-babel:babel ietf-babel:babel
186 - ietf-bgp:bgp ietf-bgp:bgp
186 gw ietf-bgp:bgp ietf-bgp:bgp
187 - ietf-isis:isis ietf-isis:isis
187 gw ietf-isis:isis ietf-isis:isis
188 - ietf-ospf:ospfv2 ietf-ospf:ospfv3
188 gw ietf-ospf:ospfv2 ietf-ospf:ospfv3
189 - ietf-rip:ripv2 ietf-rip:ripng
189 gw ietf-rip:ripv2 ietf-rip:ripng
EOF
	atf_check -o file:want "$(atf_get_srcdir)/ycollect" origins
}

atf_test_case yang_routes
yang_routes_head()
{
	atf_set "descr" "ietf-routing's RIBs: every" \
	    "FIB's routes as netstat -rn shows them, through YANG-CBOR" \
	    "and back"
}
yang_routes_body()
{
	# netstat(1)'s routes as ycollect writes them: af, prefix ("default"
	# /0, a host /32 or /128, no zone), gateway (link#N -), interface,
	# the special next hop (B blackhole, R unreachable, a host route to
	# lo without a gateway receive; none then an interface), and the
	# protocol its flags say (S static, no G direct, else any).
	cat > rt.awk <<'EOF'
/^Internet:/ { af = "inet"; next }
/^Internet6:/ { af = "inet6"; next }
af == "" || $1 == "Destination" || NF < 4 { next }
{
	d = $1; g = $2; fl = $3; i = $4
	if (d == "default")
		d = af == "inet" ? "0.0.0.0/0" : "::/0"
	z = d; sub(/%[^\/]*/, "", z); d = z
	if (d !~ /\//)
		d = d (af == "inet" ? "/32" : "/128")
	if (g ~ /^link#/)
		g = "-"
	# A route the kernel kept after its interface went: none.
	if (i == "---")
		i = "-"
	sp = "-"
	if (fl ~ /B/) sp = "blackhole"
	else if (fl ~ /R/) sp = "unreachable"
	else if (fl ~ /H/ && fl !~ /G/ && i ~ /^lo/) sp = "receive"
	if (sp != "-")
		i = "-"
	p = fl ~ /S/ ? "static" : fl !~ /G/ ? "direct" : "*"
	print af, d, g, i, sp, p
}
EOF
	nfibs=$(sysctl -n net.fibs)
	f=0
	while [ "$f" -lt "$nfibs" ]; do
		netstat -rn -F "$f" | awk -f rt.awk | sort > before
		atf_check -o save:r "$(atf_get_srcdir)/ycollect" routes "$f"
		netstat -rn -F "$f" | awk -f rt.awk | sort > after
		atf_check -o match:'^yang-cbor [0-9]+ bytes, the same back$' \
		    tail -1 r
		sed '$d' r | sort > got
		# A "*" protocol: any, a gateway's the kernel's or a daemon's.
		for w in before after; do
			awk 'NR == FNR { want[FNR] = $0; n = FNR; next }
			{ got[FNR] = $0; m = FNR }
			END {
				if (n != m) exit 1
				for (k = 1; k <= n; k++) {
					split(want[k], a); split(got[k], b)
					for (j = 1; j <= 5; j++)
						if (a[j] != b[j]) exit 1
					if (a[6] != "*" && a[6] != b[6]) exit 1
				}
			}' "$w" got && break
			[ "$w" = after ] && { diff -u before got; atf_fail \
			    "FIB $f: the collector and netstat differ"; }
		done
		f=$((f + 1))
	done
}

atf_test_case yang_interfaces
yang_interfaces_head()
{
	atf_set "descr" "ietf-interfaces as collected agrees with ifconfig" \
	    "and netstat -i: names, up, index, address, counters"
}
yang_interfaces_body()
{
	netstat -i -n -b -W > before
	atf_check -o save:y "$(atf_get_srcdir)/ycollect" interfaces
	netstat -i -n -b -W > after
	atf_check -o match:'^yang-cbor [0-9]+ bytes, the same back$' \
	    tail -1 y
	sed '$d' y > ifs
	# Each name once: two interfaces may share one (yif.c).
	ifconfig -l | tr ' ' '\n' | sort -u > names
	awk '{ print $1 }' ifs | sort > got
	atf_check cmp names got
	ifconfig -u -l | tr ' ' '\n' | sort -u > up
	awk '/ admin=up / { print $1 }' ifs | sort > gotup
	atf_check cmp up gotup
	# netstat's Link# line, the first of a name: index, address, bytes.
	awk '
	FNR == 1 { f++ }
	f < 3 && $3 ~ /^<Link#/ {
		n = $1; sub(/\*$/, "", n)
		if ((f, n) in seen) next
		seen[f, n] = 1
		idx = $3; gsub(/[^0-9]/, "", idx)
		if (f == 1) {
			index_of[n] = idx
			addr[n] = $4 ~ /:/ ? $4 : "-"
			ib0[n] = $8; ob0[n] = $11
		} else {
			ib1[n] = $8; ob1[n] = $11
		}
		next
	}
	f == 3 {
		n = $1
		split($0, kv, " ")
		for (i in kv) {
			split(kv[i], p, "=")
			v[p[1]] = p[2]
		}
		if (v["index"] != index_of[n] || v["phys"] != addr[n] ||
		    v["in-octets"] + 0 < ib0[n] + 0 ||
		    v["in-octets"] + 0 > ib1[n] + 0 ||
		    v["out-octets"] + 0 < ob0[n] + 0 ||
		    v["out-octets"] + 0 > ob1[n] + 0) {
			printf "%s: %s, netstat says index %s address %s " \
			    "in %s..%s out %s..%s\n", n, $0, index_of[n], \
			    addr[n], ib0[n], ib1[n], ob0[n], ob1[n]
			bad = 1
		}
	}
	END { exit bad }' before after ifs || atf_fail "the collector and netstat differ"

	# arcana-interfaces, and the standard leaves for what it once had,
	# beside ifconfig -m -D, as ifconfig shows it: max-frame-size the
	# MTU with an Ethernet header and FCS, and a tag of a vlan or where
	# VLAN_MTU is on; ethernet-like's addresses of an Ethernet or a
	# lagg, no hwaddr when it is the link address; no tunnelfib when 0.
	atf_check -o save:a "$(atf_get_srcdir)/ycollect" arcif
	cat > ifc.awk <<'EOF'
NR == 1 { for (i = 1; i < NF; i++) if ($i == "mtu") mtu = $(i + 1) }
$1 ~ /^options=/ { o = $1; sub(/^options=/, "", o); on = o; sub(/<.*/, "", o) }
$1 ~ /^capabilities=/ { c = $1; sub(/^capabilities=/, "", c); sub(/<.*/, "", c) }
$1 == "ether" { ether = $2 }
$1 == "hwaddr" { hw = $2 }
$1 == "groups:" { g = $2; for (i = 3; i <= NF; i++) g = g "+" $i }
$1 == "tunnelfib:" && $2 != 0 { tfib = " tunnelfib=" $2 }
$1 == "drivername:" { drv = $2 }
$1 == "status:" { st = $0; sub(/^[ \t]*status: /, "", st); gsub(/ /, "-", st) }
$1 == "media:" { m = $0; sub(/^[ \t]*media: [^ ]+ /, "", m) }
sup && $1 == "media" { s = $0; sub(/^[ \t]*media /, "", s); sp = sp (sp == "" ? "" : "+") s }
/supported media:/ { sup = 1 }
END {
	eth = type == "ethernetCsmacd" || type == "ieee8023adLag"
	printf "drv=%s", drv
	if (eth || type == "l2vlan" || type == "bridge")
		printf " frame=%d", mtu + 18 + \
		    (type == "l2vlan" || on ~ /[<,]VLAN_MTU[,>]/ ? 4 : 0)
	if (eth && ether)
		printf " mac=%s bia=%s", ether, hw ? hw : "-"
	printf " groups=%s%s options=%s capabilities=%s", g ? g : "-", tfib,
	    o, c
	if (m != "")
		printf " status=%s media=%s supported=%s", st ? st : "-", m,
		    sp ? sp : "-"
	printf "\n"
}
EOF
	# Ours: the kinds' parts left to agent_root_test, bia as ifconfig
	# hides it, a medium unchanged by autoselect without "(...)".
	cat > mine.awk <<'EOF'
{
	sub(/^[^ ]+ /, "")
	gsub(/ (vlan|lagg|aggport|bport|rstp|peer|eth)=[^ ]*/, "")
	split($0, f, " ")
	for (i in f)
		if (f[i] ~ /^mac=/)
			mac = substr(f[i], 5)
	if (mac != "")
		sub(" bia=" mac, " bia=-")
	sub(/ tunnelfib=0 /, " ")
	if (match($0, / media=.* \(/)) {
		cur = substr($0, RSTART + 7, RLENGTH - 9)
		rest = substr($0, RSTART + RLENGTH)
		act = substr(rest, 1, index(rest, ") supported=") - 1)
		if (act == cur)
			sub(/ \([^)]*\) supported=/, " supported=")
	}
	print
}
EOF
	# A name two interfaces share is ifconfig's to choose: left out.
	for i in $(ifconfig -l | tr ' ' '\n' | sort | uniq -u); do
		t=$(awk -v i="$i" '$1 == i { for (k = 2; k <= NF; k++)
		    if ($k ~ /^type=/) print substr($k, 6) }' ifs)
		ifconfig -m -D "$i" | awk -v type="$t" -f ifc.awk > exp
		grep "^$i " a | awk -f mine.awk > got
		cmp -s exp got || atf_fail "$i: ifconfig says $(cat exp), the collector $(cat got)"
	done

	# IEEE 802.3's view of an Ethernet's medium beside ifconfig's:
	# auto-negotiation where autoselect is offered (on when set,
	# complete with a carrier), the active medium's duplex, its PMD
	# type for the media named here (any other's, "*", not checked).
	cat > eth.awk <<'EOF'
$1 == "status:" { st = $2 }
$1 == "media:" {
	m = $0; sub(/^[ \t]*media: [^ ]+ /, "", m)
	split(m, w, " "); cur = w[1]
	act = m
	if (index(m, "(") > 0) { sub(/^[^(]*\(/, "", act); sub(/\).*$/, "", act) }
	split(act, aw, " "); asub = aw[1]
}
sup && $1 == "media" && $2 == "autoselect" { auto = 1 }
/supported media:/ { sup = 1 }
END {
	if (m == "") exit
	an = cur == "autoselect" ? "auto:" (st == "active" ? "complete" : \
	    "unknown") : auto ? "fixed" : "-"
	d = act ~ /full-duplex/ ? "full" : act ~ /half-duplex/ ? "half" : \
	    "unknown"
	p = "*"
	if (asub == "autoselect" || asub == "none") p = "unknown"
	else if (asub == "10Gbase-T") p = "10GBASE-T"
	else if (asub == "1000baseT") p = "1000BASE-T"
	else if (asub == "100baseTX") p = "100BASE-TX"
	else if (asub == "10baseT/UTP") p = "10BASE-T"
	printf "%s,%s,%s\n", an, d, p
}
EOF
	for i in $(ifconfig -l | tr ' ' '\n' | sort | uniq -u); do
		grep -q "^$i .* type=ethernetCsmacd " ifs || continue
		want=$(ifconfig -m "$i" | awk -f eth.awk)
		got=$(grep "^$i " a | sed -n 's/.* eth=\([^ ]*\).*/\1/p')
		[ -z "$want" ] && [ -z "$got" ] && continue
		case "$got" in
		"$want"|"${want%,\*}",*) ;;
		*) atf_fail "$i: ifconfig says $want, the collector eth=$got" ;;
		esac
	done

	# ietf-ip beside ifconfig and ndp -i: the addresses with their
	# prefix lengths and IPv6 status, IPv6 on or off and its MTU, the
	# origins by class (a link-local one ll, an autoconfigured or
	# temporary one auto, the rest static; dhcp counts as static).
	atf_check -o save:ip "$(atf_get_srcdir)/ycollect" ip
	cat > ifip.awk <<'EOF'
function bits(h,  n, d) {
	n = 0
	for (h = substr(h, 3); h != ""; h = substr(h, 2)) {
		d = index("0123456789abcdef", substr(h, 1, 1)) - 1
		n += (d >= 8) + (d % 8 >= 4) + (d % 4 >= 2) + (d % 2)
	}
	return n
}
NR == 1 { for (i = 1; i < NF; i++) if ($i == "mtu") mtu = $(i + 1) }
$1 == "inet" {
	o = $2 ~ /^169\.254\./ ? "random" : "static"
	v4 = v4 (v4 == "" ? "" : "+") $2 "/" bits($4) ":" o
}
$1 == "inet6" {
	a = $2; sub(/%.*/, "", a)
	st = "preferred"; o = a ~ /^fe80:/ ? "ll" : "static"
	for (i = 3; i <= NF; i++) {
		if ($i == "prefixlen") len = $(i + 1)
		if ($i == "duplicated") st = "duplicate"
		else if ($i == "tentative" && st != "duplicate") st = "tentative"
		else if ($i == "detached" && st == "preferred") st = "inaccessible"
		else if ($i == "deprecated" && st == "preferred") st = "deprecated"
		if ($i == "autoconf" || $i == "temporary") o = "auto"
	}
	v6 = v6 (v6 == "" ? "" : "+") a "/" len ":" o ":" st
}
$1 == "nd6" { nd = $2 ~ /IFDISABLED/ ? "off" : "on" }
$1 ~ /^linkmtu=/ { lm = $1; sub(/^linkmtu=/, "", lm); sub(/,$/, "", lm) }
END {
	m4 = v4 ? " mtu4=" mtu : ""
	if (nd != "" && lm + 0 > 0 && lm + 0 < mtu + 0)
		mtu = lm
	printf "v4=%s%s v6=%s ipv6=%s\n", v4 ? v4 : "-", m4, v6 ? v6 : "-",
	    nd ? nd "," mtu : "-"
}
EOF
	cat > myip.awk <<'EOF'
{
	sub(/^[^ ]+ /, "")
	gsub(/:dhcp/, ":static")
	n = split($0, f, " ")
	for (k = 1; k <= n; k++) {
		if (f[k] !~ /^v6=/ || f[k] == "v6=-")
			continue
		m = split(substr(f[k], 4), a, "+")
		f[k] = "v6="
		for (j = 1; j <= m; j++) {
			split(a[j], p, ":")
			# An address has colons: origin and status are the last two.
			c = split(a[j], q, ":")
			o = q[c - 1]; st = q[c]
			ad = substr(a[j], 1, length(a[j]) - length(o) - length(st) - 2)
			if (ad ~ /^fe80:/ && (o == "link-layer" || o == "other"))
				o = "ll"
			else if (o == "link-layer" || o == "random")
				o = "auto"
			f[k] = f[k] (j > 1 ? "+" : "") ad ":" o ":" st
		}
	}
	out = f[1]
	for (k = 2; k <= n; k++)
		out = out " " f[k]
	print out
}
EOF
	for i in $(ifconfig -l | tr ' ' '\n' | sort | uniq -u); do
		{ ifconfig "$i"; ndp -i "$i" 2>/dev/null; } | awk -f ifip.awk > exp
		grep "^$i " ip | awk -f myip.awk > got
		cmp -s exp got || atf_fail "$i: ifconfig says $(cat exp), the collector $(cat got)"
	done

	# The neighbours beside arp -an and ndp -an, less the host's own
	# addresses, which they list too, and those unresolved: what both
	# readings, before and after, have the collector has, and what it
	# has one of them has.
	ifconfig -a | awk '$1 == "inet" || $1 == "inet6" { a = $2;
	    sub(/%.*/, "", a); print a }' > own
	cat > nbs.sh <<'EOF'
arp -an | awk -v own=own '
BEGIN { while ((getline a < own) > 0) mine[a] = 1 }
$4 != "(incomplete)" {
	ip = $2; gsub(/[()]/, "", ip)
	if (ip in mine) next
	print $6, "inet", ip, $4, ($7 == "permanent" ? "static" : "dynamic")
}'
ndp -an | awk -v own=own '
BEGIN { while ((getline a < own) > 0) mine[a] = 1
	st["R"] = "reachable"; st["S"] = "stale"; st["D"] = "delay"
	st["P"] = "probe"; st["I"] = "incomplete" }
NR > 1 && $2 != "(incomplete)" {
	ip = $1; sub(/%.*/, "", ip)
	if (ip in mine) next
	perm = $4 == "permanent"
	print $3, "inet6", ip, $2, (perm ? "static" : "dynamic"),
	    ($6 ~ /R/ ? "router" : "-"), (perm || !($5 in st) ? "-" : st[$5])
}'
EOF
	sh nbs.sh | sort > nb.before
	atf_check -o save:nb "$(atf_get_srcdir)/ycollect" nb
	sh nbs.sh | sort > nb.after
	atf_check -o match:'^yang-cbor [0-9]+ bytes, the same back$' tail -1 nb
	sed '$d' nb | sort -o nb
	comm -12 nb.before nb.after > nb.both
	sort -u nb.before nb.after > nb.either
	comm -23 nb.both nb > nb.missing
	comm -23 nb nb.either > nb.extra
	atf_check -o empty cat nb.missing nb.extra

	# What the host sets for every interface (arcana-ip-deviations): its
	# sysctls, on each with IPv4 or IPv6; RAs' addresses the interface's
	# own flag, as ndp -i shows it.
	atf_check -o save:sys "$(atf_get_srcdir)/ycollect" ipsys
	f4=$(sysctl -n net.inet.ip.forwarding)
	f6=$(sysctl -n net.inet6.ip6.forwarding)
	sys6="dad=$(sysctl -n net.inet6.ip6.dad_count) temp=$(sysctl -n net.inet6.ip6.use_tempaddr) tvl=$(sysctl -n net.inet6.ip6.tempvltime) tpl=$(sysctl -n net.inet6.ip6.temppltime)"
	for i in $(ifconfig -l | tr ' ' '\n' | sort | uniq -u); do
		v4=-; v6=-; s6="dad=- temp=- tvl=- tpl=-"; g=-
		ifconfig "$i" | grep -q '^	inet ' && v4=$f4
		if ifconfig "$i" | grep -q '^	nd6 '; then
			v6=$f6; s6=$sys6
			ndp -i "$i" | grep -q '^Flags:.* accept_rtadv' && g=1 || g=0
		fi
		echo "$i fwd4=$v4 fwd6=$v6 $s6 global=$g" > exp
		grep "^$i " sys > got
		cmp -s exp got || atf_fail "$i: the host says $(cat exp), the collector $(cat got)"
	done
}

atf_test_case yang_jails
yang_jails_head()
{
	atf_set "descr" "the list operation's reply as arcana-jails has it" \
	    "every field, a running vnet jail's lne," \
	    "the cpu share in hundredths, through YANG-CBOR and back"
}
yang_jails_body()
{
	cat > want <<'EOF'
scope /etc/jail.conf
scope /etc/jail.conf.d/web.conf
conf-error /etc/jail.conf.d/bad.conf: line 3: syntax error
jail web state=0 jid=yes configured=1 scope=/etc/jail.conf.d/web.conf hostname=web.example path=/jails/web vnet=1 osrelease=15.0-RELEASE persist=yes securelevel=yes nproc=yes rss=yes cpu=yes interface=lo1 lne=web
  jid 7 nproc 12 rss 81920 cpu 346 securelevel 2
  ip4 lo1|192.0.2.10/24
  ip6 2001:db8::10
  param allow.raw_sockets 1
  param persist
  plugin bird
  plugin wireguard
jail db state=1 jid=- configured=1 scope=/etc/jail.conf hostname=- path=/jails/db vnet=1 osrelease=- persist=- securelevel=- nproc=- rss=- cpu=- interface=- lne=-
EOF
	"$(atf_get_srcdir)/yjails" > out
	atf_check -o match:'^yang-cbor [0-9]+ bytes, the same back$' cat out
	# Converted, and read back from YANG-CBOR, the same.
	atf_check -o file:want sh -c "sed -n '1,/^yang-cbor/p' out | sed '\$d'"
	atf_check -o file:want sh -c "sed -n '/^-- back\$/,\$p' out | sed 1d"
}

atf_test_case yang_hardware
yang_hardware_head()
{
	atf_set "descr" "a host's hardware as ietf-hardware has it (RFC" \
	    "8348): the chassis from SMBIOS, a CPU" \
	    "each with its temperature as a sensor, the disks; through" \
	    "YANG-CBOR and back"
}
yang_hardware_body()
{
	cat > hw.json <<'EOF'
{"chassis":{"maker":"Example Systems","product":"EX-1000","version":"1.2","serial":"EX123456","uuid":"4c4c4544-0042-3510-8051-b4c04f4e3332","bios":"2.14.1","os":"16.0-CURRENT"},"model":"Example CPU @ 2.00GHz","cpus":[452,null],"disks":[{"name":"nda0","descr":"Example NVMe 1TB","ident":"S5H9NX0N","rotation":"0","size":1000204886016},{"name":"ada0","descr":"Example HDD 4TB","ident":"WD-WX12","rotation":"7200","size":4000787030016},{"name":"vtbd0","ident":"BHYVE-1","size":58720256000}]}
EOF
	cat > want <<'EOF'
chassis chassis parent=- pos=-1 mfg=Example Systems model=EX-1000 serial=EX123456 hw=1.2 fw=2.14.1 sw=16.0-CURRENT uuid=4c4c4544-0042-3510-8051-b4c04f4e3332 fru=no descr=the host children=cpu0,cpu1,nda0,ada0,vtbd0
cpu0 cpu parent=chassis pos=0 mfg=- model=Example CPU @ 2.00GHz serial=- hw=- fw=- sw=- uuid=- fru=no descr=logical CPU 0 children=cpu0-temperature
cpu0-temperature sensor parent=cpu0 pos=0 mfg=- model=- serial=- hw=- fw=- sw=- uuid=- fru=- descr=the temperature of CPU 0 value=452 precision=1 type=8
cpu1 cpu parent=chassis pos=1 mfg=- model=Example CPU @ 2.00GHz serial=- hw=- fw=- sw=- uuid=- fru=no descr=logical CPU 1
nda0 storage-drive parent=chassis pos=0 mfg=- model=Example NVMe 1TB serial=S5H9NX0N hw=- fw=- sw=- uuid=- fru=yes descr=1.0 TB, solid state
ada0 storage-drive parent=chassis pos=1 mfg=- model=Example HDD 4TB serial=WD-WX12 hw=- fw=- sw=- uuid=- fru=yes descr=4.0 TB, 7200 rpm
vtbd0 storage-drive parent=chassis pos=2 mfg=- model=- serial=BHYVE-1 hw=- fw=- sw=- uuid=- fru=yes descr=59 GB
EOF
	"$(atf_get_srcdir)/yhw" hw.json > out || atf_fail "yhw failed"
	atf_check -o file:want sed '$d' out
	atf_check -o match:'^yang-cbor [0-9]+ bytes, the same back$' tail -1 out
}

atf_test_case yang_system
yang_system_head()
{
	atf_set "descr" "the kernel's modules and memory as arcana-kernel" \
	    "has them, through YANG-CBOR and back; the configuration of" \
	    "arcana-sysctl and arcana-kernel written in place:" \
	    "sysctl.conf's settings, rc.conf's kld_list"
}
yang_system_body()
{
	local y="$(atf_get_srcdir)/ysystem"

	cat > kernel.json <<'EOF'
{"files":[{"id":1,"name":"kernel","path":"/boot/kernel/kernel","refs":40,"size":34855640,"address":"0xffffffff80200000","modules":["if_lo","netlink"]},{"id":5,"name":"if_wg.ko","path":"/boot/kernel/if_wg.ko","refs":1,"size":86016,"address":"0xffffffff82a10000","modules":["wg"]}],"available":["aac","accf_data"],"kept":["if_wg","pf"],"memory":{"files":80888740,"kmem_size":25140678656,"kmem_map_size":7734583296,"kmem_map_free":17406095360,"malloc_total":632946880,"malloc":[{"name":"solaris","bytes":493063792,"count":1289305,"requests":550597237},{"name":"solaris","bytes":22530688,"count":446466,"requests":453687}],"zones":[{"name":"mbuf_cluster","bytes":2048000,"count":1000,"free":24,"size":2048,"requests":99999}]}}
EOF
	cat > want <<'EOF'
file 1 kernel path=/boot/kernel/kernel refs=40 size=34855640 address=0xffffffff80200000 modules=if_lo,netlink
file 5 if_wg.ko path=/boot/kernel/if_wg.ko refs=1 size=86016 address=0xffffffff82a10000 modules=wg
available aac
available accf_data
kept if_wg
kept pf
memory files=80888740 kmem-size=25140678656 map-size=7734583296 map-free=17406095360 malloc-total=632946880
malloc solaris bytes=493063792 count=1289305 requests=550597237
malloc solaris bytes=22530688 count=446466 requests=453687
zone mbuf_cluster bytes=2048000 free=24 size=2048
yang-cbor 318 bytes, the same back
EOF
	atf_check -o file:want "$y" kernel kernel.json
	# sysctl.conf: one changed in place, its comment kept; one no longer
	# wanted taken out; one new appended.
	printf '# Kept.\nnet.inet.ip.forwarding=1\nkern.randompid=1   # pids at random\nsecurity.bsd.see_other_uids=0\n' > sysctl.conf
	atf_check "$y" -s sysctl.conf net.inet.ip.forwarding=0 \
	    kern.randompid=1 vfs.zfs.arc_max=4294967296
	atf_check -o inline:'# Kept.
net.inet.ip.forwarding=0
kern.randompid=1   # pids at random
vfs.zfs.arc_max=4294967296
' cat sysctl.conf
	# kld_list: made, then none and taken out; the rest as it was.
	printf 'hostname="lab"\nkld_list="if_wg pf"\nsshd_enable="YES"\n' > rc.conf
	atf_check "$y" -k rc.conf if_wg pf dummynet
	atf_check -o inline:'hostname="lab"
kld_list="if_wg pf dummynet"
sshd_enable="YES"
' cat rc.conf
	atf_check "$y" -k rc.conf
	atf_check -o inline:'hostname="lab"
sshd_enable="YES"
' cat rc.conf
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

atf_test_case yang_firewall
yang_firewall_head()
{
	atf_set "descr" "the firewall as arcana-firewall has it:" \
	    "the ipfw read's kept rules, aliases, rc.conf, the rules" \
	    "with counters, dynamic rules, tables, NAT and dummynet; the kept" \
	    "file's text with its rules, other lines and aliases taken from" \
	    "it; a kernel trace's packets; through YANG-CBOR and back"
}
yang_firewall_body()
{
	local y="$(atf_get_srcdir)/yfw"

	cat > ipfw.json <<'EOT'
{"loaded":true,"enabled":true,"rules":[{"num":5,"pkts":12,"bytes":900,"set":0,"text":"skipto 500 ip from any to any out"},{"num":1001,"pkts":3,"bytes":180,"set":0,"text":"allow tcp from any to me6 22 in"},{"num":2000,"pkts":0,"bytes":0,"set":1,"text":"deny ip from any to any","disabled":true},{"num":65535,"pkts":99,"bytes":9999,"set":31,"text":"deny ip from any to any"}],"dynamic_total":2,"dynamic":[{"num":1001,"pkts":7,"bytes":560,"ttl":298,"kind":"STATE","flow":"tcp 2001:db8::9 51234 <-> 2001:db8::1 22 :default"}],"tables":[{"name":"T46","type":"addr","entries":[{"key":"10.0.0.0/8","value":"0"},{"key":"192.0.2.0/24","value":"0"}],"count":2}],"nat":["ipfw nat 1 config if em0 same_ports"],"pipes":[],"qos":{"pipes":[{"num":1,"bw":10000000,"delay":20,"burst":0,"slots":30,"plr":0.01,"mask":{"src":0,"dst":0,"src_port":0,"dst_port":0,"proto":0}}],"scheds":[{"num":1,"bw":10000000,"delay":20,"burst":0,"type":"WF2Q+","mask":{"src":24,"dst":0,"src_port":0,"dst_port":0,"proto":0},"queues":[2]}],"queues":[{"num":2,"sched":1,"weight":30,"pri":0,"slots":50,"plr":0}]},"verbose":true,"aliases":[{"name":"web","kind":"ports","value":"80 443"},{"name":"lan","kind":"addr","value":"10.0.0.0/8 192.0.2.0/24"}],"kept":[{"num":1001,"text":"allow tcp from any to me6 22 in"},{"num":1002,"text":"allow tcp from table(lan) to me 80,443 in","source":"allow tcp from $lan to me $web in"}],"other":["# the firewall","table lan create type addr"],"file":true,"path":"/usr/local/etc/arcana/ipfw.rules","rc":{"firewall_enable":"YES","firewall_script":"/usr/local/etc/arcana/ipfw.rules.sh"}}
EOT
	cat > want <<'EOT'
kept path=/usr/local/etc/arcana/ipfw.rules present=yes sha256=- text=0
rule 1001 allow tcp from any to me6 22 in
rule 1002 allow tcp from table(lan) to me 80,443 in <- allow tcp from $lan to me $web in
other # the firewall
other table lan create type addr
alias web ports 80 443
alias lan addr 10.0.0.0/8 192.0.2.0/24
rc enable=YES type=- script=/usr/local/etc/arcana/ipfw.rules.sh
state loaded=yes enabled=yes verbose=yes dynamic-total=2
rule 5 set=0 packets=12 octets=900 skipto 500 ip from any to any out
rule 1001 set=0 packets=3 octets=180 allow tcp from any to me6 22 in
rule 2000 set=1 packets=0 octets=0 disabled deny ip from any to any
rule 65535 set=31 packets=99 octets=9999 deny ip from any to any
dynamic 1001 packets=7 ttl=298 STATE tcp 2001:db8::9 51234 <-> 2001:db8::1 22 :default
table T46 type=addr count=2 10.0.0.0/8=0 192.0.2.0/24=0
nat ipfw nat 1 config if em0 same_ports
pipe 1 bw=10000000 delay=20 slots=30 plr=10000 mask=0/0:0/0/0
sched 1 bw=10000000 type=WF2Q+ queues=2 mask=24/0:0/0/0
queue 2 sched=1 weight=30 slots=50
yang-cbor 763 bytes, the same back
EOT
	atf_check -o file:want "$y" read ipfw.json
	# The kept file as ipfw-rules reads it: the rules, with the words
	# they were written in; the lines that are none; the aliases.
	cat > kept <<'EOT'
# the firewall
#arcana alias web ports 80 443
#arcana alias lan addr 10.0.0.0/8 192.0.2.0/24
table lan create type addr
add 01001 allow tcp from any to me6 22 in
#arcana add 01002 allow tcp from $lan to me $web in
add 01002 allow tcp from table(lan) to me 80,443 in
EOT
	cat > want <<'EOT'
kept path=- present=yes sha256=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef text=266
rule 1001 allow tcp from any to me6 22 in
rule 1002 allow tcp from table(lan) to me 80,443 in <- allow tcp from $lan to me $web in
other # the firewall
other table lan create type addr
alias web ports 80 443
alias lan addr 10.0.0.0/8 192.0.2.0/24
yang-cbor 562 bytes, the same back
EOT
	atf_check -o file:want "$y" kept kept \
	    0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
	cat > trace.json <<'EOT'
{"packets":[{"ms":12,"verdict":"pass","family":"inet6","source":"2001:db8::9","destination":"2001:db8::1","proto":6,"sport":51234,"dport":22,"rule":1001,"interface":"em0","direction":"in"},{"ms":40,"verdict":"deny","family":"inet","source":"10.0.0.2","destination":"10.0.0.1","proto":17,"sport":5678,"dport":5678,"rule":9100,"interface":"em0","direction":"in"}],"seconds":3,"limit":100}
EOT
	cat > want <<'EOT'
trace seconds=3 limit=100
packet ms=12 pass ipv6 2001:db8::9 -> 2001:db8::1 proto=6 51234->22 rule=1001 em0 in
packet ms=40 deny ipv4 10.0.0.2 -> 10.0.0.1 proto=17 5678->5678 rule=9100 em0 in
yang-cbor 117 bytes, the same back
EOT
	atf_check -o file:want "$y" trace trace.json
}

atf_test_case yang_troubleshoot
yang_troubleshoot_head()
{
	atf_set "descr" "path-check, traceroute and capture as" \
	    "arcana-troubleshoot has them: a packet's way at one host, its" \
	    "firewall's walks typed; a traceroute's hops; a capture's lines" \
	    "and pcap; through YANG-CBOR and back, and made the" \
	    "operations' JSON again"
}
yang_troubleshoot_body()
{
	local y="$(atf_get_srcdir)/yts"

	cat > path.json <<'EOT'
{"host":"labvm","addresses":[{"address":"10.1.0.1","prefixlen":24,"interface":"epair2b","fib":0,"up":true,"loopback":false},{"address":"10.3.0.1","prefixlen":24,"interface":"epair3a","fib":0,"up":true,"loopback":false}],"src":{"local":false,"connected":"epair2b"},"dst":{"local":false,"connected":"epair3a"},"forwarding":true,"ingress":{"interface":"epair2b","how":"by the route back to the source"},"route":{"to":"10.3.0.2","destination":"10.3.0.0","prefixlen":24,"gateway":"link#11","fib":"0","interface":"epair3a","flags":"U","metric":1,"weight":1},"neighbor":{"address":"10.3.0.2","state":"reachable"},"return":{"fib":0,"interface":"epair2b","gateway":"link#10","symmetric":true},"firewall":{"on":true,"in":{"verdict":"allow","rule":600,"text":"00600 allow tcp from 10.1.0.0/24 to any 22 in keep-state :default","keep_state":true,"walk":[{"rule":590,"text":"00590 check-state :default","how":"check-state :default: no state of it yet, on"},{"rule":600,"text":"00600 allow tcp from 10.1.0.0/24 to any 22 in keep-state :default","how":"decides"}],"uncertain":[{"text":"00550 deny ip from any to any uid 1001","because":"uid"}]},"out":{"verdict":"allow","rule":590,"text":"00590 check-state :default","by_state":true,"walk":[{"rule":590,"text":"00590 check-state :default","how":"decides: its state lets it by"}]},"reply_in":{"verdict":"allow","rule":590,"text":"00590 check-state :default","by_state":true,"walk":[{"rule":590,"text":"00590 check-state :default","how":"decides: its state lets it by"}]},"reply_out":{"verdict":"deny","rule":800,"text":"00800 deny tcp from any 22 to any","walk":[{"rule":800,"text":"00800 deny tcp from any 22 to any","how":"decides"}]}},"fib":0,"findings":[{"severity":"bad","what":"The firewall drops the reply going out by epair2b: rule 800 (00800 deny tcp from any 22 to any)"},{"severity":"info","what":"It goes out by epair3a"}]}
EOT
	cat > want <<'EOT'
host labvm forwarding=yes fib=0 delivered=-
address 10.1.0.1/24 epair2b fib=0 up=yes
address 10.3.0.1/24 epair3a fib=0 up=yes
source local=no connected=epair2b
destination local=no connected=epair3a
ingress epair2b (by the route back to the source)
route 10.3.0.0/24 via link#11 on epair3a fib=0 flags=U
neighbor 10.3.0.2 reachable
return fib=0 epair2b via link#10 symmetric=yes
firewall on=yes
in allow rule=600 by-state=- keep=yes setfib=-1 fwd=-
  590 check-state :default: no state of it yet, on
  600 decides
  ? 00550 deny ip from any to any uid 1001: uid
out allow rule=590 by-state=yes keep=- setfib=-1 fwd=-
  590 decides: its state lets it by
reply-in allow rule=590 by-state=yes keep=- setfib=-1 fwd=-
  590 decides: its state lets it by
reply-out deny rule=800 by-state=- keep=- setfib=-1 fwd=-
  800 decides
finding bad The firewall drops the reply going out by epair2b: rule 800 (00800 deny tcp from any 22 to any)
finding info It goes out by epair3a
yang-cbor 993 bytes, the same back
EOT
	atf_check -o file:want "$y" path path.json
	# Made the operation's JSON again, as the console makes it of the
	# output (ytsjson.c): the same, in pathcheck.c's order.
	atf_check -o file:path.json "$y" back-path path.json
	cat > tr.json <<'EOT'
{"address":"2001:db8::1","family":"inet6","hops":[{"ttl":1,"address":"2001:db8:1::1","rtt":0.412},{"ttl":2,"lost":true},{"ttl":3,"address":"2001:db8::1","rtt":12.5,"note":"!X"}],"reached":true}
EOT
	cat > want <<'EOT'
traceroute 2001:db8::1 ipv6 reached=yes
hop 1 2001:db8:1::1 rtt=412 note=- lost=-
hop 2 - rtt=-1 note=- lost=yes
hop 3 2001:db8::1 rtt=12500 note=!X lost=-
yang-cbor 77 bytes, the same back
EOT
	atf_check -o file:want "$y" traceroute tr.json
	atf_check -o inline:'{"address":"2001:db8::1","family":"inet6","hops":[{"ttl":1,"address":"2001:db8:1::1","rtt":0.412000},{"ttl":2,"lost":true},{"ttl":3,"address":"2001:db8::1","rtt":12.500000,"note":"!X"}],"reached":true}\n' "$y" back-traceroute tr.json
	cat > cap.json <<'EOT'
{"source":"em0","filter":"port 22","lines":["2026-10-15 12:00:00.000001 IP 10.0.0.2.51234 > 10.0.0.1.22: Flags [S]","2026-10-15 12:00:00.000200 IP 10.0.0.1.22 > 10.0.0.2.51234: Flags [S.]"],"packets":2,"limit":50,"seconds":10,"timed_out":true,"bytes":24,"pcap":"1MOyoQIABAAAAAAAAAAAAAAABAABAAAA"}
EOT
	cat > want <<'EOT'
capture em0 filter=port 22 packets=2 limit=50 seconds=10 timed-out=yes bytes=24 pcap=24 taken=yes
line 2026-10-15 12:00:00.000001 IP 10.0.0.2.51234 > 10.0.0.1.22: Flags [S]
line 2026-10-15 12:00:00.000200 IP 10.0.0.1.22 > 10.0.0.2.51234: Flags [S.]
yang-cbor 221 bytes, the same back
EOT
	atf_check -o file:want "$y" capture cap.json
	# In capture.c's order; without an interface, the sources alone.
	atf_check -o inline:'{"pcap":"1MOyoQIABAAAAAAAAAAAAAAABAABAAAA","bytes":24,"source":"em0","filter":"port 22","packets":2,"limit":50,"seconds":10,"timed_out":true,"lines":["2026-10-15 12:00:00.000001 IP 10.0.0.2.51234 > 10.0.0.1.22: Flags [S]","2026-10-15 12:00:00.000200 IP 10.0.0.1.22 > 10.0.0.2.51234: Flags [S.]"]}\n' "$y" back-capture cap.json
	echo '{"sources":["em0","lo0","ipfw100"]}' > src.json
	atf_check -o file:src.json "$y" back-capture src.json
}

atf_test_case yang_history
yang_history_head()
{
	atf_set "descr" "the history operation's reply as arcana-history has" \
	    "it: sampling and limits as configuration, the samples taken" \
	    "apart by the names of the interfaces, disks, jails and FEC" \
	    "relays, two of a second told apart; through" \
	    "YANG-CBOR and back"
}
yang_history_body()
{
	local y="$(atf_get_srcdir)/yhist"

	cat > hist.json <<'EOT'
{"limits":{"cpu":90,"mem":80,"swap":50},"rules":[{"kind":"net","name":"em0","limit":100000000,"over":false},{"kind":"jail-cpu","name":"web","limit":50,"over":true}],"racct":true,"step":5,"keep":720,"bytes":94560,"ncpu":12,"mem_total":25769803776,"swap_total":4294967296,"fields":["t","cpu","load","mem","swap","rx","tx","read","write"],"nets":["em0","em1"],"disks":["ada0"],"jails":["web"],"relays":["speederv2_c_wg0"],"samples":[[1791995110,12.5,0.42,8589934592,0,120000,34000,4096,8192,100000,30000,20000,4000,4096,8192,3.5,268435456,10000,7000],[1791995115,80.0,1.10,8600000000,1024,130000,35000,0,0,110000,31000,20000,4000,0,0,55.0,268435456,0,0],[1791995115,2.0,1.10,8600000000,1024,0,0,0,0,0,0,0,0,0,0,0,268435456,0,0]]}
EOT
	cat > want <<'EOT'
sampling step=5 keep=720 limits cpu=90 mem=80 swap=50
rule net em0 limit=100000000 over=no
rule jail-cpu web limit=50 over=yes
state bytes=94560 ncpu=12 memory=25769803776 swap=4294967296 racct=yes
interface em0
interface em1
disk ada0
jail web
relay speederv2_c_wg0
sample 2026-10-14T16:25:10Z cpu=125 load=42 memory=8589934592 swap=0 rx=120000 tx=34000 read=4096 written=8192 em0=100000/30000 em1=20000/4000 ada0=4096/8192 web=35/268435456 speederv2_c_wg0=10000+7000
sample 2026-10-14T16:25:15Z cpu=800 load=110 memory=8600000000 swap=1024 rx=130000 tx=35000 read=0 written=0 em0=110000/31000 em1=20000/4000 ada0=0/0 web=550/268435456 speederv2_c_wg0=0+0
sample 2026-10-14T16:25:15.01Z cpu=20 load=110 memory=8600000000 swap=1024 rx=0 tx=0 read=0 written=0 em0=0/0 em1=0/0 ada0=0/0 web=0/268435456 speederv2_c_wg0=0+0
yang-cbor 587 bytes, the same back
EOT
	atf_check -o file:want "$y" hist.json
}

atf_test_case yang_events
yang_events_head()
{
	atf_set "descr" "the events operation's reply as arcana-events has" \
	    "it: each kind an identity, its data the case of that kind," \
	    "typed; one event as the notification; through YANG-CBOR and" \
	    "back; every kind made the reply's JSON again as its source" \
	    "wrote it"
}
yang_events_body()
{
	local y="$(atf_get_srcdir)/yev"

	cat > ev.json <<'EOT'
{"last":12,"first":3,"kept":512,"events":[{"n":3,"t":1791995110,"kind":"route-add","data":{"destination":"10.9.0.0","gateway":"10.0.0.1","flags":"UGS","nhop":5,"metric":0,"weight":1,"fib":0,"prefixlen":16,"interface":"em0","source":"static"}},{"n":4,"t":1791995111,"kind":"routes","data":{"changed":40}},{"n":5,"t":1791995112,"kind":"link","jail":"r1","data":{"interface":"epair0b","up":true,"carrier":true,"mtu":1500}},{"n":6,"t":1791995113,"kind":"address-add","data":{"interface":"em0","address":"2001:db8::7","prefixlen":64}},{"n":7,"t":1791995114,"kind":"neigh","data":{"family":"inet","interface":"em0","address":"10.0.0.9","lladdr":"02:00:00:00:00:09","state":"reachable","router":false}},{"n":8,"t":1791995115,"kind":"threshold","data":{"what":"jail-cpu","name":"web","value":55,"limit":50,"over":true}},{"n":9,"t":1791995116,"kind":"kmsg","data":{"seq":41,"text":"em0: link state changed to UP"}},{"n":10,"t":1791995117,"kind":"sdwan-tunnel","data":{"id":"tvc-1","address":"10.202.0.2","state":"down","misses":3}},{"n":11,"t":1791995118,"kind":"sdwan-fault","data":{"type":"tunnel","severity":"Major","object":"tvc-1","by":"probe","description":"no reply","state":"set"}},{"n":12,"t":1791995119,"kind":"sdwan-security","data":{"seq":7,"rule":30010,"action":"Deny","src":"10.1.0.2:4000","dst":"10.3.0.2:22","iface":"em0","comment":"deny-ssh"}},{"n":13,"t":1791995120,"kind":"job","data":{"id":77,"title":"ipfw table T46 add","ok":false,"error":"ipfw: bad"}},{"n":14,"t":1791995121,"kind":"jail-state","data":{"jail":"web","state":"running","jid":5}},{"n":15,"t":1791995122,"kind":"crash","data":{"pid":812,"process":"nginx","jid":5,"jail":"web","uid":80,"signal":11,"core":false,"reason":"sugid process denied by kern.sugid_coredump"}},{"n":16,"t":1791995123,"kind":"conf","data":{"file":"/etc/rc.conf"}},{"n":17,"t":1791995124,"kind":"device","data":{"cdev":"md3","state":"created"}},{"n":18,"t":1791995125,"kind":"zfs","data":{"type":"pool_import","pool":"tank"}},{"n":19,"t":1791995126,"kind":"procs","data":{"started":4,"exited":3}},{"n":20,"t":1791995127,"kind":"monitor-threshold","data":{"id":"edge-b","metric":"delay","value":42.5,"threshold":40,"over":true,"interface":"gre0"}},{"n":21,"t":1791995128,"kind":"sdwan-ids","data":{"name":"sec-lan","time":"2026-10-14T16:25:28+0000","src":"10.0.0.9","sport":4444,"dst":"10.0.0.1","dport":23,"proto":"TCP","iface":"em0","sid":1000009,"rev":1,"signature":"LOCAL telnet","category":"","severity":2,"action":"allowed"}}]}
EOT
	cat > want <<'EOT'
events last=12 first=3 kept=512
3 2026-10-14T16:25:10Z route-add: route 10.9.0.0/16 via 10.0.0.1 on em0 fib=0 flags=UGS source=static nhop=5
4 2026-10-14T16:25:11Z routes: routes changed=40
5 2026-10-14T16:25:12Z link jail=r1: link epair0b up=yes carrier=yes mtu=1500
6 2026-10-14T16:25:13Z address-add: address em0 2001:db8::7/64
7 2026-10-14T16:25:14Z neigh: neighbor em0 10.0.0.9 lladdr=02:00:00:00:00:09 state=reachable router=no family=inet
8 2026-10-14T16:25:15Z threshold: threshold jail-cpu name=web value=55 limit=50 over=yes
9 2026-10-14T16:25:16Z kmsg: kmsg seq=41 text=em0: link state changed to UP more=0
10 2026-10-14T16:25:17Z sdwan-tunnel: tunnel tvc-1 10.202.0.2 down misses=3 by=- jail=-
11 2026-10-14T16:25:18Z sdwan-fault: fault tunnel Major tvc-1 by=probe set: no reply
12 2026-10-14T16:25:19Z sdwan-security: security seq=7 rule=30010 Deny 10.1.0.2:4000 -> 10.3.0.2:22 on em0 (deny-ssh)
13 2026-10-14T16:25:20Z job: job 77 ipfw table T46 add ok=no error=ipfw: bad
14 2026-10-14T16:25:21Z jail-state: jail-state web running jid=5
15 2026-10-14T16:25:22Z crash: crash pid=812 nginx jid=5 jail=web uid=80 signal=11 core=no reason=sugid process denied by kern.sugid_coredump
16 2026-10-14T16:25:23Z conf: conf /etc/rc.conf
17 2026-10-14T16:25:24Z device: device md3 created
18 2026-10-14T16:25:25Z zfs: zfs pool_import pool=tank
19 2026-10-14T16:25:26Z procs: procs started=4 exited=3
20 2026-10-14T16:25:27Z monitor-threshold: monitor edge-b delay value=42500 threshold=40000 over=yes on gre0
21 2026-10-14T16:25:28Z sdwan-ids: alert sec-lan sid=1000009 rev=1 10.0.0.9:4444 -> 10.0.0.1:23 TCP on em0 severity=2 allowed: LOCAL telnet
yang-cbor 1343 bytes, the same back
EOT
	atf_check -o file:want "$y" list ev.json
	# Each kind as its source writes it, there and back as the console
	# makes the events reply of the read (yevjson.c): the same but a
	# double's digits.
	cat > real.json <<'EOT'
{"last":40,"first":3,"kept":512,"events":[{"n":3,"t":1791995110,"kind":"route-add","data":{"destination":"198.51.100.0/24","gateway":"127.0.0.1","flags":"UGS","nhop":5,"mtu":1400,"interface-name":"lo0","metric":0,"weight":1,"fib":0,"prefixlen":24,"source":"127.0.0.1","path":1,"paths":2,"expire-time":"1791999999"}},{"n":4,"t":1791995111,"kind":"routes","data":{"changed":40}},{"n":5,"t":1791995112,"kind":"link","jail":"r1","data":{"interface":"epair0b","up":true,"carrier":true,"mtu":1500}},{"n":6,"t":1791995113,"kind":"address-add","data":{"interface":"em0","address":"2001:db8::7","prefixlen":64}},{"n":7,"t":1791995114,"kind":"neigh","data":{"family":"inet","address":"192.0.2.202","lladdr":"02:00:00:00:00:09","interface-name":"em0","state":"reachable","router":true,"next":1791995200}},{"n":8,"t":1791995115,"kind":"threshold","data":{"what":"jail-cpu","name":"web","value":55,"limit":50,"over":true}},{"n":9,"t":1791995115,"kind":"threshold","data":{"what":"mem","value":3,"limit":1,"over":true}},{"n":10,"t":1791995115,"kind":"threshold","data":{"what":"storage","name":"tank","limit":0,"over":false}},{"n":11,"t":1791995116,"kind":"kmsg","data":{"seq":41,"text":"em0: link state changed to UP"}},{"n":12,"t":1791995116,"kind":"kmsg","data":{"seq":62,"more":7}},{"n":13,"t":1791995117,"kind":"sdwan-tunnel","data":{"id":"jlo","address":"127.0.0.1","state":"up","misses":0,"jail":"arcw_sdj"}},{"n":14,"t":1791995117,"kind":"sdwan-tunnel","data":{"id":"t1","address":"100.64.0.1","interface":"gre100","state":"unknown","by":"bfd"}},{"n":15,"t":1791995117,"kind":"monitor","data":{"id":"lo","address":"127.0.0.1","state":"up","misses":0,"interface":"lo0"}},{"n":16,"t":1791995118,"kind":"sdwan-fault","data":{"type":"tunnel","severity":"Major","object":"tvc-1","by":"probe","description":"no reply","state":"set"}},{"n":17,"t":1791995118,"kind":"sdwan-fault","data":{"type":"ids","severity":"Cleared","object":"sw1","description":"Suricata sw1 runs again","state":"cleared"}},{"n":18,"t":1791995119,"kind":"sdwan-security","data":{"seq":7,"rule":30010,"action":"Deny","src":"10.1.0.2:4000","dst":"10.3.0.2:22","iface":"em0","comment":"deny-ssh"}},{"n":19,"t":1791995120,"kind":"job","data":{"id":77,"title":"ipfw table T46 add","ok":false,"error":"ipfw: bad"}},{"n":20,"t":1791995120,"kind":"job","data":{"id":78,"title":"x","ok":true}},{"n":21,"t":1791995121,"kind":"jail-state","data":{"jail":"web","state":"running","jid":5}},{"n":22,"t":1791995122,"kind":"crash","data":{"pid":812,"process":"nginx","jid":5,"jail":"web","uid":80,"signal":11,"core":false,"reason":"sugid process denied by kern.sugid_coredump"}},{"n":23,"t":1791995123,"kind":"conf","data":{"file":"/etc/rc.conf"}},{"n":24,"t":1791995124,"kind":"device","data":{"cdev":"md3","state":"created"}},{"n":25,"t":1791995125,"kind":"zfs","data":{"type":"pool_import","pool":"tank"}},{"n":26,"t":1791995126,"kind":"procs","data":{"started":4,"exited":3}},{"n":27,"t":1791995127,"kind":"monitor-threshold","data":{"id":"edge-b","metric":"delay","value":42.5,"threshold":40,"over":true,"interface":"gre0"}},{"n":28,"t":1791995128,"kind":"sdwan-ids","data":{"name":"sec-lan","time":"2026-10-14T16:25:28+0000","src":"10.0.0.9","sport":4444,"dst":"10.0.0.1","dport":23,"proto":"TCP","iface":"em0","sid":1000009,"rev":1,"signature":"LOCAL telnet","category":"","severity":2,"action":"allowed"}},{"n":29,"t":1791995129,"kind":"undo-failed","data":{"node":"/ietf-interfaces:interfaces","errno":5,"message":"why","report":"arcana-agent 0.1\n"}}]}
EOT
	cat > want <<'EOT'
{"last":40,"first":3,"kept":512,"events":[{"n":3,"t":1791995110,"kind":"route-add","data":{"destination":"198.51.100.0/24","gateway":"127.0.0.1","flags":"UGS","nhop":5,"mtu":1400,"interface-name":"lo0","metric":0,"weight":1,"fib":0,"prefixlen":24,"source":"127.0.0.1","path":1,"paths":2,"expire-time":"1791999999"}},{"n":4,"t":1791995111,"kind":"routes","data":{"changed":40}},{"n":5,"t":1791995112,"kind":"link","jail":"r1","data":{"interface":"epair0b","up":true,"carrier":true,"mtu":1500}},{"n":6,"t":1791995113,"kind":"address-add","data":{"interface":"em0","address":"2001:db8::7","prefixlen":64}},{"n":7,"t":1791995114,"kind":"neigh","data":{"family":"inet","address":"192.0.2.202","lladdr":"02:00:00:00:00:09","interface-name":"em0","state":"reachable","router":true,"next":1791995200}},{"n":8,"t":1791995115,"kind":"threshold","data":{"what":"jail-cpu","name":"web","value":55,"limit":50,"over":true}},{"n":9,"t":1791995115,"kind":"threshold","data":{"what":"mem","value":3,"limit":1,"over":true}},{"n":10,"t":1791995115,"kind":"threshold","data":{"what":"storage","name":"tank","limit":0,"over":false}},{"n":11,"t":1791995116,"kind":"kmsg","data":{"seq":41,"text":"em0: link state changed to UP"}},{"n":12,"t":1791995116,"kind":"kmsg","data":{"seq":62,"more":7}},{"n":13,"t":1791995117,"kind":"sdwan-tunnel","data":{"id":"jlo","address":"127.0.0.1","state":"up","misses":0,"jail":"arcw_sdj"}},{"n":14,"t":1791995117,"kind":"sdwan-tunnel","data":{"id":"t1","address":"100.64.0.1","interface":"gre100","state":"unknown","by":"bfd"}},{"n":15,"t":1791995117,"kind":"monitor","data":{"id":"lo","address":"127.0.0.1","state":"up","misses":0,"interface":"lo0"}},{"n":16,"t":1791995118,"kind":"sdwan-fault","data":{"type":"tunnel","severity":"Major","object":"tvc-1","by":"probe","description":"no reply","state":"set"}},{"n":17,"t":1791995118,"kind":"sdwan-fault","data":{"type":"ids","severity":"Cleared","object":"sw1","description":"Suricata sw1 runs again","state":"cleared"}},{"n":18,"t":1791995119,"kind":"sdwan-security","data":{"seq":7,"rule":30010,"action":"Deny","src":"10.1.0.2:4000","dst":"10.3.0.2:22","iface":"em0","comment":"deny-ssh"}},{"n":19,"t":1791995120,"kind":"job","data":{"id":77,"title":"ipfw table T46 add","ok":false,"error":"ipfw: bad"}},{"n":20,"t":1791995120,"kind":"job","data":{"id":78,"title":"x","ok":true}},{"n":21,"t":1791995121,"kind":"jail-state","data":{"jail":"web","state":"running","jid":5}},{"n":22,"t":1791995122,"kind":"crash","data":{"pid":812,"process":"nginx","jid":5,"jail":"web","uid":80,"signal":11,"core":false,"reason":"sugid process denied by kern.sugid_coredump"}},{"n":23,"t":1791995123,"kind":"conf","data":{"file":"/etc/rc.conf"}},{"n":24,"t":1791995124,"kind":"device","data":{"cdev":"md3","state":"created"}},{"n":25,"t":1791995125,"kind":"zfs","data":{"type":"pool_import","pool":"tank"}},{"n":26,"t":1791995126,"kind":"procs","data":{"started":4,"exited":3}},{"n":27,"t":1791995127,"kind":"monitor-threshold","data":{"id":"edge-b","metric":"delay","value":42.500000,"threshold":40,"over":true,"interface":"gre0"}},{"n":28,"t":1791995128,"kind":"sdwan-ids","data":{"name":"sec-lan","time":"2026-10-14T16:25:28+0000","src":"10.0.0.9","sport":4444,"dst":"10.0.0.1","dport":23,"proto":"TCP","iface":"em0","sid":1000009,"rev":1,"signature":"LOCAL telnet","category":"","severity":2,"action":"allowed"}},{"n":29,"t":1791995129,"kind":"undo-failed","data":{"node":"/ietf-interfaces:interfaces","errno":5,"message":"why","report":"arcana-agent 0.1\n"}}]}
EOT
	atf_check -o file:want "$y" back real.json
	cat > one.json <<'EOT'
{"n":16,"t":1791995123,"kind":"link-del","data":{"interface":"epair9a","up":false,"carrier":false,"mtu":1500}}
EOT
	atf_check -o inline:'16 2026-10-14T16:25:23Z link-del: link epair9a up=no carrier=no mtu=1500\nyang-cbor 54 bytes, the same back\n' \
	    "$y" one one.json
}

atf_test_case yang_plugins
yang_plugins_head()
{
	atf_set "descr" "BIRD, WireGuard and netgraph as arcana-bird," \
	    "arcana-wireguard and arcana-netgraph have them: birdc's" \
	    "protocols with a BGP neighbour's own and its channels, OSPF" \
	    "neighbours, BFD sessions, tables, routes, OSPF's areas and" \
	    "topology; wg show's interfaces and peers, keys only said to be" \
	    "there; ngctl's nodes and hooks; through YANG-CBOR and back"
}
yang_plugins_body()
{
	local y="$(atf_get_srcdir)/yplug"

	cat > bird.json <<'EOT'
{"status":["BIRD 3.1.2","Router ID is 10.0.0.1","Current server time is 2026-10-15 20:00:00.123","Daemon is up and running"],"protocols":[{"name":"device1","proto":"Device","table":"---","state":"up","since":"2026-10-15 19:00:00","info":""},{"name":"peer_as65002","proto":"BGP","table":"---","state":"up","since":"2026-10-15 19:00:05","info":"Established","description":"the other site","bgp-state":"Established","neighbor":"10.202.0.2","neighbor-as":"65002","local-as":"65001","neighbor-id":"10.0.0.2","source":"10.202.0.1","session":"external AS4","hold":"240/240","keepalive":"80/80","channels":[{"name":"ipv4","state":"UP","table":"master4","input-filter":"ACCEPT","output-filter":"ACCEPT","routes":"3 imported, 2 exported, 3 preferred","imported":3,"exported":2}]},{"name":"rpki1","proto":"RPKI","table":"---","state":"up","since":"2026-10-15 19:00:00","info":"Established","cache":"rpki.example.net","rpki-status":"Established","serial":"12","last-update":"2026-10-15 19:50:00"}],"ospf":[{"proto":"ospf1","router-id":"10.0.0.2","pri":"1","state":"Full/DR","dtime":"38.3","interface":"em1","address":"10.1.0.2"}],"bfd":[{"proto":"bfd1","address":"10.202.0.2","interface":"wg0","state":"Up","since":"2026-10-15 19:00:06","interval":"0.300","timeout":"1.000"}],"tables":[{"name":"master4","routes":5,"networks":5},{"name":"master6","routes":2,"networks":2}]}
EOT
	cat > want <<'EOT'
status BIRD 3.1.2
status Router ID is 10.0.0.1
status Current server time is 2026-10-15 20:00:00.123
status Daemon is up and running
protocol device1 Device table=--- up since=2026-10-15 19:00:00 info= description=-
protocol peer_as65002 BGP table=--- up since=2026-10-15 19:00:05 info=Established description=the other site
  bgp Established neighbor=10.202.0.2 as=65002 local-as=65001 id=10.0.0.2 source=10.202.0.1 session=external AS4 hold=240/240 keepalive=80/80 error=-
  channel ipv4 UP table=master4 in=ACCEPT out=ACCEPT routes=3 imported, 2 exported, 3 preferred imported=3 exported=2
protocol rpki1 RPKI table=--- up since=2026-10-15 19:00:00 info=Established description=-
  rpki cache=rpki.example.net status=Established serial=12 update=2026-10-15 19:50:00
ospf ospf1 10.0.0.2 pri=1 Full/DR dead=38.3 em1 10.1.0.2
bfd bfd1 10.202.0.2 wg0 Up since=2026-10-15 19:00:06 0.300/1.000
table master4 routes=5 networks=5
table master6 routes=2 networks=2
yang-cbor 686 bytes, the same back
EOT
	atf_check -o file:want "$y" bird bird.json
	cat > br.json <<'EOT'
{"routes":[{"table":"master4","prefix":"10.9.0.0/16","type":"unicast","protocol":"peer_as65002","from":"10.202.0.2","since":"2026-10-15 19:00:06","primary":true,"preference":"100","info":"AS65002i","nexthops":[{"via":"10.202.0.2","interface":"wg0"}],"attrs":["BGP.origin: IGP","BGP.as_path: 65002"]},{"table":"master4","prefix":"0.0.0.0/0","type":"unicast","protocol":"static1","since":"2026-10-15 19:00:00","primary":true,"preference":"200","nexthops":[{"via":"10.0.0.254","interface":"em0"}]}],"count":2}
EOT
	cat > want <<'EOT'
routes count=2 message=-
route master4 10.9.0.0/16 unicast peer_as65002 from=10.202.0.2 since=2026-10-15 19:00:06 primary=yes pref=100 info=AS65002i via 10.202.0.2 on wg0 [BGP.origin: IGP] [BGP.as_path: 65002]
route master4 0.0.0.0/0 unicast static1 from=- since=2026-10-15 19:00:00 primary=yes pref=200 info=- via 10.0.0.254 on em0
yang-cbor 245 bytes, the same back
EOT
	atf_check -o file:want "$y" bird-routes br.json
	cat > bo.json <<'EOT'
{"protocols":[{"name":"ospf1","areas":["0.0.0.0"],"topology":[{"area":"0.0.0.0","routers":[{"id":"10.0.0.1","links":[{"kind":"network","to":"10.1.0.2","metric":10},{"kind":"external","to":"0.0.0.0/0","metric2":10000}],"distance":0},{"id":"10.0.0.3","links":[],"unreachable":true}],"networks":[{"id":"10.1.0.2","routers":["10.0.0.1","10.0.0.2"],"dr":"10.0.0.2","distance":10}]}]}]}
EOT
	cat > want <<'EOT'
ospf ospf1 areas 0.0.0.0
  area 0.0.0.0
    router 10.0.0.1 distance=0
      network 10.1.0.2 metric=10 metric2=0
      external 0.0.0.0/0 metric=0 metric2=10000
    router 10.0.0.3 distance=0 unreachable
    network 10.1.0.2 dr=10.0.0.2 distance=10 10.0.0.1 10.0.0.2
EOT
	atf_check -o match:'^ospf ospf1 areas 0.0.0.0$' \
	    -o match:'yang-cbor [0-9]+ bytes, the same back' "$y" bird-ospf bo.json
	"$y" bird-ospf bo.json | sed '$d' > got
	atf_check -o file:want cat got
	cat > wg.json <<'EOT'
{"interfaces":[{"name":"wg0","private-key":true,"public-key":"xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=","listen-port":51820,"peers":[{"public-key":"TrMvSoP4jYQlY6RIzBgbssQqY3vxI2Pi+y71lOWWXX0=","preshared-key":false,"endpoint":"203.0.113.2:51820","allowed-ips":["10.202.0.2/32","fd00:5a::2/128"],"latest-handshake":1791995110,"rx":123456,"tx":654321,"keepalive":25},{"public-key":"gN65BkIKy1eCE9pP1wdc8ROUtkHLF2PfAqYdyYBz6EA=","preshared-key":true,"allowed-ips":["10.202.0.3/32"],"latest-handshake":0,"rx":0,"tx":0,"keepalive":0}]}],"now":1791995200}
EOT
	cat > want <<'EOT'
wireguard now=2026-10-14T16:26:40Z
interface wg0 private=yes public=xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg= port=51820
  peer TrMvSoP4jYQlY6RIzBgbssQqY3vxI2Pi+y71lOWWXX0= preshared=no endpoint=203.0.113.2:51820 handshake=2026-10-14T16:25:10Z rx=123456 tx=654321 keepalive=25 allowed=10.202.0.2/32,fd00:5a::2/128
  peer gN65BkIKy1eCE9pP1wdc8ROUtkHLF2PfAqYdyYBz6EA= preshared=yes endpoint=- handshake=- rx=0 tx=0 keepalive=0 allowed=10.202.0.3/32
yang-cbor 295 bytes, the same back
EOT
	atf_check -o file:want "$y" wireguard wg.json
	cat > ng.json <<'EOT'
{"nodes":[{"name":"em0","type":"ether","id":"00000001","hooks":[{"hook":"lower","peer":"ngbr0","peer-type":"bridge","peer-id":"00000005","peer-hook":"link0"}]},{"name":"ngbr0","type":"bridge","id":"00000005","hooks":[{"hook":"link0","peer":"em0","peer-type":"ether","peer-id":"00000001","peer-hook":"lower"},{"hook":"link1","peer":"ngeth0","peer-type":"eiface","peer-id":"00000007","peer-hook":"ether"}]}]}
EOT
	cat > want <<'EOT'
node 00000001 em0 ether
  hook lower -> ngbr0 bridge 00000005 link0
node 00000005 ngbr0 bridge
  hook link0 -> em0 ether 00000001 lower
  hook link1 -> ngeth0 eiface 00000007 ether
yang-cbor 174 bytes, the same back
EOT
	atf_check -o file:want "$y" netgraph ng.json
}

atf_test_case yang_host_agent
yang_host_agent_head()
{
	atf_set "descr" "the host, the agent and the jails' files as" \
	    "arcana-host, arcana-agent and arcana-jail-files have them: the" \
	    "host's facts, plugins as identities and stats, its trust store" \
	    "as read-certificates gives it;" \
	    "the agent's listeners and sessions, its TLS files, a" \
	    "configuration bundle and an apply's report, a repository's" \
	    "log; jail.conf.d's files; sshd's settings, host keys and" \
	    "users; through YANG-CBOR and back"
}
yang_host_agent_body()
{
	local y="$(atf_get_srcdir)/ymisc"

	cat > certs.json <<'EOT'
{"trusted":[{"file":"/etc/ssl/certs/abc123.0","subject":"CN=Example Root CA,O=Example,C=US","cn":"Example Root CA","org":"Example","country":"US","issuer":"CN=Example Root CA,O=Example,C=US","not_before":1600000000,"not_after":1900000000,"sha256":"aa11","key":"RSA 4096","ca":true,"self_signed":true,"local":"/usr/local/etc/ssl/certs/example.pem"}],"untrusted":[{"file":"/etc/ssl/untrusted/bad.0","subject":"CN=Bad CA","cn":"Bad CA","issuer":"CN=Bad CA","not_before":1600000000,"not_after":1700000000,"sha256":"bb22","key":"RSA 2048","ca":true,"self_signed":true}],"localbase":"/usr/local","added_dir":"/usr/local/etc/ssl/certs","distrusted_dir":"/usr/local/etc/ssl/untrusted","certctl":true,"now":1791995110}
EOT
	cat > want <<'EOT'
host labvm FreeBSD 16.0-CURRENT amd64 osreldate=1600000 ncpu=12 physmem=25769803776 boot=2026-10-14T15:00:00Z time=2026-10-14T16:25:10Z securelevel=-1 privileged=no
agent 0.123.0 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
plugin bird
plugin wireguard
stats cpu=123 load=42/50/55 memory=25769803776/8589934592/1073741824/16106127360 swap=4294967296/0
pool zroot size=107374182400 allocated=10737418240 free=96636764160 ONLINE
certificates localbase=/usr/local added=/usr/local/etc/ssl/certs distrusted=/usr/local/etc/ssl/untrusted certctl=yes now=2026-10-14T16:25:10Z
trusted /etc/ssl/certs/abc123.0 cn=Example Root CA org=Example country=US issuer=CN=Example Root CA,O=Example,C=US from=2020-09-13T12:26:40Z until=2030-03-17T17:46:40Z sha256=aa11 key=RSA 4096 ca=yes self=yes local=/usr/local/etc/ssl/certs/example.pem
untrusted /etc/ssl/untrusted/bad.0 cn=Bad CA org=- country=- issuer=CN=Bad CA from=2020-09-13T12:26:40Z until=2023-11-14T22:13:20Z sha256=bb22 key=RSA 2048 ca=yes self=yes local=-
yang-cbor 328 bytes, the same back
yang-cbor 454 bytes, the same back
EOT
	atf_check -o file:want "$y" host certs.json
	cat > transport.json <<'EOT'
{"listeners":[{"uri":"tcp://[::]:4434","transport":"tcp","up":true},{"uri":"sctp://[::]:4434","transport":"sctp","up":false,"error":"the kernel has no SCTP"},{"uri":"sctp://[::]:4435","transport":"sctp","up":true,"addresses":["2001:db8::1","192.0.2.1"],"also_error":"192.0.2.9: not here"},{"uri":"unix:/var/run/arcana-agent.sock","transport":"unix","up":true}],"sctp_also":"192.0.2.1","sctp":true,"sessions":[{"transport":"tcp","address":"[2001:db8::7]:51234","subject":"CN=console","since":1791995000},{"transport":"sctp","address":"[2001:db8::8]:51235","subject":"CN=console","since":1791995001,"local":["2001:db8::1","192.0.2.1"],"paths":[{"address":"2001:db8::8","state":"active","srtt_ms":3,"rto_ms":1000,"primary":true},{"address":"192.0.2.8","state":"unconfirmed","srtt_ms":0,"rto_ms":3000,"primary":false}]}],"seen":3,"time":1791995110}
EOT
	cat > want <<'EOT'
transport sctp=yes also=192.0.2.1 seen=3 time=2026-10-14T16:25:10Z
listener tcp://[::]:4434 tcp up=yes why=- also-why=-
listener sctp://[::]:4434 sctp up=no why=the kernel has no SCTP also-why=-
listener sctp://[::]:4435 sctp up=yes why=- also-why=192.0.2.9: not here 2001:db8::1 192.0.2.1
listener unix:/var/run/arcana-agent.sock unix up=yes why=- also-why=-
session tcp [2001:db8::7]:51234 CN=console since=2026-10-14T16:23:20Z
session sctp [2001:db8::8]:51235 CN=console since=2026-10-14T16:23:21Z local=2001:db8::1 local=192.0.2.1
path 2001:db8::8 active srtt=3 rto=1000 primary=yes
path 192.0.2.8 unconfirmed srtt=0 rto=3000 primary=no
yang-cbor 421 bytes, the same back
EOT
	atf_check -o file:want "$y" transport transport.json
	cat > tls.json <<'EOT'
{"cert":{"subject":"CN=labvm","issuer":"CN=Arcana CA","not_before":1790812800,"not_after":1822348800,"sha256":"cc33","chain":[{"subject":"CN=Arcana CA","issuer":"CN=Arcana CA","not_before":1767225600,"not_after":2082758400,"sha256":"dd44"}]},"ca":[{"subject":"CN=Arcana CA","issuer":"CN=Arcana CA","not_before":1767225600,"not_after":2082758400,"sha256":"dd44"}],"pending":false}
EOT
	cat > want <<'EOT'
certificate CN=labvm issuer=CN=Arcana CA from=2026-10-01T00:00:00Z until=2027-10-01T00:00:00Z sha256=cc33 chain=CN=Arcana CA
ca CN=Arcana CA issuer=CN=Arcana CA sha256=dd44
pending=no
yang-cbor 244 bytes, the same back
EOT
	atf_check -o file:want "$y" tls tls.json
	cat > bundle.json <<'EOT'
{"arcana":"host","format":1,"host":"labvm","agent":"0.122.0","taken":"2026-10-15T20:00:00Z","facts":{"arch":"amd64","release":"16.0-CURRENT","cpu":"AMD EPYC","ncpu":12,"memory":25769803776,"interfaces":[{"name":"vtnet0","driver":"vtnet","mac":"02:00:00:00:00:01"}],"disks":[{"name":"vtbd0","size":107374182400}]},"packages":[{"name":"bird3","origin":"net/bird3","version":"3.1.2"}],"files":[{"path":"/etc/rc.conf","mode":"0644","owner":"root","group":"wheel","text":"hostname=\"labvm\"\n"},{"path":"/usr/local/etc/wireguard/wg0.conf","mode":"0600","owner":"root","group":"wheel","secret":true}]}
EOT
	cat > want <<'EOT'
bundle host=labvm agent=0.122.0 taken=2026-10-15T20:00:00Z
facts amd64 16.0-CURRENT cpu=AMD EPYC ncpu=12 memory=25769803776
interface vtnet0 vtnet 02:00:00:00:00:01
disk vtbd0 107374182400
package bird3 net/bird3 3.1.2
file /etc/rc.conf mode=0644 root:wheel text=17 secret=no
file /usr/local/etc/wireguard/wg0.conf mode=0600 root:wheel text=0 secret=yes
yang-cbor 285 bytes, the same back
EOT
	atf_check -o file:want "$y" bundle bundle.json
	cat > apply.json <<'EOT'
{"mismatches":["interface em0 is not here"],"files":[{"path":"/etc/rc.conf","state":"changed","diff":"--- a\n+++ b\n"},{"path":"/etc/sysctl.conf","state":"same"},{"path":"/usr/local/etc/wireguard/wg0.conf","state":"withheld"}],"packages":[{"name":"bird3","origin":"net/bird3","version":"3.1.2"}],"backup":"/var/backups/arcana/config-20261015T200000","applied":true,"reboot":true}
EOT
	cat > want <<'EOT'
mismatch interface em0 is not here
file /etc/rc.conf changed diff=12
file /etc/sysctl.conf same diff=0
file /usr/local/etc/wireguard/wg0.conf withheld diff=0
package bird3
backup=/var/backups/arcana/config-20261015T200000 applied=yes reboot=yes
yang-cbor 186 bytes, the same back
EOT
	atf_check -o file:want "$y" apply apply.json
	cat > log.json <<'EOT'
[{"commit":"0785917d572e9cededae598fba95ed8f84992dd5","time":1791995110,"subject":"agent 0.122.0, console 0.183.2: BIRD, WireGuard and netgraph as YANG","body":"PLAN-SDN-YANG 3.1.8"},{"commit":"e71cf597a0bf46e0514d5f8ed904e19f8a77e4b7","time":1791990000,"subject":"agent 0.121.0","body":""}]
EOT
	cat > tags.json <<'EOT'
[{"name":"v0.1","time":1700000000,"message":"The first"}]
EOT
	cat > want <<'EOT'
head 0785917d572e9cededae598fba95ed8f84992dd5
commit 0785917d572e9cededae598fba95ed8f84992dd5 2026-10-14T16:25:10Z agent 0.122.0, console 0.183.2: BIRD, WireGuard and netgraph as YANG body=19
commit e71cf597a0bf46e0514d5f8ed904e19f8a77e4b7 2026-10-14T15:00:00Z agent 0.121.0 body=0
tag v0.1 The first 2023-11-14T22:13:20Z
yang-cbor 330 bytes, the same back
EOT
	atf_check -o file:want "$y" log \
	    0785917d572e9cededae598fba95ed8f84992dd5 log.json tags.json
	cat > jf.json <<'EOT'
{"defaults":{"path":"/etc/jail.conf.d/defaults.conf","text":"exec.clean;\n"},"dir":"/etc/jail.conf.d","templates":[{"name":"pkgbase","text":"path = \"/jails/$name\";\n"}],"jails":[{"name":"web","text":"web { }\n"}]}
EOT
	cat > want <<'EOT'
files /etc/jail.conf.d defaults=/etc/jail.conf.d/defaults.conf text=12
template pkgbase text=23
jail web text=8
yang-cbor 123 bytes, the same back
EOT
	atf_check -o file:want "$y" jail-files jf.json
	# sshd: the settings each with its values, the host keys with
	# their certificates (forever said as none), the users' keys.
	cat > sshd.json <<'EOT'
{"settings":{"permitrootlogin":["without-password"],"passwordauthentication":["no"],"port":["22","2222"]},"banner_text":"Welcome\n","host_keys":[{"path":"/etc/ssh/ssh_host_ed25519_key","type":"ED25519","bits":256,"fingerprint":"SHA256:abc","comment":"root@labvm","certificate":{"kind":"host","id":"labvm","principals":["labvm","labvm.example"],"valid_after":1791990000,"valid_before":-1,"ca":"SHA256:ca1"},"certificate_used":true},{"path":"/etc/ssh/ssh_host_rsa_key","type":"RSA","bits":3072,"fingerprint":"SHA256:def","comment":"","certificate_used":false}],"users":[{"name":"pouria","uid":1001,"home":"/home/bsdusr","shell":"/bin/sh","keys_file":"/home/bsdusr/.ssh/authorized_keys","keys":[{"type":"ED25519","fingerprint":"SHA256:k1","bits":256,"comment":"laptop","options":"restrict"}]}],"user_cas":["ssh-ed25519 AAAA ca"],"before_kept":true}
EOT
	cat > want <<'EOT'
setting permitrootlogin = without-password
setting passwordauthentication = no
setting port = 22 2222
from-file=- banner=8 before-kept=yes
host-key /etc/ssh/ssh_host_ed25519_key ED25519 256 SHA256:abc root@labvm used=yes cert host id=labvm after=2026-10-14T15:00:00Z before=- ca=SHA256:ca1 principals=labvm,labvm.example
host-key /etc/ssh/ssh_host_rsa_key RSA 3072 SHA256:def  used=no
user pouria uid=1001 home=/home/bsdusr shell=/bin/sh keys=/home/bsdusr/.ssh/authorized_keys
  key SHA256:k1 ED25519 256 laptop options=restrict
user-ca ssh-ed25519 AAAA ca
yang-cbor 439 bytes, the same back
EOT
	atf_check -o file:want "$y" sshd sshd.json
}

atf_test_case yang_sdwan
yang_sdwan_head()
{
	atf_set "descr" "the probes and the SD-WAN edge as arcana-probe and" \
	    "arcana-sdwan have them: the targets with their thresholds, what" \
	    "the probes have seen with each sample taken apart; the rules," \
	    "the steer, the instances the setters keep, and back as the JSON" \
	    "they take; the edge's state: rules, steer, BIRD, DHCP, DNS," \
	    "proxy, ClamAV, IDS, the record, keys and faults; through" \
	    "YANG-CBOR and back"
}
yang_sdwan_body()
{
	local y="$(atf_get_srcdir)/ysd"

	# Each edge's targets, links and monitors, as the agent keeps them,
	# and back as its setters take them.
	cat > targets.json <<'EOT'
{"edges":[{"jail":"","targets":[{"id":"tvc-1","address":"10.202.0.2","fib":1,"interval":100,"size":64,"count":0,"dscp":46,"down":3,"up":3,"timeout":1000,"eval":1000,"history":3600,"report":5,"tca":{"delay":50,"ipdv":10,"loss":0.01,"damping":2}},{"id":"tvc-2","address":"fd00:5a::2"}],"links":[{"id":"uni-1","interface":"em1","role":"uni"}],"monitors":[{"id":"ov-gre0","interface":"gre0","address":"10.255.0.2","fib":2,"eval":10000}]},{"jail":"gateway","targets":[{"id":"tvc-1","address":"10.202.0.1"}]}]}
EOT
	cat > want <<'EOT'
target tvc-1 10.202.0.2 fib=1 interval=100 size=64 count=0 dscp=46 down=3 up=3 timeout=1000 eval=1000 history=3600 report=5 tca delay=50000 ipdv=10000 loss=10000 damping=2
target tvc-2 fd00:5a::2 fib=0 interval=0 size=0 count=0 dscp=0 down=0 up=0 timeout=0 eval=0 history=0 report=0
link uni-1 em1 uni
monitor ov-gre0 gre0 10.255.0.2 fib=2 eval=10000
set {"targets":[{"id":"tvc-1","address":"10.202.0.2","count":0,"report":5,"fib":1,"interval":100,"size":64,"dscp":46,"down":3,"up":3,"timeout":1000,"eval":1000,"history":3600,"tca":{"delay":50.0,"ipdv":10.0,"loss":0.010000,"damping":2}},{"id":"tvc-2","address":"fd00:5a::2"}],"links":[{"id":"uni-1","interface":"em1","role":"uni"}]}
set {"jail":"","targets":[{"id":"ov-gre0","interface":"gre0","address":"10.255.0.2","fib":2,"eval":10000}]}
jail gateway
target tvc-1 10.202.0.1 fib=0 interval=0 size=0 count=0 dscp=0 down=0 up=0 timeout=0 eval=0 history=0 report=0
set {"jail":"gateway","targets":[{"id":"tvc-1","address":"10.202.0.1"}],"links":[]}
EOT
	atf_check -o save:got "$y" targets targets.json
	atf_check -o match:'yang-cbor [0-9]+ bytes, the same back' cat got
	sed '$d' got > got2
	atf_check -o file:want cat got2
	cat > probes.json <<'EOT'
{"targets":[{"id":"tvc-1","address":"10.202.0.2","family":"inet","fib":1,"state":"up","since":1791995000,"interval":100,"size":64,"eval":1000,"dscp":46,"sent":12000,"received":11990,"misses":0,"last_rtt":1.234,"now":{"sent":5,"recv":5,"delay":0.6,"ipdv":0.05,"loss":0,"age":512.3},"samples":[[1791995100,0.617,0.052,0.0,0.5,0.9,10,10],[1791995101,0.7,0.1,0.1,0.5,1.2,10,9]],"kept":2},{"id":"tvc-2","address":"fd00:5a::2","family":"inet6","fib":0,"state":"error","error":"no route","since":1791995000,"interval":100,"size":64,"eval":1000,"dscp":0,"sent":0,"received":0,"misses":0,"last_rtt":0,"samples":[],"kept":0}],"time":1791995110,"probing":true}
EOT
	cat > want <<'EOT'
probing=yes time=2026-10-14T16:25:10Z
target tvc-1 10.202.0.2 ipv4 fib=1 up error=- since=2026-10-14T16:23:20Z interval=100 size=64 eval=1000 dscp=46 sent=12000 received=11990 misses=0 last-rtt=1234 kept=2
  now sent=5 received=5 delay=600 ipdv=50 loss=0 age=512300
  sample 2026-10-14T16:25:00Z delay=617 ipdv=52 loss=0 min=500 max=900 sent=10 received=10
  sample 2026-10-14T16:25:01Z delay=700 ipdv=100 loss=100000 min=500 max=1200 sent=10 received=9
target tvc-2 fd00:5a::2 ipv6 fib=0 error error=no route since=2026-10-14T16:23:20Z interval=100 size=64 eval=1000 dscp=0 sent=0 received=0 misses=0 last-rtt=0 kept=0
yang-cbor 356 bytes, the same back
EOT
	atf_check -o file:want "$y" probes probes.json
	# The rules as sdwan.c keeps them, each in its place (ipfw lets
	# rules share a number), and back as its setter takes them.
	cat > rules.json <<'EOT'
{"set":30,"tables":[{"name":"sw1_zone","valtype":"legacy","entries":[["10.1.0.0/24","1"],["10.2.0.0/24","2"]]},{"name":"sw1_p1","valtype":"ipv4","entries":[{"prefix":"10.3.0.0/24","value":"10.202.0.2"}]}],"objects":["pipe 1 config bw 10Mbit/s","queue 2 config pipe 1 weight 30"],"rules":["00100 skipto 999 ip from any to any not recv vtnet1","00110 setfib 1 ip from table(sw1_zone) to any",{"number":120,"text":"fwd tablearg ip from any to table(sw1_p1)"},"00110 count ip from any to any"]}
EOT
	cat > want <<'EOT'
rules set=30
table sw1_zone legacy 10.1.0.0/24=1 10.2.0.0/24=2
table sw1_p1 ipv4 10.3.0.0/24=10.202.0.2
object pipe 1 config bw 10Mbit/s
object queue 2 config pipe 1 weight 30
rule 0: 100 skipto 999 ip from any to any not recv vtnet1
rule 1: 110 setfib 1 ip from table(sw1_zone) to any
rule 2: 120 fwd tablearg ip from any to table(sw1_p1)
rule 3: 110 count ip from any to any
set {"set":30,"tables":[{"name":"sw1_zone","valtype":"legacy","entries":[["10.1.0.0/24","1"],["10.2.0.0/24","2"]]},{"name":"sw1_p1","valtype":"ipv4","entries":[["10.3.0.0/24","10.202.0.2"]]}],"objects":["pipe 1 config bw 10Mbit/s","queue 2 config pipe 1 weight 30"],"rules":["100 skipto 999 ip from any to any not recv vtnet1","110 setfib 1 ip from table(sw1_zone) to any","120 fwd tablearg ip from any to table(sw1_p1)","110 count ip from any to any"]}
emptied {"set":30,"tables":[],"objects":[],"rules":[]}
yang-cbor 351 bytes, the same back
EOT
	atf_check -o file:want "$y" rules rules.json
	# The steering, with the breakout's routes.
	cat > steer.json <<'EOT'
{"entries":[{"table":"sw1_p1","prefix":"10.3.0.0/24","candidates":[{"id":"tvc-1","via":"10.202.0.2"},{"id":"tvc-2","via":"10.203.0.2"}]}],"routes":[{"fib":2,"destination":"0.0.0.0/0","candidates":[{"id":"bo:a-inet","via":"192.0.2.254"}]}]}
EOT
	cat > want <<'EOT'
entry sw1_p1 10.3.0.0/24: tvc-1 via 10.202.0.2 tvc-2 via 10.203.0.2
set {"entries":[{"table":"sw1_p1","prefix":"10.3.0.0/24","candidates":[{"id":"tvc-1","via":"10.202.0.2"},{"id":"tvc-2","via":"10.203.0.2"}]}],"routes":[{"fib":2,"destination":"0.0.0.0/0","candidates":[{"id":"bo:a-inet","via":"192.0.2.254"}]}]}
yang-cbor 112 bytes, the same back
EOT
	atf_check -o file:want "$y" steer steer.json
	# An edge that is a vnet jail: its entry's, back with its jail;
	# the state's edges, one whose ipfw could not be read.
	printf '%s\n' '{"jail":"gateway","set":30,"tables":[],"rules":["00500 count ip from any to any"]}' > jr.json
	atf_check -o match:'^rule 0: 500 count ip from any to any$' \
	    -o match:'^set \{"jail":"gateway","set":30,"tables":\[\],"objects":\[\],"rules":\["500 count ip from any to any"\]\}$' \
	    -o match:'^emptied \{"jail":"gateway","set":30,"tables":\[\],"objects":\[\],"rules":\[\]\}$' \
	    -o match:'the same back' "$y" rules jr.json gateway
	printf '%s\n' '{"jail":"gateway","entries":[{"table":"sw1_p1","prefix":"10.3.0.0/24","candidates":[{"id":"tvc-1","via":"10.202.0.2"}]}]}' > js.json
	atf_check -o match:'^set \{"jail":"gateway","entries":' -o match:'the same back' \
	    "$y" steer js.json gateway
	printf '%s\n' '{"targets":[{"id":"tvc-1","address":"10.202.0.2","family":"inet","jail":"gateway","fib":0,"state":"up","since":1791995000,"samples":[],"kept":0}],"time":1791995110,"probing":true}' > jp.json
	atf_check -o match:'^  jail gateway$' -o match:'the same back' "$y" probes jp.json
	printf '%s\n' '{"rules":{"set":0,"rules":0,"tables":[],"objects":0,"counters":[]},"steer":[],"steered":false,"edges":[{"jail":"gateway","rules":{"set":30,"rules":1,"tables":["sw1_p1"],"objects":0,"counters":[]},"steer":[{"table":"sw1_p1","prefix":"10.3.0.0/24","chosen":0,"candidates":[{"id":"tvc-1","via":"10.202.0.2","state":"up"}]}],"steered":true},{"jail":"down","error":"jail down is not running"}]}' > je.json
	atf_check -o match:'^edge gateway set=30 rules=1 tables=1 steered=yes sw1_p1/10.3.0.0/24:1$' \
	    -o match:'^edge down steered=no error=jail down is not running$' \
	    -o match:'the same back' "$y" state je.json
	# The instances: the form, JSON text in the module, an object again
	# for the setter.
	cat > inst.json <<'EOT'
{"jail":"gateway","instances":[{"name":"svc1","fib":1,"host":"edge-a","spec":{"router_id":"10.0.0.1","bfd":true}}]}
EOT
	cat > want <<'EOT'
instance svc1 fib=1 host=edge-a spec={"router_id":"10.0.0.1","bfd":true}
set {"jail":"gateway","instances":[{"name":"svc1","fib":1,"host":"edge-a","spec":{"router_id":"10.0.0.1","bfd":true}}]}
yang-cbor 60 bytes, the same back
EOT
	atf_check -o file:want "$y" bird inst.json gateway
	# The proxies and the IDS: SD-WAN's and the Security section's
	# (sec-) in one list, each group's set apart.
	cat > proxy.json <<'EOT'
{"instances":[{"name":"svc1","fib":1,"mode":"inspect","host":"edge-a","spec":{"flavor":"sdwan","zones":[]},"lists":{"zone-block":"bad.example\n"}},{"name":"sec-web","fib":0,"mode":"sni","spec":{"listen":["10.1.0.1"]}}]}
EOT
	cat > want <<'EOT'
proxy svc1 fib=1 mode=inspect host=edge-a spec={"flavor":"sdwan","zones":[]} list zone-block=12
proxy sec-web fib=0 mode=sni host=- spec={"listen":["10.1.0.1"]}
set {"instances":[{"name":"svc1","fib":1,"mode":"inspect","host":"edge-a","lists":{"zone-block":"bad.example\n"},"spec":{"flavor":"sdwan","zones":[]}}]}
set {"group":"security","instances":[{"name":"sec-web","fib":0,"mode":"sni","lists":{},"spec":{"listen":["10.1.0.1"]}}]}
yang-cbor 130 bytes, the same back
EOT
	atf_check -o file:want "$y" proxy proxy.json
	cat > ids.json <<'EOT'
{"instances":[{"name":"svc1","interfaces":["vtnet1","vtnet2"],"conf":"%YAML 1.1\n","rules":"alert tcp any any -> any 23 (msg:\"telnet\"; sid:1;)\n","divert":8000},{"name":"sec-lan","host":"edge-a","interfaces":["em0"],"capture":"netmap","offload":false,"lua":{"a.lua":"return 1\n"},"plugins":["/usr/local/lib/x.so"],"stopped":true,"thresholds":"suppress gen_id 1, sig_id 1\n","spec":{"home":["any"]}}]}
EOT
	cat > want <<'EOT'
ids svc1 divert=8000 conf=10 rules=51 interfaces=vtnet1,vtnet2 host=- capture=- offload=- stopped=- thresholds=0 lua=0 plugins=0 spec=-
ids sec-lan divert=0 conf=0 rules=0 interfaces=em0 host=edge-a capture=netmap offload=no stopped=yes thresholds=28 lua=1 plugins=1 spec={"home":["any"]}
set {"instances":[{"name":"svc1","interfaces":["vtnet1","vtnet2"],"divert":8000,"rules":"alert tcp any any -> any 23 (msg:\"telnet\"; sid:1;)\n","conf":"%YAML 1.1\n"}]}
set {"group":"security","instances":[{"name":"sec-lan","host":"edge-a","interfaces":["em0"],"capture":"netmap","offload":false,"lua":{"a.lua":"return 1\n"},"plugins":["/usr/local/lib/x.so"],"stopped":true,"thresholds":"suppress gen_id 1, sig_id 1\n","spec":{"home":["any"]}}]}
yang-cbor 226 bytes, the same back
EOT
	atf_check -o file:want "$y" ids ids.json
	# The state, all of it.
	cat > state.json <<'EOT'
{"targets":[],"probing":false,"time":1791995110,"rules":{"set":30,"rules":3,"tables":[{"name":"sw1_zone","count":2}],"objects":2,"counters":[{"rule":100,"pkts":12,"bytes":900,"text":"skipto 999 ip from any to any not recv vtnet1"}]},"steer":[{"table":"sw1_p1","prefix":"10.3.0.0/24","chosen":0,"candidates":[{"id":"tvc-1","via":"10.202.0.2","state":"up","bfd":"up"},{"id":"tvc-2","via":"10.203.0.2","state":"not probed"}]}],"steered":true,"routes":[{"fib":2,"destination":"0.0.0.0/0","chosen":0,"candidates":[{"id":"bo:a-inet","via":"192.0.2.254","state":"down"}]}],"bird":[{"name":"svc1","fib":1,"jail":"gateway","running":true,"protocols":[{"name":"peer1","proto":"BGP","state":"up","info":"Established"}],"bfd":[{"address":"10.202.0.2","interface":"wg0","state":"up","since":"2026-10-15 19:00:06"}]}],"dhcp":[{"name":"svc1","fib":1,"running":true,"leases":[{"expires":1792081510,"id":"02:00:00:00:00:09","address":"10.1.0.50","name":"laptop"}]}],"dns":[{"name":"svc1","fib":1,"running":false,"tls_cert":"-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"}],"proxy":[{"name":"svc1","fib":1,"mode":"inspect","running":true,"icap":true,"ca":"-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"}],"clamav":{"databases":[{"name":"main","file":"/var/db/clamav/main.cvd","built":"16 Sep 2021","version":62,"signatures":6647427}],"freshclam":true,"conf":true,"mirrors":["database.clamav.net"],"log":["ClamAV update process started"]},"ids":[{"name":"svc1","interfaces":["vtnet1"],"mode":"prevent","divert":8000,"running":true,"alerts_seen":4,"alerts":[{"name":"svc1","time":"2026-10-15T19:30:00.123456+0000","src":"10.1.0.50","sport":4000,"dst":"10.3.0.2","dport":23,"proto":"TCP","iface":"vtnet1","sid":1,"rev":2,"signature":"telnet","category":"","severity":2,"action":"blocked"}],"stats":{"fields":["t","pkts"],"series":[[1791995100,10],[1791995110,20]],"flows":{"http":7}},"capture":"divert","pcaps":[{"path":"/x/log.pcap.1791995000","size":24,"at":1791995000,"from":1791995000}],"captures":[],"replay":{"file":"a.pcap","alerts":1},"offload":{"vtnet1":["rxcsum","tso4"]}}],"ids_build":{"version":"8.0.7","lua":true,"ipfw":true},"ids_host":{"ncpu":4,"ndomains":1,"irqs":[{"irq":20,"name":"vtnet1:rxq0","cpus":"0-3"}]},"ids_ruleset":{"path":"/var/lib/suricata/rules/suricata.rules","at":1791990000,"size":1024},"record":{"count":7,"seq":7,"untold":1,"last":[{"t":1791995119,"seq":7,"rule":30010,"action":"Deny","src":"10.1.0.2:4000","dst":"10.3.0.2:22","iface":"vtnet1","comment":"deny-ssh"}]},"keys":[{"interface":"ipsec0","public":"AAAA","next":"BBBB","keyed_at":1791990000,"lifetime":86400,"spi_in":1001,"spi_out":1002,"pending":true}],"faults":[{"t":1791995118,"type":"tunnel","severity":"Major","object":"tvc-2","by":"probe","description":"no reply","cleared":false,"compressed":true}]}
EOT
	cat > want <<'EOT'
rules set=30 rules=3 objects=2
  table sw1_zone count=2
  counter 100 packets=12 octets=900 skipto 999 ip from any to any not recv vtnet1
steered=yes
steer sw1_p1 10.3.0.0/24 chosen=0: tvc-1 via 10.202.0.2 up bfd=up tvc-2 via 10.203.0.2 not-probed bfd=-
route fib=2 0.0.0.0/0 chosen=0: bo:a-inet down
bird svc1 fib=1 running=yes jail=gateway
  protocol peer1 BGP up Established
  bfd 10.202.0.2 wg0 up since=2026-10-15 19:00:06
dhcp svc1 fib=1 running=yes
  lease 2026-10-15T16:25:10Z 02:00:00:00:00:09 10.1.0.50 laptop
dns svc1 fib=1 running=no tls-cert=59
proxy svc1 fib=1 running=yes mode=inspect icap=yes ca=59
ids svc1 prevent divert=8000 running=yes seen=4
  alert 2026-10-15T19:30:00.123456+0000 telnet 10.1.0.50:4000 -> 10.3.0.2:23 TCP
  stats fields=2 series=2 flows={"http":7}
  pcap /x/log.pcap.1791995000 size=24 at=2026-10-14T16:23:20Z
  offload vtnet1 2
  replay {"file":"a.pcap","alerts":1}
ids-build 8.0.7 lua=yes ipfw=yes
ids-host ncpu=4 ndomains=1 irqs=1
ids-ruleset /var/lib/suricata/rules/suricata.rules size=1024 at=2026-10-14T15:00:00Z
clamav databases=1 freshclam=yes mirrors=1 log=1
record count=7 seq=7
  2026-10-14T16:25:19Z 7 rule=30010 Deny 10.1.0.2:4000 -> 10.3.0.2:22 vtnet1 (deny-ssh)
key ipsec0 public=AAAA next=BBBB at=2026-10-14T15:00:00Z lifetime=86400 spi=1001/1002 next-spi=0 pending=yes
fault 2026-10-14T16:25:18Z tunnel Major was=- tvc-2 by=probe cleared=no at=-: no reply
yang-cbor 1330 bytes, the same back
EOT
	atf_check -o file:want "$y" state state.json
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

atf_test_case yang_log
yang_log_head()
{
	atf_set "descr" "the log operation's replies as arcana-log has" \
	    "them, a line's facility and severity (names or numbers)" \
	    "ietf-syslog's; syslog.conf and newsyslog.conf as ietf-syslog," \
	    "what it cannot hold said; through YANG-CBOR and back," \
	    "committed as they read, nothing changed"
}
yang_log_body()
{
	local y="$(atf_get_srcdir)/ylog"

	cat > files.json <<'EOF'
{"name":"messages","files":[{"name":"auth.log","size":4120,"mtime":1791990000},{"name":"messages","size":88211,"mtime":1791995110},{"name":"messages.0.bz2","size":9100,"mtime":1791900000,"packed":true}],"lines":[],"size":88211,"position":88211}
EOF
	cat > want <<'EOF'
directory /var/log
file auth.log size=4120 modified=2026-10-14T15:00:00Z packed=-
file messages size=88211 modified=2026-10-14T16:25:10Z packed=-
file messages.0.bz2 size=9100 modified=2026-10-13T14:00:00Z packed=yes
yang-cbor 134 bytes, the same back
EOF
	atf_check -o file:want "$y" files files.json
	# syslogd -vv's "facility.level", -v's numbers: security is RFC
	# 5424's audit.  The files of the directory read with the lines.
	cat > read.json <<'EOF'
{"name":"messages","files":[{"name":"messages","size":88211,"mtime":1791995110}],"lines":[{"time":"Oct 14 12:00:01","level":"auth.info","host":"labvm","tag":"sshd","pid":"812","text":"Accepted publickey for root"},{"time":"Oct 14 12:00:02","level":"security.warn","host":"labvm","tag":"kernel","text":"ipfw: 100 Deny"},{"time":"Oct 14 12:00:03","host":"labvm","text":"-- MARK --"},{"text":"a line of no form"},{"time":"Oct 14 12:00:04","level":"16.3","host":"labvm","tag":"app","text":"local0's"}],"size":88211,"position":88211,"rotated":true}
EOF
	cat > want <<'EOF'
name messages size=88211 position=88211 rotated=yes
line time=Oct 14 12:00:01 host=labvm facility=auth severity=info tag=sshd pid=812 seq=-1 seen=- text=Accepted publickey for root
line time=Oct 14 12:00:02 host=labvm facility=audit severity=warning tag=kernel pid=- seq=-1 seen=- text=ipfw: 100 Deny
line time=Oct 14 12:00:03 host=labvm facility=- severity=- tag=- pid=- seq=-1 seen=- text=-- MARK --
line time=- host=- facility=- severity=- tag=- pid=- seq=-1 seen=- text=a line of no form
line time=Oct 14 12:00:04 host=labvm facility=local0 severity=error tag=app pid=- seq=-1 seen=- text=local0's
file messages size=88211 modified=2026-10-14T16:25:10Z
yang-cbor 304 bytes, the same back
EOF
	atf_check -o file:want "$y" read read.json
	cat > dmesg.json <<'EOF'
{"name":"@dmesg","lines":[{"seq":41,"text":"em0: link state changed to UP"},{"seq":42,"seen":1791995110,"text":"epair0a: Ethernet address: 02:00:00:00:00:0a"}],"position":42}
EOF
	atf_check -o match:'^line .* seq=42 seen=2026-10-14T16:25:10Z ' \
	    -o match:'same back' "$y" read dmesg.json

	mkdir syslog.d
	cat > syslog.conf <<'EOF'
*.err;kern.warning;auth.notice;mail.crit		/dev/console
*.notice;authpriv.none;kern.debug;lpr.info;mail.crit;news.err	/var/log/messages
security.*					/var/log/security
auth.info;authpriv.info				/var/log/auth.log
mail.info					/var/log/maillog
cron.*						-/var/log/cron
*.=debug					/var/log/debug.log
local0.*					@logs.example.net:5514
local1.*					@[2001:db8::1]
local5.*					@192.0.2.9
!-devd
daemon.info					/var/run/rc.log
!*
*.emerg						*
local2.<info					/var/log/l2
local3.*					|exec /usr/bin/logger
mark.*						/var/log/marks
:msg, contains, "x"				/var/log/x
include	syslog.d
EOF
	echo 'devd.* /var/log/devd.log' > syslog.d/devd.conf
	echo 'local4.*;local4.!debug /var/log/l4' > syslog.d/l4.conf
	echo 'local6.info /var/log/l6' > syslog.d/l6.txt
	cat > newsyslog.conf <<'EOF'
# logfilename          [owner:group]    mode count size when  flags [/pid_file] [sig_num]
/var/log/auth.log			600  7	   1000	@0101T JC
/var/log/messages	root:wheel	644  5	   1000	*	JC
/var/log/security			600  10	   100	*     JC
/var/log/cron				600  3	   100	*     JC
/var/log/debug.log			600  7	   *	24    JC
/var/log/maillog			640  7	   *	$D0  JC
EOF
	# The file's selectors in order; newsyslog's KiB in MiB rounded
	# up, its hours in minutes; a block, a pipe, users told, '<' and
	# '!', mark, a property filter, a name no facility's, newsyslog's
	# time of day: said, none guessed.  An include's .conf files only.
	cat > want <<'EOF'
console all.error kern.warning auth.notice mail.critical
file file:/var/log/messages files=5 size=1 rollover=-1 all.notice authpriv.none kern.debug lpr.info mail.critical news.error
file file:/var/log/security files=10 size=1 rollover=-1 audit.all
file file:/var/log/auth.log files=7 size=1 rollover=-1 auth.info authpriv.info
file file:/var/log/maillog files=7 size=-1 rollover=-1 mail.info
file file:/var/log/cron files=3 size=1 rollover=-1 cron.all
file file:/var/log/debug.log files=7 size=-1 rollover=1440 all.=debug
remote logs.example.net udp name logs.example.net port=5514 local0.all
remote 2001:db8::1 udp ipv6 2001:db8::1 port=-1 local1.all
remote 192.0.2.9 udp ipv4 192.0.2.9 port=-1 local5.all
unread syslog.conf:12: in a block of one program or host: ietf-syslog has no such selector
unread syslog.conf:14: users or everyone told: ietf-syslog has no such action
unread syslog.conf:15: a level compared by '<', '>' or '!': ietf-syslog's selectors compare equal, or that level and above
unread syslog.conf:16: a pipe to a program: ietf-syslog has no such action
unread syslog.conf:17: facility mark, syslogd's own marks, is none of RFC 5424's
unread syslog.conf:18: a property filter: ietf-syslog selects by facility and severity
unread syslog.d/devd.conf:1: a facility syslog has no name for
unread syslog.d/l4.conf:1: a level compared by '<', '>' or '!': ietf-syslog's selectors compare equal, or that level and above
unread newsyslog.conf:2: turned over at a time of day (@, $): ietf-syslog's rollover is an interval
unread newsyslog.conf:7: turned over at a time of day (@, $): ietf-syslog's rollover is an interval
yang-cbor 683 bytes, the same back
EOF
	atf_check -o file:want "$y" conf syslog.conf newsyslog.conf
	# The same files committed as they read: nothing to change.
	mkdir -p root/etc
	cp syslog.conf newsyslog.conf root/etc/
	cat > want <<'EOF'
yang-cbor 683 bytes, the same back
changed no take 0 create 0 included no/no
EOF
	atf_check -o file:want "$y" plan "$(pwd)/root"
}

atf_test_case yang_processes
yang_processes_head()
{
	atf_set "descr" "the processes operation's replies as" \
	    "arcana-processes has them, OpenConfig" \
	    "procmon's shape with FreeBSD's besides, a kernel process" \
	    "told; one process's files and threads on its entry, the CPU" \
	    "each thread ran on last, through YANG-CBOR and back"
}
yang_processes_body()
{
	local y="$(atf_get_srcdir)/yprocs"

	cat > ps.json <<'EOF'
{"processes":[{"pid":812,"ppid":1,"user":"root","jid":0,"state":"sleep","wait":"select","nice":0,"pri":20,"threads":1,"rss":9437184,"size":14680064,"time":1.27,"wcpu":0.05,"cpu":0.0,"in":12,"out":3,"io":0.0,"start":1791990000,"comm":"sshd","args":"/usr/sbin/sshd -D"},{"pid":4100,"ppid":4099,"user":"www","jid":3,"jail":"web","state":"run","nice":-5,"pri":52,"threads":4,"rss":104857600,"size":209715200,"time":3600.5,"wcpu":151.25,"cpu":180.4,"in":0,"out":0,"io":2.5,"start":1791995110,"comm":"nginx","args":"nginx: worker process"},{"pid":11,"ppid":0,"user":"root","jid":0,"state":"run","nice":0,"pri":155,"threads":4,"rss":0,"size":0,"time":9000.0,"wcpu":390.0,"cpu":395.5,"in":0,"out":0,"io":0.0,"start":1791980000,"kernel":true,"comm":"idle"}],"jails":[{"jid":3,"name":"web","procs":5,"threads":9,"cpu":180.4,"wcpu":151.25,"rss":130000000}],"ncpu":4,"elapsed":0.25}
EOF
	cat > one.json <<'EOF'
{"pid":812,"comm":"sshd","files":[{"use":"cwd","type":"file","path":"/","mode":"r"},{"fd":3,"type":"socket","proto":"TCP","local":"192.0.2.1:22","remote":"198.51.100.7:51000","mode":"rw"}],"threads":[{"tid":100812,"name":"sshd","state":"sleep","wait":"select","pri":20,"wcpu":0.05,"time":1.27,"cpu":0}]}
EOF
	# The args split on blanks; OpenConfig's utilization at most 100,
	# the exact share in cpu; start in nanoseconds.
	cat > want <<'EOF'
ncpu 4 elapsed 0.25
process 812 name=sshd args=/usr/sbin/sshd|-D start=1791990000000000000 util=0 memory=9437184 ppid=1 user=root jail=0/- state=sleep wait=select nice=0 pri=20 threads=1 size=14680064 time=1.27 cpu=0.00 wcpu=0.05 in=12 out=3 io=0.00
  file use=cwd type=file path=/ proto=- local=- remote=- mode=r
  file fd=3 type=socket path=- proto=TCP local=192.0.2.1:22 remote=198.51.100.7:51000 mode=rw
  thread 100812 name=sshd state=sleep wait=select pri=20 wcpu=0.05 time=1.27 on=0
process 4100 name=nginx args=nginx:|worker|process start=1791995110000000000 util=100 memory=104857600 ppid=4099 user=www jail=3/web state=run wait=- nice=-5 pri=52 threads=4 size=209715200 time=3600.50 cpu=180.40 wcpu=151.25 in=0 out=0 io=2.50
process 11 name=idle args= start=1791980000000000000 util=100 memory=0 ppid=0 user=root jail=0/- state=run wait=- nice=0 pri=155 threads=4 size=0 time=9000.00 cpu=395.50 wcpu=390.00 in=0 out=0 io=0.00 kernel
jail 3 web procs=5 threads=9 cpu=180.40 wcpu=151.25 rss=130000000
yang-cbor 502 bytes, the same back
EOF
	atf_check -o file:want "$y" ps.json one.json
	# Without the detail, no files or threads.
	atf_check -o not-match:'^  ' "$y" ps.json
}

atf_test_case yang_storage
yang_storage_head()
{
	atf_set "descr" "the storage operation's replies as arcana-storage" \
	    "has them: each kind's JSON in typed" \
	    "lists, health on its disks, a truncated list's total, through" \
	    "YANG-CBOR and back"
}
yang_storage_body()
{
	local y="$(atf_get_srcdir)/ystorage"

	cat > disks.json <<'EOF'
{"disks":[{"name":"ada0","size":500107862016,"sectorsize":512,"ident":"S3Z9NB0K000001","descr":"Samsung SSD 860 EVO 500GB","rotation":"0","scheme":"GPT","first":40,"last":976773127,"parts":[{"name":"ada0p1","size":524288,"index":1,"type":"freebsd-boot","label":"gptboot0","start":40,"end":1063},{"name":"ada0p2","size":499582287872,"index":2,"type":"freebsd-zfs","label":"zfs0","start":2048,"end":975769599}]},{"name":"nda0","size":1000204886016,"sectorsize":512,"rotation":"0"}]}
EOF
	cat > health.json <<'EOF'
{"disks":[{"name":"ada0","by":"smartctl","ok":true,"temperature":34,"power_on_hours":12345,"power_cycles":210,"reallocated":0,"pending":0},{"name":"nda0","by":"nvmecontrol","ok":true,"temperature":41,"used_pct":3,"spare_pct":100},{"name":"da9","note":"smartmontools is not installed"}]}
EOF
	cat > pools.json <<'EOF'
{"pools":[{"name":"tank","size":499289948160,"alloc":120259084288,"free":379030863872,"frag":12,"cap":24,"dedup":"1.00","health":"DEGRADED","state":"DEGRADED","status":"One or more devices has been removed.","action":"Online the device using zpool online.","scan":"scrub repaired 0B in 00:10:02 with 0 errors","errors":"No known data errors","vdevs":[{"name":"tank","depth":0,"state":"DEGRADED","read":"0","write":"0","cksum":"0"},{"name":"mirror-0","depth":1,"state":"DEGRADED","read":"0","write":"0","cksum":"0"},{"name":"ada0p2","depth":2,"state":"ONLINE","read":"0","write":"0","cksum":"0"},{"name":"ada1p2","depth":2,"state":"REMOVED","read":"0","write":"0","cksum":"0","note":"was /dev/ada1p2"}]}]}
EOF
	cat > importable.json <<'EOF'
{"importable":[{"id":"1234567890123456789","name":"backup","state":"ONLINE","status":""}]}
EOF
	cat > datasets.json <<'EOF'
{"datasets":[{"name":"tank","type":"filesystem","used":120259084288,"avail":363034263552,"refer":98304,"mountpoint":"/tank","compression":"lz4","ratio":"2.05","quota":0,"reservation":0,"mounted":"yes","canmount":"on","readonly":"off","encryption":"off","keylocation":"none","jailed":"off"},{"name":"tank/vm/disk0","type":"volume","used":21474836480,"avail":363034263552,"refer":8589934592,"mountpoint":"-","compression":"zstd","ratio":"1.10","quota":0,"reservation":0,"mounted":"-","canmount":"noauto","readonly":"on","encryption":"aes-256-gcm","keylocation":"prompt","jailed":"on","origin":"tank/vm/base@gold"}]}
EOF
	cat > snapshots.json <<'EOF'
{"snapshots":[{"name":"tank@daily-2026-10-14","used":1048576,"refer":98304,"creation":1791936000}]}
EOF
	cat > mounts.json <<'EOF'
{"mounts":[{"from":"tank","on":"/tank","type":"zfs","options":"local, nfsv4acls","size":363034361856,"used":98304,"avail":363034263552},{"from":"198.51.100.7:/export","on":"/mnt/export","type":"nfs","options":"","size":1099511627776,"used":549755813888,"avail":549755813888}],"fstab":[{"spec":"/dev/ada0p3","file":"none","vfstype":"swap","mntops":"sw","type":"sw","freq":0,"passno":0,"mounted":true},{"spec":"198.51.100.7:/export","file":"/mnt/export","vfstype":"nfs","mntops":"rw,nfsv4","type":"rw","freq":0,"passno":0,"mounted":true}],"swap":[{"device":"/dev/ada0p3","size":4294967296,"used":0}]}
EOF
	"$y" disks=disks.json pools=pools.json importable=importable.json \
	    total=40 datasets=datasets.json snapshots=snapshots.json \
	    mounts=mounts.json health=health.json > out
	atf_check -o match:'^yang-cbor [0-9]+ bytes, the same back$' cat out
	sed -n '1,/^yang-cbor/p' out | sed '$d' > first
	atf_check -o file:first sh -c "sed -n '/^-- back\$/,\$p' out | sed 1d"
	cat > want <<'EOF'
disk ada0 size=500107862016 sectorsize=512 ident=S3Z9NB0K000001 descr=Samsung SSD 860 EVO 500GB rotation=0 scheme=GPT first=40 last=976773127
  partition ada0p1 index=1 size=524288 type=freebsd-boot label=gptboot0 start=40 end=1063
  partition ada0p2 index=2 size=499582287872 type=freebsd-zfs label=zfs0 start=2048 end=975769599
  health by=smartctl ok=yes temperature=34 power-on-hours=12345 reallocated=yes note=-
disk nda0 size=1000204886016 sectorsize=512 ident=- descr=- rotation=0 scheme=- first=0 last=0
  health by=nvmecontrol ok=yes temperature=41 power-on-hours=0 reallocated=- note=-
disk da9 size=0 sectorsize=0 ident=- descr=- rotation=- scheme=- first=0 last=0
  health by=- ok=- temperature=0 power-on-hours=0 reallocated=- note=smartmontools is not installed
pool tank size=499289948160 alloc=120259084288 free=379030863872 frag=12 cap=24 dedup=1.00 health=DEGRADED state=DEGRADED status=One or more devices has been removed. scan=scrub repaired 0B in 00:10:02 with 0 errors errors=No known data errors
  vdev tank depth=0 state=DEGRADED read=0 write=0 cksum=0 note=-
  vdev mirror-0 depth=1 state=DEGRADED read=0 write=0 cksum=0 note=-
  vdev ada0p2 depth=2 state=ONLINE read=0 write=0 cksum=0 note=-
  vdev ada1p2 depth=2 state=REMOVED read=0 write=0 cksum=0 note=was /dev/ada1p2
importable 1234567890123456789 name=backup state=ONLINE
datasets-total 40
dataset tank type=filesystem used=120259084288 avail=363034263552 refer=98304 quota=0 mountpoint=/tank mounted=yes canmount=on compression=lz4 ratio=205 readonly=no encryption=off keylocation=none jailed=no origin=-
dataset tank/vm/disk0 type=volume used=21474836480 avail=363034263552 refer=8589934592 quota=0 mountpoint=- mounted=- canmount=noauto compression=zstd ratio=110 readonly=yes encryption=aes-256-gcm keylocation=prompt jailed=yes origin=tank/vm/base@gold
snapshot tank@daily-2026-10-14 used=1048576 refer=98304 creation=1791936000
mount tank on=/tank type=zfs options=local, nfsv4acls size=363034361856
mount 198.51.100.7:/export on=/mnt/export type=nfs options= size=1099511627776
fstab /dev/ada0p3 file=none vfstype=swap mntops=sw type=sw freq=0 passno=0 mounted=yes
fstab 198.51.100.7:/export file=/mnt/export vfstype=nfs mntops=rw,nfsv4 type=rw freq=0 passno=0 mounted=yes
swap /dev/ada0p3 size=4294967296 used=0
EOF
	atf_check -o file:want cat first
}

atf_test_case yang_packages
yang_packages_head()
{
	atf_set "descr" "the packages operations' replies as arcana-packages" \
	    "has them: installed and outdated merged," \
	    "the host's and a jail's through YANG-CBOR and back, an" \
	    "upgrade's output"
}
yang_packages_body()
{
	cat > want <<'EOF'
host bash installed=5.3.3 available=- automatic=no size=yes origin=shells/bash comment=GNU Project's Bourne Again SHell
host curl installed=8.16.0 available=8.17.0 automatic=yes size=yes origin=ftp/curl comment=Command line tool and library for transferring data with URLs
host git installed=2.51.0 available=- automatic=no size=- origin=devel/git comment=-
host vim installed=9.1.1 available=9.1.2 automatic=- size=- origin=- comment=-
host yang-cbor 250 bytes, the same back
back bash installed=5.3.3 available=- automatic=no size=yes origin=shells/bash comment=GNU Project's Bourne Again SHell
back curl installed=8.16.0 available=8.17.0 automatic=yes size=yes origin=ftp/curl comment=Command line tool and library for transferring data with URLs
back git installed=2.51.0 available=- automatic=no size=- origin=devel/git comment=-
back vim installed=9.1.1 available=9.1.2 automatic=- size=- origin=- comment=-
back repository FreeBSD-ports
back repository builder
jail yang-cbor 261 bytes, the same back
web bash installed=5.3.3 available=- automatic=no size=yes origin=shells/bash comment=GNU Project's Bourne Again SHell
web curl installed=8.16.0 available=8.17.0 automatic=yes size=yes origin=ftp/curl comment=Command line tool and library for transferring data with URLs
web git installed=2.51.0 available=- automatic=no size=- origin=devel/git comment=-
web vim installed=9.1.1 available=9.1.2 automatic=- size=- origin=- comment=-
upgraded 1
upgrade curl installed=8.16.0 available=8.17.0 automatic=- size=- origin=- comment=-
EOF
	atf_check -o file:want "$(atf_get_srcdir)/ypackages"
}

atf_test_case yang_services
yang_services_head()
{
	atf_set "descr" "the services as arcana-services has them," \
	    "through YANG-CBOR and back; one as its read action" \
	    "gives it; a configuration wanted made into its rcvar" \
	    "and its variables set or unset"
}
yang_services_body()
{
	cat > want <<'EOF'
service sshd enabled=yes path=/etc/rc.d/sshd rcvar=sshd_enable running=yes pid=yes status=sshd is running as pid 812. description=-
  variable sshd_flags=-o UseDNS=no
  variable sshd_program=/usr/sbin/sshd
service ntpd enabled=no path=/etc/rc.d/ntpd rcvar=ntpd_enable running=- pid=- status=- description=-
service bird enabled=yes path=/usr/local/etc/rc.d/bird rcvar=bird_enable running=no pid=- status=bird is not running. description=-
EOF
	cat > diffs <<'EOF'
changed: set sshd_flags=-o UseDNS=yes set sshd_rsa_enable=NO
the same: nothing
disabled, one gone: disable unset sshd_program
its rcvar: refused (Invalid argument)
another: refused (Invalid argument)
new: enable
EOF
	"$(atf_get_srcdir)/yservices" > out
	atf_check -o match:'^yang-cbor [0-9]+ bytes, the same back$' cat out
	atf_check -o file:want sh -c "sed -n '1,/^yang-cbor/p' out | sed '\$d'"
	atf_check -o file:want sh -c "sed -n '/^-- back\$/,/^read /p' out | sed '1d;\$d'"
	cat > read <<'EOF'
read enabled=yes path=/etc/rc.d/sshd rcvar=sshd_enable running=yes pid=812 status=sshd is running as pid 812. description=Secure Shell Daemon
  command configtest
  command keygen
  command reload
EOF
	atf_check -o file:read sh -c "sed -n '/^read /,/^changed:/p' out | sed '\$d'"
	atf_check -o file:diffs sh -c "sed -n '/^changed:/,\$p' out"
}

atf_test_case yang_subscribe cleanup
yang_subscribe_head()
{
	atf_set "descr" "RFC 8639's subscriptions over cblink's YANG family" \
	    "the operational datastore" \
	    "pushed every period, filtered; the NETCONF stream filtered to" \
	    "job events; the streams and the subscriptions listed; a bad" \
	    "filter refused"
}
yang_subscribe_body()
{
	start_daemon
	# RFC 8641's periodic push-update, what the filter selects alone.
	atf_check -o save:push "$JGC" -c "$SOCK" subscribe -n 2 -p 0.2 \
	    -x "/ietf-interfaces:interfaces/interface[name='lo0']/oper-status"
	atf_check -o match:'^2$' sh -c 'wc -l < push | tr -d " "'
	atf_check -o match:'^\{"ietf-restconf:notification":\{"eventTime":"[0-9T:.-]+Z","ietf-yang-push:push-update":\{"datastore-contents":\{"ietf-interfaces:interfaces":\{"interface":\[\{"name":"lo0","oper-status":"up"\}\]\}\},"id":[0-9]+\}\}\}$' \
	    head -1 push
	# The NETCONF stream, the events that have a job; and a periodic
	# one left running, both listed.
	"$JGC" -c "$SOCK" subscribe -n 1 -x '/arcana-events:event/job' \
	    > stream.out 2>&1 &
	echo $! > sub.pid
	"$JGC" -c "$SOCK" subscribe -p 30 > /dev/null 2>&1 &
	echo $! > sub2.pid
	sleep 0.5
	atf_check -o match:'"stream":"NETCONF","stream-xpath-filter":"/arcana-events:event/job"' \
	    -o match:'"period":3000' -o match:'"sent-event-records":"[0-9]+"' \
	    "$JGC" -c "$SOCK" get subscriptions
	atf_check -o match:'"name":"NETCONF"' "$JGC" -c "$SOCK" get streams
	atf_check -o ignore "$(atf_get_srcdir)/ysubmit" "$SOCK" arcw0
	for i in 1 2 3 4 5 6 7 8 9 10; do
		kill -0 "$(cat sub.pid)" 2>/dev/null || break
		sleep 0.5
	done
	atf_check -o match:'^1$' sh -c 'wc -l < stream.out | tr -d " "'
	atf_check -o match:'"arcana-events:event":\{' -o match:'"job":\{' \
	    cat stream.out
	# On-change: the jobs' titles whole first, then a job made as
	# a YANG Patch's create, its target the entry's api-path.
	"$JGC" -c "$SOCK" subscribe -n 2 -o 0 -x '/arcana-jobs:jobs/job/title' \
	    > change.out 2>&1 &
	echo $! > sub3.pid
	sleep 1.5
	atf_check -o ignore "$(atf_get_srcdir)/ysubmit" "$SOCK" arcw1
	for i in 1 2 3 4 5 6 7 8 9 10; do
		kill -0 "$(cat sub3.pid)" 2>/dev/null || break
		sleep 0.5
	done
	atf_check -o match:'^2$' sh -c 'wc -l < change.out | tr -d " "'
	atf_check -o match:'"ietf-yang-push:push-update":' head -1 change.out
	atf_check -o match:'"ietf-yang-push:push-change-update":\{"datastore-changes":\{"yang-patch":\{"edit":\[\{"edit-id":"1","operation":"create","target":"/arcana-jobs:jobs/job=[0-9]+","value":\{"arcana-jobs:job":\[\{"id":"[0-9]+","title":"arcw1: up"\}\]\}\}\],"patch-id":"1"\}\},"id":[0-9]+\}' \
	    tail -1 change.out
	# The events are read when one is told, not every period: the
	# newest's number replaced when a job's event comes.
	"$JGC" -c "$SOCK" subscribe -n 2 -o 0 -x '/arcana-events:events/last' \
	    > told.out 2>&1 &
	echo $! > sub4.pid
	sleep 1.5
	atf_check -o ignore "$(atf_get_srcdir)/ysubmit" "$SOCK" arcw2
	for i in 1 2 3 4 5 6 7 8 9 10; do
		kill -0 "$(cat sub4.pid)" 2>/dev/null || break
		sleep 0.5
	done
	atf_check -o match:'^2$' sh -c 'wc -l < told.out | tr -d " "'
	atf_check -o match:'"operation":"replace","target":"/arcana-events:events/last"' \
	    tail -1 told.out
	# Replay: the job events kept since an hour ago, then
	# replay-completed; the stream then ends at its stop-time.
	from=$(date -u -v-1H '+%Y-%m-%dT%H:%M:%SZ')
	stop=$(date -u -v+3S '+%Y-%m-%dT%H:%M:%SZ')
	atf_check -o save:replay.out -e ignore "$JGC" -c "$SOCK" subscribe \
	    -r "$from" -s "$stop" -x '/arcana-events:event/job'
	atf_check -o match:'"arcana-events:event":\{.*"job":\{' \
	    -o match:'"ietf-subscribed-notifications:replay-completed":\{"id":[0-9]+\}' \
	    cat replay.out
	atf_check -o match:'"replay-support":\[null\]' \
	    -o match:'"replay-log-creation-time":"[0-9T:-]+Z"' \
	    "$JGC" -c "$SOCK" get streams
	# A filter that is no XPath: refused at the open.
	atf_check -s exit:1 -e match:'subscribe: ' -o empty \
	    "$JGC" -c "$SOCK" subscribe -p 0.2 -x '/ietf-interfaces:interfaces['
}
yang_subscribe_cleanup()
{
	for f in sub.pid sub2.pid sub3.pid sub4.pid; do
		[ -f "$f" ] && kill "$(cat "$f")" 2>/dev/null
	done
	stop_daemon
}

atf_test_case yang_actions cleanup
yang_actions_head()
{
	atf_set "descr" "Actions of the models over cblink's YANG family: a " \
	    "log read, a process signalled, a job and a key refused"
}
yang_actions_body()
{
	mkdir logs
	printf 'one\ntwo\nthree\n' > logs/test.log
	DAEMON_ARGS="-v $(pwd)/logs"
	start_daemon
	# arcana-log's read, on the logs container: its last lines.
	atf_check -o match:'"name":"test.log"' -o match:'"text":"three"' \
	    -o not-match:'"text":"one"' \
	    "$JGC" -c "$SOCK" action logs read name=test.log lines=2
	# A process of this test's, signalled by its pid, the list's key.
	sleep 60 &
	echo $! > sleep.pid
	atf_check -o inline:'{}\n' "$JGC" -c "$SOCK" action processes/process \
	    "$(cat sleep.pid)" signal signal=TERM
	sleep 0.5
	kill -0 "$(cat sleep.pid)" 2>/dev/null && atf_fail "not signalled"
	# What the agent refuses, and what arcanactl does before asking.
	atf_check -s exit:1 -e match:'no such job' -o ignore \
	    "$JGC" -c "$SOCK" action jobs/job 99999 cancel
	atf_check -s exit:1 -e match:'pid: x is not one' -o ignore \
	    "$JGC" -c "$SOCK" action processes/process x signal signal=TERM
	atf_check -s exit:1 -e match:'has no action reset' -o ignore \
	    "$JGC" -c "$SOCK" action processes reset
	# The reads by a time or a number; what refuses before a program
	# runs; a module's rpc by its name alone.
	atf_check -o match:'^\{.*\}$' "$JGC" -c "$SOCK" action events read \
	    after=0
	atf_check -o match:'^\{.*\}$' "$JGC" -c "$SOCK" action history read
	atf_check -o inline:'{"purged-alarms":0}\n' "$JGC" -c "$SOCK" \
	    action alarms/alarm-list purge-alarms alarm-clearance-status=cleared
	atf_check -o inline:'{}\n' "$JGC" -c "$SOCK" action agent/transport \
	    retry
	atf_check -s exit:1 -e match:"not a module's name" -o ignore \
	    "$JGC" -c "$SOCK" action load 'name=a;b'
	atf_check -s exit:1 -e match:'no such file in the kernel' -o ignore \
	    "$JGC" -c "$SOCK" action kernel/file 99999 unload
	atf_check -s exit:1 -e match:'a dataset is pool/name' -o ignore \
	    "$JGC" -c "$SOCK" action storage/dataset 'bad;x' load-key key=12345678
	atf_check -s exit:1 -e match:'not the one this was made from' \
	    -o ignore "$JGC" -c "$SOCK" action storage/fstab replace text=x \
	    sha256=00
	# A jail's or a service's name is checked whoever asks: neither
	# reaches jail(8) or service(8).
	atf_check -s exit:1 -e match:'invalid jail name' -o ignore \
	    "$JGC" -c "$SOCK" action jails/jail 'a;b' restart
	atf_check -s exit:1 -e match:'invalid service name' -o ignore \
	    "$JGC" -c "$SOCK" action services/service 'a;b' restart
	# arcana-jobs' submit: changes made jobs as jobs.yaml says, queued
	# as job-submit queues them, their ids back; one of them confirmed
	# is refused, not waiting for it.  The events of it told as
	# arcana-events' notifications on the family's group, RFC 8040's
	# JSON of each.
	"$JGC" -c "$SOCK" notifications > notif.out 2>&1 &
	echo $! > notif.pid
	sleep 0.5
	atf_check -o save:ids "$(atf_get_srcdir)/ysubmit" "$SOCK" arcw0 arcw1
	atf_check -o match:'^2$' sh -c 'wc -l < ids | tr -d " "'
	atf_check -o match:'"arcana-jobs:jobs":\{"job":\[' \
	    -o match:'"title":"arcw0: up"' -o match:'"title":"arcw1: up"' \
	    "$JGC" -c "$SOCK" get jobs
	atf_check -s exit:1 -e match:'not waiting to be confirmed' -o ignore \
	    "$JGC" -c "$SOCK" action jobs/job "$(head -1 ids)" confirm
	sleep 1
	kill "$(cat notif.pid)"
	atf_check -o match:'^\{"ietf-restconf:notification":\{"eventTime":"[0-9T:.-]+Z","arcana-events:event":\{' \
	    -o match:'"kind":"arcana-events:job' cat notif.out
	# A change the agent refuses for itself: none queued.
	atf_check -s exit:1 -e match:'invalid interface name' -o empty \
	    "$(atf_get_srcdir)/ysubmit" "$SOCK" 'bad;name'
}
yang_actions_cleanup()
{
	[ -f sleep.pid ] && kill "$(cat sleep.pid)" 2>/dev/null
	[ -f notif.pid ] && kill "$(cat notif.pid)" 2>/dev/null
	stop_daemon
}

atf_test_case yang_get cleanup
yang_get_head()
{
	atf_set "descr" "The standard models served by cblink's YANG family: " \
	    "ietf-interfaces and ietf-ip as RFC 7951's JSON"
}
yang_get_body()
{
	start_daemon
	# The loopback, its type IANA's, its address ietf-ip's; the counters
	# 64-bit, so strings.
	atf_check -o save:get.json "$JGC" -c "$SOCK" get interfaces
	atf_check -o match:'^\{"ietf-interfaces:interfaces":\{"interface":\[' \
	    -o match:'"name":"lo0"' -o match:'"type":"iana-if-type:softwareLoopback"' \
	    -o match:'"ietf-ip:ipv4":\{"address":\[\{"ip":"127.0.0.1"' \
	    -o match:'"in-octets":"[0-9]+"' cat get.json
	# Every top-level node when none is named; the deprecated
	# interfaces-state not among them.
	atf_check -o match:'"ietf-interfaces:interfaces"' \
	    -o not-match:'"ietf-interfaces:interfaces-state"' "$JGC" -c "$SOCK" get
	# The host's routes, RFC 8349's RIBs: the loopback's own address
	# is received; and what an address goes by.
	atf_check -o save:rt.json "$JGC" -c "$SOCK" get routing
	atf_check -o match:'^\{"ietf-routing:routing":\{' \
	    -o match:'"name":"ipv4-master"' -o match:'"name":"ipv6-master"' \
	    -o match:'"ietf-ipv4-unicast-routing:destination-prefix":"127.0.0.1/32"' \
	    cat rt.json
	# RFC 8525's YANG library: the modules it implements with their
	# revisions and features, those imported only, NMDA's three
	# datastores.
	atf_check -o match:'"name":"ietf-interfaces","namespace":"urn:ietf:params:xml:ns:yang:ietf-interfaces","revision":"2018-02-20"' \
	    -o match:'"import-only-module":\[\{"name":"ietf-ospf"' \
	    -o match:'"name":"ietf-datastores:running"' \
	    -o match:'"name":"ietf-datastores:candidate"' \
	    -o match:'"name":"ietf-datastores:operational"' \
	    -o match:'"content-id":"[0-9a-f]{16}"' \
	    "$JGC" -c "$SOCK" get yang-library
	# RFC 8348's hardware: the chassis holding the CPUs and disks.
	atf_check -o match:'"class":"iana-hardware:chassis","contains-child":\["cpu0"' \
	    -o match:'"class":"iana-hardware:cpu"' \
	    "$JGC" -c "$SOCK" get hardware
	# RFC 8632's alarms: the faults' kinds as arcana-alarms' types,
	# the list and the summary by severity.
	atf_check -o match:'"alarm-type-id":"arcana-alarms:tunnel","alarm-type-qualifier":"","description":"[^"]+","severity-level":\["major"\],"will-clear":true' \
	    -o match:'"alarm-list":\{' -o match:'"number-of-alarms":[0-9]+' \
	    -o match:'"alarm-summary":\[\{"cleared":[0-9]+,"not-cleared":[0-9]+,"severity":"indeterminate"' \
	    "$JGC" -c "$SOCK" get alarms
	# One interface, by an XPath filter (RFC 6241's): its entry alone,
	# the containers above it with it.
	atf_check -o save:lo0.json "$JGC" -c "$SOCK" get \
	    -x "/ietf-interfaces:interfaces/interface[name='lo0']" interfaces
	atf_check -o match:'^\{"ietf-interfaces:interfaces":\{"interface":\[' \
	    -o match:'"name":"lo0"' cat lo0.json
	atf_check -o inline:'1\n' sh -c "grep -o '{\"admin-status\"' lo0.json | wc -l | tr -d ' '"
	atf_check -s exit:1 -e match:'unexpected text after the expression' -o ignore \
	    "$JGC" -c "$SOCK" get -x '/[' interfaces
	# Arcana's own modules, each the operation that reads the same:
	# the kernel's settings, the jobs, the agent's listeners.
	atf_check -o match:'^\{"arcana-sysctl:sysctl":\{' \
	    -o match:'"name":"kern.ostype"' "$JGC" -c "$SOCK" get sysctl
	atf_check -o match:'^\{"arcana-jobs:jobs":\{' "$JGC" -c "$SOCK" get jobs
	atf_check -o match:'"arcana-agent:agent":\{"transport":\{"listener":\[' \
	    -o match:'"transport":"unix"' "$JGC" -c "$SOCK" get agent
	# Every module at once: what the agent cannot read (BIRD not
	# running, netgraph not root's) left out, not a failure of all.
	atf_check -o match:'"arcana-sysctl:sysctl"' -o match:'"arcana-processes:processes"' \
	    "$JGC" -c "$SOCK" get
	atf_check -s exit:1 -e match:'nowhere is no node the agent serves' \
	    -o ignore "$JGC" -c "$SOCK" get nowhere
}
yang_get_cleanup()
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
	atf_check -o match:'\[daemon\] arcana-agent: jails' cat trace.out
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
	# An address jail(8) -e reads in lab through a variable.
	printf 'lab {\n\t$a = "10.0.0.60";\n\tip4.addr = "$a";\n}\n' \
	    >> etc/jail.conf
	cp etc/jail.conf before
	atf_check -s exit:1 -o ignore -e match:'is already in ip4.addr' \
	    "$JGC" -c "$SOCK" address add -p web 10.0.0.11
	atf_check -s exit:1 -o ignore \
	    -e match:'10.0.0.60 is already in ip4.addr' \
	    "$JGC" -c "$SOCK" address add -p lab 10.0.0.60
	atf_check -s exit:1 -o ignore \
	    -e match:"10.0.0.60 is not set by jail 'lab' itself" \
	    "$JGC" -c "$SOCK" address remove -p lab 10.0.0.60
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
	# Its own 400, each once (a jail running on the host is listed too).
	atf_check -o inline:'400\n' sh -c "grep -Ec '^j[0-9]+ ' many.out"
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
	# The files rc(8) reads, the case's own.
	mkdir -p root/etc/defaults
	cp /etc/defaults/rc.conf root/etc/defaults/
	printf 'sshd_enable="YES"\nsshd_flags="-4"\nntpd_enable="NO"\n' \
	    > root/etc/rc.conf
	DAEMON_ARGS="--root $(pwd)/root"
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
	atf_set "descr" "start and stop through service(8), arcana-services'" \
	    "actions; enable and disable its configuration, committed to" \
	    "Arcana's rc.conf file"
}
service_actions_body()
{
	mkdir -p root/etc/defaults root/usr/local/etc
	cp /etc/defaults/rc.conf root/etc/defaults/
	printf 'ntpd_enable="NO"\n' > root/etc/rc.conf
	DAEMON_ARGS="--root $(pwd)/root"
	start_daemon
	atf_check -o match:'Running: yes' -o match:'pid 4242' \
	    "$JGC" -c "$SOCK" service sshd start
	atf_check -o match:'Running: no' "$JGC" -c "$SOCK" service sshd stop
	# The commit's warnings, accepted with -a.
	atf_check -s exit:1 -e match:'-a rc-conf-files' \
	    "$JGC" -c "$SOCK" service ntpd enable
	atf_check -s exit:1 -e match:'ntpd_enable .*rc.conf line 1.*-a rc-conf-conflict' \
	    "$JGC" -c "$SOCK" service -a rc-conf-files ntpd enable
	atf_check -o match:'Enabled: yes' "$JGC" -c "$SOCK" service \
	    -a rc-conf-files -a rc-conf-conflict ntpd enable
	atf_check -o match:'^ntpd_enable="YES"$' \
	    cat root/usr/local/etc/rc.conf.d/arcana
	atf_check -o match:'^#ntpd_enable="NO"  # taken by Arcana$' \
	    cat root/etc/rc.conf
	atf_check -o match:'Enabled: no' "$JGC" -c "$SOCK" service ntpd disable
	atf_check -o match:'^ntpd_enable="NO"$' \
	    cat root/usr/local/etc/rc.conf.d/arcana
	# The rest as running has it, rc.conf by sysrc(8) untouched.
	atf_check -o not-match:'ntpd' cat sysrc.log
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
	atf_set "descr" "rc.conf variables of a service as running has them," \
	    "set and unset by arcana-services' configuration, committed"
}
service_config_body()
{
	mkdir -p root/etc/defaults root/usr/local/etc
	cp /etc/defaults/rc.conf root/etc/defaults/
	printf 'rc_conf_files="/etc/rc.conf /etc/rc.conf.local /usr/local/etc/rc.conf.d/arcana"\nsshd_enable="YES"\nsshd_flags="-4"\nntpd_enable="NO"\n' \
	    > root/etc/rc.conf
	DAEMON_ARGS="--root $(pwd)/root"
	start_daemon
	atf_check -o save:cfg.out "$JGC" -c "$SOCK" service sshd config
	atf_check -o match:'Enabled: yes' cat cfg.out
	atf_check -o match:'sshd_flags=-4' cat cfg.out
	atf_check -o not-match:'ntpd' cat cfg.out
	atf_check -o match:'Describe: The sshd daemon' cat cfg.out
	atf_check -o match:'Commands: reload,configtest' cat cfg.out
	atf_check -o match:'sshd_flags=-6 -D' "$JGC" -c "$SOCK" service \
	    -a rc-conf-conflict sshd config 'sshd_flags=-6 -D'
	atf_check -o match:'^sshd_flags="-6 -D"$' \
	    cat root/usr/local/etc/rc.conf.d/arcana
	atf_check -o not-match:'sshd_flags' \
	    "$JGC" -c "$SOCK" service sshd config -x sshd_flags
	atf_check -o not-match:'sshd_flags' \
	    cat root/usr/local/etc/rc.conf.d/arcana
	# Only the service's own variables, none more than a name, no value
	# rc.conf would read as more than a value; one refused leaves the
	# ones before it unwritten.
	cp root/usr/local/etc/rc.conf.d/arcana arcana.before
	atf_check -s exit:1 -o ignore \
	    -e match:"'ntpd_enable' is not a variable of sshd" \
	    "$JGC" -c "$SOCK" service sshd config ntpd_enable=YES
	atf_check -s exit:1 -o ignore -e match:'does not match pattern' \
	    "$JGC" -c "$SOCK" service sshd config 'sshd_x;y=1'
	atf_check -s exit:1 -o ignore -e match:'does not match pattern' \
	    "$JGC" -c "$SOCK" service sshd config 'x:-$(id)=1'
	atf_check -s exit:1 -e match:'rc.conf would read it as more' -o ignore \
	    "$JGC" -c "$SOCK" service sshd config 'sshd_flags=$(id)'
	atf_check -s exit:1 -e match:'is not a variable of sshd' -o ignore \
	    "$JGC" -c "$SOCK" service sshd config sshd_first=1 other_x=2
	atf_check cmp arcana.before root/usr/local/etc/rc.conf.d/arcana
	atf_check -o not-match:'sshd' cat sysrc.log
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

atf_test_case jail_base cleanup
jail_base_head()
{
	atf_set "descr" "a jail's base system to pkgbase and to a newer release, through pkg(8); and the lanes of pkg jobs"
}
jail_base_body()
{
	local R i

	R="$(pwd)/web"
	mkdir -p "$R/etc" "$R/usr/local/etc"
	printf 'hostname="web"\n' > "$R/etc/rc.conf"
	start_daemon
	# The jails: web runs, on 15.1; old, an older release; nothing else.
	cat > jails <<EOS
web 7 inherit $R 15.1-RELEASE-p3
old 8 inherit $R 14.3-RELEASE
EOS
	# Not running, not a verb, no release to go to: refused at once.
	atf_check -s exit:1 -o match:'not running' \
	    "$JGC" -c "$SOCK" jail-base nope convert
	atf_check -s exit:2 -o ignore -e match:'usage' \
	    "$JGC" -c "$SOCK" jail-base web reinstall
	atf_check -s exit:2 -o ignore -e match:'usage' \
	    "$JGC" -c "$SOCK" jail-base web upgrade
	# Too old for pkgbase.
	atf_check -s exit:1 -o match:'needs FreeBSD 15.1' \
	    "$JGC" -c "$SOCK" jail-base old convert
	# Converted: the repository's file in the jail, /etc kept aside,
	# pkg update then install of the default set from FreeBSD-base.
	atf_check -o save:cv.out "$JGC" -t -c "$SOCK" jail-base web convert
	atf_check -o match:'pkg.FreeBSD.org/\$\{ABI\}/base_release_1' cat "$R/usr/local/etc/pkg/repos/arcana-base.conf"
	atf_check test -s "$R/var/backups/etc-before-pkgbase.tar"
	atf_check -o match:'rc.conf' tar -tf "$R/var/backups/etc-before-pkgbase.tar"
	atf_check -o match:'fake-pkg -j web update -r arcana-base' cat cv.out
	atf_check -o match:'^install -r arcana-base -y FreeBSD-set-base-jail$' cat install.log
	atf_check -o match:'^arcana-base: \{' cat "$R/usr/local/etc/pkg/repos/arcana-base.conf"
	atf_check -o match:'restart the jail' cat cv.out
	# The jail's own files, which pkg put aside as it installed the
	# stock ones, back in place: its users and groups with the new
	# base's added (not one whose id the jail uses), the stock files
	# beside them as .pkgnew, the databases made again in the jail; a
	# .pkgsave from before left as it is.
	echo "$R" > jroot
	mkdir stock
	printf 'root:*:0:0::0:0:Charlie:/root:/bin/sh\n_newd:*:77:77::0:0:d:/:/usr/sbin/nologin\n_clash:*:2001:2001::0:0:c:/:/usr/sbin/nologin\n' > stock/master.passwd
	printf 'wheel:*:0:root\n_newd:*:77:\n' > stock/group
	printf 'stock\n' > stock/login.conf
	printf 'same\n' > stock/hosts
	printf 'root:*:0:0::0:0:Charlie:/root:/bin/sh\nalice:*:2001:2001::0:0:Alice:/home/alice:/bin/sh\n' > "$R/etc/master.passwd"
	printf 'wheel:*:0:root\nalice:*:2001:\n' > "$R/etc/group"
	printf 'own\n' > "$R/etc/login.conf"
	printf 'same\n' > "$R/etc/hosts"
	printf 'old\n' > "$R/etc/hosts.pkgsave"
	printf '#!/bin/sh\necho "jexec $*" >> %s/jexec.log\n' "$(pwd)" > fake-jexec
	chmod +x fake-jexec
	atf_check -o save:keep.out "$JGC" -t -c "$SOCK" jail-base web convert
	atf_check -o match:'^alice:' -o match:'^_newd:' -o not-match:'_clash' \
	    cat "$R/etc/master.passwd"
	atf_check -o match:'^alice:' -o match:'^_newd:' cat "$R/etc/group"
	atf_check -o inline:'own\n' cat "$R/etc/login.conf"
	atf_check -o inline:'stock\n' cat "$R/etc/login.conf.pkgnew"
	atf_check cmp stock/master.passwd "$R/etc/master.passwd.pkgnew"
	atf_check test ! -e "$R/etc/master.passwd.pkgsave" -a ! -e "$R/etc/login.conf.pkgsave"
	atf_check -o inline:'old\n' cat "$R/etc/hosts.pkgsave"
	atf_check -o match:'^jexec 7 /usr/sbin/pwd_mkdb -p /etc/master.passwd$' \
	    -o match:'^jexec 7 /usr/bin/cap_mkdb /etc/login.conf$' cat jexec.log
	atf_check -o match:'kept: .*master.passwd \(not added from the new base, its name or id taken: _clash\)' \
	    -o match:"the new base's users added: 1; its groups added: 1" \
	    -o match:'/etc/login.conf.pkgnew' cat keep.out
	rm -r stock jexec.log
	# Sets named, and one the repository has not; a branch named.
	rm install.log
	atf_check -o ignore "$JGC" -c "$SOCK" jail-base web convert -b 16 \
	    FreeBSD-set-minimal-jail
	atf_check -o match:'^install -r arcana-base -y FreeBSD-set-minimal-jail$' cat install.log
	atf_check -o match:'base_latest' cat "$R/usr/local/etc/pkg/repos/arcana-base.conf"
	# From one of the jail's own repositories instead: nothing written,
	# the one named used; one pkg has not, refused.
	rm install.log "$R/usr/local/etc/pkg/repos/arcana-base.conf"
	atf_check -o ignore "$JGC" -c "$SOCK" jail-base web convert -r builder
	atf_check -o match:'^install -r builder -y FreeBSD-set-base-jail$' cat install.log
	atf_check test ! -e "$R/usr/local/etc/pkg/repos/arcana-base.conf"
	atf_check -s exit:1 -o match:'pkg has no repository nosuch in jail web' \
	    "$JGC" -c "$SOCK" jail-base web convert -r nosuch
	atf_check -s exit:1 -o match:'repository arcana-base has no FreeBSD-set-tests; its sets: FreeBSD-set-base-jail, FreeBSD-set-minimal-jail' \
	    "$JGC" -c "$SOCK" jail-base web convert FreeBSD-set-tests
	atf_check -s exit:1 -o match:"'bsd' is not a set's name" \
	    "$JGC" -c "$SOCK" jail-base web convert bsd
	# Not on pkgbase yet: no upgrade; on it: no second conversion.
	atf_check -s exit:1 -o match:'not on pkgbase' \
	    "$JGC" -c "$SOCK" jail-base web upgrade 16
	touch pkgbase
	atf_check -s exit:1 -o match:'on pkgbase already' \
	    "$JGC" -c "$SOCK" jail-base web convert
	# Upgraded to the latest 16: the new ABI and OSVERSION on every
	# pkg, past OSVERSION for the base, the base then the rest.
	rm -f opts.log
	atf_check -o save:up.out "$JGC" -t -c "$SOCK" jail-base web upgrade 16
	atf_check -o match:'opt ABI=FreeBSD:16:[a-z0-9]+' -o match:'opt OSVERSION=1600000' \
	    -o match:'opt IGNORE_OSVERSION=yes' cat opts.log
	atf_check -o match:'base_latest' cat "$R/usr/local/etc/pkg/repos/arcana-base.conf"
	atf_check -o match:'upgrade from arcana-base' cat repo.log
	atf_check -o match:'fake-pkg -o ABI=FreeBSD:16:[a-z0-9]+ -o OSVERSION=1600000 -j web upgrade -y' cat up.out
	# A release of its own; beyond the host's kernel, refused.
	atf_check -o ignore "$JGC" -c "$SOCK" jail-base web upgrade 15.2
	atf_check -o match:'opt OSVERSION=1502000' cat opts.log
	atf_check -o match:'base_release_2' cat "$R/usr/local/etc/pkg/repos/arcana-base.conf"
	atf_check -s exit:1 -o match:'cannot run a newer userland' \
	    "$JGC" -c "$SOCK" jail-base web upgrade 99
	atf_check -s exit:1 -o match:'is not a release' \
	    "$JGC" -c "$SOCK" jail-base web upgrade sixteen
	# The lanes of pkg jobs in jails: said, set, kept for the next start.
	atf_check -o match:'^Lanes: 4 ' "$JGC" -c "$SOCK" jobs
	atf_check -o match:'^Lanes: 2 ' "$JGC" -c "$SOCK" jobs lanes 2
	atf_check -o match:'^Lanes: 2 ' "$JGC" -c "$SOCK" jobs
	atf_check -o match:'^lanes=2$' cat jobs.conf
	atf_check -s exit:2 -o ignore -e match:'lanes 40' "$JGC" -c "$SOCK" jobs lanes 40
	stop_daemon
	start_daemon
	for i in $(seq 1 100); do
		"$JGC" -c "$SOCK" jobs > /dev/null 2>&1 && break
		sleep 0.05
	done
	atf_check -o match:'^Lanes: 2 ' "$JGC" -c "$SOCK" jobs
}
jail_base_cleanup()
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
	# A link-local gateway with its zone, as a router advertisement gives it.
	atf_check -o ignore "$JGC" -c "$SOCK" route add 2001:db8:79::/48 fe80::1%lo0
	atf_check -o match:'2001:db8:79::/48 fe80::1%lo0' cat route.log
	atf_check -s exit:1 -o match:'neither an address nor an interface' \
	    "$JGC" -c "$SOCK" route add 2001:db8:79::/48 fe80::1%nope0
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
	# packets; kept as words of ifconfig_<if>, first, so that at boot
	# its addresses come after (their routes in its table); 0 taken
	# out again.
	atf_check -o match:'fake-ifconfig lo0 fib 2' -o match:'set fib' \
	    "$JGC" -p -c "$SOCK" interface lo0 fib 2
	atf_check -o match:'^ifconfig_lo0="fib 2 inet 127.0.0.1/8 mtu 1300 up"$' \
	    cat rc.conf
	sed -i '' -e 's|^ifconfig_lo0=.*|ifconfig_lo0="inet 127.0.0.1/8 mtu 1300 up fib 2"|' rc.conf
	atf_check -o ignore "$JGC" -p -c "$SOCK" interface lo0 fib 3
	atf_check -o match:'^ifconfig_lo0="fib 3 inet 127.0.0.1/8 mtu 1300 up"$' \
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
	atf_check -o match:'^ifconfig_gre4="fib 3 tunnel 192.0.2.1 192.0.2.2 up"$' \
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

	# Kept by the name given; another route's name is refused; one
	# kept is found by its destination and table whatever its name.
	atf_check -o ignore "$JGC" -p -c "$SOCK" route add 10.90.0.0/16 10.0.0.1 \
	    name router1
	atf_check -o match:'^route_router1="10.90.0.0/16 10.0.0.1"$' \
	    -o match:'^static_routes="arc_10_80_0_0_16_fib3 router1"$' cat rc.conf
	atf_check -s exit:1 -o match:'another route by the name router1' \
	    "$JGC" -p -c "$SOCK" route add 10.91.0.0/16 10.0.0.1 name router1
	atf_check -s exit:1 -o match:'cannot name a route' \
	    "$JGC" -p -c "$SOCK" route add 10.91.0.0/16 10.0.0.1 name 9lives
	# A route kept by hand, with words the agent does not write:
	# renamed in rc.conf alone, its words as they are; the kernel's
	# table not asked.
	printf 'route_home="10.92.0.0/16 -gateway 10.0.0.3 -mtu 1400"\n' >> rc.conf
	sed -i '' -e 's/^static_routes="\(.*\)"$/static_routes="\1 home"/' rc.conf
	atf_check -o not-match:'route-add' -o not-match:'route-del' \
	    "$JGC" -t -c "$SOCK" route keep add 10.92.0.0/16 name edge2_gre0
	atf_check -o match:'^route_edge2_gre0="10.92.0.0/16 -gateway 10.0.0.3 -mtu 1400"$' \
	    -o not-match:'route_home' \
	    -o match:'^static_routes="arc_10_80_0_0_16_fib3 router1 edge2_gre0"$' \
	    cat rc.conf
	# Added again by another name: the old name goes.
	atf_check -o ignore "$JGC" -p -c "$SOCK" route add 10.90.0.0/16 10.0.0.1 \
	    name router2
	atf_check -o match:'^route_router2="10.90.0.0/16 10.0.0.1"$' \
	    -o not-match:'router1' cat rc.conf
	# Kept in rc.conf alone, and forgotten there alone; not in safe
	# mode, there being nothing live to undo.
	atf_check -o not-match:'route-add' \
	    "$JGC" -t -c "$SOCK" route keep add 10.93.0.0/16 10.0.0.1 name lan2
	atf_check -o match:'^route_lan2="10.93.0.0/16 10.0.0.1"$' cat rc.conf
	atf_check -s exit:1 -e match:'nothing to undo' \
	    "$JGC" -s -c "$SOCK" route keep delete 10.93.0.0/16
	# What rc.conf keeps, read: each by its name, read as route(8)
	# would; one the list does not name; the default routers.
	printf 'route_stray="10.94.0.0/16 10.0.0.1"\n' >> rc.conf
	atf_check -o match:'"name":"lan2","family":"inet","list":"static_routes","variable":"route_lan2","listed":true,"value":"10.93.0.0/16 10.0.0.1","destination":"10.93.0.0/16","gateway":"10.0.0.1","kind":"gateway","fib":0' \
	    -o match:'"name":"arc_10_80_0_0_16_fib3".*"gateway":"lo0","kind":"interface","fib":3' \
	    -o match:'"name":"edge2_gre0".*"gateway":"10.0.0.3"' \
	    -o match:'"name":"stray".*"listed":false' \
	    -o match:'"name":"arc_2001_db8_7___48","family":"inet6"' \
	    "$JGC" -c "$SOCK" net kept-routes
	atf_check -o not-match:'route-del' \
	    "$JGC" -t -c "$SOCK" route keep delete 10.93.0.0/16
	atf_check -o not-match:'lan2' cat rc.conf
	# Deleted with -p: found by its destination, whatever its name.
	atf_check -o ignore "$JGC" -p -c "$SOCK" route delete 10.90.0.0/16
	atf_check -o not-match:'router2' cat rc.conf
	sed -i '' -e '/^route_stray=/d' -e '/^route_edge2_gre0=/d' \
	    -e 's/^static_routes=.*/static_routes="arc_10_80_0_0_16_fib3"/' rc.conf
	atf_check -o match:'fake-helper --scope-helper 0 routes 4 2 - -' \
	    "$JGC" -t -F 2 -c "$SOCK" net routes -4

	# A default route is rc.conf's defaultrouter, per table past the
	# first; one there already is kept all the same when asked; a
	# default kept by a name before moves to the variable.
	atf_check -o ignore "$JGC" -p -c "$SOCK" route add default 10.0.0.254
	atf_check -o ignore "$JGC" -p -F 3 -c "$SOCK" route add default 10.0.0.253
	atf_check -o ignore "$JGC" -p -c "$SOCK" route add default 2001:db8::fe
	atf_check -o match:'^defaultrouter="10.0.0.254"$' \
	    -o match:'^defaultrouter_fib3="10.0.0.253"$' \
	    -o match:'^ipv6_defaultrouter="2001:db8::fe"$' \
	    -o not-match:'route_arc_default' cat rc.conf
	atf_check -o ignore "$JGC" -p -c "$SOCK" route delete default 10.0.0.254
	atf_check -o not-match:'^defaultrouter=' -o match:'^defaultrouter_fib3=' cat rc.conf
	atf_check -o ignore "$JGC" -p -c "$SOCK" route add 10.66.0.0/16 10.0.0.1
	atf_check -o match:'^route_arc_10_66_0_0_16="10.66.0.0/16 10.0.0.1"$' cat rc.conf
	# A default route kept by a name before: in the list as sysrc +=
	# leaves it, one assignment.
	sed -i '' -e 's/^static_routes="\(.*\)"$/static_routes="\1 arc_default_fib2"/' rc.conf
	printf 'route_arc_default_fib2="default 10.0.0.252 -fib 2"\n' >> rc.conf
	atf_check -o ignore "$JGC" -p -F 2 -c "$SOCK" route add default 10.0.0.252
	atf_check -o match:'^defaultrouter_fib2="10.0.0.252"$' -o not-match:'arc_default_fib2' \
	    -o match:'^static_routes="arc_10_80_0_0_16_fib3 arc_10_66_0_0_16"$' cat rc.conf

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

	# Netgraph: the nodes with their hooks (arcana-netgraph's read
	# action), and the few commands.
	atf_check -o match:'\{"hook":\[\{"name":"lower","peer":"bridge0","peer-hook":"link0","peer-id":"0000000c","peer-type":"bridge"\}\],"id":"00000002","name":"em0","type":"ether"\}' \
	    -o match:'\{"id":"00000010","name":"ngctl1234","type":"socket"\}' \
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
"show protocols") printf 'BIRD 2.15.1 ready.\nName       Proto      Table      State  Since         Info\nbgp_core   BGP        ---        up     2026-10-01    Established\nospf1      OSPF       master4    up     2026-10-01    Running\n' ;;
"show ospf ospf1") printf 'BIRD 2.15.1 ready.\nospf1:\nRFC1583 compatibility: disabled\nNumber of areas: 1\n\tArea: 0.0.0.0 (0) [BACKBONE]\n\t\tStub:\tNo\n' ;;
"show ospf topology all ospf1") printf 'BIRD 2.15.1 ready.\n\narea 0.0.0.0\n\n\trouter 192.0.2.1\n\t\tdistance 0\n\t\trouter 10.0.0.2 metric 10\n\t\tnetwork 10.255.0.0/24 metric 10\n\n\trouter 10.0.0.2\n\t\tdistance 10\n\t\trouter 192.0.2.1 metric 10\n\t\tstubnet 10.9.0.0/24 metric 10\n\t\texternal 0.0.0.0/0 metric2 10000\n\n\tnetwork 10.255.0.0/24\n\t\tdr 192.0.2.1\n\t\tdistance 10\n\t\trouter 192.0.2.1\n\t\trouter 10.0.0.2\n' ;;
"show ospf neighbors") printf 'BIRD 2.15.1 ready.\nospf1:\nRouter ID   \tPri\t     State     \tDTime\tInterface  Router IP\n10.0.0.2    \t  1\tFull/PtP  \t00:00:35\tgif0       10.255.0.2\n' ;;
"show bfd sessions") printf 'BIRD 2.15.1 ready.\nbfd1:\nIP address                Interface  State      Since         Interval  Timeout\nfe80::1                   gif0       Up         13:01:27.605    0.200    1.000\nfe80::2                   gre1       Down       13:02:00.000    1.000    0.000\n' ;;
"show symbols table") printf 'BIRD 2.15.1 ready.\nmaster4    routing table\nr4         routing table\n' ;;
"show route table master4 count") printf 'BIRD 2.15.1 ready.\n845236 of 845236 routes for 845233 networks in table master4\n' ;;
"show route table r4 count") printf 'BIRD 2.15.1 ready.\n512345 of 512345 routes for 512345 networks in table r4\n' ;;
"restart nope") printf 'BIRD 2.15.1 ready.\nNo protocols match\n' ;;
restart*|reload*|enable*|disable*) printf 'BIRD 2.15.1 ready.\n%s: done\n' "\$2" ;;
configure) printf 'BIRD 2.15.1 ready.\nReading configuration from /usr/local/etc/bird.conf\nReconfigured\n' ;;
"configure timeout "*) printf 'BIRD 2.15.1 ready.\nReconfigured\n' ;;
"configure undo") printf 'BIRD 2.15.1 ready.\nUndo requested\n' ;;
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
	# arcana-wireguard's read action, as RFC 7951's JSON.
	atf_check -o match:'"listen-port":51820,"name":"wg0",' \
	    -o match:'"name":"wg1","private-key":false' -o not-match:'none' \
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
	atf_check -o match:"\"private-key\":true,\"public-key\":\"$PUB\"" \
	    -o match:"\{\"allowed-ip\":\[\"10.9.9.2/32\",\"fd00::2/128\"\],\"endpoint\":\"192.0.2.9:51820\",\"keepalive\":25,\"latest-handshake\":\"2023-11-14T22:13:20Z\",\"preshared-key\":false,\"public-key\":\"$PEER\",\"received\":\"1024\",\"sent\":\"2048\"\}" \
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
	# Safe too (safe_wireguard); what wg refuses fails as before.
	atf_check -s exit:1 -o match:'No such device' \
	    "$JGC" -s -c "$SOCK" wg wg9 init

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
	# without the right to change anything: arcana-bird's read action,
	# as RFC 7951's JSON.
	atf_check -o save:bird.json "$JGC" -c "$SOCK" net bird
	atf_check -o match:'"status":\["BIRD 2.15.1","Router ID is 192.0.2.1","Hostname is lab","Daemon is up and running"\]' \
	    -o match:'\{"info":"","name":"device1","since":"2026-10-01","state":"up","table":"---","type":"Device"\}' \
	    -o match:'"info":"Established","name":"bgp_core","since":"12:01:02.345","state":"up","table":"---","type":"BGP"' \
	    -o match:'"info":"Active        Socket: Connection refused","name":"bgp_edge","since":"12:01:02.345","state":"start"' \
	    cat bird.json
	# Of a neighbour: who it is, and of each channel its filters and
	# how many routes came and went; show protocols all's lines too.
	atf_check -o match:'"bgp":\{"hold":"150.012/240","local-as":65000,"neighbor":"192.0.2.1","neighbor-as":65001,"neighbor-id":"192.0.2.1","state":"Established"\}' \
	    -o match:'\{"exported":"12","imported":"845233","input-filter":"bgp_in","name":"ipv4","output-filter":"bgp_out","routes":"845233 imported, 12 exported, 400000 preferred","state":"UP","table":"master4"\}' \
	    -o match:'"exported":"0","imported":"190000","input-filter":"bgp_in","name":"ipv6","output-filter":"REJECT"' \
	    -o match:'"description":"Core uplink","detail":\["  Description:    Core uplink","  BGP state:          Established"' \
	    -o match:'"bgp":\{"last-error":"Socket: Connection refused","local-as":65000,"neighbor":"198.51.100.7","neighbor-as":65002,"state":"Active"\}' \
	    -o match:'"rpki":\{"cache":"rpki.example.net","serial":"42","status":"Established"\}' \
	    -o match:'"ospf-neighbor":\[\{"address":"10.255.0.2","dead-time":"00:00:35","interface":"gif0","priority":"1","protocol":"ospf1","router-id":"10.0.0.2","state":"Full/PtP"\}\]' \
	    -o match:'"bfd-session":\[\{"address":"fe80::1","interface":"gif0","interval":"0.200","protocol":"bfd1","since":"13:01:27.605","state":"Up","timeout":"1.000"\},\{"address":"fe80::2","interface":"gre1","interval":"1.000","protocol":"bfd1","since":"13:02:00.000","state":"Down"' \
	    -o match:'"table":\[\{"name":"master4","networks":"845233","routes":"845236"\},\{"name":"r4","networks":"512345","routes":"512345"\}\]' \
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

	# Its configuration (arcana-bird): read whole from running, with the
	# files it includes; put back whole by a commit, once bird(8) has
	# parsed it, and the daemon told.
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
	# Running has them, arcana-bird's configuration.
	atf_check -o match:'"arcana-bird:bird"' -o match:'peers/edge.conf' \
	    "$JGC" -c "$SOCK" get -d running bird

	# BIRD's routes, said in birdc's words; an address alone is the
	# route that covers it.  Each route with where it leads, and with
	# all, what it carries.
	atf_check -o save:r.json "$JGC" -c "$SOCK" bird routes 10.1.2.3 all
	atf_check -o match:'"attribute":\["Type: BGP univ","BGP.as_path: 65001 65010","BGP.large_community: \(65001, 1, 100\)"\],"from":"192.0.2.1","info":"AS65001i","nexthop":\[\{"interface":"em0","via":"192.0.2.1"\}\],"preference":"100","prefix":"10.1.0.0/16","primary":true,"protocol":"bgp_core","since":"2026-10-01","table":"master4","type":"unicast"' \
	    -o match:'"preference":"100/20","prefix":"10.1.0.0/16","primary":false,"protocol":"bgp_edge","since":"12:01:02.345"' \
	    -o match:'\{"interface":"gre0","via":"198.51.100.7"\},\{"interface":"gre1","via":"198.51.100.9"\}' \
	    -o match:'"count":"2"' cat r.json
	atf_check -o not-match:'"route"' "$JGC" -c "$SOCK" bird routes table master6

	# OSPF: each protocol with the areas it is in; with topology, what
	# its link-state database says, routers with their links and the
	# transit networks; a protocol's name is a word.
	atf_check -o match:'"protocol":\[\{"area":\["0.0.0.0"\],"name":"ospf1"\}\]' \
	    "$JGC" -c "$SOCK" bird ospf
	atf_check -o save:o.json "$JGC" -c "$SOCK" bird ospf topology ospf1
	atf_check -o match:'"distance":10,"id":"10.0.0.2","link":\[\{"kind":"router","metric":10,"to":"192.0.2.1"\},\{"kind":"stubnet","metric":10,"to":"10.9.0.0/24"\},\{"kind":"external","metric2":10000,"to":"0.0.0.0/0"\}\]' \
	    -o match:'"network":\[\{"distance":10,"dr":"192.0.2.1","id":"10.255.0.0/24","router":\["192.0.2.1","10.0.0.2"\]\}\]' \
	    cat o.json
	atf_check -s exit:1 -e match:"does not match pattern '\[A-Za-z0-9_\]\+'" \
	    -o ignore "$JGC" -c "$SOCK" bird ospf topology 'x-y'
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

	# In safe mode a confirmed commit: BIRD is told to take the change
	# back by itself a little after the commit's timeout, should the
	# agent be gone; the commit undone at its timeout, BIRD is told to go
	# back now, and the file goes back with it.
	sed -e 's/reject;/accept; # safe/' bird/bird.conf > safe.conf
	: > birdc.log
	atf_check -o match:'taken back unless confirmed' -o save:safe.out \
	    "$JGC" -c "$SOCK" bird config -c 2 -w safe.conf
	TOK=$(sed -n 's/.*bird confirm //p' safe.out)
	atf_check -o match:'^configure timeout 7$' cat birdc.log
	atf_check -o match:'# safe' cat bird/bird.conf
	# Another change waits for this one.
	atf_check -s exit:1 -e match:'confirmed commit' -o ignore \
	    "$JGC" -c "$SOCK" bird config -w safe.conf
	for i in $(seq 1 80); do
		grep -q '# safe' bird/bird.conf || break
		sleep 0.1
	done
	atf_check -o match:'reject;' -o not-match:'# safe' cat bird/bird.conf
	atf_check -o match:'^configure undo$' cat birdc.log
	atf_check -s exit:1 -e match:'no confirmed commit' -o ignore \
	    "$JGC" -c "$SOCK" bird confirm "$TOK"
	# Confirmed, it stays, and BIRD is told so.
	for i in $(seq 1 50); do
		"$JGC" -c "$SOCK" bird config -c 2 -w safe.conf > out 2>&1 && break
		sleep 0.1
	done
	atf_check -o match:'taken back unless confirmed' cat out
	TOK=$(sed -n 's/.*bird confirm //p' out)
	atf_check -o match:'confirmed: it stays' "$JGC" -c "$SOCK" bird confirm "$TOK"
	for i in $(seq 1 30); do
		grep -q '^configure confirm$' birdc.log && break
		sleep 0.1
	done
	atf_check -o match:'^configure confirm$' cat birdc.log
	sleep 3
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
	# the file parses, and stays for it to read when it is started; the
	# commit stands, warned of it.
	touch bird.dies
	atf_check -o match:'BIRD stopped answering when told to read' \
	    -o match:'The file is in place and parses' \
	    "$JGC" -c "$SOCK" bird config -w two.conf
	atf_check -o match:'# two' cat bird/bird.conf
	rm bird.dies
	# One that does not run: the file put in place for when it is
	# started, warned of; in safe mode taken back at the timeout.
	sed -e 's/# two/# twob/' bird/bird.conf > twob.conf
	atf_check -o match:'reads it when it is started' \
	    "$JGC" -c "$SOCK" bird config -c 2 -w twob.conf
	atf_check -o match:'# twob' cat bird/bird.conf
	for i in $(seq 1 80); do
		grep -q '# twob' bird/bird.conf || break
		sleep 0.1
	done
	atf_check -o match:'# two$' cat bird/bird.conf
	atf_check -o match:'reads it when it is started' \
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
	    "$JGC" -c "$SOCK" bird config -c 2 -w gone.conf
	touch bird.dead
	sleep 4
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
		"$JGC" -c "$SOCK" bird config -c 2 -w three.conf > out 2>&1 && break
		sleep 0.1
	done
	atf_check -o match:'taken back unless confirmed' cat out
	atf_check -s exit:1 -o match:'waits to be confirmed' \
	    "$JGC" -c "$SOCK" bird configure
	# Left alone it is taken back, BIRD told to go back and the file
	# as it was; a file somebody changed meanwhile is left to them.
	: > birdc.log
	for i in $(seq 1 80); do
		grep -q '# three' bird/bird.conf || break
		sleep 0.1
	done
	atf_check -o match:'# two' -o not-match:'# three' cat bird/bird.conf
	atf_check -o match:'^configure undo$' cat birdc.log
	for i in $(seq 1 50); do
		"$JGC" -c "$SOCK" bird config -c 2 -w three.conf > out 2>&1 && break
		sleep 0.1
	done
	atf_check -o match:'taken back unless confirmed' cat out
	printf '# somebody else\n' >> bird/bird.conf
	sleep 4
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
	echo "gateway 4 new $R" > jails
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
	chmod +x fake-jexec fake-ipfw
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
	    -o match:'^add 500 set 30 fwd tablearg ip from any to table\(sw1_p0\)$' \
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
	# Read as its own sysctl reads them (arcana-sysctl's read action);
	# only its network's.
	atf_check -o match:'^\{"value":\[\{"name":"net.fibs","value":"4"\}\]\}$' \
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
	# The jails: gateway runs with a network of its own, web shares the
	# host's, and nothing else runs.
	cat > jails <<EOS
gateway 4 new $R
web 7 inherit $(pwd)/web
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
	chmod +x fake-jexec fake-helper fake-ifconfig fake-wg fake-birdc fake-bird
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

	# BIRD there: the jail's birdc and bird (arcana-bird's read action
	# on the jail's node), its configuration read and put back beneath
	# the jail's root (arcana-bird's jail).
	atf_check -o match:'"bgp":\{"neighbor":"192.0.2.1"[^}]*\}.*"name":"bgp_up"' \
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
	# A plugin's, by its module's read action on the jail's node.
	atf_check -s exit:1 -e match:'net netgraph: .*has no network of its own' \
	    "$JGC" -j web -c "$SOCK" net netgraph
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
atf_test_case safe_sysctl cleanup
safe_sysctl_head()
{
	atf_set "descr" "A sysctl set in safe mode is put back: the kernel's value and sysctl.conf's line; one that cannot be read is not changed"
}
safe_sysctl_body()
{
	# sysctl -n answers from a file of values; a set rewrites it, and
	# net.fibs takes no smaller value, as the kernel refuses some.
	cat > fake-sysctl <<EOS
#!/bin/sh
echo "sysctl \$*" >> $(pwd)/sysctl.log
if [ "\$1" = -n ]; then
	v=\$(sed -n "s/^\$2=//p" $(pwd)/sysctl.values)
	[ -n "\$v" ] || { echo "sysctl: unknown oid '\$2'" >&2; exit 1; }
	echo "\$v"
	exit 0
fi
name=\${1%%=*}
val=\${1#*=}
cur=\$(sed -n "s/^\$name=//p" $(pwd)/sysctl.values)
[ -n "\$cur" ] || { echo "sysctl: unknown oid '\$name'" >&2; exit 1; }
if [ "\$name" = net.fibs ] && [ "\$val" -lt "\$cur" ]; then
	echo "sysctl: net.fibs: Invalid argument" >&2
	exit 1
fi
sed -i '' "s/^\$name=.*/\$name=\$val/" $(pwd)/sysctl.values
exit 0
EOS
	chmod +x fake-sysctl
	printf 'net.inet.ip.forwarding=0\nkern.ipc.somaxconn=1024\nnet.inet.tcp.blackhole=0\nnet.fibs=1\n' > sysctl.values
	printf '# kept\nkern.ipc.somaxconn=1024\n' > sysctl.conf
	DAEMON_ARGS="-Q $(pwd)/fake-sysctl -O $(pwd)/sysctl.conf"
	start_daemon

	# Confirmed: it stays.
	atf_check -o match:'done' -o match:'confirmed: it stays' \
	    "$JGC" -s -c "$SOCK" sysctl net.inet.ip.forwarding=1
	atf_check -o match:'^net.inet.ip.forwarding=1$' cat sysctl.values

	# Not confirmed: the kernel's value and the file's line as they
	# were; a line the change added is taken out again.
	: > sysctl.log
	atf_check -o match:'queued' "$JGC" -q -s -p -c "$SOCK" sysctl kern.ipc.somaxconn=4096
	atf_check -o match:'queued' "$JGC" -q -s -p -c "$SOCK" sysctl net.inet.tcp.blackhole=2
	for i in $(seq 1 200); do
		"$JGC" -c "$SOCK" jobs | grep -q 'unconfirmed\|queued\|running' ||
		    break
		sleep 0.1
	done
	atf_check -s exit:1 -o match:'not confirmed within 2 s: undone' \
	    -o match:'kern.ipc.somaxconn=1024 again' "$JGC" -c "$SOCK" job 2
	atf_check -s exit:1 -o match:'not confirmed within 2 s: undone' \
	    -o match:'net.inet.tcp.blackhole no longer set' "$JGC" -c "$SOCK" job 3
	atf_check -o match:'^sysctl kern.ipc.somaxconn=4096$' \
	    -o match:'^sysctl kern.ipc.somaxconn=1024$' \
	    -o match:'^sysctl net.inet.tcp.blackhole=2$' \
	    -o match:'^sysctl net.inet.tcp.blackhole=0$' cat sysctl.log
	atf_check -o match:'^kern.ipc.somaxconn=1024$' \
	    -o match:'^net.inet.tcp.blackhole=0$' cat sysctl.values
	atf_check -o match:'^# kept$' -o match:'^kern.ipc.somaxconn=1024$' \
	    -o not-match:'4096' -o not-match:'blackhole' cat sysctl.conf

	# One whose value cannot be read is not changed at all.
	: > sysctl.log
	atf_check -s exit:1 -o match:'could not be read, so it could not be put back' \
	    "$JGC" -s -c "$SOCK" sysctl kern.nosuch=1
	atf_check -o not-match:'kern.nosuch=1' cat sysctl.log

	# One the kernel takes only once keeps the new value, and the job
	# says so; the file is still put back.
	atf_check -o match:'queued' "$JGC" -q -s -p -c "$SOCK" sysctl net.fibs=4
	for i in $(seq 1 200); do
		"$JGC" -c "$SOCK" jobs | grep -q 'unconfirmed\|queued\|running' ||
		    break
		sleep 0.1
	done
	atf_check -s exit:1 -o match:'could not be undone' \
	    -o match:'the kernel keeps net.fibs=4 until it boots again, when sysctl.conf, put back as it was, sets it' \
	    "$JGC" -c "$SOCK" job 5
	atf_check -o match:'^net.fibs=4$' cat sysctl.values
	atf_check -o not-match:'net.fibs' cat sysctl.conf

	# What was so already is left so.
	atf_check -o match:'queued' "$JGC" -q -s -c "$SOCK" sysctl net.inet.ip.forwarding=1
	for i in $(seq 1 200); do
		"$JGC" -c "$SOCK" jobs | grep -q 'unconfirmed\|queued\|running' ||
		    break
		sleep 0.1
	done
	atf_check -s exit:1 -o match:'it was so before, and is left so' \
	    "$JGC" -c "$SOCK" job 6
}
safe_sysctl_cleanup()
{
	stop_daemon
}

atf_test_case safe_route_delete cleanup
safe_route_delete_head()
{
	atf_set "descr" "A route deleted without its gateway in safe mode is put back as the kernel listed it; a route of several ways, or none, is not deleted"
}
safe_route_delete_body()
{
	# The kernel's routes, as a file of lines; a FIB's (\$2), those a
	# filter (\$3) matches.
	cat > routes.json <<EOS
{"destination":"10.78.0.0/16","gateway":"10.0.0.1","flags":"UGS","nhop":1,"mtu":1500,"interface-name":"em0","metric":3,"weight":1,"fib":0,"prefixlen":16,"source":"10.0.0.9"}
{"destination":"10.0.0.0/24","gateway":"link#1","flags":"U","nhop":2,"mtu":16384,"interface-name":"lo0","metric":1,"weight":1,"fib":0,"prefixlen":24}
{"destination":"default","gateway":"10.1.0.1","flags":"UGS","nhop":3,"mtu":1500,"interface-name":"em1","metric":1,"weight":1,"fib":1,"prefixlen":0}
{"destination":"10.80.0.0/16","gateway":"10.0.0.1","flags":"UGS","nhop":4,"mtu":1500,"interface-name":"em0","metric":1,"weight":1,"fib":0,"prefixlen":16,"path":1,"paths":2}
{"destination":"10.80.0.0/16","gateway":"10.0.0.2","flags":"UGS","nhop":5,"mtu":1500,"interface-name":"em0","metric":1,"weight":1,"fib":0,"prefixlen":16,"path":2,"paths":2}
EOS
	cat > fake-helper <<EOS
#!/bin/sh
echo "fake-helper \$*" >&2
shift
jid=\$1 verb=\$2
shift 2
case "\$verb" in
routes)
	grep -e "\\"fib\\":\$2," $(pwd)/routes.json | grep -e "\${3#-}"
	echo "#total 5" ;;
route-add|route-del)
	echo "\$jid \$verb \$*" >> $(pwd)/route.log ;;
exists) echo 1 ;;
esac
exit 0
EOS
	chmod +x fake-helper
	start_daemon
	printf 'static_routes="arc_10_78_0_0_16"\nroute_arc_10_78_0_0_16="10.78.0.0/16 10.0.0.1 -ifa 10.0.0.9 -metric 3"\n' >> rc.conf

	# Not confirmed: added back with the gateway, cost, share and
	# source it had, and into rc.conf, where it was kept.
	atf_check -o match:'queued' "$JGC" -q -s -p -c "$SOCK" route delete 10.78.0.0/16
	for i in $(seq 1 200); do
		"$JGC" -c "$SOCK" jobs | grep -q 'unconfirmed\|queued\|running' ||
		    break
		sleep 0.1
	done
	atf_check -s exit:1 -o match:'not confirmed within 2 s: undone' \
	    "$JGC" -c "$SOCK" job 1
	atf_check -o match:'^0 route-del 10.78.0.0/16 - - 0 0$' \
	    -o match:'^0 route-add 10.78.0.0/16 10.0.0.1 - 0 3 0 10.0.0.9$' cat route.log
	atf_check -o match:'^static_routes="arc_10_78_0_0_16"$' \
	    -o match:'^route_arc_10_78_0_0_16="10.78.0.0/16 10.0.0.1 -ifa 10.0.0.9 -metric 3"$' cat rc.conf

	# A route of an interface comes back by the interface's name; one
	# rc.conf did not keep is not put there.
	: > route.log
	atf_check -o match:'queued' "$JGC" -q -s -p -c "$SOCK" route delete 10.0.0.0/24
	for i in $(seq 1 200); do
		"$JGC" -c "$SOCK" jobs | grep -q 'unconfirmed\|queued\|running' ||
		    break
		sleep 0.1
	done
	atf_check -o match:'^0 route-del 10.0.0.0/24 - - 0 0$' \
	    -o match:'^0 route-add 10.0.0.0/24 - lo0 0 1 0 -$' cat route.log
	atf_check -o not-match:'10_0_0_0_24' cat rc.conf

	# In another FIB: that FIB's route.
	: > route.log
	atf_check -o match:'queued' "$JGC" -q -s -F 1 -c "$SOCK" route delete default
	for i in $(seq 1 200); do
		"$JGC" -c "$SOCK" jobs | grep -q 'unconfirmed\|queued\|running' ||
		    break
		sleep 0.1
	done
	atf_check -o match:'^0 route-del 0.0.0.0/0 - - 1 0$' \
	    -o match:'^0 route-add 0.0.0.0/0 10.1.0.1 - 1 1 0 -$' cat route.log

	# A route of two ways is not deleted: it could not be put back.
	: > route.log
	atf_check -s exit:1 -o match:'not changed: it could not be put back: 10.80.0.0/16 in FIB 0 has 2 ways' \
	    "$JGC" -s -c "$SOCK" route delete 10.80.0.0/16
	atf_check -o empty cat route.log

	# Confirmed: it stays gone.
	atf_check -o match:'done' -o match:'confirmed: it stays' \
	    "$JGC" -s -c "$SOCK" route delete 10.78.0.0/16
	atf_check -o match:'^0 route-del 10.78.0.0/16 - - 0 0$' \
	    -o not-match:'route-add' cat route.log
}
safe_route_delete_cleanup()
{
	stop_daemon
}

atf_test_case safe_bird cleanup
safe_bird_head()
{
	atf_set "descr" "BIRD told something in safe mode: a protocol put back as it was, configure on BIRD's own timer confirmed or undone with the job, a reload with nothing to put back"
}
safe_bird_body()
{
	# birdc: a protocol's state in a file; configure timeout keeps a
	# timer that confirm and undo take away.
	cat > fake-birdc <<EOS
#!/bin/sh
echo "\$*" >> $(pwd)/birdc.log
[ "\$1" = -r ] && shift
printf 'BIRD 3.1.2 ready.\n'
case "\$*" in
"show status") printf 'BIRD 3.1.2\nDaemon is up and running\n' ;;
"show protocols "*) [ -f $(pwd)/proto.\$3 ] && printf 'Name       Proto      Table      State  Since         Info\n%s   BGP        ---        %s     12:01:02.345  Established\n' "\$3" "\$(cat $(pwd)/proto.\$3)" || echo "No protocols match" ;;
"enable "*) echo up > $(pwd)/proto.\$2; echo "\$2: enabled" ;;
"disable "*) echo down > $(pwd)/proto.\$2; echo "\$2: disabled" ;;
"reload "*|"restart "*) echo "\$2: reloading" ;;
"configure timeout "*) touch $(pwd)/bird.timer; printf 'Reading configuration from bird.conf\nReconfigured\n' ;;
"configure confirm") if [ -f $(pwd)/bird.timer ] && [ ! -f $(pwd)/bird.late ]; then rm $(pwd)/bird.timer; echo "Reconfiguration confirmed"; else echo "Nothing to do"; fi ;;
"configure undo") rm -f $(pwd)/bird.timer; echo "Undo requested" ;;
configure) printf 'Reading configuration from bird.conf\nReconfigured\n' ;;
esac
exit 0
EOS
	printf '#!/bin/sh\nexit 0\n' > fake-bird
	chmod +x fake-birdc fake-bird
	mkdir -p bird
	printf 'router id 192.0.2.1;\n' > bird/bird.conf
	echo up > proto.bgp_core
	start_daemon

	# Confirmed: it stays.
	atf_check -o match:'done' -o match:'confirmed: it stays' \
	    "$JGC" -s -c "$SOCK" bird disable bgp_core
	atf_check -o match:'^down$' cat proto.bgp_core

	# Not confirmed: the protocol as it was.
	: > birdc.log
	atf_check -o match:'queued' "$JGC" -q -s -c "$SOCK" bird enable bgp_core
	for i in $(seq 1 200); do
		"$JGC" -c "$SOCK" jobs | grep -q 'unconfirmed\|queued\|running' ||
		    break
		sleep 0.1
	done
	atf_check -s exit:1 -o match:'not confirmed within 2 s: undone' \
	    "$JGC" -c "$SOCK" job 2
	atf_check -o match:'^enable bgp_core$' -o match:'^disable bgp_core$' cat birdc.log
	atf_check -o match:'^down$' cat proto.bgp_core

	# What was so already is left so; a reload has nothing to put
	# back, and the job says so; a protocol BIRD lacks is not touched.
	: > birdc.log
	atf_check -o match:'queued' "$JGC" -q -s -c "$SOCK" bird disable bgp_core
	atf_check -o match:'queued' "$JGC" -q -s -c "$SOCK" bird reload all
	for i in $(seq 1 200); do
		"$JGC" -c "$SOCK" jobs | grep -q 'unconfirmed\|queued\|running' ||
		    break
		sleep 0.1
	done
	atf_check -s exit:1 -o match:'it was so before, and is left so' \
	    "$JGC" -c "$SOCK" job 3
	atf_check -s exit:1 -o match:'not confirmed within 2 s; a reload is not undone: there is nothing to put back' \
	    "$JGC" -c "$SOCK" job 4
	atf_check -o not-match:'^enable' cat birdc.log
	atf_check -s exit:1 -o match:'not changed: its state now could not be read, so it could not be put back: BIRD has no protocol nosuch' \
	    "$JGC" -s -c "$SOCK" bird enable nosuch
	atf_check -o not-match:'^enable nosuch' cat birdc.log

	# configure: BIRD's own timer, 5 s past the job's wait; confirmed,
	# BIRD is told to keep it.
	: > birdc.log
	atf_check -o match:'done' -o match:'confirmed: it stays' \
	    -o match:'configure confirm' "$JGC" -s -c "$SOCK" bird configure
	atf_check -o match:'^configure timeout 7$' -o match:'^configure confirm$' cat birdc.log
	atf_check test ! -f bird.timer
	# Not confirmed: BIRD is told to take it back.
	: > birdc.log
	atf_check -o match:'queued' "$JGC" -q -s -c "$SOCK" bird configure
	for i in $(seq 1 200); do
		"$JGC" -c "$SOCK" jobs | grep -q 'unconfirmed\|queued\|running' ||
		    break
		sleep 0.1
	done
	atf_check -s exit:1 -o match:'not confirmed within 2 s: undone' \
	    "$JGC" -c "$SOCK" job 7
	atf_check -o match:'^configure timeout 7$' -o match:'^configure undo$' cat birdc.log
	# Confirmed too late for BIRD: the change is gone, and the job
	# says so.
	touch bird.late
	atf_check -s exit:1 -o match:'confirmed, but BIRD did not keep it: its timer had run out, and BIRD had taken the change back' \
	    "$JGC" -s -c "$SOCK" bird configure
	rm bird.late bird.timer
	# Cancelled while it waits, it is undone at once (another change to
	# BIRD, job or operation, waits for the job to end: the lock on
	# changes is held through the wait).
	atf_check -o save:q.out "$JGC" -q -s -W 60 -c "$SOCK" bird configure
	id=$(awk '/queued/ {print $1; exit}' q.out)
	for i in $(seq 1 100); do
		"$JGC" -c "$SOCK" jobs | grep -q "^ *$id unconfirmed" && break
		sleep 0.1
	done
	: > birdc.log
	atf_check -o ignore "$JGC" -c "$SOCK" job-cancel "$id"
	for i in $(seq 1 100); do
		"$JGC" -c "$SOCK" jobs | grep -q "^ *$id \(unconfirmed\|running\)" ||
		    break
		sleep 0.1
	done
	atf_check -o match:'^configure undo$' cat birdc.log
	atf_check -o match:'done' "$JGC" -c "$SOCK" bird configure
}
safe_bird_cleanup()
{
	stop_daemon
}

atf_test_case safe_wireguard cleanup
safe_wireguard_head()
{
	atf_set "descr" "A WireGuard change in safe mode is put back with wg syncconf from what showconf printed before; wg-quick's file and rc.conf as they were; the key never in the trace"
}
safe_wireguard_body()
{
	PEER='xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg='
	mkdir wg
	printf '#!/bin/sh\necho "$*" >> %s/ifconfig.log\n' "$(pwd)" > fake-ifconfig
	# wg: the interface's peers in a file; showconf prints them; syncconf
	# puts the file given in their place, and keeps what it read.
	cat > fake-wg <<EOS
#!/bin/sh
d=$(pwd)
echo "\$*" >> \$d/wg.log
case "\$1 \$2 \$3" in
"show all dump")
	printf 'wg0\tSECRETKEY\tPUBKEY\t51820\toff\n' ;;
"show wg0 private-key") echo SECRETKEY ;;
"showconf wg0 ")
	printf '[Interface]\nListenPort = 51820\nPrivateKey = SECRETKEY\n'
	cat \$d/peers ;;
"set wg0 peer") printf '\n[Peer]\nPublicKey = %s\nAllowedIPs = 10.9.9.2/32\n' "\$4" >> \$d/peers ;;
"syncconf wg0 "*) cp "\$3" \$d/sync.got; ls -la "\$3" | cut -c1-10 > \$d/sync.mode; grep -v 'PrivateKey\|ListenPort\|Interface' "\$3" > \$d/peers ;;
"showconf wg9 ") echo "Unable to access interface: No such device" >&2; exit 1 ;;
esac
exit 0
EOS
	chmod +x fake-wg fake-ifconfig
	: > peers
	DAEMON_ARGS="-k $(pwd)/fake-wg -o $(pwd)/wg"
	start_daemon

	# Confirmed: it stays.
	atf_check -o match:'done' -o match:'confirmed: it stays' \
	    "$JGC" -s -c "$SOCK" wg wg0 peer $PEER allowed-ips 10.9.9.2/32
	atf_check -o match:"$PEER" cat peers

	# Not confirmed: the peers as they were, by syncconf from what
	# showconf printed; the file wg read is gone after; the key is in
	# neither the trace nor the log.
	: > peers
	: > wg.log
	atf_check -o match:'queued' "$JGC" -q -s -c "$SOCK" wg wg0 peer $PEER endpoint 192.0.2.9:51820
	for i in $(seq 1 200); do
		"$JGC" -c "$SOCK" jobs | grep -q 'unconfirmed\|queued\|running' ||
		    break
		sleep 0.1
	done
	atf_check -s exit:1 -o match:'not confirmed within 2 s: undone' \
	    -o match:'syncconf wg0: the key, the port and the peers as they were' \
	    -o not-match:'SECRETKEY' "$JGC" -t -c "$SOCK" job 2
	atf_check -o match:"^set wg0 peer $PEER endpoint" -o match:'^syncconf wg0 ' \
	    cat wg.log
	atf_check -o match:'^\[Interface\]$' -o match:'^PrivateKey = SECRETKEY$' \
	    -o not-match:'Peer' cat sync.got
	atf_check -o match:'^-rw-------' cat sync.mode
	atf_check -o empty cat peers
	atf_check -o empty ls wg
	atf_check -o not-match:'SECRETKEY' cat daemon.out

	# With persist: wg-quick's file and rc.conf as they were, which
	# was without them.
	atf_check -o match:'queued' "$JGC" -q -s -p -c "$SOCK" wg wg0 peer $PEER
	for i in $(seq 1 200); do
		"$JGC" -c "$SOCK" jobs | grep -q 'unconfirmed\|queued\|running' ||
		    break
		sleep 0.1
	done
	atf_check -s exit:1 -o match:'not confirmed within 2 s: undone' \
	    -o match:'wg0.conf, as it was' "$JGC" -c "$SOCK" job 3
	atf_check -o empty ls wg
	atf_check -o not-match:'wireguard' cat rc.conf
	# And with a file and variables there before: those again.
	printf '[Interface]\nPrivateKey = OLDKEY\n' > wg/wg0.conf
	printf 'wireguard_interfaces="wg0"\nwireguard_enable="YES"\n' >> rc.conf
	atf_check -o match:'queued' "$JGC" -q -s -p -c "$SOCK" wg wg0 peer $PEER
	for i in $(seq 1 200); do
		"$JGC" -c "$SOCK" jobs | grep -q 'unconfirmed\|queued\|running' ||
		    break
		sleep 0.1
	done
	atf_check -s exit:1 -o match:'not confirmed within 2 s: undone' \
	    "$JGC" -c "$SOCK" job 4
	atf_check -o match:'^PrivateKey = OLDKEY$' -o not-match:'SECRETKEY' cat wg/wg0.conf
	atf_check -o match:'^wireguard_interfaces="wg0"$' \
	    -o match:'^wireguard_enable="YES"$' cat rc.conf

	# One wg cannot show is not changed.
	atf_check -s exit:1 -o match:'not changed: wg9 could not be read, so it could not be put back' \
	    "$JGC" -s -c "$SOCK" wg wg9 peer $PEER
	atf_check -o not-match:'set wg9' cat wg.log
}
safe_wireguard_cleanup()
{
	stop_daemon
}

atf_test_case safe_ipsec cleanup
safe_ipsec_head()
{
	atf_set "descr" "An IPsec connection changed in safe mode: its files back as they were and the daemon told; up and down each other's undo; init and start refused"
}
safe_ipsec_body()
{
	mkdir -p swanctl/conf.d swanctl/pkcs8 swanctl/pubkey
	printf '#!/bin/sh\necho "$*" >> %s/ifconfig.log\n' "$(pwd)" > fake-ifconfig
	cat > fake-swanctl <<EOS
#!/bin/sh
d=$(pwd)
echo "\$*" >> \$d/swanctl.log
case "\$1" in
--list-conns|--list-sas) echo "" ;;
--load-all)	ls \$d/swanctl/conf.d > \$d/loaded ; echo "successfully loaded" ;;
--load-creds|--initiate|--terminate|--stats) echo ok ;;
*)		exit 2 ;;
esac
EOS
	chmod +x fake-ifconfig fake-swanctl
	start_daemon
	atf_check -o ignore "$JGC" -c "$SOCK" -p ipsec init
	PUB=$(sed -e '/-----/d' swanctl/pubkey/arcana.pub | tr -d '\n')

	# A key made or the daemon started has nothing to put back.
	atf_check -s exit:1 -o ignore -e match:'not in safe mode' \
	    "$JGC" -s -c "$SOCK" ipsec init
	atf_check -s exit:1 -o ignore -e match:'not in safe mode' \
	    "$JGC" -s -c "$SOCK" ipsec start

	# A connection made and not confirmed: its SAs ended, its files
	# gone again, the daemon told to read conf.d again.
	: > swanctl.log
	atf_check -o match:'queued' "$JGC" -q -s -c "$SOCK" ipsec conn t1 10.202.0.1 10.202.0.2 mode transport pubkey "$PUB"
	for i in $(seq 1 200); do
		"$JGC" -c "$SOCK" jobs | grep -q 'unconfirmed\|queued\|running' ||
		    break
		sleep 0.1
	done
	atf_check -s exit:1 -o match:'not confirmed within 2 s: undone' \
	    -o match:'arcana-t1.conf, as it was' "$JGC" -c "$SOCK" job 2
	atf_check -o match:'^--terminate --ike t1 --force$' cat swanctl.log
	atf_check -o inline:'--load-all --noprompt\n' tail -1 swanctl.log
	atf_check -o empty ls swanctl/conf.d
	atf_check -o inline:'arcana.pub\n' ls swanctl/pubkey

	# Confirmed, it stays; a child added and not confirmed leaves the
	# files as they were, and the daemon is told, no SA ended.
	atf_check -o match:'done' -o match:'confirmed: it stays' \
	    "$JGC" -s -c "$SOCK" ipsec conn t1 10.202.0.1 10.202.0.2 mode transport pubkey "$PUB"
	cp swanctl/conf.d/arcana-t1.conf t1.conf.was
	cp swanctl/conf.d/arcana-t1.json t1.json.was
	: > swanctl.log
	atf_check -o match:'queued' "$JGC" -q -s -c "$SOCK" ipsec child t1 c2 tunnel
	for i in $(seq 1 200); do
		"$JGC" -c "$SOCK" jobs | grep -q 'unconfirmed\|queued\|running' ||
		    break
		sleep 0.1
	done
	atf_check -s exit:1 -o match:'not confirmed within 2 s: undone' \
	    "$JGC" -c "$SOCK" job 4
	atf_check cmp t1.conf.was swanctl/conf.d/arcana-t1.conf
	atf_check cmp t1.json.was swanctl/conf.d/arcana-t1.json
	atf_check -o not-match:'terminate' -o match:'^--load-all --noprompt$' cat swanctl.log

	# Taken away and not confirmed: back, files and all.
	: > swanctl.log
	atf_check -o match:'queued' "$JGC" -q -s -c "$SOCK" ipsec unconn t1
	for i in $(seq 1 200); do
		"$JGC" -c "$SOCK" jobs | grep -q 'unconfirmed\|queued\|running' ||
		    break
		sleep 0.1
	done
	atf_check -s exit:1 -o match:'not confirmed within 2 s: undone' \
	    "$JGC" -c "$SOCK" job 5
	atf_check cmp t1.conf.was swanctl/conf.d/arcana-t1.conf
	atf_check cmp t1.json.was swanctl/conf.d/arcana-t1.json
	atf_check test -f swanctl/pubkey/arcana-t1.pub
	atf_check -o inline:'--load-all --noprompt\n' tail -1 swanctl.log

	# up not confirmed is down again, and down up again.
	: > swanctl.log
	atf_check -o match:'queued' "$JGC" -q -s -c "$SOCK" ipsec up t1
	atf_check -o match:'queued' "$JGC" -q -s -c "$SOCK" ipsec down t1
	for i in $(seq 1 200); do
		"$JGC" -c "$SOCK" jobs | grep -q 'unconfirmed\|queued\|running' ||
		    break
		sleep 0.1
	done
	atf_check -o inline:'--initiate --child t1 --timeout 20\n--terminate --ike t1 --timeout 10\n--terminate --ike t1 --timeout 10\n--initiate --child t1 --timeout 20\n' cat swanctl.log
}
safe_ipsec_cleanup()
{
	stop_daemon
}

atf_test_case safe_ipsec_sa cleanup
safe_ipsec_sa_head()
{
	atf_set "descr" "Manually keyed SAs in safe mode: not confirmed, the key files and what was set go back and the SAs derived again as they were; set by hand, they cannot be and the job is refused before the change"
}
safe_ipsec_sa_body()
{
	write_rc
	cat > fake-setkey <<EOS
#!/bin/sh
echo "setkey \$*" >> $(pwd)/setkey.log
[ "\$1" = -f ] && cat "\$2" >> $(pwd)/setkey.conf
exit 0
EOS
	chmod +x fake-setkey
	start_daemon
	K=00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff
	A=0011223344556677889900112233445566778899
	wait_jobs() {
		for i in $(seq 1 200); do
			"$JGC" -c "$SOCK" jobs | grep -q 'unconfirmed\|queued\|running' ||
			    break
			sleep 0.1
		done
	}
	last_job() {
		"$JGC" -c "$SOCK" jobs | awk '$1 ~ /^[0-9]+$/ {print $1}' | sort -n | tail -1
	}

	# Set by hand where nothing was, not confirmed: the SAs put in are
	# taken out again and nothing is kept.
	rm -f setkey.conf
	atf_check -o match:'queued' "$JGC" -q -s -c "$SOCK" ipsec-sa set ipsec0 100 10.202.0.1 10.202.0.2 spi-in 0x1001 spi-out 0x1002 enc aes-cbc auth hmac-sha1 key-in $K key-out $K akey-in $A akey-out $A
	wait_jobs
	atf_check -s exit:1 -o match:'not confirmed within 2 s: undone' \
	    -o match:'none were in: none put in' "$JGC" -c "$SOCK" job $(last_job)
	atf_check -o match:'^add 10.202.0.1 10.202.0.2 esp 0x1002 ' \
	    -o match:'^deleteall 10.202.0.1 10.202.0.2 esp ;$' \
	    -o match:'^deleteall 10.202.0.2 10.202.0.1 esp ;$' cat setkey.conf
	test -z "$(find . -name sdwan-sa-ipsec0.json)" || atf_fail "the state kept"

	# Set by hand and confirmed, it stays; on top of it, a safe derive
	# is refused before it changes anything: the keys set by hand are
	# nowhere to put back.
	atf_check -o match:'confirmed: it stays' "$JGC" -s -c "$SOCK" ipsec-sa set ipsec0 100 10.202.0.1 10.202.0.2 spi-in 0x1001 spi-out 0x1002 enc aes-cbc auth hmac-sha1 key-in $K key-out $K akey-in $A akey-out $A
	atf_check -o ignore "$JGC" -c "$SOCK" ipsec-sa key ipsec0
	atf_check -o ignore "$JGC" -c "$SOCK" ipsec-sa key ipsec1
	P0=$("$JGC" -c "$SOCK" sdwan | sed -E 's/.*"keys":\[//' | tr '}' '\n' | grep '"interface":"ipsec0"' | sed -E 's/.*"public":"([^"]*)".*/\1/')
	P1=$("$JGC" -c "$SOCK" sdwan | sed -E 's/.*"keys":\[//' | tr '}' '\n' | grep '"interface":"ipsec1"' | sed -E 's/.*"public":"([^"]*)".*/\1/')
	rm -f setkey.conf
	atf_check -s exit:1 -o match:'set by hand, not derived' -o match:'not in safe mode' "$JGC" -s -c "$SOCK" ipsec-sa derive ipsec0 100 10.202.0.1 10.202.0.2 peer "$P1" enc aes-cbc auth hmac-sha2-256
	test ! -e setkey.conf || atf_fail "changed before the refusal"
	atf_check -o ignore "$JGC" -c "$SOCK" ipsec-sa clear ipsec0 100 10.202.0.1 10.202.0.2

	# Derived and confirmed; derived again at another epoch and not
	# confirmed: the SAs of the first epoch put in again, the same
	# SPIs, and what was set as it was.
	atf_check -o match:'confirmed: it stays' "$JGC" -s -c "$SOCK" ipsec-sa derive ipsec0 100 10.202.0.1 10.202.0.2 peer "$P1" enc aes-cbc auth hmac-sha2-256 encap esn
	S_IN=$(grep '^add 10.202.0.2 10.202.0.1 .* -u 100 ' setkey.conf | tail -1 | sed -E 's/.*esp (0x[0-9a-f]+).*/\1/')
	S_OUT=$(grep '^add 10.202.0.1 10.202.0.2 .* -u 100 ' setkey.conf | tail -1 | sed -E 's/.*esp (0x[0-9a-f]+).*/\1/')
	KEY_OUT=$(grep '^add 10.202.0.1 10.202.0.2 .* -u 100 ' setkey.conf | tail -1 | sed -E 's/.*-E aes-cbc (0x[0-9a-f]+).*/\1/')
	STATE=$(find . -name sdwan-sa-ipsec0.json)
	cp "$STATE" state.was
	atf_check -o match:'"derive":\{"peer":"' -o match:'"install":"both"' -o match:'"encap":true' cat state.was
	rm -f setkey.conf
	atf_check -o match:'queued' "$JGC" -q -s -c "$SOCK" ipsec-sa derive ipsec0 100 10.202.0.1 10.202.0.2 peer "$P1" enc aes-gcm-16 epoch 1
	wait_jobs
	atf_check -s exit:1 -o match:'not confirmed within 2 s: undone' \
	    -o match:'sdwan-sa-ipsec0.json, as it was' \
	    -o match:'derived again as kept' "$JGC" -c "$SOCK" job $(last_job)
	# The new SAs in, then everything out, then the old ones in again:
	# the same SPIs and keys as the first time.
	atf_check -o match:'^add 10.202.0.1 10.202.0.2 esp 0x[0-9a-f]+ -m tunnel -u 100 -r 128 -E aes-gcm-16 ' cat setkey.conf
	atf_check -o inline:'1\n' sh -c "grep -c '^deleteall 10.202.0.1 10.202.0.2 esp' setkey.conf"
	atf_check -o match:"^add 10.202.0.1 10.202.0.2 esp $S_OUT -m tunnel -u 100 -r 128 -esn -natt .* -E aes-cbc $KEY_OUT -A hmac-sha2-256 " \
	    -o match:"^add 10.202.0.2 10.202.0.1 esp $S_IN -m tunnel -u 100 " cat setkey.conf
	atf_check -o inline:'1\n' sh -c "tail -1 setkey.conf | grep -c '^add 10.202.0.2 10.202.0.1 esp $S_IN '"
	atf_check -o match:"\"spi_in\":$((S_IN)),\"spi_out\":$((S_OUT))" -o match:'"interface":"ipsec0",.*"pending":false' "$JGC" -c "$SOCK" sdwan

	# A key pair made over the one there, not confirmed: the file as
	# it was, the SAs untouched.
	cp "$(dirname "$STATE")/sdwan-key-ipsec0.pem" key.was
	rm -f setkey.conf
	atf_check -o match:'queued' "$JGC" -q -s -c "$SOCK" ipsec-sa key ipsec0
	wait_jobs
	atf_check -s exit:1 -o match:'not confirmed within 2 s: undone' \
	    -o match:'sdwan-key-ipsec0.pem, as it was' "$JGC" -c "$SOCK" job $(last_job)
	atf_check cmp key.was "$(dirname "$STATE")/sdwan-key-ipsec0.pem"
	test ! -e setkey.conf || atf_fail "the SAs touched for a key"

	# A rotation under way (the next pair, its SAs in and out), then
	# committed in safe mode and not confirmed: the next pair back, the
	# state back to pending, the pair's SAs and the next ones derived
	# again.
	atf_check -o ignore "$JGC" -c "$SOCK" ipsec-sa key ipsec0 next
	atf_check -o ignore "$JGC" -c "$SOCK" ipsec-sa key ipsec1 next
	N1=$("$JGC" -c "$SOCK" sdwan | sed -E 's/.*"keys":\[//' | tr '}' '\n' | grep '"interface":"ipsec1"' | sed -E 's/.*"next":"([^"]*)".*/\1/')
	atf_check -o ignore "$JGC" -c "$SOCK" ipsec-sa derive ipsec0 100 10.202.0.1 10.202.0.2 peer "$N1" enc aes-cbc auth hmac-sha2-256 next install in
	atf_check -o ignore "$JGC" -c "$SOCK" ipsec-sa derive ipsec0 100 10.202.0.1 10.202.0.2 peer "$N1" enc aes-cbc auth hmac-sha2-256 next install out
	atf_check -o match:'"next_derive":\{"peer":"' -o match:'"install":"both"' cat "$STATE"
	cp "$STATE" state.pending
	cp "$(dirname "$STATE")/sdwan-key-ipsec0-next.pem" next.was
	rm -f setkey.conf
	atf_check -o match:'queued' "$JGC" -q -s -c "$SOCK" ipsec-sa commit ipsec0 100 10.202.0.1 10.202.0.2
	wait_jobs
	atf_check -s exit:1 -o match:'not confirmed within 2 s: undone' \
	    -o match:'sdwan-key-ipsec0-next.pem, as it was' \
	    -o match:'derived again as kept' "$JGC" -c "$SOCK" job $(last_job)
	atf_check cmp next.was "$(dirname "$STATE")/sdwan-key-ipsec0-next.pem"
	atf_check -o match:'"interface":"ipsec0",.*"pending":true' "$JGC" -c "$SOCK" sdwan
	# Four SAs in again after the deleteall: the pair's two, the next's two.
	atf_check -o inline:'4\n' sh -c "sed -n '/^deleteall 10.202.0.2 10.202.0.1/,\$p' setkey.conf | grep -c '^add '"
	# Committed and confirmed: done.
	atf_check -o match:'confirmed: it stays' "$JGC" -s -c "$SOCK" ipsec-sa commit ipsec0 100 10.202.0.1 10.202.0.2
	test ! -e "$(dirname "$STATE")/sdwan-key-ipsec0-next.pem" || atf_fail "the next pair still there"
	atf_check -o match:'"derive":\{"peer":"' -o not-match:'next_derive' cat "$STATE"
}
safe_ipsec_sa_cleanup()
{
	stop_daemon
}

atf_test_case safe_sysfile cleanup
safe_sysfile_head()
{
	atf_set "descr" "A file of the system's written in safe mode goes back as it was and its daemon is told again; periodic.conf and rc.conf's variables too; dma is refused"
}
safe_sysfile_body()
{
	mkdir -p root/etc/defaults
	printf '# defaults\ndaily_clean_tmps_enable="NO"\n' > root/etc/defaults/periodic.conf
	printf 'daily_status_disks_enable="YES"\n' > root/etc/periodic.conf
	DAEMON_ARGS="--root $(pwd)/root"
	start_daemon
	printf '#!/bin/sh\n' > rc.d/syslogd
	chmod +x rc.d/syslogd
	touch running.syslogd

	# A file that was not there is gone again; one that was is as it
	# was; the daemon told each time.
	printf '*.err\t/var/log/errors\n' > syslog.new
	atf_check -o match:'queued' "$JGC" -q -s -c "$SOCK" sysfile syslog.conf syslog.new
	for i in $(seq 1 200); do
		"$JGC" -c "$SOCK" jobs | grep -q 'unconfirmed\|queued\|running' ||
		    break
		sleep 0.1
	done
	atf_check -s exit:1 -o match:'not confirmed within 2 s: undone' \
	    -o match:'syslog.conf, as it was' "$JGC" -c "$SOCK" job 1
	atf_check test ! -f root/etc/syslog.conf
	printf '*.*\t/var/log/all\n' > root/etc/syslog.conf
	atf_check -o match:'queued' "$JGC" -q -s -c "$SOCK" sysfile syslog.conf syslog.new
	for i in $(seq 1 200); do
		"$JGC" -c "$SOCK" jobs | grep -q 'unconfirmed\|queued\|running' ||
		    break
		sleep 0.1
	done
	atf_check -s exit:1 -o match:'not confirmed within 2 s: undone' \
	    "$JGC" -c "$SOCK" job 2
	atf_check -o inline:'*.*\t/var/log/all\n' cat root/etc/syslog.conf
	# Confirmed: it stays.
	atf_check -o match:'done' -o match:'confirmed: it stays' \
	    "$JGC" -s -c "$SOCK" sysfile syslog.conf syslog.new
	atf_check -o inline:'*.err\t/var/log/errors\n' cat root/etc/syslog.conf

	# periodic.conf whole as it was; rc.conf's variables as they were.
	atf_check -o match:'queued' "$JGC" -q -s -c "$SOCK" sysfile periodic daily_clean_tmps_enable=YES
	atf_check -o match:'queued' "$JGC" -q -s -c "$SOCK" sysfile rc kern_securelevel_enable=YES kern_securelevel=2
	for i in $(seq 1 200); do
		"$JGC" -c "$SOCK" jobs | grep -q 'unconfirmed\|queued\|running' ||
		    break
		sleep 0.1
	done
	atf_check -o inline:'daily_status_disks_enable="YES"\n' cat root/etc/periodic.conf
	atf_check -o not-match:'securelevel' cat rc.conf
	atf_check -s exit:1 -o match:'not confirmed within 2 s: undone' "$JGC" -c "$SOCK" job 4
	atf_check -s exit:1 -o match:'not confirmed within 2 s: undone' "$JGC" -c "$SOCK" job 5

	# dma's smart host is not put back.
	atf_check -s exit:1 -o ignore -e match:'not in safe mode' \
	    "$JGC" -s -c "$SOCK" sysfile dma smarthost=mail.example.net
}
safe_sysfile_cleanup()
{
	stop_daemon
}

atf_test_case safe_if_destroy cleanup
safe_if_destroy_head()
{
	atf_set "descr" "An interface destroyed in safe mode is made again as it was: addresses, MTU, state and rc.conf; only a tunnel, tap, tun or lo"
}
safe_if_destroy_body()
{
	printf '#!/bin/sh\necho "$*" >> %s/ifconfig.log\n' "$(pwd)" > fake-ifconfig
	chmod +x fake-ifconfig
	start_daemon

	# lo0 is here to be read; ifconfig is a fake, so nothing happens
	# to it: what the undo would run is in its log.
	printf 'cloned_interfaces="lo0"\nifconfig_lo0="inet 127.0.0.1/8 mtu 16384 up"\nifconfig_lo0_descr="the loopback"\n' >> rc.conf
	atf_check -o match:'queued' "$JGC" -q -s -p -c "$SOCK" interface lo0 destroy
	for i in $(seq 1 200); do
		"$JGC" -c "$SOCK" jobs | grep -q 'unconfirmed\|queued\|running' ||
		    break
		sleep 0.1
	done
	atf_check -s exit:1 -o match:'not confirmed within 2 s: undone' \
	    "$JGC" -c "$SOCK" job 1
	atf_check -o match:'^lo0 destroy$' -o match:'^lo0 create$' \
	    -o match:'^lo0 inet6? [0-9a-f.:]+\/[0-9]+$' -o match:'^lo0 inet6? [0-9a-f.:]+\/[0-9]+ alias$' \
	    -o match:'^lo0 mtu [0-9]+$' -o match:'^lo0 up$' cat ifconfig.log
	atf_check -o match:'^cloned_interfaces="lo0"$' \
	    -o match:'^ifconfig_lo0="inet 127.0.0.1/8 mtu 16384 up"$' \
	    -o match:'^ifconfig_lo0_descr="the loopback"$' cat rc.conf

	# What cannot be made again as it was is refused; what was not
	# listed is destroyed as asked, with nothing to make again.
	atf_check -s exit:1 -o ignore -e match:'not in safe mode' \
	    "$JGC" -s -c "$SOCK" interface wg0 destroy
	atf_check -s exit:1 -o ignore -e match:'not in safe mode' \
	    "$JGC" -s -c "$SOCK" interface epair3a destroy
	: > ifconfig.log
	atf_check -o match:'queued' "$JGC" -q -s -c "$SOCK" interface gif9 destroy
	for i in $(seq 1 200); do
		"$JGC" -c "$SOCK" jobs | grep -q 'unconfirmed\|queued\|running' ||
		    break
		sleep 0.1
	done
	atf_check -s exit:1 -o match:'gif9 was not listed before: there is nothing to make again' \
	    "$JGC" -c "$SOCK" job 2
	atf_check -o inline:'gif9 destroy\n' cat ifconfig.log
}
safe_if_destroy_cleanup()
{
	stop_daemon
}

atf_test_case safe_l2 cleanup
safe_l2_head()
{
	atf_set "descr" "A bridge's member, flag, vlanfilter or static address in safe mode is taken back by the inverse word, a geneve made destroyed again, rc.conf as it was; what sets a value is refused"
}
safe_l2_body()
{
	printf '#!/bin/sh\necho "$*" >> %s/ifconfig.log\n' "$(pwd)" > fake-ifconfig
	chmod +x fake-ifconfig
	start_daemon
	printf 'ifconfig_bridge0="addm em1 up"\n' >> rc.conf

	atf_check -o match:'queued' "$JGC" -q -s -p -c "$SOCK" bridge bridge0 addm tap9
	atf_check -o match:'queued' "$JGC" -q -s -c "$SOCK" bridge bridge0 deletem em1
	atf_check -o match:'queued' "$JGC" -q -s -c "$SOCK" bridge bridge0 vlanfilter on
	atf_check -o match:'queued' "$JGC" -q -s -c "$SOCK" bridge bridge0 flag tap9 -stp
	atf_check -o match:'queued' "$JGC" -q -s -c "$SOCK" bridge bridge0 static tap9 00:11:22:33:44:55
	atf_check -o match:'queued' "$JGC" -q -s -p -c "$SOCK" geneve geneve7 create id 7 local 192.0.2.1 remote 192.0.2.2
	for i in $(seq 1 300); do
		"$JGC" -c "$SOCK" jobs | grep -q 'unconfirmed\|queued\|running' ||
		    break
		sleep 0.1
	done
	for n in 1 2 3 4 5 6; do
		atf_check -s exit:1 -o match:'not confirmed within 2 s: undone' \
		    "$JGC" -c "$SOCK" job $n
	done
	atf_check -o match:'^bridge0 addm tap9$' -o match:'^bridge0 deletem tap9$' \
	    -o match:'^bridge0 deletem em1$' -o match:'^bridge0 addm em1$' \
	    -o match:'^bridge0 vlanfilter$' -o match:'^bridge0 -vlanfilter$' \
	    -o match:'^bridge0 -stp tap9$' -o match:'^bridge0 stp tap9$' \
	    -o match:'^bridge0 static tap9 00:11:22:33:44:55$' \
	    -o match:'^bridge0 deladdr 00:11:22:33:44:55$' \
	    -o match:'^geneve7 create geneveid 7 genevelocal 192.0.2.1 geneveremote 192.0.2.2 up$' \
	    -o match:'^geneve7 destroy$' cat ifconfig.log
	atf_check -o match:'^ifconfig_bridge0="addm em1 up"$' -o not-match:'geneve7' \
	    -o not-match:'cloned_interfaces' -o not-match:'ifconfig_tap9' cat rc.conf

	# Confirmed: it stays, in rc.conf too.
	atf_check -o match:'done' -o match:'confirmed: it stays' \
	    "$JGC" -s -p -c "$SOCK" bridge bridge0 addm tap9
	atf_check -o match:'^ifconfig_bridge0="addm em1 up addm tap9"$' \
	    -o match:'^ifconfig_tap9="up"$' cat rc.conf

	# What sets a value over another, or forgets what was learned, is
	# not taken back.
	for c in "bridge bridge0 set proto stp" "bridge bridge0 access tap9 20" \
	    "bridge bridge0 flush" "geneve geneve7 set learn off"; do
		atf_check -s exit:1 -o ignore -e match:'not in safe mode' \
		    "$JGC" -s -c "$SOCK" $c
	done
}
safe_l2_cleanup()
{
	stop_daemon
}

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

	# A route deleted without its gateway is put back as the kernel
	# listed it; one the kernel does not list is not deleted at all.
	atf_check -s exit:1 -o match:'not changed: it could not be put back: no route to 10.79.0.0/16 in FIB 0' \
	    "$JGC" -s -c "$SOCK" route delete 10.79.0.0/16
	atf_check -o not-match:'10.79' cat route.log

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
	atf_check -o match:'confirmed: it stays' \
	    "$JGC" -s -c "$SOCK" interface gif4 destroy
	atf_check -s exit:1 -e match:'not in safe mode' -o ignore \
	    "$JGC" -q -s -c "$SOCK" ng shutdown em0:

	# A variable's name is given to sysrc(8), which evaluates it: one
	# that is more than a name never gets there in a job (without one,
	# arcana-services' commit: service_config's case); nor does a value
	# rc.conf would read as more than a value.
	: > sysrc.log
	atf_check -s exit:1 -e match:"name is letters, digits and _" -o ignore \
	    "$JGC" -q -s -c "$SOCK" service sshd config 'x:-$(id)=1'
	atf_check -s exit:1 -e match:"name is letters, digits and _" -o ignore \
	    "$JGC" -q -s -c "$SOCK" service sshd config -x '-a'
	atf_check -s exit:1 -e match:'rc.conf would read it as more' -o ignore \
	    "$JGC" -q -c "$SOCK" service sshd config 'sshd_flags=a"; id; "'
	atf_check -o not-match:'id' cat rc.conf
	atf_check -o not-match:'id' -o not-match:'x:' cat sysrc.log

	# The queue has an end: jobs that wait hold memory.  The first holds
	# the runner while it waits to be confirmed, longer than queueing the
	# rest takes on a busy host (the daemon's own wait is 2 s).
	atf_check -o match:'queued' "$JGC" -q -s -W 50 -c "$SOCK" interface lo0 down
	for i in $(seq 1 255); do
		"$JGC" -q -c "$SOCK" interface lo0 up > /dev/null ||
		    atf_fail "job $i was refused"
	done
	atf_check -s exit:1 -e match:'too many jobs wait already' -o ignore \
	    "$JGC" -q -c "$SOCK" interface lo0 up
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
while ps -o state= -p "\$pid" 2>/dev/null | grep -qv Z; do sleep 0.1; done
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
	# A minute: under the whole suite at once the job's sysrc(8) -A
	# alone has taken most of one.
	for i in $(seq 1 600); do
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

# The SD-WAN services' daemons as stand-ins: bird(8) and birdc(8),
# setfib(1) starting each, dnsmasq(8), local-unbound and its checker,
# and in the tools directory (-2) squid(8), its certificate maker and
# c-icap; each says what it was run with, and refuses a file that has
# BROKEN in it.
sdwan_daemons()
{
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
	chmod +x fake-bird fake-birdc fake-setfib fake-dnsmasq \
	    fake-local-unbound fake-local-unbound-checkconf tools/squid \
	    tools/security_file_certgen tools/c-icap
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
[ "\$1" = list ] && [ -f $(pwd)/diverting ] && echo "00100 divert 8001 ip from any to any"
exit 0
EOS
	chmod +x fake-ipfw
	printf '#!/bin/sh\necho "kldload $*" >> %s/kldload.log\nexit 0\n' "$(pwd)" > fake-kldload
	chmod +x fake-kldload
	mkdir -p root/var/db/clamav
	DAEMON_ARGS="-h $(pwd)/fake-ipfw -3 $(pwd)/fake-setfib -2 $(pwd)/tools --suricata-rules $(pwd)/rules --root $(pwd)/root"
	start_daemon
	atf_check -o match:'"targets":\[\]' -o match:'"probing":true' \
	    -o match:'"rules":\{"set":0,"rules":0,"tables":\[\],"objects":0,"counters":\[\]\}' \
	    -o match:'"steer":\[\],"steered":false' "$JGC" -c "$SOCK" sdwan
	# What is not a target list: refused as arcana-probe has them.
	atf_check -s exit:1 -e match:'JSON array' -o ignore \
	    "$JGC" -c "$SOCK" sdwan probes '{"id":"x"}'
	atf_check -s exit:1 -e match:'address: mandatory, missing' -o ignore \
	    "$JGC" -c "$SOCK" sdwan probes '[{"id":"x"}]'
	atf_check -s exit:1 -e match:'address' -o ignore \
	    "$JGC" -c "$SOCK" sdwan probes '[{"id":"x","address":"nowhere"}]'
	atf_check -s exit:1 -e match:'interval' -o ignore \
	    "$JGC" -c "$SOCK" sdwan probes '[{"id":"x","address":"127.0.0.1","interval":1}]'
	atf_check -s exit:1 -e match:'twice' -o ignore \
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
	atf_check -s exit:1 -e match:'set: 1 out of range' -o ignore "$JGC" -c "$SOCK" sdwan rules \
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
	# Disabled, loaded, enabled: in that order (a commit reads the
	# firewall before).
	atf_check -o match:'set disable 30$' sh -c "grep 'set 30\\|set disable 30\\|set enable 30' ipfw.log | head -1"
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
	# NAT64 instances (nat64lsn, nat64clat): named, created before the
	# rules, their module loaded, destroyed with the rules.
	: > ipfw.log
	: > kldload.log
	atf_check -o empty "$JGC" -c "$SOCK" sdwan rules \
	    '{"set":30,"tables":[],"objects":["nat64lsn sw1_64 create prefix4 192.0.2.64/26 prefix6 64:ff9b::/96 allow_private","nat64clat sw1_chq create clat_prefix 2001:db8:c::/96 plat_prefix 64:ff9b::/96"],"rules":["10 nat64lsn sw1_64 ip6 from any to 64:ff9b::/96 in","99 count ip from any to any"]}'
	atf_check -o match:'^nat64lsn sw1_64 create prefix4 192.0.2.64/26 prefix6 64:ff9b::/96 allow_private$' \
	    -o match:'^nat64clat sw1_chq create clat_prefix 2001:db8:c::/96 plat_prefix 64:ff9b::/96$' \
	    -o match:'^add 10 set 30 nat64lsn sw1_64 ip6 from any to 64:ff9b::/96 in$' cat ipfw.log
	atf_check -o match:'ipfw_nat64' cat kldload.log
	atf_check -s exit:1 -e match:'an object is' -o ignore "$JGC" -c "$SOCK" sdwan rules \
	    '{"set":30,"tables":[],"objects":["nat64lsn sw1_64 config prefix4 192.0.2.64/26"],"rules":["10 allow ip from any to any"]}'
	: > ipfw.log
	atf_check -o empty "$JGC" -c "$SOCK" sdwan rules '{"set":30,"tables":[],"rules":[]}'
	atf_check -o match:'^ipfw -q nat64clat sw1_chq destroy$' -o match:'^ipfw -q nat64lsn sw1_64 destroy$' cat ipfw.log
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
	sdwan_daemons
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
# DIESTART: daemonized, its pid file written, then its engine fails (as
# a divert port it cannot open does), the rules it left out said first.
grep -q DIESTART "\$2" && { sh -c 'echo \$\$ > "\$0"; sleep 1' "\$4" & { echo "[1 - Main] 2026-10-19 Error: detect: Complete IP space negated."; echo "[1 - Main] 2026-10-19 Error: detect: error parsing signature \\"alert\\" from file x at line 1"; echo "[2 - RX] 2026-10-19 Error: ipfw: Can't create divert socket: Address family not supported by protocol family"; echo "[1 - Main] 2026-10-19 Error: suricata: Engine initialization failed, aborting..."; } >> "\$d/suricata.log"; exit 0; }
"\$0" --hold "\$4" &
echo "[1 - Main] 2026-10-19 Notice: threads: Threads created -> W: 1 FM: 1 FR: 1   Engine started." >> "\$d/suricata.log"
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
	    '{"instances":[{"name":"../x","fib":1,"spec":{"router_id":"1.1.1.1"}}]}'
	atf_check -s exit:1 -e match:'twice' -o ignore "$JGC" -c "$SOCK" sdwan bird \
	    '{"instances":[{"name":"sw1","fib":1,"spec":{"router_id":"1.1.1.1"}},{"name":"sw1","fib":2,"spec":{"router_id":"1.1.1.1"}}]}'
	# What the form is not: refused before any file is written; what
	# bird -p refuses is not run.
	atf_check -s exit:1 -e match:'sw1: the form.s router_id' -o ignore "$JGC" -c "$SOCK" sdwan bird \
	    '{"instances":[{"name":"sw1","fib":1,"spec":{"router_id":"x"}}]}'
	atf_check -s exit:1 -e match:'sw1: the form.s service: a word' -o ignore "$JGC" -c "$SOCK" sdwan bird \
	    '{"instances":[{"name":"sw1","fib":1,"spec":{"service":"a\";\nprotocol x","router_id":"1.1.1.1"}}]}'
	atf_check -s exit:1 -e match:'does not take it' -o ignore "$JGC" -c "$SOCK" sdwan bird \
	    '{"instances":[{"name":"sw1","fib":1,"spec":{"service":"BROKEN","router_id":"1.1.1.1"}}]}'
	atf_check -o empty "$JGC" -c "$SOCK" sdwan bird \
	    '{"instances":[{"name":"sw1","fib":1,"host":"edge-a","spec":{"service":"acme","fib":1,"table":1,"router_id":"100.64.0.0"}}]}'
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
	# The breakout's default route steered too: by the first candidate
	# whose beacon is not down (none probed here: the first), put in its
	# table in place of what was there; told in the read.
	: > route.log
	atf_check -o empty "$JGC" -c "$SOCK" sdwan steer \
	    '{"entries":[{"table":"sw1_known","prefix":"10.1.0.0/24","candidates":[{"id":"t1","via":"100.64.0.1"},{"id":"t2","via":"100.64.0.3"}]}],"routes":[{"fib":2,"destination":"0.0.0.0/0","candidates":[{"id":"bo:a-inet","via":"192.0.2.254"},{"id":"bo:a-wg","via":"192.0.2.253"}]}]}'
	atf_check -o match:'^0 route-del 0.0.0.0/0 - - 2 0$' -o match:'^0 route-add 0.0.0.0/0 192.0.2.254 - 2 0 0 -$' cat route.log
	atf_check -o match:'"routes":\[\{"fib":2,"destination":"0.0.0.0/0","chosen":0,"candidates":\[\{"id":"bo:a-inet","via":"192.0.2.254","state":"not probed"\},\{"id":"bo:a-wg","via":"192.0.2.253","state":"not probed"\}\]\}\]' \
	    "$JGC" -c "$SOCK" sdwan
	atf_check -s exit:1 -e match:"fib: 'x' is not a value" -o ignore "$JGC" -c "$SOCK" sdwan steer \
	    '{"entries":[],"routes":[{"fib":"x"}]}'
	atf_check -o empty "$JGC" -c "$SOCK" sdwan bird \
	    '{"instances":[{"name":"sw1","fib":1,"host":"edge-a","spec":{"service":"acme","fib":1,"table":1,"router_id":"100.64.0.0","direct":["lo1"]}}]}'
	atf_check -o match:'configure$' cat birdc.log
	atf_check -o inline:'1\n' sh -c "grep -c '^setfib' setfib.log"
	# An edge that is a vnet jail: its instance run in the jail by jexec,
	# its file beneath the jail's root, named with the jail, kept in a
	# file of its own; the host's instance beside it, untouched.
	R=$(pwd)/jroot
	mkdir -p "$R/var/run"
	echo "gw 7 new $R" > jails
	cat > fake-jexec <<EOS
#!/bin/sh
echo "jexec \$*" >> $(pwd)/jexec.log
shift
# The jail's /var/run is beneath its root here.
n=0; for a; do case "\$a" in /var/run/*) a="$R\$a" ;; esac; set -- "\$@" "\$a"; n=\$((n+1)); done
shift \$n
exec "\$@"
EOS
	chmod +x fake-jexec
	atf_check -s exit:1 -e match:'not running' -o ignore "$JGC" -c "$SOCK" sdwan bird \
	    '{"jail":"nope","instances":[{"name":"sw1-nope","fib":1,"spec":{"service":"acme","router_id":"100.64.0.2"}}]}'
	atf_check -o empty "$JGC" -c "$SOCK" sdwan bird \
	    '{"jail":"gw","instances":[{"name":"sw1-gw","fib":1,"host":"edge-a/gw","spec":{"service":"acme","fib":1,"table":1,"router_id":"100.64.0.2"}}]}'
	atf_check -o match:'^jexec 7 .*fake-bird -p -c /var/run/arcana-sdwan-bird-sw1-gw.conf$' \
	    -o match:'^jexec 7 .*fake-setfib -F 1 .*fake-bird -c /var/run/arcana-sdwan-bird-sw1-gw.conf -s /var/run/arcana-sdwan-bird-sw1-gw.ctl -P /var/run/arcana-sdwan-bird-sw1-gw.pid$' \
	    -o match:'^jexec 7 .*fake-birdc -s /var/run/arcana-sdwan-bird-sw1-gw.ctl show status$' cat jexec.log
	atf_check -o match:'^router id 100.64.0.2;$' cat "$R/var/run/arcana-sdwan-bird-sw1-gw.conf"
	atf_check -o match:'"name":"sw1","fib":1,"running":true' -o match:'"name":"sw1-gw","fib":1,"jail":"gw","running":true' \
	    "$JGC" -c "$SOCK" sdwan
	test -f "$(dirname "$f")/sdwan-bird@gw.json" || atf_fail "the jail's instances are not kept"
	atf_check -o empty "$JGC" -c "$SOCK" sdwan bird '{"jail":"gw","instances":[]}'
	atf_check -o match:'"name":"sw1","fib":1' -o not-match:'sw1-gw' "$JGC" -c "$SOCK" sdwan
	atf_check -o match:'^jexec 7 .*fake-birdc -s /var/run/arcana-sdwan-bird-sw1-gw.ctl down$' cat jexec.log
	test ! -f "$R/var/run/arcana-sdwan-bird-sw1-gw.conf" || atf_fail "the jail's file stayed"
	test ! -f "$(dirname "$f")/sdwan-bird@gw.json" || atf_fail "the jail's kept file stayed"
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
	# dnsmasq --test not run; one rendered from its form, started in
	# its table with the pid and lease files added to its file; listed
	# with the leases it gave; stopped when not named.
	atf_check -s exit:1 -e match:'an instance is' -o ignore "$JGC" -c "$SOCK" sdwan dhcp \
	    '{"instances":[{"name":"sw1","fib":1,"conf":"port=0\n"}]}'
	atf_check -s exit:1 -e match:'does not take it' -o ignore "$JGC" -c "$SOCK" sdwan dhcp \
	    '{"instances":[{"name":"sw1","fib":1,"spec":{"service":"BROKEN","unis":[]}}]}'
	atf_check -o empty "$JGC" -c "$SOCK" sdwan dhcp \
	    '{"instances":[{"name":"sw1","fib":1,"host":"edge-a","spec":{"service":"acme","fib":1,"unis":[{"id":"uni-hq","interface":"lo1","ipv4":{"mode":"dhcp","prefix":"10.1.0.0/24","provider":["10.1.0.1"]}}]}}]}'
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
	    '{"instances":[{"name":"sw1","fib":1,"spec":{"service":"BROKEN"}}]}'
	atf_check -s exit:1 -e match:'a zone is named' -o ignore "$JGC" -c "$SOCK" sdwan dns \
	    '{"instances":[{"name":"sw1","fib":1,"spec":{"service":"acme","zones":[{"name":"z 0"}]}}]}'
	atf_check -o empty "$JGC" -c "$SOCK" sdwan dns \
	    '{"instances":[{"name":"sw1","fib":1,"host":"edge-a","spec":{"service":"acme","fib":1,"unis":[{"id":"uni-hq","address":"10.1.0.1","prefix":"10.1.0.0/24"}],"zones":[{"name":"z0","prefixes":["10.1.0.0/24"],"dnf":{"no-match":"allow","block":["ads.example"]}}]}}]}'
	atf_check -o match:'^setfib -F 1 .*fake-local-unbound -c .*sdwan-dns-sw1.conf$' cat setfib.log
	atf_check -o match:'^checkconf .*sdwan-dns-sw1.conf$' cat unbound.log
	atf_check -o match:'^	interface: 10.1.0.1$' -o match:'^	pidfile: ".*sdwan-dns-sw1.pid"$' -o match:'^	username: ""$' \
	    cat "$(dirname "$f")/sdwan-dns-sw1.conf"
	atf_check -o match:'"dns":\[\{"name":"sw1","fib":1,"running":true\}\]' "$JGC" -c "$SOCK" sdwan
	# A PDNS's CNAME and NS entries as a response policy zone of the
	# zone's, a file of its own named in the configuration; DNS over
	# TLS with a key and a certificate of the UNIs' addresses, made
	# once and told in the read, made again for other addresses.
	atf_check -o empty "$JGC" -c "$SOCK" sdwan dns \
	    '{"instances":[{"name":"sw1","fib":1,"host":"edge-a","spec":{"service":"acme","fib":1,"dot":true,"unis":[{"id":"uni-hq","address":"10.1.0.1","prefix":"10.1.0.0/24"}],"zones":[{"name":"z0","prefixes":["10.1.0.0/24"],"pdns":{"no-match":"allow","block":[{"type":"CNAME","value":"bad.example"}]}}]}}]}'
	atf_check -o match:'zonefile: ".*sdwan-dns-sw1.rpz-z0"$' -o match:'tls-service-key: ".*sdwan-dns-sw1.tls.key"$' \
	    -o match:'tls-service-pem: ".*sdwan-dns-sw1.tls.pem"$' -o match:'^	interface: 10.1.0.1@853$' cat "$(dirname "$f")/sdwan-dns-sw1.conf"
	atf_check -o match:'^bad.example CNAME \.$' cat "$(dirname "$f")/sdwan-dns-sw1.rpz-z0"
	atf_check -o match:'IP Address:10.1.0.1' openssl x509 -noout -text -in "$(dirname "$f")/sdwan-dns-sw1.tls.pem"
	atf_check -o match:'"dns":\[\{"name":"sw1","fib":1,"running":true,"tls_cert":"-----BEGIN CERTIFICATE-----' "$JGC" -c "$SOCK" sdwan
	cp "$(dirname "$f")/sdwan-dns-sw1.tls.pem" tls.was
	atf_check -o empty "$JGC" -c "$SOCK" sdwan dns \
	    '{"instances":[{"name":"sw1","fib":1,"host":"edge-a","spec":{"service":"acme","fib":1,"dot":true,"unis":[{"id":"uni-hq","address":"10.1.0.1","prefix":"10.1.0.0/24"}],"zones":[]}}]}'
	atf_check cmp -s tls.was "$(dirname "$f")/sdwan-dns-sw1.tls.pem"
	test ! -f "$(dirname "$f")/sdwan-dns-sw1.rpz-z0" || atf_fail "a response policy zone not named stayed"
	atf_check -o empty "$JGC" -c "$SOCK" sdwan dns \
	    '{"instances":[{"name":"sw1","fib":1,"host":"edge-a","spec":{"service":"acme","fib":1,"dot":true,"unis":[{"id":"uni-hq","address":"10.1.0.2","prefix":"10.1.0.0/24"}],"zones":[]}}]}'
	atf_check -o match:'IP Address:10.1.0.2' openssl x509 -noout -text -in "$(dirname "$f")/sdwan-dns-sw1.tls.pem"
	atf_check -s exit:1 -e match:'upstream: each a server' -o ignore "$JGC" -c "$SOCK" sdwan dns \
	    '{"instances":[{"name":"sw1","fib":1,"spec":{"service":"acme","upstream":["not an address"]}}]}'
	atf_check -o empty "$JGC" -c "$SOCK" sdwan dns '{"instances":[]}'
	test ! -f "$(dirname "$f")/sdwan-dns-sw1.conf" || atf_fail "the dns instance's file stayed"
	atf_check -o match:'"dns":\[\]' "$JGC" -c "$SOCK" sdwan
	# The proxies (Squid, a plugin): one not taken by squid -k parse not
	# run; one rendered from its form, started in its table with the
	# agent's paths in it, its CA made by openssl once and told; the
	# certificate cache made for inspect; a running one reconfigured;
	# stopped when not named.
	sni='{"flavor":"sdwan","service":"acme","fib":1,"listen":[{"end_point":"hq","address":"10.1.0.1"}],"zones":[]}'
	atf_check -s exit:1 -e match:'an instance is' -o ignore "$JGC" -c "$SOCK" sdwan proxy \
	    '{"instances":[{"name":"sw1","fib":1,"mode":"sni","conf":"pid_filename /x\n"}]}'
	atf_check -s exit:1 -e match:'does not take it' -o ignore "$JGC" -c "$SOCK" sdwan proxy \
	    '{"instances":[{"name":"sw1","fib":1,"mode":"sni","spec":{"flavor":"sdwan","service":"BROKEN"}}]}'
	atf_check -o empty "$JGC" -c "$SOCK" sdwan proxy \
	    '{"instances":[{"name":"sw1","fib":1,"mode":"sni","host":"edge-a","spec":'"$sni"'}]}'
	atf_check -o match:'^setfib -F 1 .*tools/squid -f .*sdwan-proxy-sw1.conf$' cat setfib.log
	atf_check -o match:'^squid -k parse -f .*sdwan-proxy-sw1.conf$' cat squid.log
	atf_check -o match:'^pid_filename .*sdwan-proxy-sw1.pid$' -o match:'^https_port 10.1.0.1:3129 intercept ssl-bump tls-cert=.*sdwan-proxy-sw1.pem generate-host' \
	    -o match:'^sslcrtd_program .*tools/security_file_certgen -s .*sdwan-proxy-sw1.ssl_db -M 4MB$' \
	    cat "$(dirname "$f")/sdwan-proxy-sw1.conf"
	atf_check -o empty cat "$(dirname "$f")/sdwan-proxy-sw1.deny"
	atf_check -o match:'BEGIN CERTIFICATE' -o match:'BEGIN PRIVATE KEY' cat "$(dirname "$f")/sdwan-proxy-sw1.pem"
	atf_check -o match:'"proxy":\[\{"name":"sw1","fib":1,"mode":"sni","running":true,"ca":"-----BEGIN CERTIFICATE-----' "$JGC" -c "$SOCK" sdwan
	cp "$(dirname "$f")/sdwan-proxy-sw1.crt" ca.was
	atf_check -o empty "$JGC" -c "$SOCK" sdwan proxy \
	    '{"instances":[{"name":"sw1","fib":1,"mode":"inspect","host":"edge-a","spec":'"$sni"'}]}'
	atf_check -o match:'^squid -k reconfigure -f .*sdwan-proxy-sw1.conf$' -o match:'^certgen -c -s .*sdwan-proxy-sw1.ssl_db -M 4MB$' cat squid.log
	atf_check cmp -s ca.was "$(dirname "$f")/sdwan-proxy-sw1.crt"
	# Lists by name (a zone's Block and Allow): each a file beside the
	# conf, named in it; those not named again gone; names of other
	# letters refused.
	atf_check -o empty "$JGC" -c "$SOCK" sdwan proxy \
	    '{"instances":[{"name":"sw1","fib":1,"mode":"sni","host":"edge-a","spec":{"flavor":"sdwan","service":"acme","fib":1,"listen":[],"zones":[{"name":"z0","prefixes":["10.1.0.0/24"],"urlf":{"no-match":"allow"}}]},"lists":{"z0-block":".bad.example\n","z0-allow":".good.example\n"}}]}'
	atf_check -o match:'^acl z0_fblock_d dstdomain ".*sdwan-proxy-sw1.list-z0-block"$' -o match:'^acl z0_fallow_d dstdomain ".*sdwan-proxy-sw1.list-z0-allow"$' \
	    -o match:'^acl z0_fblock_n ssl::server_name ".*sdwan-proxy-sw1.list-z0-block"$' \
	    cat "$(dirname "$f")/sdwan-proxy-sw1.conf"
	atf_check -o inline:'.bad.example\n' cat "$(dirname "$f")/sdwan-proxy-sw1.list-z0-block"
	atf_check -o inline:'.good.example\n' cat "$(dirname "$f")/sdwan-proxy-sw1.list-z0-allow"
	atf_check -o empty "$JGC" -c "$SOCK" sdwan proxy \
	    '{"instances":[{"name":"sw1","fib":1,"mode":"sni","host":"edge-a","spec":{"flavor":"sdwan","service":"acme","fib":1,"listen":[],"zones":[{"name":"z0","prefixes":["10.1.0.0/24"],"urlf":{"no-match":"allow"}}]},"lists":{"z0-block":".worse.example\n"}}]}'
	atf_check -o inline:'.worse.example\n' cat "$(dirname "$f")/sdwan-proxy-sw1.list-z0-block"
	atf_check -o not-match:'z0_fallow' cat "$(dirname "$f")/sdwan-proxy-sw1.conf"
	test ! -f "$(dirname "$f")/sdwan-proxy-sw1.list-z0-allow" || atf_fail "a list not named stayed"
	atf_check -s exit:1 -e match:'its lists' -o ignore "$JGC" -c "$SOCK" sdwan proxy \
	    '{"instances":[{"name":"sw1","fib":1,"mode":"sni","spec":'"$sni"',"lists":{"../x":"y"}}]}'
	# Malware scanned: c-icap of the instance's own, its file rendered
	# from the same form, started first in its table, its pid file and
	# command socket in it, told in the read; gone with the instance.
	atf_check -o empty "$JGC" -c "$SOCK" sdwan proxy \
	    '{"instances":[{"name":"sw1","fib":1,"mode":"sni","host":"edge-a","spec":{"flavor":"sdwan","service":"acme","fib":1,"listen":[{"end_point":"hq","address":"10.1.0.1"}],"icap":true,"zones":[]}}]}'
	atf_check -o match:'^setfib -F 1 .*tools/c-icap -f .*sdwan-icap-sw1.conf$' cat setfib.log
	atf_check -o match:'^PidFile .*sdwan-icap-sw1.pid$' -o match:'^CommandsSocket .*sdwan-icap-sw1.ctl$' \
	    -o match:'^Port 10.1.0.1:1354$' cat "$(dirname "$f")/sdwan-icap-sw1.conf"
	atf_check -o match:'^icap_service sdwan_av respmod_precache bypass=off icap://10.1.0.1:1354/avscan$' \
	    cat "$(dirname "$f")/sdwan-proxy-sw1.conf"
	atf_check -o match:'"proxy":\[\{"name":"sw1","fib":1,"mode":"sni","running":true,"icap":true' "$JGC" -c "$SOCK" sdwan
	ipid=$(cat "$(dirname "$f")/sdwan-icap-sw1.pid")
	# The MD+R policies' hashes as ClamAV's signature files in its
	# database directory, rendered from the zones' forms (MD5 in hdb
	# with its size, SHA-256 of an Allow in sfp, the name saying whose)
	# and written before c-icap starts; a file with nothing for it
	# gone; an entry that is not a hash refused.
	atf_check -o empty "$JGC" -c "$SOCK" sdwan proxy \
	    '{"instances":[{"name":"sw1","fib":1,"mode":"sni","host":"edge-a","spec":{"flavor":"sdwan","service":"acme","fib":1,"listen":[{"end_point":"hq","address":"10.1.0.1"}],"icap":true,"zones":[{"name":"z0","prefixes":["10.1.0.0/24"],"mdr":{"id":"g-mdr","no-match":"allow","block":["44D88612FEA8A8F36DE82E1278ABB02F:68"],"allow":["275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"]}}]}}]}'
	atf_check -o inline:'44d88612fea8a8f36de82e1278abb02f:68:Arcana.acme.g-mdr.block\n' cat root/var/db/clamav/arcana-sdwan.hdb
	atf_check -o inline:'275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f:*:Arcana.acme.g-mdr.allow:73\n' cat root/var/db/clamav/arcana-sdwan.sfp
	test ! -f root/var/db/clamav/arcana-sdwan.hsb || atf_fail "a signature file with nothing for it stayed"
	atf_check -s exit:1 -e match:'is not a hash' -o ignore "$JGC" -c "$SOCK" sdwan proxy \
	    '{"instances":[{"name":"sw1","fib":1,"mode":"sni","host":"edge-a","spec":{"flavor":"sdwan","service":"acme","fib":1,"listen":[],"zones":[{"name":"z0","prefixes":["10.1.0.0/24"],"mdr":{"id":"g-mdr","no-match":"allow","block":["44d8; rm -rf /"]}}]}}]}'
	atf_check -o empty "$JGC" -c "$SOCK" sdwan proxy '{"instances":[]}'
	test ! -f root/var/db/clamav/arcana-sdwan.hdb || atf_fail "the hashes stayed"
	atf_check -o empty "$JGC" -c "$SOCK" sdwan proxy \
	    '{"instances":[{"name":"sw1","fib":1,"mode":"sni","host":"edge-a","spec":{"flavor":"sdwan","service":"acme","fib":1,"listen":[{"end_point":"hq","address":"10.1.0.1"}],"icap":true,"zones":[]}}]}'
	ipid=$(cat "$(dirname "$f")/sdwan-icap-sw1.pid")
	atf_check -o empty "$JGC" -c "$SOCK" sdwan proxy '{"instances":[]}'
	test ! -f "$(dirname "$f")/sdwan-proxy-sw1.conf" || atf_fail "the proxy instance's file stayed"
	test ! -f "$(dirname "$f")/sdwan-icap-sw1.conf" || atf_fail "the c-icap file stayed"
	alive "$ipid" && atf_fail "c-icap still runs"
	atf_check -o match:'"proxy":\[\]' "$JGC" -c "$SOCK" sdwan
	# The Security section's own (group security, named sec-): kept
	# apart, neither list stopping the other's; rendered from its form
	# (the page's), the domains it denies a file named in it; its
	# forms told back.
	web='{"name":"sec-web","listen":["10.1.0.1"],"allow":["10.1.0.0/24"],"deny":[".bad.example"]}'
	atf_check -o empty "$JGC" -c "$SOCK" sdwan proxy \
	    '{"instances":[{"name":"sw1","fib":1,"mode":"sni","host":"edge-a","spec":'"$sni"'}]}'
	atf_check -s exit:1 -e match:'named sec-' -o ignore "$JGC" -c "$SOCK" sdwan proxy \
	    '{"group":"security","instances":[{"name":"web","fib":0,"mode":"sni","spec":'"$web"'}]}'
	atf_check -s exit:1 -e match:'named sec-' -o ignore "$JGC" -c "$SOCK" sdwan proxy \
	    '{"instances":[{"name":"sec-web","fib":0,"mode":"sni","spec":'"$web"'}]}'
	atf_check -s exit:1 -e match:'sec-web: allow \(the networks that may use it\): 10.1.0.0/x is not one' -o ignore "$JGC" -c "$SOCK" sdwan proxy \
	    '{"group":"security","instances":[{"name":"sec-web","fib":0,"mode":"sni","spec":{"name":"sec-web","listen":["10.1.0.1"],"allow":["10.1.0.0/x"]}}]}'
	atf_check -o empty "$JGC" -c "$SOCK" sdwan proxy \
	    '{"group":"security","instances":[{"name":"sec-web","fib":0,"mode":"sni","host":"edge-a","spec":'"$web"'}]}'
	atf_check -o match:'^acl denied_site ssl::server_name ".*sdwan-proxy-sec-web.deny"$' \
	    -o match:'^http_port 10.1.0.1:3128 ssl-bump tls-cert=.*sdwan-proxy-sec-web.pem ' \
	    cat "$(dirname "$f")/sdwan-proxy-sec-web.conf"
	atf_check -o inline:'.bad.example\n' cat "$(dirname "$f")/sdwan-proxy-sec-web.deny"
	atf_check -o match:'"name":"sw1",[^]]*"group":"sdwan"' -o match:'"name":"sec-web",[^]]*"group":"security"' \
	    -o match:'"security_proxy":\[\{"name":"sec-web","listen":\["10.1.0.1"\],"allow":\["10.1.0.0/24"\],"deny":\[".bad.example"\]\}\]' "$JGC" -c "$SOCK" sdwan
	atf_check -o empty "$JGC" -c "$SOCK" sdwan proxy '{"instances":[]}'
	atf_check -o match:'"proxy":\[\{"name":"sec-web"' "$JGC" -c "$SOCK" sdwan
	atf_check -o empty "$JGC" -c "$SOCK" sdwan proxy '{"group":"security","instances":[]}'
	atf_check -o match:'"proxy":\[\]' -o match:'"security_proxy":\[\]' "$JGC" -c "$SOCK" sdwan
	# Intrusion detection: Suricata of each instance checked,
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
	# The same again: nothing to commit, arcana-sdwan's apply sets it
	# again, as it was.
	atf_check -o match:'suricata sw1 on 1 interface, detects: as it was' "$JGC" -t -c "$SOCK" sdwan ids "$ids"
	atf_check -o inline:"$spid\n" cat "$(dirname "$f")/sdwan-ids-sw1.pid"
	# One that prevents: run on its divert port; not running, a
	# Critical fault (what it guards passes nothing), cleared once it
	# runs again.
	atf_check -s exit:1 -e match:"divert: '70000' is not a value" -o ignore "$JGC" -c "$SOCK" sdwan ids \
	    '{"instances":[{"name":"sw1","interfaces":["wg5"],"conf":"x","divert":70000}]}'
	ipsd=$(echo "$ids" | sed 's/"name":"sw1",/"name":"sw1","divert":8001,/')
	atf_check -o match:'suricata sw1 on 1 interface, prevents by divert 8001: started' \
	    "$JGC" -t -c "$SOCK" sdwan ids "$ipsd"
	atf_check -o match:'^suricata -c .*sdwan-ids-sw1.yaml --pidfile .*sdwan-ids-sw1.pid -d 8001 -D$' cat suricata.log
	atf_check -o match:'"ids":\[\{"name":"sw1","interfaces":\["wg5"\],"mode":"prevent","divert":8001,"running":true' \
	    "$JGC" -c "$SOCK" sdwan
	kill "$(cat "$(dirname "$f")/sdwan-ids-sw1.pid")"
	sleep 2
	# No rule of ipfw's diverts to it: nothing held up, a Warning;
	# one that does, read again, makes it Critical.
	atf_check -o match:'"kind":"sdwan-fault","data":\{"type":"ids","severity":"Warning","object":"sw1","by":"suricata","description":"Suricata sw1, which prevents, is not running; no rule of ipfw' \
	    -o not-match:'"severity":"Critical","object":"sw1"' "$JGC" -c "$SOCK" events
	touch diverting
	sleep 11
	rm diverting
	atf_check -o match:'"kind":"sdwan-fault","data":\{"type":"ids","severity":"Critical","object":"sw1","by":"suricata","description":"Suricata sw1, which prevents, is not running: what ipfw diverts' \
	    "$JGC" -c "$SOCK" events
	atf_check -o empty "$JGC" -c "$SOCK" sdwan ids "$ipsd"
	sleep 2
	atf_check -o match:'"kind":"sdwan-fault","data":\{"type":"ids","severity":"Cleared","object":"sw1","description":"Suricata sw1 runs again"' \
	    "$JGC" -c "$SOCK" events
	atf_check -o empty "$JGC" -c "$SOCK" sdwan ids '{"instances":[]}'
	test ! -f "$(dirname "$f")/sdwan-ids-sw1.yaml" || atf_fail "the suricata file stayed"
	alive "$spid" && atf_fail "suricata still runs"
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
	atf_check -o match:'"matched":3,"offset":1,"limit":1,"rules":\[\{"sid":2000005,[^]]*\],"groups"' \
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
	# A group at a time: a classtype's rules (matched by their option),
	# a source's file; each classtype counted; modify.conf kept and
	# given; each back to the default.
	atf_check -o match:'done' "$JGC" -c "$SOCK" suricata rule \
	    off=classtype:policy-violation on=group:emerging-games.rules
	atf_check -o match:'^re:classtype:\\s\*policy-violation\\s\*;$' cat suricata-disable.conf
	atf_check -o match:'^group:emerging-games.rules$' cat suricata-enable.conf
	atf_check -o match:'"groups":\[\{"match":"classtype:policy-violation","state":"off"\},\{"match":"group:emerging-games.rules","state":"on"\}\]' \
	    -o match:'"classes":\[\{"classtype":"policy-violation","rules":1,"enabled":0\},\{"classtype":"bad-unknown","rules":1,"enabled":1\}\]' \
	    "$JGC" -c "$SOCK" suricata rules
	atf_check -s exit:1 -e match:'a group classtype:NAME or group:FILE' \
	    "$JGC" -c "$SOCK" suricata rule off=classtype:Bad!
	printf '2000005 "flow:established" "flow:established,to_server"\n' > mod.txt
	atf_check -o match:'done' "$JGC" -c "$SOCK" suricata rule modify mod.txt
	atf_check -o match:' --modify-conf .*/suricata-modify.conf --offline$' tail -1 suricata-update.log
	atf_check -o match:'"modify":"2000005 \\"flow:established\\" \\"flow:established,to_server\\"\\n"' \
	    "$JGC" -c "$SOCK" suricata rules
	printf 'foo "a" "b"\n' > mod2.txt
	atf_check -s exit:1 -e match:'begins with a sid, group: or re:' \
	    "$JGC" -c "$SOCK" suricata rule modify mod2.txt
	printf '2000005 "a"\n' > mod2.txt
	atf_check -s exit:1 -e match:'which rules, "the pattern" "what it becomes"' \
	    "$JGC" -c "$SOCK" suricata rule modify mod2.txt
	printf '' > mod3.txt
	atf_check -o match:'done' "$JGC" -c "$SOCK" suricata rule modify mod3.txt
	atf_check -o match:'done' "$JGC" -c "$SOCK" suricata rule \
	    default=classtype:policy-violation,group:emerging-games.rules
	atf_check -o match:'"groups":\[\]' -o not-match:'"modify":"2000005' "$JGC" -c "$SOCK" suricata rules
	atf_check -o not-match:'modify-conf' tail -1 suricata-update.log
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
	atf_check -o match:'1 rule of the ruleset left out, as Suricata does when it runs: they say what is outside HOME_NET, and with home any nothing is' \
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
	# Only its thresholds new: read again live, not started again.
	n0=$(grep -c '^usr2$' suricata.log)
	atf_check -o match:'detects: its rules read again' "$JGC" -t -c "$SOCK" sdwan ids \
	    "$(echo "$rs7" | sed 's/ip 10.0.0.9/ip 10.0.0.8/')"
	for i in $(seq 1 30); do
		[ "$(grep -c '^usr2$' suricata.log)" -gt "$n0" ] && break
		sleep 0.1
	done
	[ "$(grep -c '^usr2$' suricata.log)" -gt "$n0" ] || atf_fail "no USR2"
	atf_check -o match:'ip 10.0.0.8' cat "$(dirname "$f")/sdwan-ids-sw1.threshold"
	atf_check -s exit:1 -e match:'thresholds is a text' -o ignore "$JGC" -c "$SOCK" sdwan ids \
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
	    -o match:'"ids_host":\{"ncpu":[1-9][0-9]*,"ndomains":[1-9][0-9]*,"irqs":\[' \
	    "$JGC" -c "$SOCK" sdwan
	atf_check -s exit:1 -e match:"netmap's alone" -o ignore "$JGC" -c "$SOCK" sdwan ids \
	    "$(echo "$rs4" | sed 's/"interfaces":\["any"\]/"interfaces":["wg5^"]/')"
	atf_check -s exit:1 -e match:"capture: 'bpf' is not a value" -o ignore "$JGC" -c "$SOCK" sdwan ids \
	    "$(echo "$rs4" | sed 's/"interfaces":/"capture":"bpf","interfaces":/')"
	# What its Suricata is built with; and Suricata's own answers, by
	# the instance's command socket, those that read alone.
	atf_check -o match:'"ids_build":\{"version":"8.0.7","lua":true,"profiling":false,"profiling_rules":false,"hyperscan":false,"netmap":true,"ipfw":true,"plugins":true\}' \
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
	atf_check -o match:'"pcaps":\[\{"path":"[^"]*/sdwan-ids-sw1.d/log.pcap.1792400000","size":7,"at":[0-9]+,"from":1792400000\}' \
	    "$JGC" -c "$SOCK" sdwan
	# One of them read back whole, as a stream (the alert's download);
	# one past a stream's window too; what is not pcap-log's refused.
	atf_check -o inline:'PCAPLOG' "$JGC" -c "$SOCK" suricata pcap-get instance=sw1 file=log.pcap.1792400000
	dd if=/dev/random of=big.pcap bs=1m count=9 2>/dev/null
	cp big.pcap sdwan-ids-sw1.d/log.pcap.1792400100
	atf_check -o save:got.pcap "$JGC" -c "$SOCK" suricata pcap-get instance=sw1 file=log.pcap.1792400100
	atf_check cmp big.pcap got.pcap
	atf_check -s exit:1 -e match:'log.pcap or a rotation of it' "$JGC" -c "$SOCK" suricata pcap-get instance=sw1 file=eve.json
	atf_check -s exit:1 -e match:'log.pcap or a rotation of it' "$JGC" -c "$SOCK" suricata pcap-get instance=sw1 file=../sdwan-ids-sw1.yaml
	atf_check -s exit:1 -e match:'has no such file' "$JGC" -c "$SOCK" suricata pcap-get instance=sw1 file=log.pcap.1
	ln -sf ../big.pcap sdwan-ids-sw1.d/log.pcap.1792400200
	atf_check -s exit:1 -e match:'not a file of its pcap-log' "$JGC" -c "$SOCK" suricata pcap-get instance=sw1 file=log.pcap.1792400200
	rm sdwan-ids-sw1.d/log.pcap.1792400100 sdwan-ids-sw1.d/log.pcap.1792400200
	# A capture sent to the host (the console's upload): whole, or in
	# parts each where the one before ended; kept beside the replay,
	# which leaves it, replayed from there, listed.
	atf_check -o match:'"path":"[^"]*/sdwan-ids-sw1.replay.d/captures/up.pcap"' \
	    "$JGC" -c "$SOCK" suricata pcap-put instance=sw1 file=up.pcap last=1 < lab.pcap
	atf_check -o inline:'PCAP' cat sdwan-ids-sw1.replay.d/captures/up.pcap
	printf 'AB' > ab
	printf 'CD' > cd
	atf_check -o ignore "$JGC" -c "$SOCK" suricata pcap-put instance=sw1 file=two.pcap < ab
	test -f sdwan-ids-sw1.replay.d/captures/two.pcap && atf_fail "a part was taken for the whole"
	atf_check -s exit:1 -e match:'the part before ended at 2, not 5' \
	    "$JGC" -c "$SOCK" suricata pcap-put instance=sw1 file=two.pcap offset=5 < cd
	atf_check -o ignore "$JGC" -c "$SOCK" suricata pcap-put instance=sw1 file=two.pcap offset=2 last=1 < cd
	atf_check -o inline:'ABCD' cat sdwan-ids-sw1.replay.d/captures/two.pcap
	test -f sdwan-ids-sw1.replay.d/captures/two.pcap.part && atf_fail "the part stayed"
	atf_check -s exit:1 -e match:'no part of it came before' \
	    "$JGC" -c "$SOCK" suricata pcap-put instance=sw1 file=three.pcap offset=2 < cd
	atf_check -o ignore "$JGC" -c "$SOCK" suricata pcap-put instance=sw1 file=big.pcap last=1 < big.pcap
	atf_check cmp big.pcap sdwan-ids-sw1.replay.d/captures/big.pcap
	atf_check -s exit:1 -e match:'its name alone' "$JGC" -c "$SOCK" suricata pcap-put instance=sw1 file=../x.pcap < ab
	atf_check -s exit:1 -e match:'its name alone' "$JGC" -c "$SOCK" suricata pcap-put instance=sw1 file=x.txt < ab
	atf_check -s exit:1 -e match:'no such instance here' "$JGC" -c "$SOCK" suricata pcap-put instance=nosuch file=x.pcap < ab
	atf_check -o match:'done +suricata replays .*/captures/up.pcap through sw1' \
	    "$JGC" -c "$SOCK" suricata pcap instance=sw1 file="$(pwd)/sdwan-ids-sw1.replay.d/captures/up.pcap"
	test -f sdwan-ids-sw1.replay.d/captures/up.pcap || atf_fail "the replay emptied the captures"
	atf_check -o match:'"captures":\[[^]]*"path":"[^"]*/captures/up.pcap","size":4,' "$JGC" -c "$SOCK" sdwan
	rm big.pcap got.pcap
	# What its profiling wrote, read back: the last dump of the packets'
	# ticks, each table's rows; the rules' last JSON; the locks' text.
	printf '\n\nPacket profile dump:\n\n IPv4       1             1              1              1              1  1   100.00\n' > sdwan-ids-sw1.d/packet_stats.log
	printf '\n\nPacket profile dump:\n\nIP ver   Proto   cnt            min            max            avg            tot           %%%%\n------   -----   ------------   ------------   ------------   ------------   ------------  ---\n IPv4       6           100            200           9000            500          50.0k   80.00\n IPv6      17            10            100           1000            300           3000   20.00\n\nPer Thread module stats:\n\nThread Module              IP ver   Proto   cnt            min            max            avg            tot           %%%%\nPcapReceive                  IPv4       6           100             50            900             70           7000   12.50\n\nFlow Worker            IP ver   Proto   cnt            min            max            avg\ndetect                  IPv4     6           100            30            800            120         12.0k  30.00\n' >> sdwan-ids-sw1.d/packet_stats.log
	printf '{"timestamp":"2026-10-19T11:00:00","sort":"ticks","rules":[{"signature_id":1}]}\n{"timestamp":"2026-10-19T12:00:00","sort":"ticks","rules":[{"signature_id":2000009,"gid":1,"rev":1,"checks":40,"matches":2,"ticks_total":9000,"ticks_max":800,"ticks_avg":225,"ticks_avg_match":400,"ticks_avg_nomatch":215,"percent":75}]}\n' > sdwan-ids-sw1.d/rule_perf.log
	printf 'lock contention: none\n' > sdwan-ids-sw1.d/lock_stats.log
	printf '\n\nPacket profile dump:\n\nIP ver   Proto   cnt\n IPv4      17             5             10             20             15             75  100.00\n' > sdwan-ids-sw1.replay.d/packet_stats.log
	atf_check -o save:prof.json "$JGC" -c "$SOCK" suricata rules instance=sw1 profiling=1
	atf_check -o match:'"build":\{"packets":false,"rules":false,"locks":false\}' \
	    -o match:'"running":\{"packets":\{"sections":\[\{"title":"Packets","rows":\[\{"name":"","ip":"IPv4","proto":6,"cnt":100,"min":200,"max":9000,"avg":500,"tot":"50.0k","pct":80' \
	    -o match:'"ip":"IPv6","proto":17,"cnt":10,' \
	    -o match:'\{"title":"Thread Module","rows":\[\{"name":"PcapReceive","ip":"IPv4","proto":6,"cnt":100,"min":50,' \
	    -o match:'\{"title":"Flow Worker","rows":\[\{"name":"detect",[^}]*"avg":120,"tot":"12.0k"' \
	    -o not-match:'"proto":1,' \
	    -o match:'"rules":\{"timestamp":"2026-10-19T12:00:00","sort":"ticks","rules":\[\{"signature_id":2000009,' \
	    -o match:'"locks":\{"text":"lock contention: none\\n","at":[0-9]+\}' \
	    -o match:'"replay":\{"packets":\{"sections":\[\{"title":"Packets","rows":\[\{"name":"","ip":"IPv4","proto":17,"cnt":5,' \
	    cat prof.json
	atf_check -s exit:1 -e match:'no instance nosuch here' "$JGC" -c "$SOCK" suricata rules instance=nosuch profiling=1
	atf_check -s exit:1 -e match:'read by instance= and profiling=1' "$JGC" -c "$SOCK" suricata rules profiling=1
	# Stopped by the admin: not run, its files and its place kept;
	# started again as it was.
	atf_check -o ignore "$JGC" -c "$SOCK" sdwan ids "$rs4"
	pid=$(cat "$(dirname "$f")/sdwan-ids-sw1.pid")
	rs6=$(echo "$rs4" | sed 's/"name":"sw1",/"name":"sw1","stopped":true,/')
	atf_check -o match:'suricata sw1 stopped, kept' \
	    "$JGC" -t -c "$SOCK" sdwan ids "$rs6"
	alive "$pid" && atf_fail "a stopped suricata still runs"
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
	    -o match:'^        - http$' -o match:'^# mine$' -o match:'^unix-command:$' \
	    -o match:'^autofp-scheduler: hash$' cat "$(dirname "$f")/sdwan-ids-sec-x.yaml"
	atf_check -s exit:1 -e match:"autofp's scheduler is hash, ippair or ftp-hash" -o ignore "$JGC" -c "$SOCK" sdwan ids \
	    '{"group":"security","instances":[{"name":"sec-x","interfaces":["lo0"],"spec":{"interfaces":["lo0"],"autofp_scheduler":"round-robin"},"rules":"x"}]}'
	# Its profiling: the sections named on, the others off, each its
	# file; rules from the start, by ticks, as JSON.
	atf_check -o match:'suricata sec-x on 1 interface, detects: started' "$JGC" -t -c "$SOCK" sdwan ids \
	    '{"group":"security","instances":[{"name":"sec-x","host":"edge-a","interfaces":["lo0"],"spec":{"interfaces":["lo0"],"home":["any"],"profiling":["rules","packets"],"profiling_sample_rate":4},"rules":"alert tcp any any -> any 23 (sid:1000001;)\n"}]}'
	atf_check -o match:'^profiling:$' -o match:'^  sample-rate: 4$' \
	    -o match:'^  rules:$' -o match:'^    filename: rule_perf.log$' -o match:'^    active: yes$' \
	    -o match:'^    sort: ticks$' -o match:'^    json: yes$' -o match:'^    filename: packet_stats.log$' \
	    -o match:'^    filename: lock_stats.log$' cat "$(dirname "$f")/sdwan-ids-sec-x.yaml"
	atf_check -o inline:'  rules: yes\n  keywords: no\n  prefilter: no\n  rulegroups: no\n  packets: yes\n  locks: no\n' \
	    awk '/^profiling:/ { p = 1; next } p && /^[a-z]/ { p = 0 } p && /^  [a-z]+:$/ { s = $0 } p && /^    enabled:/ { print s " " $2 }' \
	    "$(dirname "$f")/sdwan-ids-sec-x.yaml"
	atf_check -s exit:1 -e match:"sec-x: profiling's sections are rules, keywords" -o ignore "$JGC" -c "$SOCK" sdwan ids \
	    '{"group":"security","instances":[{"name":"sec-x","interfaces":["lo0"],"spec":{"interfaces":["lo0"],"profiling":["cpu"]},"rules":"x"}]}'
	atf_check -s exit:1 -e match:"sec-x: profiling's sample rate is a power of 2" -o ignore "$JGC" -c "$SOCK" sdwan ids \
	    '{"group":"security","instances":[{"name":"sec-x","interfaces":["lo0"],"spec":{"interfaces":["lo0"],"profiling":["rules"],"profiling_sample_rate":3},"rules":"x"}]}'
	atf_check -s exit:1 -e match:'sec-x: its own YAML may not set profiling' -o ignore "$JGC" -c "$SOCK" sdwan ids \
	    '{"group":"security","instances":[{"name":"sec-x","interfaces":["lo0"],"spec":{"interfaces":["lo0"],"yaml":"profiling:\n  rules:\n"},"rules":"x"}]}'
	# netmap's pair of a bridge's member: refused, the bridge would
	# carry its packets around the pair.
	cp fake-ifconfig fake-ifconfig.was
	printf '#!/bin/sh\n[ "$1" = -av ] && printf "bridge0: flags=8843<UP> metric 0 mtu 1500\\n\\tid 58:9c:fc:10:ff:aa priority 32768 hellotime 2 fwddelay 15\\n\\tmember: wg6 flags=143<LEARNING,DISCOVER>\\n"\nexit 0\n' > fake-ifconfig
	atf_check -s exit:1 -e match:'sec-y: wg6 is a member of bridge0' -o ignore "$JGC" -c "$SOCK" sdwan ids \
	    '{"group":"security","instances":[{"name":"sec-y","interfaces":["wg6","wg7"],"spec":{"pairs":["wg6:wg7"],"capture":"netmap","home":["any"]},"rules":"x"}]}'
	mv fake-ifconfig.was fake-ifconfig
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
	# Its pid file written, then stopped: not started, and why is the
	# first error of the start, not the rules it left out.
	rs6=$(echo "$rs3" | sed 's/rule-files:/# DIESTART\\nrule-files:/')
	atf_check -s exit:1 -e match:"did not start: Error: ipfw: Can't create divert socket: .*; Error: suricata: Engine initialization failed" \
	    -e not-match:'IP space' -o ignore "$JGC" -c "$SOCK" sdwan ids "$rs6"
	atf_check -o empty "$JGC" -c "$SOCK" sdwan ids '{"instances":[]}'
}
sdwan_cleanup()
{
	stop_daemon
}

atf_test_case sdwan_forms cleanup
sdwan_forms_head()
{
	atf_set "descr" "The SD-WAN daemons' files rendered from the console's forms: dnsmasq's, unbound's, Squid's, c-icap's and BIRD's, as the console's plans have them"
}
# Whether a file holds a text, lines and all, as written.
has_text()
{
	case "$(cat "$1")" in
	*"$2"*) return 0 ;;
	esac
	return 1
}
# The kept file of a name, beside the agent's kept files.
kept()
{
	find . -name "$1" | head -1
}
sdwan_forms_body()
{
	mkdir -p tools
	sdwan_daemons
	DAEMON_ARGS="-3 $(pwd)/fake-setfib -2 $(pwd)/tools"
	start_daemon
	# dnsmasq: hq's IPv4 by DHCP, its ranges the subnet less the
	# reserved prefixes and the provider's address, the router and the
	# DNS servers told.
	cat > dhcp.json <<'EOS'
{"instances":[{"name":"sw1","fib":1,"host":"a","spec":{"service":"acme","fib":1,"unis":[{"id":"uni-hq","interface":"lo0","ipv4":{"mode":"dhcp","prefix":"10.1.0.0/24","provider":["10.1.0.1"],"reserved":["10.1.0.0/26","10.1.0.200/30"],"lease":"1h","dns":["10.1.0.1"]}}]}}]}
EOS
	atf_check -o empty "$JGC" -c "$SOCK" sdwan dhcp "$(cat dhcp.json)"
	c=$(kept sdwan-dhcp-sw1.conf)
	atf_check -o match:'^# Written by arcana-agent for the Arcana console: SD-WAN service acme at a, in routing table 1\.$' cat "$c"
	has_text "$c" "$(printf 'interface=lo0\ndhcp-range=set:lo0,10.1.0.64,10.1.0.199,255.255.255.0,1h\ndhcp-range=set:lo0,10.1.0.204,10.1.0.254,255.255.255.0,1h\ndhcp-option=tag:lo0,option:router,10.1.0.1\ndhcp-option=tag:lo0,option:dns-server,10.1.0.1\n')" ||
	    atf_fail "dnsmasq's ranges are not the subnet less the reserved"
	# A form that would end a line early is refused.
	atf_check -s exit:1 -e match:'a word of printable characters' -o ignore "$JGC" -c "$SOCK" sdwan dhcp \
	    '{"instances":[{"name":"sw1","fib":1,"spec":{"service":"acme","unis":[{"id":"x","interface":"lo0\nenable-tftp"}]}}]}'

	# unbound: hq's provider address, a view of the zone's own by its
	# prefixes, the Block's names nxdomain, the Allow's transparent,
	# the lists' domains too; checked by the base system's
	# local-unbound-checkconf as well as the stand-in.
	cat > dns.json <<'EOS'
{"instances":[{"name":"sw1","fib":1,"host":"a","spec":{"service":"acme","fib":1,"unis":[{"id":"uni-hq","address":"10.1.0.1","prefix":"10.1.0.0/24"}],"zones":[{"name":"z0","prefixes":["10.1.0.0/16","10.30.0.2/32","10.30.0.64/32"],"dnf":{"no-match":"allow","block":["ads.example"],"allow":["ok.ads.example"],"listed":{"block":["bad-feed.example","bad.example"]}}}]}}]}
EOS
	atf_check -o empty "$JGC" -c "$SOCK" sdwan dns "$(cat dns.json)"
	c=$(kept sdwan-dns-sw1.conf)
	has_text "$c" "$(printf '\tinterface: 10.1.0.1\n\taccess-control: 10.1.0.0/24 allow\n')" ||
	    atf_fail "unbound does not listen on the UNI"
	has_text "$c" "$(printf 'view:\n\tname: "z0"\n\tview-first: yes\n\tlocal-zone: "ads.example." always_nxdomain\n')" ||
	    atf_fail "the zone's view is not there"
	atf_check -o match:'^	access-control-view: 10.1.0.0/16 z0$' \
	    -o match:'^	local-zone: "bad-feed.example." always_nxdomain$' \
	    -o match:'^	local-zone: "bad.example." always_nxdomain$' \
	    -o match:'^	local-zone: "ok.ads.example." always_transparent$' cat "$c"
	atf_check -o ignore local-unbound-checkconf "$c"
	# The PDNS's answers by response-ip, the Default zone's view by all
	# its prefixes.
	cat > dns.json <<'EOS'
{"instances":[{"name":"sw1","fib":1,"host":"a","spec":{"service":"acme","fib":1,"unis":[{"id":"uni-hq","address":"10.1.0.1","prefix":"10.1.0.0/24"}],"zones":[{"name":"z0","prefixes":["10.1.0.0/16","10.30.0.2/32","10.30.0.64/32"],"dnf":{"no-match":"allow","block":["ads.example"],"allow":["ok.ads.example"]},"pdns":{"no-match":"allow","block":[{"type":"A","value":"192.0.2.66"}],"allow":[{"type":"AAAA","value":"any"}]}},{"name":"z1","prefixes":["0.0.0.0/0","::/0"],"dnf":{"no-match":"allow","block":["ads.example"],"allow":["ok.ads.example"]},"pdns":{"no-match":"allow","block":[{"type":"A","value":"192.0.2.66"}],"allow":[{"type":"AAAA","value":"any"}]}}]}}]}
EOS
	atf_check -o empty "$JGC" -c "$SOCK" sdwan dns "$(cat dns.json)"
	atf_check -o match:'^	access-control-view: 0.0.0.0/0 z1$' \
	    -o match:'^	response-ip: 192.0.2.66/32 always_nxdomain$' \
	    -o match:'^	response-ip: ::/0 always_transparent$' cat "$c"
	atf_check -o ignore local-unbound-checkconf "$c"
	# The PDNS's CNAME and NS entries (R104) by a response policy zone
	# of the zone's, for the zone's prefixes alone (a tag); DNS over
	# TLS on the UNI's address, port 853 (D22), and to the servers it
	# asks (D21); a name with a * inside left to Squid; taken by the
	# real unbound.
	cat > dns.json <<'EOS'
{"instances":[{"name":"sw1","fib":1,"host":"a","spec":{"service":"acme","fib":1,"dot":true,"upstream":["192.0.2.53#dns.example","2001:db8::53@8853#dns.example"],"upstream_tls":true,"unis":[{"id":"uni-hq","address":"10.1.0.1","prefix":"10.1.0.0/24"}],"zones":[{"name":"z0","prefixes":["10.1.0.0/16"],"dnf":{"no-match":"allow","block":["ads.example","cdn.*.example"]},"pdns":{"no-match":"allow","block":[{"type":"A","value":"192.0.2.66"},{"type":"CNAME","value":"*.tracker.example"},{"type":"NS","value":"ns.evil.example"},{"type":"NS","value":"198.51.100.53"},{"type":"NS","value":"2001:db8::53/128"}],"allow":[{"type":"CNAME","value":"ok.tracker.example"}]}},{"name":"z1","prefixes":["0.0.0.0/0","::/0"],"dnf":{"no-match":"allow","block":["ads.example"]}}]}}]}
EOS
	atf_check -o empty "$JGC" -c "$SOCK" sdwan dns "$(cat dns.json)"
	c=$(kept sdwan-dns-sw1.conf)
	atf_check -o match:'^	define-tag: "z0"$' -o match:'^	access-control-tag: 10.1.0.0/16 "z0"$' \
	    -o match:'^	interface: 10.1.0.1@853$' -o match:'^	tls-port: 853$' \
	    -o match:'^	tls-service-key: ".*sdwan-dns-sw1.tls.key"$' -o match:'^	tls-cert-bundle: "/etc/ssl/cert.pem"$' \
	    -o not-match:'cdn' cat "$c"
	atf_check -o match:'^rpz:$' -o match:'^	name: "z0.rpz."$' -o match:'^	zonefile: ".*sdwan-dns-sw1.rpz-z0"$' \
	    -o match:'^	tags: "z0"$' -o not-match:'name: "z1.rpz."' cat "$c"
	has_text "$c" "$(printf 'forward-zone:\n\tname: "."\n\tforward-tls-upstream: yes\n\tforward-addr: 192.0.2.53@853#dns.example\n\tforward-addr: 2001:db8::53@8853#dns.example\n')" ||
	    atf_fail "the upstream servers are not asked over TLS"
	z=$(kept sdwan-dns-sw1.rpz-z0)
	has_text "$z" "$(printf '*.tracker.example CNAME .\nns.evil.example.rpz-nsdname CNAME .\n32.53.100.51.198.rpz-nsip CNAME .\n128.53.0.0.0.0.0.db8.2001.rpz-nsip CNAME .\nok.tracker.example CNAME rpz-passthru.\n')" ||
	    atf_fail "the response policy zone's triggers are not as the entries say"
	atf_check -o ignore local-unbound-checkconf "$c"

	# Squid, the URL filter alone (no MBSF): the zone by its prefixes,
	# the TLS name of the Block's host ended, the rest let through
	# unopened, the zone's malware scanned by c-icap, which takes
	# Squid's address alone.
	cat > proxy.json <<'EOS'
{"instances":[{"name":"sw1","fib":1,"mode":"sni","host":"a","spec":{"flavor":"sdwan","service":"acme","fib":1,"listen":[{"end_point":"hq","address":"10.1.0.1"},{"end_point":"road","address":"10.30.0.1"}],"resolver":true,"icap":true,"zones":[{"name":"z0","prefixes":["10.1.0.0/16","10.30.0.2/32","10.30.0.64/32"],"urlf":{"no-match":"allow","block":["bad.example"]},"mdr":true}]},"lists":{}}]}
EOS
	atf_check -o empty "$JGC" -c "$SOCK" sdwan proxy "$(cat proxy.json)"
	c=$(kept sdwan-proxy-sw1.conf)
	atf_check -o match:'^https_port 10.1.0.1:3129 intercept ssl-bump tls-cert=.*sdwan-proxy-sw1.pem generate-host-certificates=on dynamic_cert_mem_cache_size=4MB$' \
	    -o match:'^acl z0 src 10.1.0.0/16 10.30.0.2/32 10.30.0.64/32$' \
	    -o match:'^dns_nameservers 10.1.0.1$' \
	    -o match:'^icap_service sdwan_av respmod_precache bypass=off icap://10.1.0.1:1354/avscan$' cat "$c"
	has_text "$c" "$(printf 'acl z0_u0_n ssl::server_name bad.example\nacl z0_u0_d dstdomain bad.example\n')" ||
	    atf_fail "the Block's host is not an acl"
	has_text "$c" "$(printf 'ssl_bump peek step1\nssl_bump terminate z0 z0_u0_n\nssl_bump splice z0\nssl_bump splice all\n')" ||
	    atf_fail "the TLS steps are not in order"
	has_text "$c" "$(printf 'adaptation_access sdwan_av allow z0\nhttp_access deny z0 z0_u0_d\nhttp_access allow z0\nadaptation_access sdwan_av deny all\nhttp_access deny all\n')" ||
	    atf_fail "the requests' rules are not in order"
	c=$(kept sdwan-icap-sw1.conf)
	atf_check -o match:'^Service avscan virus_scan.so$' -o match:'^client_access deny all$' cat "$c"
	has_text "$c" "$(printf 'Port 10.1.0.1:1354\nacl squid src 10.1.0.1/255.255.255.255\n')" ||
	    atf_fail "c-icap does not take Squid's address alone"
	# A DNF's names with a * inside (R71), which unbound does not take:
	# the zone's Squid ends them at the TLS name and refuses them by
	# the request's host, before the rest of the zone's.
	cat > proxy.json <<'EOS'
{"instances":[{"name":"sw1","fib":1,"mode":"sni","host":"a","spec":{"flavor":"sdwan","service":"acme","fib":1,"listen":[{"end_point":"hq","address":"10.1.0.1"}],"zones":[{"name":"z0","dnf":["cdn.*.example","*.track.*"],"prefixes":["10.1.0.0/16"],"urlf":{"no-match":"allow","block":["bad.example"]}}]},"lists":{}}]}
EOS
	atf_check -o empty "$JGC" -c "$SOCK" sdwan proxy "$(cat proxy.json)"
	c=$(kept sdwan-proxy-sw1.conf)
	has_text "$c" "$(printf 'acl z0_dw ssl::server_name_regex -i ^(.+\\.)?cdn\\.[^.]+\\.example$ ^(.+\\.)?track\\.[^.]+$\nacl z0_dwd dstdom_regex -i ^(.+\\.)?cdn\\.[^.]+\\.example$ ^(.+\\.)?track\\.[^.]+$\n')" ||
	    atf_fail "the names with a * inside are not acls"
	has_text "$c" "$(printf 'ssl_bump peek step1\nssl_bump terminate z0 z0_dw\nssl_bump terminate z0 z0_u0_n\n')" ||
	    atf_fail "the names are not ended before the URLF's"
	has_text "$c" "$(printf 'http_access deny z0 z0_dwd\nhttp_access deny z0 z0_u0_d\n')" ||
	    atf_fail "the names are not refused before the URLF's"
	# With an MBSF: TLS opened (inspect), the oldest let through 1.2
	# both ways; the office zone first, Default after it; bank.example
	# never opened; plain HTTP blocked; the URLF's paths by their regex,
	# the more specific Allow before the Block of its host; No-match
	# block, the requests deciding: no name ends a connection.
	cat > proxy.json <<'EOS'
{"instances":[{"name":"sw1","fib":1,"mode":"inspect","host":"a","spec":{"flavor":"sdwan","service":"acme","fib":1,"listen":[{"end_point":"hq","address":"10.1.0.1"},{"end_point":"road","address":"10.30.0.1"}],"resolver":true,"icap":true,"zones":[{"name":"z0","prefixes":["10.1.0.0/16","10.30.0.2/32","10.30.0.64/32"],"urlf":{"no-match":"block","block":["bad.example","*.worse.example/ads/*"],"allow":["bad.example/ok"]},"mbsf":{"no-match":"block","block":["tls1.0","tls1.1"],"allow":["tls1.2","tls1.3"],"pass-through":["bank.example"],"invalid-server-certificate":"block","unencrypted":"block"},"mdr":true},{"name":"z1","default":true,"urlf":{"no-match":"block","block":["bad.example","*.worse.example/ads/*"],"allow":["bad.example/ok"]},"mbsf":{"no-match":"block","block":["tls1.0","tls1.1"],"allow":["tls1.2","tls1.3"],"pass-through":["bank.example"],"invalid-server-certificate":"block","unencrypted":"block"},"mdr":true}]},"lists":{}}]}
EOS
	atf_check -o empty "$JGC" -c "$SOCK" sdwan proxy "$(cat proxy.json)"
	c=$(kept sdwan-proxy-sw1.conf)
	atf_check -o match:' tls-min-version=1\.2$' -o match:'^tls_outgoing_options min-version=1\.2$' \
	    -o match:'^acl z1 src all$' -o match:'^acl z0_pass ssl::server_name bank\.example$' \
	    -o match:'^ssl_bump splice z0 z0_pass$' -o match:'^http_access deny z0 plain$' \
	    -o match:'url_regex -i \^https\?://bad\\\.example/ok\$$' \
	    -o match:'url_regex -i \^https\?://\(\[\^/\]\*\\\.\)\?worse\\\.example/ads/\.\*$' \
	    -o not-match:'ssl::server_name bad\.example' cat "$c"
	atf_check -o inline:'yes\n' sh -c "test \$(grep -n '^acl z0 ' '$c' | cut -d: -f1) -lt \$(grep -n '^acl z1 ' '$c' | cut -d: -f1) && echo yes"
	has_text "$c" "$(printf 'http_access allow z0 z0_u0_r\nhttp_access deny z0 z0_u1_d\nhttp_access deny z0 z0_u2_r\nhttp_access deny z0\n')" ||
	    atf_fail "the URLF's entries are not most specific first"
	has_text "$c" "$(printf 'ssl_bump splice z0 z0_pass\nssl_bump bump z0\n')" ||
	    atf_fail "TLS is not opened but for the pass-through"

	# BIRD of a service: the router id, the kernel's table learned and
	# kept, the connected routes of the UNI and the tunnels, BFD on
	# the tunnels, what does not go to the other edges, iBGP by the
	# control tunnel alone (a the reflector), and BGP with the
	# subscriber at hq's UNI as its entry says.
	cat > bird.json <<'EOS'
{"instances":[{"name":"sw1","fib":1,"host":"a","spec":{"service":"acme","fib":1,"table":1,"as":64600,"router_id":"100.64.0.0","direct":["lo0","gre100","gif102","gre104"],"bfd":{"interfaces":["gre100","gif102","gre104"],"interval":200,"multiplier":3,"sessions":true},"reject":["100.64.0.0/24","100.64.0.0/24"],"md5":"edges-secret","peers":[{"tunnel":"acme/a-inet-b-inet/ctvc","to":"b","local":"100.64.0.4","neighbor":"100.64.0.5","role":"client","cluster_id":"192.0.2.1"}],"unis":[{"id":"uni-hq","end_point":"hq","interface":"lo0","bgp":{"family":"ipv4","as":65010,"neighbors":["10.1.0.2"],"password":"s3cret","hold_time":90,"distance":150,"communities":[[64600,100]]}}]}},{"name":"ucs3","fib":3,"host":"a","spec":{"flavor":"ucs","end_point":"a-inet","table":3,"router_id":"192.0.2.1","interface":"vtnet0","as":64512,"bgp":{"family":"ipv4","as":65000,"neighbors":["192.0.2.254"],"password":"up"}}}]}
EOS
	atf_check -o empty "$JGC" -c "$SOCK" sdwan bird "$(cat bird.json)"
	c=$(kept sdwan-bird-sw1.conf)
	atf_check -o match:'^# Written by arcana-agent for the Arcana console: SD-WAN service acme at a, in routing table 1\.$' \
	    -o match:'^router id 100\.64\.0\.0;$' -o match:'&& dest = RTD_UNICAST;$' \
	    -o match:'import filter \{ preference = 200; accept; \};' \
	    -o match:'export filter to_edges;' -o not-match:'^# acme/a-inet-b-inet, to' \
	    -o not-match:'protocol bgp edge1 from edge' cat "$c"
	has_text "$c" "$(printf 'kernel table 1;\n\tlearn;\n\tmerge paths on;\n\tpersist;')" ||
	    atf_fail "the kernel's table is not learned and kept"
	has_text "$c" "$(printf 'protocol direct {\n\tipv4;\n\tipv6;\n\tinterface "lo0", "gre100", "gif102", "gre104";\n}')" ||
	    atf_fail "the connected routes are not the UNI's and the tunnels'"
	has_text "$c" "$(printf 'filter to_edges {\n\tif source = RTS_INHERIT then reject;\n\tif net ~ [ 100.64.0.0/24+, 100.64.0.0/24+ ] then reject;\n\taccept;\n}')" ||
	    atf_fail "the reserved prefixes go to the edges"
	has_text "$c" "$(printf '# acme/a-inet-b-inet/ctvc, to b, a client of this reflector\nprotocol bgp edge0 from edge {\n\tlocal 100.64.0.4 as 64600;\n\tneighbor 100.64.0.5 as 64600;\n\trr client;\n\trr cluster id 192.0.2.1;\n}')" ||
	    atf_fail "a does not reflect to b by the control tunnel"
	has_text "$c" "$(printf 'protocol bfd {\n\tinterface "gre100", "gif102", "gre104" {\n\t\tinterval 200 ms;\n\t\tmultiplier 3;\n\t};\n}')" ||
	    atf_fail "BFD is not on the tunnels"
	has_text "$c" "$(printf 'hold time 30;\n\terror wait time 10, 60;\n\tbfd on;\n\tauthentication md5;\n\tpassword "edges-secret";\n')" ||
	    atf_fail "the iBGP template is not BFD's and MD5's"
	has_text "$c" "$(printf 'protocol bgp uni_hq_0 {\n\tlocal as 64600;\n\tneighbor 10.1.0.2 as 65010;\n\tinterface "lo0";\n\tauthentication md5;\n\tpassword "s3cret";\n\thold time 90;\n\tipv4 {\n\t\tpreference 106;\n\t\timport all;\n\t\texport filter {\n\t\t\tbgp_community.add((64600, 100));\n\t\t\taccept;\n\t\t};\n\t};\n}')" ||
	    atf_fail "BGP at hq's UNI is not as its entry says"
	if [ -x /usr/local/sbin/bird ] && [ "$(sysctl -n net.fibs)" -ge 2 ]; then
		atf_check /usr/local/sbin/bird -p -c "$c"
	fi
	# The UCS end point's, with the underlay in its table.
	c=$(kept sdwan-bird-ucs3.conf)
	atf_check -o match:'^# Written by arcana-agent for the Arcana console: UCS end point a-inet at a, routing with the underlay in table 3\.$' cat "$c"
	has_text "$c" "$(printf 'protocol bgp ucs_a_inet_0 {\n\tlocal as 64512;\n\tneighbor 192.0.2.254 as 65000;\n\tinterface "vtnet0";')" ||
	    atf_fail "BGP with the underlay is not there"
	# b's: the control plane, a, its one peer.
	cat > bird.json <<'EOS'
{"instances":[{"name":"sw1","fib":1,"host":"b","spec":{"service":"acme","fib":1,"table":1,"as":64600,"router_id":"100.64.0.1","direct":["vlan106","gre101","gif103","gre105"],"bfd":{"interfaces":["gre101","gif103","gre105"],"interval":200,"multiplier":3,"sessions":true},"reject":["100.64.0.0/24","100.64.0.0/24"],"md5":"edges-secret","peers":[{"tunnel":"acme/a-inet-b-inet/ctvc","to":"a","local":"100.64.0.5","neighbor":"100.64.0.4","role":"control"}],"unis":[]}}]}
EOS
	atf_check -o empty "$JGC" -c "$SOCK" sdwan bird "$(cat bird.json)"
	c=$(kept sdwan-bird-sw1.conf)
	atf_check -o match:'^# Written by arcana-agent for the Arcana console: SD-WAN service acme at b, in routing table 1\.$' cat "$c"
	has_text "$c" "$(printf '# acme/a-inet-b-inet/ctvc, to a, the control plane\nprotocol bgp edge0 from edge {\n\tlocal 100.64.0.5 as 64600;\n\tneighbor 100.64.0.4 as 64600;\n}')" ||
	    atf_fail "b does not peer with the control plane alone"
	# iBGP between loopbacks: a static to b's loopback by the gre
	# tunnel, the backup in a lower static, a multihop session from
	# loopback to loopback with rr client (a carries transit), the
	# UNI's subnet and static route and the remote end point's prefix
	# as its own statics, kept out of the kernel.
	cat > bird.json <<'EOS'
{"instances":[{"name":"sw1","fib":1,"host":"a","spec":{"service":"acme","fib":1,"table":1,"as":64600,"router_id":"100.64.0.4","direct":["lo0","gre100","geneve102","lo104"],"loopback":true,"bfd":{"interfaces":["gre100","geneve102"],"interval":200,"multiplier":3,"multihop":true,"sessions":true},"reject":["100.64.0.0/24","100.64.0.0/24"],"md5":"edges-secret","loop":{"local4":"100.64.0.4","transit":true,"edges":[{"name":"b","ipv4":"100.64.0.6","paths4":["100.64.0.1"],"backup4":["100.64.0.3"]}],"origins":[{"id":"hq","interface":"lo0","ipv4":[{"prefix":"10.1.0.0/24"},{"prefix":"10.1.8.0/22","next_hop":"10.1.0.2"}]},{"id":"road","interface":"wg5","ipv4":[{"prefix":"10.30.0.0/24"}]}]},"peers":[],"unis":[]}}]}
EOS
	atf_check -o empty "$JGC" -c "$SOCK" sdwan bird "$(cat bird.json)"
	c=$(kept sdwan-bird-sw1.conf)
	has_text "$c" "$(printf 'protocol static loop4_0 {\n\tipv4;\n\troute 100.64.0.6/32 via 100.64.0.1 bfd;\n}')" ||
	    atf_fail "b's loopback is not by the tunnel"
	has_text "$c" "$(printf 'protocol static loop4b_0 {\n\tipv4 { preference 150; };\n\troute 100.64.0.6/32 via 100.64.0.3 bfd;\n}')" ||
	    atf_fail "the backup is not a lower static"
	has_text "$c" "$(printf 'local 100.64.0.4 as 64600;\n\tneighbor 100.64.0.6 as 64600;\n\tmultihop;\n\trr client;\n}')" ||
	    atf_fail "the session is not loopback to loopback"
	has_text "$c" "$(printf 'protocol static orig4_hq {\n\tipv4;\n\troute 10.1.0.0/24 via "lo0";\n\troute 10.1.8.0/22 via 10.1.0.2;\n}')" ||
	    atf_fail "hq's own are not its statics"
	atf_check -o match:'route 10\.30\.0\.0/24 via "wg5";' -o match:'proto !~ "orig\*";' \
	    -o match:'"gre100", "geneve102", "lo104"' cat "$c"
	has_text "$c" "$(printf 'multihop {\n\t\tinterval 200 ms;')" ||
	    atf_fail "multihop BFD is not there"
	if [ -x /usr/local/sbin/bird ] && [ "$(sysctl -n net.fibs)" -ge 2 ]; then
		atf_check /usr/local/sbin/bird -p -c "$c"
	fi
	# Destination sets by BGP attribute: the filters to the kernel, the
	# gateway rewritten, the rest of BGP kept out.
	cat > bird.json <<'EOS'
{"instances":[{"name":"sw1","fib":1,"host":"a","spec":{"service":"acme","fib":1,"table":1,"as":64600,"router_id":"100.64.0.0","direct":["lo0","gre100","geneve102"],"sets":{"only":true,"sets":[{"name":"country","via":"a-inet","gateway":"192.0.2.254","as_path":[64600,64601],"communities":[[64600,100]]}]},"bfd":{"interfaces":["gre100","geneve102"],"interval":200,"multiplier":3,"sessions":true},"reject":["100.64.0.0/24","100.64.0.0/24"],"md5":"edges-secret","peers":[{"tunnel":"acme/a-inet-b-inet","to":"b","local":"100.64.0.0","neighbor":"100.64.0.1"},{"tunnel":"acme/a-mpls-b-mpls","to":"b","local":"100.64.0.2","neighbor":"100.64.0.3"}],"unis":[]}}]}
EOS
	atf_check -o empty "$JGC" -c "$SOCK" sdwan bird "$(cat bird.json)"
	c=$(kept sdwan-bird-sw1.conf)
	has_text "$c" "$(printf 'filter to_kernel4 {\n\tif source = RTS_DEVICE || source = RTS_INHERIT || dest != RTD_UNICAST then reject;\n\t# country, by a-inet\n\tif bgp_path ~ [64600, 64601] || bgp_community ~ [(64600, 100)] then { gw = 192.0.2.254; accept; }\n\tif source = RTS_BGP then reject;\n\taccept;\n}')" ||
	    atf_fail "the set's filter is not there"
	has_text "$c" "$(printf 'filter to_kernel6 {\n\tif source = RTS_DEVICE || source = RTS_INHERIT || dest != RTD_UNICAST then reject;\n\tif source = RTS_BGP then reject;\n\taccept;\n}')" ||
	    atf_fail "IPv6's filter is not there"
	atf_check -o match:'export filter to_kernel4;' -o match:'export filter to_kernel6;' cat "$c"
	# Routing neighbours at a UNI: several BGP entries, one multihop
	# from a source of the edge's, BFD on both; OSPF of each family.
	cat > bird.json <<'EOS'
{"instances":[{"name":"sw1","fib":1,"host":"a","spec":{"service":"acme","fib":1,"table":1,"as":64600,"router_id":"100.64.0.0","direct":["lo0","gre100","geneve102"],"bfd":{"interfaces":["gre100","geneve102","lo0"],"interval":200,"multiplier":3,"multihop":true,"sessions":true},"reject":["100.64.0.0/24","100.64.0.0/24"],"md5":"edges-secret","peers":[{"tunnel":"acme/a-inet-b-inet","to":"b","local":"100.64.0.0","neighbor":"100.64.0.1"}],"unis":[{"id":"uni-hq","end_point":"hq","interface":"lo0","bgp":[{"family":"ipv4","as":65010,"neighbors":["10.1.0.2"],"password":"s3cret","hold_time":90,"distance":150,"communities":[[64600,100]],"bfd":true},{"family":"ipv4","as":64600,"neighbors":["10.1.0.3"],"source":"10.1.0.1","multihop":true,"bfd":true}]},{"id":"uni-br","end_point":"branch","interface":"vlan104","ospf":[{"family":"ipv6","area":0,"cost":50,"bfd":true},{"family":"ipv4","area":1}]}]}}]}
EOS
	atf_check -o empty "$JGC" -c "$SOCK" sdwan bird "$(cat bird.json)"
	c=$(kept sdwan-bird-sw1.conf)
	has_text "$c" "$(printf 'protocol bgp uni_hq_0 {\n\tlocal as 64600;\n\tneighbor 10.1.0.2 as 65010;\n\tinterface "lo0";\n\tbfd on;\n\tauthentication md5;')" ||
	    atf_fail "the first neighbour is not watched by BFD"
	has_text "$c" "$(printf ', iBGP, multihop\nprotocol bgp uni_hq_1 {\n\tlocal 10.1.0.1 as 64600;\n\tneighbor 10.1.0.3 as 64600;\n\tmultihop;\n\tbfd on;\n\tipv4 {\n\t\tpreference 56;\n\t\timport all;\n\t\texport all;\n\t\tnext hop self;\n\t};\n}')" ||
	    atf_fail "the multihop iBGP neighbour is not there"
	has_text "$c" "$(printf 'protocol bfd {\n\tinterface "gre100", "geneve102", "lo0" {')" ||
	    atf_fail "BFD is not on the UNI"
	atf_check -o match:'^	multihop \{$' -o match:'^protocol ospf v3 uni_branch_v3 \{$' \
	    -o match:'^protocol ospf v2 uni_branch_v2_1 \{$' -o match:'^	area 1 \{$' cat "$c"
	has_text "$c" "$(printf '\tarea 0 {\n\t\tinterface "vlan104" {\n\t\t\tcost 50;\n\t\t\tbfd on;\n')" ||
	    atf_fail "OSPFv3's area is not as its entry says"
	# What a form may not hold: a quote that would end a word.
	atf_check -s exit:1 -e match:'a word of printable characters' -o ignore "$JGC" -c "$SOCK" sdwan bird \
	    '{"instances":[{"name":"sw1","fib":1,"spec":{"service":"acme","router_id":"100.64.0.0","md5":"x\";}\nprotocol x {"}}]}'
	atf_check -o empty "$JGC" -c "$SOCK" sdwan bird '{"instances":[]}'
	atf_check -o empty "$JGC" -c "$SOCK" sdwan proxy '{"instances":[]}'
	atf_check -o empty "$JGC" -c "$SOCK" sdwan dns '{"instances":[]}'
	atf_check -o empty "$JGC" -c "$SOCK" sdwan dhcp '{"instances":[]}'
}
sdwan_forms_cleanup()
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
"show stats") printf 'control.session=1\\nscheduler.delivery.ok=2\\nscheduler.delivery.permfail=4\\nscheduler.envelope=7\\nuptime=44\\nuptime.human=44s\\n' ;;
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
	cat > tools/makemap <<EOS
#!/bin/sh
echo "makemap \$*" >> $(pwd)/makemap.log
[ "\$1" = -U ] && { printf 'x.example\\n'; exit 0; }
while [ \$# -gt 1 ]; do [ "\$1" = -o ] && out=\$2; shift; done
cp "\$1" "\$out"
EOS
	chmod +x tools/smtpd tools/smtpctl tools/encrypt tools/makemap
	DAEMON_ARGS="-2 $(pwd)/tools --smtpd-conf $(pwd)/smtpd.conf --smtpd-dir $(pwd)/smtpd.d --smtpd-watch 1"
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
	atf_check -s exit:1 -o match:'smtpd.conf declares no table nosuch' "$JGC" -c "$SOCK" smtpd table nosuch aliases.txt
	# Enabled and started; then the read asks smtpd itself: its status,
	# counters and queue, as smtpctl prints them.
	atf_check -o match:'done +smtpd enable' "$JGC" -c "$SOCK" smtpd enable yes
	atf_check -o match:'^smtpd_enable="YES"$' cat rc.conf
	test -f running.smtpd || atf_fail "smtpd was not started"
	atf_check -o match:'"running":true' -o match:'"status":\{"mda":"running","mta":"paused","smtp":"running"\}' \
	    -o match:'"stats":\{"control.session":1,"scheduler.delivery.ok":2,"scheduler.delivery.permfail":4,"scheduler.envelope":7,"uptime":44,"uptime.human":"44s"\}' \
	    -o match:'"queue":\[\{"evpid":"6022923fc9341b9d","source":"local","type":"mta","flags":"auth","from":"root@edge-a.example","to":"nobody@example.invalid","dest":"nobody@example.invalid","created":1792491081,"expires":1792491081,"retries":3,"lasttry":1792491200,"state":"pending","next":-2,"error":"\(TempFail\) no route"\}\]' \
	    -o match:'"queued":1' "$JGC" -c "$SOCK" smtpd
	# Watched while it runs: its counters kept for the graphs; more
	# queued than the tab's limit a mail fault, cleared under it.
	atf_check -o match:'done +smtpd watch 5' "$JGC" -c "$SOCK" smtpd watch 5
	atf_check -o inline:'{"queue_max":5}\n' cat smtpd.d/watch.json
	sleep 2.5
	atf_check -o match:'"queue_max":5' -o match:'"series":\[\[[0-9]+,7,2,0,4,0\]' \
	    "$JGC" -c "$SOCK" smtpd
	atf_check -o match:'"arcana-alarms:mail"' -o match:'"alarm-text":"7 messages queued, over 5"' \
	    "$JGC" -c "$SOCK" get alarms
	atf_check -o match:'done' "$JGC" -c "$SOCK" smtpd watch 0
	sleep 2.5
	atf_check -o match:'"arcana-alarms:mail"' -o match:'"is-cleared":true' \
	    "$JGC" -c "$SOCK" get alarms
	atf_check -s exit:1 -e match:'how many may be queued' -o ignore "$JGC" -c "$SOCK" smtpd watch many
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
	# The admin's own smtpd.conf, its tables at their own paths and of
	# their own backends: read as it declares them, the users of an
	# auth table and of a passwd table by name alone; entries put in
	# and taken out where they are, a passwd user's other fields and
	# its hash's {SCHEME} kept; the form refused over it, the text
	# checked and put in place with the one before kept.
	mkdir -p own
	printf 'root: admin@example.org\n' > own/aliases
	printf 'carol:{SHA512-CRYPT}$6$old$hash:1001:1001::/var/vmail/carol:/usr/sbin/nologin\ndave:{SHA512-CRYPT}$6$d$h:1001:1001::/var/vmail/dave:/usr/sbin/nologin\n' > own/passwd
	chmod 640 own/passwd
	printf 'relay user@example.net:pw\n' > own/secrets
	cat > smtpd.conf <<EOS
# the admin's own
table aliases file:$(pwd)/own/aliases
table passwd passwd:$(pwd)/own/passwd
table secrets $(pwd)/own/secrets
table big db:$(pwd)/own/big.db
table inl { a.example, b.example }
listen on lo0 port submission auth <passwd>
action "out" relay host smtp+tls://relay@smtp.example.net:587 auth <secrets>
match from any for domain <big> action "out"
EOS
	atf_check -o match:'"conf_arcana":false' \
	    -o match:'"conf_tables":\[\{"name":"aliases","backend":"file","path":"[^"]*own/aliases","kind":"","secret":false,"editable":true,"entries":\[\{"key":"root","value":"admin@example.org"\}\]\}' \
	    -o match:'\{"name":"passwd","backend":"passwd","path":"[^"]*own/passwd","kind":"auth","secret":true,"editable":true,"entries":\[\{"key":"carol"\},\{"key":"dave"\}\]\}' \
	    -o match:'\{"name":"secrets","backend":"file","path":"[^"]*own/secrets","kind":"relay","secret":true' \
	    -o match:'\{"name":"big","backend":"db","path":"[^"]*own/big.db","kind":"","secret":false,"editable":true,"source":"[^"]*own/big","entries":\[\{"key":"x.example","value":""\}\]\}' \
	    -o not-match:'"name":"inl"' -o not-match:'old\$hash' -o not-match:'user@example.net:pw' \
	    "$JGC" -c "$SOCK" smtpd
	printf 'carol newpass\nerin pw5\n' > pw.txt
	atf_check -o match:'done +smtpd entry passwd' -o not-match:'newpass' "$JGC" -t -c "$SOCK" smtpd entry passwd pw.txt
	atf_check -o inline:'dave:{SHA512-CRYPT}$6$d$h:1001:1001::/var/vmail/dave:/usr/sbin/nologin\ncarol:{SHA512-CRYPT}$6$fake$hashOf$1:1001:1001::/var/vmail/carol:/usr/sbin/nologin\nerin:{SHA512-CRYPT}$6$fake$hashOf$1:::::\n' cat own/passwd
	atf_check -o match:'^-rw-r-----' ls -l own/passwd
	atf_check -o match:'done' "$JGC" -c "$SOCK" smtpd unentry passwd dave
	atf_check -o not-match:'^dave:' cat own/passwd
	printf 'postmaster: root\n' > a3.txt
	atf_check -o match:'done' "$JGC" -c "$SOCK" smtpd entry aliases a3.txt
	atf_check -o inline:'root: admin@example.org\npostmaster: root\n' cat own/aliases
	# A db: table: its lines as makemap -U dumps them (no text beside
	# it yet), written back as text and made by makemap as the set
	# smtpd.conf matches domains against.
	printf 'y.example\n' > d.txt
	atf_check -o match:'done' "$JGC" -c "$SOCK" smtpd entry big d.txt
	atf_check -o inline:'x.example\ny.example\n' cat own/big
	atf_check -o inline:'x.example\ny.example\n' cat own/big.db
	atf_check -o match:"^makemap -t set -o $(pwd)/own/big.db $(pwd)/own/big\$" cat makemap.log
	atf_check -o match:'"entries":\[\{"key":"x.example","value":""\},\{"key":"y.example","value":""\}\]' \
	    "$JGC" -c "$SOCK" smtpd
	atf_check -s exit:1 -o match:'is not Arcana.s' "$JGC" -c "$SOCK" smtpd conf form.json
	atf_check -o match:'^# the admin.s own$' cat smtpd.conf
	cp smtpd.conf mine.conf
	printf 'listen on lo0 port 2525\n' >> mine.conf
	atf_check -o match:'done +smtpd conf-text check' "$JGC" -c "$SOCK" smtpd conf-text check mine.conf
	atf_check -o not-match:'2525' cat smtpd.conf
	atf_check -o match:'done +smtpd conf-text' "$JGC" -c "$SOCK" smtpd conf-text mine.conf
	atf_check -o match:'port 2525' cat smtpd.conf
	atf_check -o match:'^# the admin.s own$' -o not-match:'2525' cat smtpd.conf.arcana-old
	printf '# BROKEN\n' > broken.conf
	atf_check -s exit:1 -o match:'smtpd does not take it' "$JGC" -c "$SOCK" smtpd conf-text broken.conf
	atf_check -o match:'port 2525' cat smtpd.conf
	# A jail's, with or without a network of its own: entered first
	# (none runs here); never safe.
	atf_check -s exit:1 -e match:'the jail web is not running' -o ignore "$JGC" -j web -c "$SOCK" smtpd
	atf_check -s exit:1 -e match:'not in safe mode' -o ignore "$JGC" -s -c "$SOCK" smtpd pause mta
}
smtpd_cleanup()
{
	stop_daemon
}

atf_test_case speeder cleanup
speeder_head()
{
	atf_set "descr" "UDPspeeder's relays, a plugin, run by Arcana's own rc script: read (the flags, the key never; the groups and the reports from the log, the overhead in all and of the last interval; the admin's relay of the port's script beside, never changed); conf written word by word, the key kept or taken away and never traced; what a shell would take refused; the ratios sent by its fifo; enabled and disabled; several, each a profile, one moved from the port's name; a safe conf undone"
}
speeder_body()
{
	mkdir -p tools
	printf '#!/bin/sh\nexit 0\n' > tools/speederv2
	chmod +x tools/speederv2
	cat > messages <<'EOM'
Oct 23 14:22:39 h arcana_relay[44253]: [2026-10-23 14:22:39][INFO]fec_inner_parameter=1:2,2:3,3:4,4:4
Oct 23 14:22:40 h sshd[1]: unrelated
Oct 23 14:22:49 h arcana_relay[44253]: [2026-10-23 14:22:49][INFO][report]client-->server:(original:100 pkt;100000 byte) (fec:150 pkt,160000 byte)  server-->client:(original:50 pkt;40000 byte) (fec:80 pkt;60000 byte)
Oct 23 14:22:59 h arcana_relay[44253]: [2026-10-23 14:22:59][INFO][report]client-->server:(original:200 pkt;200000 byte) (fec:300 pkt,330000 byte)  server-->client:(original:100 pkt;80000 byte) (fec:160 pkt;120000 byte)
Oct 23 14:23:00 h speederv2[9]: [2026-10-23 14:23:00][INFO]fec_inner_parameter=5:2
EOM
	DAEMON_ARGS="-2 $(pwd)/tools --speederv2-log $(pwd)/messages"
	start_daemon
	printf '#!/bin/sh\n' > rc.d/arcana_relay
	chmod +x rc.d/arcana_relay
	atf_check -o match:'Plugins: .*speederv2' "$JGC" -c "$SOCK" hello
	# Not set yet: what the log says of arcana_relay; 65 % over all,
	# 70 % of late.  Without the port's script, no relay of the admin's.
	atf_check -o match:'"installed":true' -o match:'"running":false' \
	    -o match:'"profiles_supported":true' -o not-match:'"speederv2":' \
	    -o not-match:'"role"' -o not-match:'sshd' \
	    -o match:'"fec_groups":\[\[1,2\],\[2,3\],\[3,4\],\[4,4\]\]' \
	    -o match:'"interval":10' \
	    -o match:'"client_to_server":\{"plain_packets":200,"plain_bytes":200000,"fec_packets":300,"fec_bytes":330000,"overhead":65(\.0*)?,"overhead_now":70(\.0*)?,"plain_rate":10000(\.0*)?,"fec_rate":17000' \
	    -o match:'"server_to_client":\{[^}]*"overhead":50(\.0*)?,' \
	    -o match:'"series":\[\[[0-9]+,70(\.0*)?,50(\.0*)?,10000(\.0*)?,4000(\.0*)?\]\]' \
	    "$JGC" -c "$SOCK" speeder

	# The flags, word by word; the key in rc.conf alone.
	atf_check -o match:'done +speederv2: conf, a client from 127.0.0.1:51821 to 192.0.2.1:14350' \
	    "$JGC" -c "$SOCK" speeder conf role=client listen=127.0.0.1:51821 \
	    remote=192.0.2.1:14350 mode=1 mtu=1456 fec=1:2,2:3,8:4,20:10 report=10 \
	    fifo=$(pwd)/fifo key=s3cr3tkey 'extra=--sock-buf 2048'
	atf_check -o match:'^arcana_relay_flags="-c -l127.0.0.1:51821 -r192.0.2.1:14350 -k s3cr3tkey --mode 1 --mtu 1456 -f1:2,2:3,8:4,20:10 --report 10 --fifo .*/fifo --sock-buf 2048"$' \
	    cat rc.conf
	atf_check -o match:'"key":true' -o match:'-k <hidden>' -o not-match:'s3cr3tkey' \
	    -o match:'"role":"client"' -o match:'"mtu":1456' -o match:'"extra":"--sock-buf 2048"' \
	    "$JGC" -c "$SOCK" speeder
	atf_check -o match:'<hidden>' -o not-match:'s3cr3tkey' "$JGC" -c "$SOCK" job 1
	# Kept when not given; nokey takes it away.
	atf_check -o match:done "$JGC" -c "$SOCK" speeder conf role=client \
	    listen=127.0.0.1:51821 remote=192.0.2.1:14350 fifo=$(pwd)/fifo
	atf_check -o match:'-k s3cr3tkey --fifo' cat rc.conf
	atf_check -o match:done "$JGC" -c "$SOCK" speeder conf role=client \
	    listen=127.0.0.1:51821 remote=192.0.2.1:14350 fifo=$(pwd)/fifo nokey
	atf_check -o not-match:'s3cr3tkey' cat rc.conf
	# What a shell would take, and options not passed on, refused.
	atf_check -s exit:1 -e match:'listen is an address' -o ignore "$JGC" -c "$SOCK" \
	    speeder conf role=client 'listen=127.0.0.1:1;reboot' remote=192.0.2.1:1
	atf_check -s exit:1 -e match:'a key is 64' -o ignore "$JGC" -c "$SOCK" \
	    speeder conf role=client listen=127.0.0.1:1 remote=192.0.2.1:1 'key=a$(id)'
	atf_check -s exit:1 -e match:'not an option passed on' -o ignore "$JGC" -c "$SOCK" \
	    speeder conf role=client listen=127.0.0.1:1 remote=192.0.2.1:1 'extra=--exec x'
	atf_check -s exit:1 -e match:'needs role=, listen= and remote=' -o ignore \
	    "$JGC" -c "$SOCK" speeder conf role=client
	atf_check -s exit:1 -e match:'fec takes the ratios' -o ignore "$JGC" -c "$SOCK" speeder fec 0:3

	# Enabled: started.  The ratios then by its fifo, not restarted,
	# and kept in the flags.
	atf_check -o match:done "$JGC" -c "$SOCK" speeder enable
	atf_check -o match:'^arcana_relay_enable="YES"$' cat rc.conf
	atf_check test -f running.arcana_relay
	: > fifo
	atf_check -o match:done "$JGC" -c "$SOCK" speeder fec 1:3,10:8
	atf_check -o inline:'fec 1:3,10:8\n' cat fifo
	atf_check -o match:'-f1:3,10:8' cat rc.conf

	# Safe: a conf not confirmed is undone, the flags as they were and
	# the relay running again.
	atf_check -o match:'queued' "$JGC" -q -s -c "$SOCK" speeder conf role=server \
	    listen=192.0.2.2:14350 remote=127.0.0.1:51820
	for i in $(seq 1 200); do
		"$JGC" -c "$SOCK" jobs | grep -q 'unconfirmed\|queued\|running' ||
		    break
		sleep 0.1
	done
	atf_check -s exit:1 -o match:'not confirmed within 2 s: undone' \
	    "$JGC" -c "$SOCK" job 6
	atf_check -o match:'^arcana_relay_flags="-c -l127.0.0.1:51821' cat rc.conf
	atf_check test -f running.arcana_relay
	# Disabled: stopped.  A jail's is not undone, so not safe there.
	atf_check -o match:done "$JGC" -c "$SOCK" speeder disable
	atf_check -o match:'^arcana_relay_enable="NO"$' cat rc.conf
	atf_check test ! -f running.arcana_relay
	atf_check -s exit:1 -e match:"a jail's relay is not undone" -o ignore \
	    "$JGC" -j web -s -c "$SOCK" speeder stop

	# Several relays, each a profile of arcana_relay.  One made under
	# the port's script's name before (speederv2_b_*) is moved at its
	# conf: those variables unset, its name out of speederv2_profiles.
	printf 'speederv2_profiles="b"\nspeederv2_b_flags="-s -l192.0.2.2:14351 -r127.0.0.1:51822"\nspeederv2_b_svcj="YES"\n' \
	    >> rc.conf
	atf_check -o match:'done +speederv2 b: conf, a server from 192.0.2.2:14351 to 127.0.0.1:51822' \
	    "$JGC" -c "$SOCK" speeder conf profile=b role=server \
	    listen=192.0.2.2:14351 remote=127.0.0.1:51822 key=bkey
	atf_check -o not-match:'speederv2_' cat rc.conf
	atf_check -o match:done "$JGC" -c "$SOCK" speeder conf profile=c \
	    role=client listen=127.0.0.1:51823 remote=192.0.2.3:14352
	atf_check -o match:'^arcana_relay_profiles="b c"$' \
	    -o match:'^arcana_relay_b_flags="-s -l192.0.2.2:14351 -r127.0.0.1:51822 -k bkey' \
	    -o match:'^arcana_relay_c_flags="-c -l127.0.0.1:51823' cat rc.conf
	atf_check -o match:done "$JGC" -c "$SOCK" speeder start profile=b
	atf_check test -f running.arcana_relay_b
	# In rc.subr's service jail, held to its addresses: a running relay
	# stopped under the jail it is in and started in the new one, not
	# restarted in the old; the same jail again is a restart.
	: > arcana_relay.verbs
	atf_check -o match:done "$JGC" -c "$SOCK" speeder conf profile=b \
	    role=server listen=192.0.2.2:14351 remote=127.0.0.1:51822 \
	    svcj=yes svcj_ipaddrs=192.0.2.2,127.0.0.1
	atf_check -o match:'^arcana_relay_b_svcj="YES"$' \
	    -o match:'^arcana_relay_b_svcj_options="net_basic"$' \
	    -o match:'^arcana_relay_b_svcj_ipaddrs="192.0.2.2 127.0.0.1"$' \
	    -o match:'^arcana_relay_b_flags="-s -l192.0.2.2:14351 -r127.0.0.1:51822 -k bkey' \
	    cat rc.conf
	atf_check -o inline:'onestatus arcana_relay_b\nonestop arcana_relay_b\nonestart arcana_relay_b\n' \
	    cat arcana_relay.verbs
	: > arcana_relay.verbs
	atf_check -o match:done "$JGC" -c "$SOCK" speeder conf profile=b \
	    role=server listen=192.0.2.2:14351 remote=127.0.0.1:51822
	atf_check -o inline:'onestatus arcana_relay_b\nonerestart arcana_relay_b\n' \
	    cat arcana_relay.verbs
	atf_check -o match:'"name":"b","running":true,[^]]*"svcj":true,"svcj_options":"net_basic","svcj_ipaddrs":"192.0.2.2 127.0.0.1"' \
	    "$JGC" -c "$SOCK" speeder
	atf_check -s exit:1 -e match:'svcj_ipaddrs is up to 8 addresses' -o ignore \
	    "$JGC" -c "$SOCK" speeder conf profile=b role=server \
	    listen=192.0.2.2:14351 remote=127.0.0.1:51822 'svcj_ipaddrs=192.0.2.2;x'
	atf_check -s exit:1 -e match:'svcj=no takes no svcj_ipaddrs' -o ignore \
	    "$JGC" -c "$SOCK" speeder conf profile=b role=server \
	    listen=192.0.2.2:14351 remote=127.0.0.1:51822 svcj=no \
	    svcj_ipaddrs=192.0.2.2
	# Each read with its own lines, by its tag; the key never.  The
	# admin's relay too, where the port's script is: its own variables
	# and tag, read alone.
	cat >> messages <<'EOM'
Oct 23 14:23:09 h arcana_relay_b[45]: [2026-10-23 14:23:09][INFO][report]client-->server:(original:10 pkt;1000 byte) (fec:20 pkt,2000 byte)  server-->client:(original:10 pkt;1000 byte) (fec:20 pkt;2000 byte)
EOM
	printf '#!/bin/sh\n' > rc.d/speederv2
	chmod +x rc.d/speederv2
	printf 'speederv2_enable="YES"\nspeederv2_flags="-c -l127.0.0.1:1 -r192.0.2.9:2 -k adminkey"\n' \
	    >> rc.conf
	touch running.speederv2
	atf_check -o match:'"profiles_supported":true' \
	    -o match:'"profiles":\[\{"name":"b","running":true,"flags":"-s -l192.0.2.2:14351 -r127.0.0.1:51822 -k <hidden>"' \
	    -o match:'"name":"b".*"plain_bytes":1000,"fec_packets":20,"fec_bytes":2000,"overhead":100' \
	    -o match:'\{"name":"c","running":false,"flags":"-c -l127.0.0.1:51823' \
	    -o match:'"speederv2":\{"enabled":true,"running":true,"flags":"-c -l127.0.0.1:1 -r192.0.2.9:2 -k <hidden>","role":"client",[^}]*"fec_groups":\[\[5,2\]\]' \
	    -o not-match:'bkey' -o not-match:'adminkey' "$JGC" -c "$SOCK" speeder
	atf_check -s exit:1 -e match:'no profile=' -o ignore "$JGC" -c "$SOCK" \
	    speeder enable profile=b
	atf_check -s exit:1 -e match:'remove takes profile=<name> alone' -o ignore \
	    "$JGC" -c "$SOCK" speeder remove
	atf_check -s exit:1 -e match:'a profile is 32 letters' -o ignore \
	    "$JGC" -c "$SOCK" speeder start 'profile=b;x'
	# Taken away safe, not confirmed: back, listed and running.
	atf_check -o match:'queued' "$JGC" -q -s -c "$SOCK" speeder remove profile=b
	for i in $(seq 1 200); do
		"$JGC" -c "$SOCK" jobs | grep -q 'unconfirmed\|queued\|running' ||
		    break
		sleep 0.1
	done
	atf_check -s exit:1 -o match:'not confirmed within 2 s: undone' \
	    -o match:'speederv2 b: remove' "$JGC" -c "$SOCK" job 13
	atf_check -o match:'^arcana_relay_profiles="b c"$' \
	    -o match:'^arcana_relay_b_flags="-s ' \
	    -o match:'^arcana_relay_b_svcj_ipaddrs="192.0.2.2 127.0.0.1"$' cat rc.conf
	atf_check test -f running.arcana_relay_b
	# Taken away for good.  Enabled: every listed relay started, the
	# admin's left alone.
	atf_check -o match:done "$JGC" -c "$SOCK" speeder remove profile=b
	atf_check -o match:'^arcana_relay_profiles="c"$' -o not-match:'arcana_relay_b_' \
	    cat rc.conf
	atf_check test ! -f running.arcana_relay_b
	: > arcana_relay.verbs
	atf_check -o match:done "$JGC" -c "$SOCK" speeder enable
	atf_check -o inline:'onestatus arcana_relay_c\nonestart arcana_relay_c\n' \
	    cat arcana_relay.verbs
	atf_check -o match:'^arcana_relay_enable="YES"$' -o match:'^speederv2_enable="YES"$' \
	    cat rc.conf
	atf_check test -f running.arcana_relay_c
	atf_check test -f running.speederv2

	# Its overhead in the history, beside the interfaces' rates: the
	# bytes taken in plain and added by the FEC, both ways, a second,
	# over its last interval; read on from the log's end as it grows.
	# The admin's relay by its tag as well.
	atf_check -o ignore "$JGC" -c "$SOCK" history set 1 20
	sleep 1.5
	printf '%s h speederv2[7]: [%s][INFO][report]client-->server:(original:100 pkt;100000 byte) (fec:150 pkt,160000 byte)  server-->client:(original:50 pkt;40000 byte) (fec:80 pkt;60000 byte)\n' \
	    "$(date '+%b %e %T')" "$(date -v-10S '+%Y-%m-%d %H:%M:%S')" >> messages
	printf '%s h speederv2[7]: [%s][INFO][report]client-->server:(original:200 pkt;200000 byte) (fec:300 pkt,330000 byte)  server-->client:(original:100 pkt;80000 byte) (fec:160 pkt;120000 byte)\n' \
	    "$(date '+%b %e %T')" "$(date '+%Y-%m-%d %H:%M:%S')" >> messages
	for i in $(seq 1 100); do
		"$JGC" -c "$SOCK" history > h.json
		grep -q ',14000,9000\]\]' h.json && break
		sleep 0.1
	done
	atf_check -o match:'"relays":\["arcana_relay_b","speederv2"\]' \
	    -o match:',14000,9000\]\]\}$' cat h.json
}
speeder_cleanup()
{
	stop_daemon
}

atf_test_case relay_rc cleanup
relay_rc_head()
{
	atf_set "descr" "Arcana's rc script for the FEC relays, share/rc.d/arcana_relay, under the real rc.subr(8): each profile by its own rc.subr name, variables, pidfile and syslog tag, run under daemon(8) with its flags; every listed one at once, one not enabled left alone; the one relay without profiles, refused without flags"
}
relay_rc_body()
{
	script="$(atf_get_srcdir)/arcana_relay"
	atf_check /bin/sh -n "$script"
	printf '#!/bin/sh\necho "$*" >> %s/argv\nexec sleep 30\n' "$(pwd)" \
	    > fake-speederv2
	chmod +x fake-speederv2
	# rc.conf's variables from the environment, the defaults taken as
	# read; run as this user, within its limits (the login class's
	# would be raised, which root alone may).
	lim="-d $(ulimit -H -d)k"
	export _rc_conf_loaded=true rc_debug=yes
	export arcana_relay_enable=YES arcana_relay_user=
	export arcana_relay_speederv2="$(pwd)/fake-speederv2"
	export arcana_relay_profiles="p q"
	export arcana_relay_p_flags="-c -l127.0.0.1:51821 -r192.0.2.1:14350 -f20:10"
	export arcana_relay_p_pidfile="$(pwd)/run/p.pid" arcana_relay_p_limits="$lim"
	export arcana_relay_q_flags="-s -l127.0.0.1:1 -r127.0.0.1:2"
	export arcana_relay_q_pidfile="$(pwd)/run/q.pid" arcana_relay_q_limits="$lim"
	export arcana_relay_q_enable=NO
	# A profile: its rcvar from the service's, or its own.
	atf_check -o match:'^arcana_relay_p_enable="YES"$' -e ignore \
	    /bin/sh "$script" rcvar p
	atf_check -s exit:1 -e ignore /bin/sh "$script" enabled q
	# Started: daemon(8) with its tag and pidfile, the relay with its
	# flags; seen running by its pidfile.
	atf_check -o match:'Starting arcana_relay_p' \
	    -e match:'daemon +-S -T arcana_relay_p -r -R 5 -P .*/run/p.pid .*/fake-speederv2 --disable-color -c -l127.0.0.1:51821' \
	    /bin/sh "$script" start p
	atf_check -o match:'arcana_relay_p is running as pid' -e ignore \
	    /bin/sh "$script" status p
	atf_check -o inline:'--disable-color -c -l127.0.0.1:51821 -r192.0.2.1:14350 -f20:10\n' \
	    cat argv
	atf_check test -s run/p.pid
	# All listed at once: p runs already, q is not enabled.
	atf_check -o match:'profile: p' -o match:'profile: q' \
	    -o match:"Cannot 'start' arcana_relay_q" \
	    -e match:'arcana_relay_p already running' /bin/sh "$script" start
	atf_check -o match:'arcana_relay_p is running' \
	    -o match:'arcana_relay_q is not running' -e ignore \
	    /bin/sh "$script" status
	atf_check -o match:'Stopping arcana_relay_p' -e ignore \
	    /bin/sh "$script" stop p
	atf_check -s exit:1 -o match:'arcana_relay_p is not running' -e ignore \
	    /bin/sh "$script" status p
	for i in $(seq 1 50); do
		pgrep -qf "$(pwd)/fake-speederv2" || break
		sleep 0.1
	done
	atf_check -s exit:1 pgrep -qf "$(pwd)/fake-speederv2"
	# Without profiles, the one relay of arcana_relay_flags: refused
	# while they are not set.
	unset arcana_relay_profiles
	export arcana_relay_pidfile="$(pwd)/run/plain.pid" arcana_relay_limits="$lim"
	atf_check -s exit:1 -o ignore -e match:'arcana_relay_flags is not set' \
	    /bin/sh "$script" start
	export arcana_relay_flags="-c -l127.0.0.1:3 -r127.0.0.1:4"
	atf_check -o match:'Starting arcana_relay\.' \
	    -e match:'daemon +-S -T arcana_relay -r -R 5 -P .*/run/plain.pid' \
	    /bin/sh "$script" start
	atf_check -o match:'arcana_relay is running' -e ignore /bin/sh "$script" status
	atf_check -o match:'^--disable-color -c -l127.0.0.1:3 -r127.0.0.1:4$' tail -1 argv
	atf_check -o ignore -e ignore /bin/sh "$script" stop
	atf_check -s exit:1 -o ignore -e ignore /bin/sh "$script" status
}
relay_rc_cleanup()
{
	for f in run/*.pid; do
		[ -f "$f" ] && kill "$(cat "$f")" 2>/dev/null
	done
	:
}

atf_test_case monitors cleanup
monitors_head()
{
	atf_set "descr" "Tunnel monitors outside SD-WAN: set with an interface, an address, a table and thresholds, read back and kept; SD-WAN's targets a list apart that never takes them; changed in place; again at a start; what is wrong refused; removed with their file"
}
monitors_body()
{
	start_daemon
	atf_check -o match:'done +monitor set m1 on lo0' "$JGC" -c "$SOCK" \
	    monitor set name=m1 interface=lo0 address=192.0.2.9 fib=0 \
	    interval=500 eval=2000 delay-max=50 loss-max=5
	atf_check -o match:'"monitors":\[\{"id":"m1","address":"192.0.2.9","family":"inet","fib":0,"state":"(unknown|error)",' \
	    -o match:'"interval":500,' -o match:'"eval":2000,' \
	    -o match:'"interface":"lo0"' \
	    -o match:'"tca":\{"delay":50(\.0*)?,"ipdv":0(\.0*)?,"loss":0\.05' \
	    "$JGC" -c "$SOCK" monitor
	atf_check -o match:'"id":"m1"' cat monitors.json
	# SD-WAN's targets are a list of their own: set, and emptied, they
	# leave the monitors as they were, and its read shows none of them.
	atf_check -o empty "$JGC" -c "$SOCK" sdwan probes \
	    '[{"id":"t1","address":"192.0.2.10"}]'
	atf_check -o not-match:'"m1"' -o match:'"id":"t1"' "$JGC" -c "$SOCK" sdwan
	atf_check -o empty "$JGC" -c "$SOCK" sdwan probes '[]'
	atf_check -o match:'"id":"m1"' -o not-match:'"t1"' "$JGC" -c "$SOCK" monitor
	# Changed in place; at a start, read from its file again.
	atf_check -o match:done "$JGC" -c "$SOCK" monitor set name=m1 \
	    interface=lo0 address=192.0.2.9 interval=1000
	atf_check -o match:'"interval":1000,' -o not-match:'"tca"' \
	    "$JGC" -c "$SOCK" monitor
	stop_daemon
	start_daemon
	atf_check -o match:'"id":"m1","address":"192.0.2.9"' \
	    -o match:'"interval":1000,' "$JGC" -c "$SOCK" monitor
	# What is wrong, refused: no far end on a link that is not point to
	# point, a loss over 100 %, safe mode, an interval out of bounds, a
	# name that is none, one not there.
	atf_check -s exit:1 -o match:'lo0 has no far end to probe' \
	    "$JGC" -c "$SOCK" monitor set name=m2 interface=lo0
	atf_check -s exit:1 -e match:'loss-max a per cent' -o ignore \
	    "$JGC" -c "$SOCK" monitor set name=m2 address=192.0.2.1 loss-max=150
	atf_check -s exit:1 -e match:'not in safe mode' -o ignore \
	    "$JGC" -s -c "$SOCK" monitor set name=m2 address=192.0.2.1
	atf_check -s exit:1 -o match:'interval \(10-60000 ms\)' \
	    "$JGC" -c "$SOCK" monitor set name=m2 address=192.0.2.1 interval=5
	atf_check -s exit:1 -e match:'a monitor has a name' -o ignore \
	    "$JGC" -c "$SOCK" monitor set name=a/b address=192.0.2.1
	atf_check -s exit:1 -o match:'no monitor nosuch' \
	    "$JGC" -c "$SOCK" monitor remove name=nosuch
	# Removed: none left, and no file.
	atf_check -o match:done "$JGC" -c "$SOCK" monitor remove name=m1
	atf_check -o match:'"monitors":\[\]' "$JGC" -c "$SOCK" monitor
	atf_check test ! -f monitors.json
}
monitors_cleanup()
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
	atf_check -s exit:1 -e match:'iscsi takes no jail' \
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
	# dma(8): its smart host, port, TLS and sign-in, dma.conf's keys of
	# these alone (the admin's other lines kept), the sign-in a line of
	# auth.conf for that host, root's and mail's alone; the password
	# never read back; a user kept with no password given keeps it.
	mkdir -p root/etc/dma
	printf '# the admin'"'"'s\nMASQUERADE arcana@example.org\nSMARTHOST old.example.net\nPORT 25\n' > root/etc/dma/dma.conf
	printf 'other|elsewhere.example.net:keepme\n' > root/etc/dma/auth.conf
	atf_check -o match:"done +dma's smart host written" env ARCANA_DMA_PASSWORD='s3cret:x' \
	    "$JGC" -c "$SOCK" sysfile dma smarthost=smtp.example.net port=587 tls=starttls user=alerts@example.net
	atf_check -o inline:"# the admin's
MASQUERADE arcana@example.org
# The smart host, set by Arcana:
SMARTHOST smtp.example.net
PORT 587
SECURETRANSFER
STARTTLS
AUTHPATH /etc/dma/auth.conf
" cat root/etc/dma/dma.conf
	atf_check -o inline:'other|elsewhere.example.net:keepme\nalerts@example.net|smtp.example.net:s3cret:x\n' cat root/etc/dma/auth.conf
	atf_check -o match:'^-rw-r-----' ls -l root/etc/dma/auth.conf
	atf_check -o match:'"dma":\{"conf_path":"/etc/dma/dma.conf","smarthost":"smtp.example.net","port":"587","tls":"starttls","user":"alerts@example.net","password_set":true\}' \
	    -o not-match:'s3cret' "$JGC" -c "$SOCK" system host
	atf_check -o match:'done' "$JGC" -c "$SOCK" sysfile dma smarthost=smtp.example.net port=465 tls=tls user=alerts@example.net
	atf_check -o match:'s3cret:x' cat root/etc/dma/auth.conf
	atf_check -o match:'^PORT 465$' -o match:'^SECURETRANSFER$' -o not-match:'STARTTLS' cat root/etc/dma/dma.conf
	atf_check -s exit:1 -o match:'a password for bob at smtp.example.net is needed' \
	    "$JGC" -c "$SOCK" sysfile dma smarthost=smtp.example.net user=bob
	# No sign-in, then no smart host: delivered straight, the admin's
	# lines and the other host's sign-in kept.
	atf_check -o match:'done' "$JGC" -c "$SOCK" sysfile dma smarthost=smtp.example.net user=
	atf_check -o inline:'other|elsewhere.example.net:keepme\n' cat root/etc/dma/auth.conf
	atf_check -o not-match:'AUTHPATH' cat root/etc/dma/dma.conf
	atf_check -o match:'done' "$JGC" -c "$SOCK" sysfile dma smarthost=
	atf_check -o inline:"# the admin's
MASQUERADE arcana@example.org
" cat root/etc/dma/dma.conf
	atf_check -s exit:1 -e match:'smarthost is a host' "$JGC" -c "$SOCK" sysfile dma smarthost='a;b'
	atf_check -s exit:1 -e match:'tls is none' "$JGC" -c "$SOCK" sysfile dma smarthost=x.example tls=maybe
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
	atf_check -s exit:1 -e match:'verb is mirror, stripe' "$JGC" -c "$SOCK" geom gpart add x
	atf_check -s exit:1 -e match:'not a subcommand of the class' "$JGC" -c "$SOCK" geom mirror rm gm0
	atf_check -s exit:1 -e match:'a word is a flag or a name' "$JGC" -c "$SOCK" geom mirror label 'gm0;reboot' /dev/md1
	atf_check -s exit:1 -e match:"a passphrase is geli init's" "$JGC" -c "$SOCK" geom mirror label gm0 /dev/md1 -P pass.txt
	# What it does not write, and what it does not take.
	atf_check -s exit:1 -e match:'verb is devfs.rules, devd' "$JGC" -c "$SOCK" sysfile passwd syslog.new
	printf 'bad\001\n' > ctl.new
	atf_check -s exit:1 -e match:'lines of printable characters' "$JGC" -c "$SOCK" sysfile krb5.conf ctl.new
	atf_check -s exit:1 -e match:'name_enable=YES or NO' "$JGC" -c "$SOCK" sysfile periodic daily_x=1
	atf_check -s exit:1 -e match:'sysfile takes no jail' "$JGC" -j web -c "$SOCK" sysfile krb5.conf syslog.new
	# Safe: the file is kept to be put back (safe_sysfile, which also
	# has dma refused as safe).
	atf_check -o match:'confirmed: it stays' "$JGC" -s -c "$SOCK" sysfile krb5.conf syslog.new
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
*/usr.sbin/arcana-agent*) src="$JGD"; [ -f $(pwd)/big-agent ] && src=$(pwd)/big-agent
	mkdir -p "\$dir/obj" && cp "\$src" "\$dir/obj/arcana-agent" ;;
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
	    -o match:'deflate\(3\)' \
	    "$JGC" -t -c "$SOCK" agent-build -o built https://example.org/arcana.git main
	atf_check cmp -s "$JGD" built
	atf_check test -x built
	# cblink (the submodule: cblink-gen makes arcana.h) and the
	# libraries the agent links, before it, in that order.
	atf_check -o inline:'cblink-build\nlibjailconf\nlibvarconf\narcana-agent\n' \
	    sh -c "grep -v -e '^HOME=' -e '-V .OBJDIR' made | sed -n \
	    -e 's,.* cblink-build\$,cblink-build,p' -e 's,.*/lib/\\(lib[a-z]*\\) .*,\\1,p' \
	    -e 's,.*/usr.sbin/arcana-agent .*,arcana-agent,p'"
	# Sent back compressed: past max-binary, as a frame would not carry
	# it as it is.
	dd if=/dev/zero of=zeros bs=1m count=7 2>/dev/null
	cat "$JGD" zeros > big-agent
	chmod +x big-agent
	atf_check -o match:'^Built: ' "$JGC" -c "$SOCK" agent-build -o built \
	    https://example.org/arcana.git main
	atf_check cmp -s big-agent built
	rm big-agent zeros
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
		alive "$pid" || break
		sleep 0.1
	done
	alive "$pid" && atf_fail "it still runs"
	atf_check -o match:'signal 15, stopping' cat daemon.out

	# In the middle of a change, with more queued: the change ends
	# first, and the log says what it is and what will not run.
	start_daemon
	pid=$(cat daemon.pid)
	# Under way until the test lets it end, however loaded the machine.
	touch slow hold
	"$JGC" -c "$SOCK" service sshd restart > change.out 2>&1 &
	change=$!
	# Once the change is under way, not at a guess of when: a minute at
	# most, for the whole suite at once can be slow to start it.
	for i in $(seq 1 600); do
		"$JGC" -c "$SOCK" jobs 2>/dev/null | grep -q 'Under way' && break
		sleep 0.1
	done
	# What is under way and is not a job is said with the jobs.
	atf_check -o match:'Under way: +service sshd restart' \
	    -o not-match:'Stopping' "$JGC" -c "$SOCK" jobs
	atf_check -o ignore "$JGC" -q -c "$SOCK" start web
	kill "$pid"
	for i in $(seq 1 600); do
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
	atf_check -o match:'^Service: sshd ' -o match:'^Running: yes' cat change.out
	for i in $(seq 1 60); do
		alive "$pid" || break
		sleep 0.1
	done
	alive "$pid" && atf_fail "it still runs"
	atf_check test -e running.sshd
	# The queued job did not start behind the change.
	atf_check -o not-match:'job 1: start web: ok' cat daemon.out

	# Signalled twice, it does not wait.
	start_daemon
	pid=$(cat daemon.pid)
	touch slow hold
	"$JGC" -c "$SOCK" service sshd restart > /dev/null 2>&1 &
	# Under way before the signals, however loaded the machine is.
	for i in $(seq 1 600); do
		"$JGC" -c "$SOCK" jobs 2>/dev/null | grep -q 'Under way' && break
		sleep 0.1
	done
	atf_check -o match:'Under way' "$JGC" -c "$SOCK" jobs
	kill "$pid"
	sleep 0.3
	kill "$pid"
	for i in $(seq 1 15); do
		alive "$pid" || break
		sleep 0.1
	done
	alive "$pid" && atf_fail "it still runs"
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
	# The real one does, sent compressed, and the one before is kept.
	atf_check -o match:'^Agent: +[0-9]+\.[0-9]+.* in place' \
	    -o match:'inflate\(3\)' \
	    "$JGC" -t -c "$SOCK" agent-update "$JGD"
	atf_check cmp -s "$JGD" installed-agent
	atf_check -o inline:'old\n' cat installed-agent.old
	atf_check test ! -e running.arcana_agent
	# As it is with -p, as to an agent before compressed updates.
	rm -f installed-agent && echo old > installed-agent
	atf_check -o match:'^Agent: +[0-9]+\.[0-9]+.* in place' \
	    -o not-match:'inflate' \
	    "$JGC" -t -c "$SOCK" agent-update -p "$JGD"
	atf_check cmp -s "$JGD" installed-agent
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

atf_test_case agent_update_gzip cleanup
agent_update_gzip_head()
{
	atf_set "descr" "A program sent compressed is inflated, bounded, " \
	    "and checked as it runs"
}
agent_update_gzip_body()
{
	start_daemon
	echo old > installed-agent
	atf_check -o match:'gzip-update' "$JGC" --libxo json -c "$SOCK" hello
	# Past max-binary, which a frame does not carry as it is: the real
	# agent with 7 MiB of zeros after it still runs.
	dd if=/dev/zero of=zeros bs=1m count=7 2>/dev/null
	cat "$JGD" zeros > big-agent
	chmod +x big-agent
	atf_check -o match:'in place' -o match:'inflate\(3\)' \
	    "$JGC" -t -c "$SOCK" agent-update big-agent
	atf_check cmp -s big-agent installed-agent
	# Compressed or not, what is not arcana-agent is refused by -V.
	rm -f installed-agent && echo old > installed-agent
	printf '#!/bin/sh\necho hello\n' > bogus
	atf_check -s exit:1 -e match:'does not run on this host' \
	    -o match:'inflate\(3\)' "$JGC" -t -c "$SOCK" agent-update bogus
	atf_check -o inline:'old\n' cat installed-agent
	atf_check test ! -e installed-agent.new
	# An inflate bomb: 64 MiB of zeros said to be 1 KiB stops a byte
	# past it; said to be more than max-program, it is not inflated.
	dd if=/dev/zero bs=1m count=64 2>/dev/null | gzip -9 > bomb.gz
	sha=$(sha256 -q bogus)
	atf_check -s exit:1 -o match:'inflates past the size it came with' \
	    "$(atf_get_srcdir)/zupdate" "$SOCK" bomb.gz 1024 "$sha"
	atf_check -s exit:1 -o match:'past what this host takes' \
	    "$(atf_get_srcdir)/zupdate" "$SOCK" bomb.gz 33554433 "$sha"
	# Not gzip, and gzip that ends short.
	atf_check -s exit:1 -o match:'not gzip' \
	    "$(atf_get_srcdir)/zupdate" "$SOCK" bogus 1024 "$sha"
	gzip -9 < "$JGD" | head -c 100000 > short.gz
	atf_check -s exit:1 -o match:'ends short' \
	    "$(atf_get_srcdir)/zupdate" "$SOCK" short.gz \
	    "$(stat -f %z "$JGD")" "$(sha256 -q "$JGD")"
	# Its SHA-256 is the program's, inflated.
	gzip -9 < "$JGD" > agent.gz
	atf_check -s exit:1 -o match:'does not match its SHA-256' \
	    "$(atf_get_srcdir)/zupdate" "$SOCK" agent.gz \
	    "$(stat -f %z "$JGD")" "$(sha256 -q agent.gz)"
	atf_check -o inline:'ok\n' \
	    "$(atf_get_srcdir)/zupdate" "$SOCK" agent.gz \
	    "$(stat -f %z "$JGD")" "$(sha256 -q "$JGD")"
	atf_check cmp -s "$JGD" installed-agent
}
agent_update_gzip_cleanup()
{
	stop_daemon
}

atf_test_case agent_update_old cleanup
agent_update_old_head()
{
	atf_set "descr" "An agent before compressed updates is sent the " \
	    "program as it is, within max-binary"
}
agent_update_old_body()
{
	# Without gzip-update in hello's features, as one before it.
	DAEMON_ARGS="--features none"
	start_daemon
	echo old > installed-agent
	atf_check -o not-match:'gzip-update' \
	    "$JGC" --libxo json -c "$SOCK" hello
	atf_check -o match:'in place' -o not-match:'inflate' \
	    "$JGC" -t -c "$SOCK" agent-update "$JGD"
	atf_check cmp -s "$JGD" installed-agent
	# One past max-binary is not sent: the agent is to be updated first.
	dd if=/dev/zero of=zeros bs=1m count=7 2>/dev/null
	cat "$JGD" zeros > big-agent
	atf_check -s exit:1 -e match:'update it to arcana-agent [0-9.]+ first' \
	    "$JGC" -c "$SOCK" agent-update big-agent
	# What it would not decode, it refuses.
	gzip -9 < "$JGD" > agent.gz
	atf_check -s exit:1 -o match:'program-size' \
	    "$(atf_get_srcdir)/zupdate" "$SOCK" agent.gz \
	    "$(stat -f %z "$JGD")" "$(sha256 -q "$JGD")"
}
agent_update_old_cleanup()
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
	# kld_list as running has it: the files rc(8) reads, under the
	# agent's root; the jobs change ./rc.conf through sysrc.
	mkdir -p root/etc/defaults
	cp /etc/defaults/rc.conf root/etc/defaults/
	printf 'kld_list="if_bridge"\n' > root/etc/rc.conf
	DAEMON_ARGS="-Q $(pwd)/fake-sysctl -O $(pwd)/sysctl.conf --root $(pwd)/root"
	start_daemon
	printf 'kld_list="if_bridge"\n' >> rc.conf

	# What is in the kernel is read from the kernel: the kernel itself
	# first, with the modules it holds; what its memory went to; as
	# arcana-kernel has them (get kernel).
	atf_check -o save:k.json "$JGC" -c "$SOCK" kmod
	atf_check -o match:'^\{"arcana-kernel:kernel":\{' \
	    -o match:'"file":\[\{"address":"0x[0-9a-f]+","id":1,"module":\["' \
	    -o match:'"name":"kernel","path":"/boot/[^"]*kernel","refs":[0-9]+,"size":"[0-9]+"\}' \
	    -o match:'"available":\[' -o match:'"kept":\["if_bridge"\]' \
	    -o match:'"memory":\{"files":"[0-9]+"' \
	    -o match:'"malloc":\[\{"bytes":"[0-9]+","count":"[0-9]+","name":"[^"]+","requests":"[0-9]+"\}' \
	    -o match:'"malloc-total":"[0-9]+"' \
	    -o match:'"zone":\[\{"bytes":"[0-9]+","count":"[0-9]+","free":"[0-9]+","name":"[^"]+","requests":"[0-9]+","size":"[0-9]+"\}' \
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
	atf_check -s exit:1 -e match:'kmod takes no jail' -o ignore \
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
	# The module in already (kldstat -m: compiled in is no module to
	# unload, and the fake loads nothing), the agent leaves it.
	if kldstat -q -m sctp 2>/dev/null; then
		atf_check -o not-match:'kldunload' cat kld.log
	else
		atf_check -o match:'^kldunload sctp$' cat kld.log
	fi

	# The kernel's state: read from the kernel by arcana-sysctl's read
	# action, a name or the start of one; what sysctl.conf sets at
	# boot is running's.
	atf_check -o save:s.json "$JGC" -c "$SOCK" sysctl kern.ostype
	atf_check -o match:'^\{"value":\[\{"description":"[^"]+","name":"kern.ostype","tunable":false,"type":"string","value":"FreeBSD","writable":false\}' \
	    cat s.json
	atf_check -o inline:'{"arcana-sysctl:sysctl":{"kept":[{"name":"kern.ipc.somaxconn","value":"1024"},{"name":"net.inet.ip.forwarding","value":"1"}]}}\n' \
	    "$JGC" -c "$SOCK" get -d running sysctl
	atf_check -o match:'"name":"kern.maxproc","tunable":[a-z]+,"type":"integer","value":"[0-9]+"' \
	    -o match:'"description":"' "$JGC" -c "$SOCK" sysctl kern.maxproc
	atf_check -o match:'"name":"kern.ipc.maxsockbuf"' \
	    -o not-match:'"name":"vm\.' "$JGC" -c "$SOCK" sysctl kern.ipc.
	# All of it is more than one part: the first, and where to go on.
	atf_check -o match:'"name":"kern.ostype"' -o match:'"next":"' \
	    -o match:'"total":"[0-9]+"' -e match:'the first part: go on after' \
	    "$JGC" -c "$SOCK" sysctl
	# In parts: the whole tree, nothing left out for size, each part
	# the action's output; and a part of the tree the same.
	atf_check -o save:parts.json "$JGC" -c "$SOCK" sysctl parts
	[ "$(wc -l < parts.json)" -gt 10 ] || atf_fail "the tree came in $(wc -l < parts.json) parts"
	atf_check -o match:'^\{"next":"[^"]+","total":"[0-9]+","value":\[\{"description":"[^"]*","name":"kern.ostype"' \
	    head -1 parts.json
	atf_check -o match:'"name":"vm\.' -o match:'"name":"net\.' cat parts.json
	atf_check -o not-match:'"next"' tail -1 parts.json
	atf_check -o match:'^\{"value":\[\{[^]]*"name":"kern.ostype"[^]]*\]\}$' \
	    "$JGC" -c "$SOCK" sysctl parts kern.ostype
	atf_check -s exit:1 -e match:'does not match pattern' -o ignore \
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
	    "$JGC" -c "$SOCK" get -d running sysctl
	atf_check -o not-match:'"name"' "$JGC" -c "$SOCK" sysctl kern.nothing-there
	# A name the kernel leaves out of its list is found by itself.
	if sysctl -n kern.ipc.somaxconn >/dev/null 2>&1; then
		atf_check -o match:'"value":\[\{[^]]*"name":"kern.ipc.somaxconn",[^]]*"value":"[0-9]+"' \
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
	atf_check -o match:'confirmed: it stays' "$JGC" -s -c "$SOCK" sysctl kern.hostname=x
	atf_check -o match:'sysctl kern.hostname=x' cat kld.log

	# How the agent is reached: its listeners, and who is connected
	# now, which is at least who asks.
	atf_check -o match:'"listeners":\[\{"uri":"unix:[^"]*","transport":"unix","up":true\}\]' \
	    -o match:'"sessions":\[\{"transport":"unix"' \
	    -o match:'"seen":[0-9]+' "$JGC" -c "$SOCK" transport
	# SCTP is tried again only where the kernel has it.
	if has_sctp; then
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
	# Its member kept up too: a bridge passes nothing to one down.
	atf_check -o match:'^ifconfig_bridge0="vlanfilter iftagged epair5a 30-40 addm tap9 stp tap9"$' \
	    -o match:'^ifconfig_tap9="up"$' cat rc.conf
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
	atf_check -o match:'confirmed: it stays' "$JGC" -s -c "$SOCK" bridge bridge0 vlanfilter on
	atf_check -o match:'bridge0 vlanfilter' cat ifconfig.log
	: > ifconfig.log

	# A member of a bridge takes no address: the bridge does.  One it
	# has may be taken away.
	atf_check -s exit:1 -o match:'em1 is a member of bridge0' \
	    "$JGC" -c "$SOCK" interface em1 add 10.1.1.1/24
	atf_check -o empty cat ifconfig.log

	# A geneve tunnel made, in the mode it will keep, and up; its
	# options set.
	atf_check -o match:'done +geneve5 create' "$JGC" -c "$SOCK" geneve \
	    geneve5 create mode l3 id 77 local 192.0.2.1 remote 192.0.2.2 \
	    ttl inherit df inherit
	atf_check -o match:'^geneve5 create genevemode l3 geneveid 77 genevelocal 192.0.2.1 geneveremote 192.0.2.2 genevettl inherit genevedf inherit up$' \
	    tail -1 ifconfig.log
	atf_check -o ignore "$JGC" -c "$SOCK" geneve geneve0 set learn off \
	    portrange 5000-6000 group ff08::1 dev em0 dscpinherit on
	atf_check -o match:'^geneve0 -genevelearn geneveportrange 5000 6000 genevegroup ff08::1 genevedev em0 genevedscpinherit$' \
	    tail -1 ifconfig.log
	atf_check -o ignore "$JGC" -c "$SOCK" geneve geneve0 flush all
	atf_check -o match:'^geneve0 geneveflushall$' tail -1 ifconfig.log
	atf_check -o ignore "$JGC" -p -c "$SOCK" geneve geneve6 create mode l2 \
	    id 9 local 192.0.2.1 group 239.0.0.9 dev em0
	# Kept: its mode in create_args, which it is made with at boot.
	atf_check -o match:'^ifconfig_geneve6="geneveid 9 genevelocal 192.0.2.1 genevegroup 239.0.0.9 genevedev em0 up"$' \
	    -o match:'^create_args_geneve6="genevemode l2"$' \
	    -o match:'^cloned_interfaces="geneve6"$' cat rc.conf
	atf_check -o ignore "$JGC" -p -c "$SOCK" geneve geneve6 set id 10
	atf_check -o match:'^ifconfig_geneve6="genevelocal 192.0.2.1 genevegroup 239.0.0.9 genevedev em0 up geneveid 10"$' \
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
	# Each jail's share, added up: none here, the host's own processes
	# being no jail's; and one process with its files and threads.
	atf_check -o match:'"jails":\[\],"ncpu"' cat ps.json
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
	atf_check -o match:"\"size\":$size,\"position\":[0-9]+" cat log.json
	# A position: the file's (its inode's tag, above 40 bits) and the
	# offset in it.
	pos=$(grep -o '"position":[0-9]*' log.json | cut -d: -f2)
	[ $((pos % 1099511627776)) -eq "$size" ] || atf_fail "position $pos"
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
	atf_check -o match:'"lines":\[\]' -o match:"\"position\":$pos" \
	    "$JGC" -c "$SOCK" log -f "$pos"
	printf 'Oct  5 12:00:09 web1 ntpd[5]: time set\nOct  5 12:00:10 web1 half' >> log/messages
	atf_check -o match:'"lines":\[\{[^}]*"tag":"ntpd","text":"time set"\}\]' \
	    -o match:"\"position\":$((pos + 39))" \
	    "$JGC" -c "$SOCK" log -f "$pos"
	pos=$((pos + 39))
	# Turned over as newsyslog(8) does, moved aside and a new one: the
	# rest of the file before (now messages.0), then the new one whole,
	# nothing lost and nothing read from its middle.
	printf ' done\n' >> log/messages
	mv log/messages log/messages.0
	printf 'Oct  5 13:00:00 web1 newsyslog[9]: logfile turned over\n' > log/messages
	atf_check -o match:'"lines":\[\{[^}]*"text":"half done"\},\{[^}]*"tag":"newsyslog"[^}]*\}\]' \
	    -o not-match:'"rotated"' "$JGC" -c "$SOCK" log -f "$pos"
	pos=$("$JGC" -c "$SOCK" log | grep -o '"position":[0-9]*' | cut -d: -f2)
	# The same file shorter than it was: read again from its start.
	printf 'Oct  5 14:00:00 web1 sshd[9]: again\n' > log/messages
	atf_check -o match:'"rotated":true' -o match:'"tag":"sshd"' \
	    "$JGC" -c "$SOCK" log -f "$pos"
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
	# Thinned once the eight are full and more came: a loaded run
	# samples late, so a minute at most, not a guess of when.
	for i in $(seq 1 60); do
		sleep 1
		"$JGC" -c "$SOCK" history > h3.json
		grep -o '\[[0-9][0-9]*,' h3.json | tr -d '[,' > t3
		[ "$(awk 'NR > 1 { g[NR - 1] = $1 - p } { p = $1 }
		    END { print (g[1] >= 2 && g[7] <= 2 && g[1] > g[7]) ? "ok" :
		    "no" }' t3)" = ok ] && break
	done
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
	# A jail's firewall: the trace of its entry, in its network.
	atf_check -s exit:1 -e match:'jail nosuchjail is not running' -o ignore \
	    "$JGC" -j nosuchjail -c "$SOCK" ipfw trace 192.0.2.7 1
}
fw_trace_cleanup()
{
	stop_daemon
}

atf_test_case firewall_long cleanup
firewall_long_head()
{
	atf_set "descr" "the kept rules written again however long they grow:" \
	    "a long port list changed under ten rules, twenty unpadded" \
	    "lines renumbered; a number past ipfw's from ipfw is no rule"
}
firewall_long_body()
{
	cat > fake-ipfw <<EOS
#!/bin/sh
echo "ipfw \$*" >> $(pwd)/ipfw.log
case "\$*" in
"-S list") echo "99999999999 set 0 allow ip from any to any" ;;
"-S list "*) echo "ipfw: rule \$3 does not exist" >&2 ;;
"-n /dev/stdin") sed -e 's/^add //' ;;
esac
exit 0
EOS
	chmod +x fake-ipfw
	mkdir fw
	i=1
	while [ $i -le 20 ]; do
		echo "add 7 count ip from any to any" >> fw/ipfw.rules
		i=$((i + 1))
	done
	DAEMON_ARGS="-h $(pwd)/fake-ipfw -J $(pwd)/fw/ipfw.rules"
	start_daemon
	# Twenty kept lines of one number, unpadded, renumbered: each
	# written whole, none cut.
	atf_check -o ignore "$JGC" -c "$SOCK" ipfw keep renumber 7 8
	atf_check -o match:'^20$' sh -c \
	    "grep -c '^add 00008 count ip from any to any\$' fw/ipfw.rules"
	# A port list, then a longer one, under ten kept rules.
	short=$(seq -s, 1000 1150)
	long=$(seq -s, 2000 2400)
	atf_check -o match:'done' "$JGC" -c "$SOCK" ipfw alias p ports "$short"
	i=100
	while [ $i -lt 110 ]; do
		atf_check -o ignore "$JGC" -c "$SOCK" -p ipfw add $i allow tcp \
		    from any to me '$p' in
		i=$((i + 1))
	done
	atf_check -o match:'done' "$JGC" -c "$SOCK" ipfw alias p ports "$long"
	atf_check -o match:'^10$' sh -c \
	    "grep -c '^add 001[0-9][0-9] allow tcp from any to me $long in\$' fw/ipfw.rules"
	atf_check -o match:'^10$' sh -c \
	    "grep -c '^#arcana add 001[0-9][0-9] allow tcp from any to me \\\$p in\$' fw/ipfw.rules"
	# The kernel's rule numbered past ipfw's: none to move.
	atf_check -s exit:1 -o match:'there is no rule 100 to move' \
	    sh -c '"$0" -c "$1" ipfw renumber 100 200 2>&1' "$JGC" "$SOCK"
}
firewall_long_cleanup()
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
	# A kept rule written with a set of its own (a staging script's):
	# loaded in set 1 once, not "set 1 set 1".
	printf 'add 00010 set 1 allow ip from any to any\n' > set1.rules
	atf_check -o ignore "$JGC" -c "$SOCK" ipfw rules -w set1.rules
	atf_check -o ignore "$JGC" -c "$SOCK" ipfw apply
	atf_check -o inline:'add 00010 set 1 allow ip from any to any\n' cat loaded.rules
	atf_check -o match:'"kept":\[\{"num":10,"text":"allow ip from any to any"' "$JGC" -c "$SOCK" net ipfw
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
	cat > fw2.sh <<'EOS'
#!/bin/sh
set -e
ipfw -q -f set 1 flush
ipfw -q set 1 table all destroy
ipfw -q set 1 nat64lsn all destroy
ipfw set disable 1
cmd="/sbin/ipfw -q add"
v4="192.0.2.64/27"
v6="2001:db8:ff::/96"
ipfw -q set 1 nat64lsn NAT64 create prefix4 $v4 prefix6 $v6
ipfw -q set 1 table T1 create type addr
$cmd 00001 set 1 call 9000 ipv6 from any to any
$cmd 00310 set 1 nat64lsn NAT64 ipv4 from any to $v4 in
ipfw set swap 0 1
ipfw delete set 1
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
	# A script that stages its rules in set 1 and swaps them in, as
	# Apply does: the shell's set -e its own; its set 1 objects kept
	# without the set; its rules without their set, which Apply gives
	# them; its staging and swap left to Apply.
	sed -i '' -e '/^firewall_script=/d' rc.conf
	printf 'firewall_script="%s/fw2.sh"\n' "$(pwd)" >> rc.conf
	atf_check -o inline:"# from $(pwd)/fw2.sh
# left out, the script's own: set -e
# left out, applying does it: ipfw -q -f set 1 flush
# left out, applying does it: ipfw -q set 1 table all destroy
# left out, applying does it: ipfw -q set 1 nat64lsn all destroy
# left out, applying does it: ipfw set disable 1
# left out, the script's own: cmd=\"/sbin/ipfw -q add\"
# left out, the script's own: v4=\"192.0.2.64/27\"
# left out, the script's own: v6=\"2001:db8:ff::/96\"
nat64lsn NAT64 create prefix4 192.0.2.64/27 prefix6 2001:db8:ff::/96
table T1 create type addr
add 00001 call 9000 ipv6 from any to any
add 00310 nat64lsn NAT64 ipv4 from any to 192.0.2.64/27 in
# left out, applying does it: ipfw set swap 0 1
# left out, applying does it: ipfw delete set 1
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
	# What the kept rules need loaded at boot, said in rc.conf for
	# rc.d/ipfw.
	atf_check -o match:'^firewall_nat_enable="YES"$' \
	    -o not-match:'dummynet_enable' cat rc.conf
	# Object lines in the order given, so one is made before it is
	# configured, all before the rules.
	atf_check -o ignore "$JGC" -p -c "$SOCK" ipfw nat64lsn n1 create \
	    prefix4 192.0.2.9/32 prefix6 64:ff9b::/96
	atf_check -o ignore "$JGC" -p -c "$SOCK" ipfw nat64lsn n1 config allow_private
	atf_check -o inline:'nat 1 config if em0 same_ports|nat64lsn n1 create prefix4 192.0.2.9/32 prefix6 64:ff9b::/96|nat64lsn n1 config allow_private|' \
	    sh -c "grep -v '^#' fw/ipfw.rules | grep -v '^add' | grep . | tr '\n' '|'"
	atf_check -o match:'^firewall_nat64_enable="YES"$' cat rc.conf
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
	atf_check -s exit:1 -e match:'zfs takes no jail' -o ignore \
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
	atf_check -o match:'^600$' stat -f %Lp "./sdwan-key-ipsec0.pem"
	atf_check -o match:'BEGIN PRIVATE KEY' cat "./sdwan-key-ipsec0.pem"
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
	atf_check -o match:'^600$' stat -f %Lp "./sdwan-key-ipsec0-next.pem"
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
	test ! -e "./sdwan-key-ipsec0-next.pem" || atf_fail "the next pair still there"
	atf_check -o match:"\"interface\":\"ipsec0\",\"public\":\"$(echo "$N0" | sed 's|/|\\/|g; s|+|\\+|g')\"" -o match:'"interface":"ipsec0",.*"pending":false' -o match:'"type":"key-rotation",.*"cleared":true' "$JGC" -c "$SOCK" sdwan
	atf_check -s exit:1 -o match:'nothing to commit' -e ignore "$JGC" -c "$SOCK" ipsec-sa commit ipsec0 100 10.202.0.1 10.202.0.2
	# Cleared: the next pair and what was kept go with the SAs.
	atf_check -o ignore "$JGC" -c "$SOCK" ipsec-sa key ipsec1 next
	atf_check -o ignore "$JGC" -c "$SOCK" ipsec-sa clear ipsec1 101 10.202.0.2 10.202.0.1
	test ! -e "./sdwan-key-ipsec1-next.pem" -a ! -e "./sdwan-sa-ipsec1.json" || atf_fail "ipsec1 not cleared"
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

atf_test_case jail_allow cleanup
jail_allow_head()
{
	atf_set "descr" "jail-allow: a jail's allow.* parameters in its file (replaced, or taken out), the running jail alone refused when it does not run, the words and names checked, and the file back in safe mode"
}
jail_allow_body()
{
	start_daemon
	# A parameter the kernel lacks, a bad value, a bad name, unset
	# without the file, and nothing to do on a stopped jail.
	atf_check -s exit:1 -o match:'no such parameter' -e ignore "$JGC" -p -c "$SOCK" allow vpn allow.nosuchthing=1
	atf_check -s exit:1 -e match:'0, 1 or unset' -o ignore "$JGC" -p -c "$SOCK" allow vpn allow.raw_sockets=maybe
	atf_check -s exit:1 -e match:"jail\(8\)'s allow" -o ignore "$JGC" -p -c "$SOCK" allow vpn persist=1
	atf_check -s exit:1 -e match:'say persist' -o ignore "$JGC" -c "$SOCK" allow vpn allow.raw_sockets=unset
	atf_check -s exit:1 -o match:'is not running' -e ignore "$JGC" -c "$SOCK" allow vpn allow.raw_sockets=1
	# In its file, in jail.conf.d: two set, the file read back; one
	# set again replaces; unset takes it out with its line.
	atf_check -o match:'jail vpn allow: allow.raw_sockets=1 \.\.\. \(kept\)' -o match:'jc_replace' "$JGC" -t -p -c "$SOCK" allow -n vpn allow.raw_sockets=1 allow.mount.zfs=0
	atf_check -o inline:'vpn {\n\tpath = /usr/jails/vpn;\n\tvnet;\n\tvnet.interface = epair0b;\n\tallow.raw_sockets = 1;\n\tallow.mount.zfs = 0;\n}\n' cat etc/jail.conf.d/vpn.conf
	atf_check -o match:'not running: its file alone' "$JGC" -t -p -c "$SOCK" allow vpn allow.raw_sockets=0
	atf_check -o inline:'vpn {\n\tpath = /usr/jails/vpn;\n\tvnet;\n\tvnet.interface = epair0b;\n\tallow.raw_sockets = 0;\n\tallow.mount.zfs = 0;\n}\n' cat etc/jail.conf.d/vpn.conf
	atf_check -o ignore "$JGC" -p -c "$SOCK" allow -n vpn allow.raw_sockets=unset
	atf_check -o inline:'vpn {\n\tpath = /usr/jails/vpn;\n\tvnet;\n\tvnet.interface = epair0b;\n\tallow.mount.zfs = 0;\n}\n' cat etc/jail.conf.d/vpn.conf
	# A jail of the main file: its block there, the others untouched.
	atf_check -o ignore "$JGC" -p -c "$SOCK" allow -n web allow.sysvipc=1
	atf_check -o match:'allow.sysvipc = 1;' -o match:'interface = lo0;' cat etc/jail.conf
	# Safe mode, not confirmed: the file as it was.
	cp etc/jail.conf.d/vpn.conf vpn.was
	atf_check -o match:'queued' "$JGC" -q -s -p -c "$SOCK" allow -n vpn allow.chflags=1
	for i in $(seq 1 200); do
		"$JGC" -c "$SOCK" jobs | grep -q 'unconfirmed\|queued\|running' ||
		    break
		sleep 0.1
	done
	atf_check -s exit:1 -o match:'not confirmed within 2 s: undone' \
	    -o match:'vpn.conf, as it was' "$JGC" -c "$SOCK" job $("$JGC" -c "$SOCK" jobs | awk '$1 ~ /^[0-9]+$/ {print $1}' | sort -n | tail -1)
	atf_check cmp vpn.was etc/jail.conf.d/vpn.conf
	# Confirmed, it stays.
	atf_check -o match:'confirmed: it stays' "$JGC" -s -p -c "$SOCK" allow -n vpn allow.chflags=1
	atf_check -o match:'allow.chflags = 1;' cat etc/jail.conf.d/vpn.conf
}
jail_allow_cleanup()
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
	atf_check -s exit:1 -e match:'clamav takes no jail' -o ignore \
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
	atf_check -s exit:1 -e match:'poudriere takes no jail' -o ignore \
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
	# BIRD's alone: on a busy host the sampler may raise its own (cpu).
	sleep 2.5
	atf_check -o not-match:'"by":"bird"' "$JGC" -c "$SOCK" events
	touch bgp.down ospf.gone bfd.down
	for i in $(seq 1 40); do
		[ $("$JGC" -c "$SOCK" events | grep -oE '"type":"(bgp-neighbor|ospf-neighbor|bfd)"[^}]*"state":"set"' | wc -l) -ge 3 ] && break
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
		[ $("$JGC" -c "$SOCK" events | grep -oE '"type":"(bgp-neighbor|ospf-neighbor|bfd)"[^}]*"state":"cleared"' | wc -l) -ge 3 ] && break
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

atf_test_case jail_boot cleanup
jail_boot_head()
{
	atf_set "descr" "a jail started at boot or not by the jail-action job, jail_list and jail_enable, never left an empty list that starts every jail"
}
jail_boot_body()
{
	start_daemon
	# The jail-action job's way, the console's: rc.conf through
	# sysrc(8), each job done before the next is looked at.
	q()
	{
		atf_check -o ignore "$JGC" -q -c "$SOCK" "$@"
		for i in $(seq 1 100); do
			"$JGC" -c "$SOCK" jobs | grep -q 'queued\|running' || return 0
			sleep 0.05
		done
	}
	# jail_enable off: the list is the jail alone, then turned on.
	q enable web
	atf_check -o match:'^jail_list="web"$' -o match:'^jail_enable="YES"$' \
	    cat rc.conf
	q disable db
	q enable db
	atf_check -o match:'^jail_list="web db"$' cat rc.conf
	q disable web
	atf_check -o match:'^jail_list="db"$' cat rc.conf
	# The last one named: jail_enable off, not an empty list.
	q disable db
	atf_check -o match:'^jail_enable="NO"$' cat rc.conf
	# Every jail started (an empty list): one left out is every other.
	sed -i '' -e '/^jail_list=/d' -e 's/^jail_enable=.*/jail_enable="YES"/' \
	    rc.conf
	q disable vpn
	atf_check -o match:'^jail_list=".*web' -o match:'^jail_list=".*db' \
	    -o match:'^jail_list=".*mail' -o not-match:'vpn' cat rc.conf
	# Started at boot already: nothing written.
	cp rc.conf rc.before
	q enable web
	atf_check -o empty diff rc.before rc.conf
	# Only a jail defined.
	q enable nosuch
	atf_check -o match:'failed +enable nosuch' "$JGC" -c "$SOCK" jobs
}
jail_boot_cleanup()
{
	stop_daemon
}

atf_test_case reboot cleanup
reboot_head()
{
	atf_set "descr" "the host rebooted by shutdown(8) -r a minute from now; never in safe mode, never a jail"
}
reboot_body()
{
	mkdir -p tools
	# shutdown(8): the parent says its child's pid and goes.
	printf '#!/bin/sh\necho "$*" >> %s/shutdown.log\necho "shutdown: [pid 4242]" >&2\nexit 0\n' \
	    "$(pwd)" > tools/shutdown
	chmod +x tools/shutdown
	DAEMON_ARGS="-2 $(pwd)/tools"
	start_daemon
	atf_check -o match:'done +reboot, a minute after' "$JGC" -c "$SOCK" reboot
	atf_check -o inline:'-r +1 rebooted from Arcana\n' cat shutdown.log
	atf_check -s exit:1 -e match:'not undone: not in safe mode' \
	    "$JGC" -s -c "$SOCK" reboot
	atf_check -s exit:2 -e match:'restarted' "$JGC" -j web -c "$SOCK" reboot
	atf_check -o inline:'-r +1 rebooted from Arcana\n' cat shutdown.log
}
reboot_cleanup()
{
	stop_daemon
}

# The datastores (RFC 8342): running read from what rc(8) reads, with
# RFC 6243's modes and the origins; the candidate edited and committed; Arcana's rc.conf file named in
# rc_conf_files and the user's variables taken out only where accepted;
# a commit whose kernel change fails leaves every file as it was.
atf_test_case datastores cleanup
datastores_head()
{
	atf_set "descr" "Running and the candidate; a commit's rc.conf rules and undo"
}
datastores_body()
{
	mkdir -p root/etc/defaults root/usr/local/etc
	cp /etc/defaults/rc.conf root/etc/defaults/
	printf 'hostname="lab"\nstatic_routes="r1"\nroute_r1="-net 198.51.100.0/24 127.0.0.1"\n' \
	    > root/etc/rc.conf
	cp root/etc/rc.conf rc.conf.before
	DAEMON_ARGS="--root $(pwd)/root"
	start_daemon
	atf_check -o match:'"destination-prefix":"198.51.100.0/24"' \
	    -o not-match:'"route-preference"' \
	    "$JGC" -c "$SOCK" get -d running routing
	# RFC 6243's modes: a default in use reported, or one left out.
	atf_check -o not-match:'enable-external-groups' \
	    "$JGC" -c "$SOCK" get nacm
	atf_check -o match:'"enable-external-groups":true' \
	    "$JGC" -c "$SOCK" get -w report-all nacm
	atf_check -o not-match:'"read-default"' \
	    "$JGC" -c "$SOCK" get -w trim nacm
	atf_check -o match:'"@enable-external-groups":\{"ietf-defaults:default":true\}' \
	    "$JGC" -c "$SOCK" get -w report-all-tagged nacm
	# RFC 8342's origins, the operational datastore's alone: the
	# interfaces running has, intended; what the host made, system.
	atf_check -o match:'^\{"ietf-interfaces:interfaces":\{"@":\{"ietf-origin:origin":"ietf-origin:intended"\},' \
	    "$JGC" -c "$SOCK" get -o interfaces
	# lo0's link-local address, the host's own: system.
	if ifconfig lo0 inet6 2>/dev/null | grep -q 'fe80::1%lo0'; then
		atf_check -o match:'\{"@":\{"ietf-origin:origin":"ietf-origin:system"\},"ip":"fe80::1"' \
		    "$JGC" -c "$SOCK" get -o interfaces
	fi
	atf_check -s exit:1 -e match:'with-origin is for the operational datastore' \
	    "$JGC" -c "$SOCK" get -d running -o interfaces
	# Running changes by a commit of the candidate alone.
	"$JGC" -c "$SOCK" get -d running routing > run.json
	sed -e 's|"route":\[|"route":[{"destination-prefix":"203.0.113.0/24","next-hop":{"next-hop-address":"127.0.0.1"}},|' \
	    run.json > new.json
	atf_check -s exit:1 -e match:'confirmed commit of the candidate' \
	    "$JGC" -c "$SOCK" edit -r routing @new.json
	atf_check "$JGC" -c "$SOCK" edit routing @new.json
	atf_check -o match:'"203.0.113.0/24"' "$JGC" -c "$SOCK" get -d candidate routing
	atf_check -o not-match:'"203.0.113.0/24"' "$JGC" -c "$SOCK" get -d running routing
	# What is accepted first: rc_conf_files, then the user's variable.
	atf_check -s exit:1 -e match:'rc_conf_files names it.*-a rc-conf-files' \
	    "$JGC" -c "$SOCK" commit
	atf_check -s exit:1 -e match:'static_routes .*rc.conf line 2.*-a rc-conf-conflict' \
	    "$JGC" -c "$SOCK" commit -a rc-conf-files
	# Accepted, the kernel refuses (not root): the files as they were.
	atf_check -s exit:1 -e match:'not permitted' \
	    "$JGC" -c "$SOCK" commit -a rc-conf-files -a rc-conf-conflict
	atf_check cmp rc.conf.before root/etc/rc.conf
	atf_check test ! -e root/usr/local/etc/rc.conf.d/arcana
	atf_check "$JGC" -c "$SOCK" discard
	atf_check -o not-match:'"203.0.113.0/24"' "$JGC" -c "$SOCK" get -d candidate routing
	# Only the static routes are changed so far.
	sed -e 's|"name":"ipv4-master"|"name":"v4"|' run.json > ribs.json
	atf_check "$JGC" -c "$SOCK" edit routing @ribs.json
	atf_check -s exit:1 -e match:'only rc.conf.s static routes' \
	    "$JGC" -c "$SOCK" commit
}
datastores_cleanup()
{
	stop_daemon
}

# The interfaces as configuration: running without what DHCP, SLAAC or
# the kernel made; a commit of a description and an address refused
# without its consent, then by the kernel (not root): the files as they
# were; a change of more than is supported refused.
atf_test_case datastores_interfaces cleanup
datastores_interfaces_head()
{
	atf_set "descr" "Interfaces in running; a commit's rules and undo"
}
datastores_interfaces_body()
{
	mkdir -p root/etc/defaults root/usr/local/etc
	cp /etc/defaults/rc.conf root/etc/defaults/
	printf 'hostname="lab"\nifconfig_lo0="inet 127.0.0.1/8"\n' > root/etc/rc.conf
	cp root/etc/rc.conf rc.conf.before
	DAEMON_ARGS="--root $(pwd)/root"
	start_daemon
	"$JGC" -c "$SOCK" get -d running interfaces > run.json
	atf_check -o match:'"ip":"127.0.0.1"' cat run.json
	atf_check -o not-match:'"ip":"fe80::' cat run.json
	atf_check -o not-match:'"origin"' cat run.json
	sed -e 's|{"ip":"127.0.0.1","prefix-length":8}|{"ip":"127.0.0.1","prefix-length":8},{"ip":"192.0.2.9","prefix-length":32}|' \
	    -e 's|"enabled":true,"name":"lo0"|"description":"lab loopback","enabled":true,"name":"lo0"|' \
	    run.json > new.json
	atf_check "$JGC" -c "$SOCK" edit interfaces @new.json
	atf_check -o match:'"description":"lab loopback"' \
	    "$JGC" -c "$SOCK" get -d candidate interfaces
	atf_check -s exit:1 -e match:'-a rc-conf-files' "$JGC" -c "$SOCK" commit
	atf_check -s exit:1 -e match:'commit: lo0: ' \
	    "$JGC" -c "$SOCK" commit -a rc-conf-files
	atf_check cmp rc.conf.before root/etc/rc.conf
	atf_check test ! -e root/usr/local/etc/rc.conf.d/arcana
	atf_check "$JGC" -c "$SOCK" discard
	sed -e 's|"type":"iana-if-type:softwareLoopback"|"type":"iana-if-type:other"|' \
	    run.json > type.json
	atf_check "$JGC" -c "$SOCK" edit interfaces @type.json
	atf_check -s exit:1 -e match:'lo0: only its description, enabled, IPv4 MTU and static addresses' \
	    "$JGC" -c "$SOCK" commit -a rc-conf-files
	atf_check "$JGC" -c "$SOCK" discard
	# Made by a commit: what a cloner makes alone, with what it takes.
	sed -e 's|"interface":\[|"interface":[{"name":"em57","type":"iana-if-type:ethernetCsmacd"},|' \
	    run.json > phys.json
	atf_check "$JGC" -c "$SOCK" edit interfaces @phys.json
	atf_check -s exit:1 -e match:'em57: no such interface; a commit makes one a cloner makes' \
	    "$JGC" -c "$SOCK" commit -a rc-conf-files
	atf_check "$JGC" -c "$SOCK" discard
	sed -e 's|"interface":\[|"interface":[{"name":"gif57","type":"iana-if-type:tunnel","arcana-interfaces:tunnel-fib":3},|' \
	    run.json > fib.json
	atf_check "$JGC" -c "$SOCK" edit interfaces @fib.json
	atf_check -s exit:1 -e match:'gif57: made with its type, tunnel ends' \
	    "$JGC" -c "$SOCK" commit -a rc-conf-files
	# The physical are not taken away.
	atf_check "$JGC" -c "$SOCK" discard
	sed -e 's|{"arcana-interfaces:capabilities":"[^"]*","arcana-interfaces:group":\["lo"\],"enabled":true,"name":"lo0"[^]]*\]}[^]]*\]}},||' \
	    run.json > nolo.json
	if ! cmp -s run.json nolo.json; then
		atf_check "$JGC" -c "$SOCK" edit interfaces @nolo.json
		atf_check -s exit:1 -e match:'lo0: not one a cloner made' \
		    "$JGC" -c "$SOCK" commit -a rc-conf-files
	fi
}
datastores_interfaces_cleanup()
{
	stop_daemon
}

# Network instances (RFC 8529), a FIB each: renamed by a commit, kept in
# fibs.conf; one past the last FIB asks net.fibs raised, which is never
# lowered again: refused unless accepted, then kept in Arcana's
# loader.conf.d file and, the kernel not letting it live (not root),
# told to come at the next boot.
atf_test_case datastores_instances cleanup
datastores_instances_head()
{
	atf_set "descr" "Network instances renamed and a FIB asked for by a commit"
}
datastores_instances_body()
{
	local n

	n=$(sysctl -n net.fibs)
	[ "$n" -ge 2 ] || atf_skip "one FIB alone here: net.fibs is $n"
	mkdir -p root/etc/defaults root/usr/local/etc root/boot/loader.conf.d
	cp /etc/defaults/rc.conf root/etc/defaults/
	printf 'hostname="lab"\n' > root/etc/rc.conf
	DAEMON_ARGS="--root $(pwd)/root"
	start_daemon
	# Each vrf-root's schema, RFC 8528's: shared, the interfaces its
	# parent-reference, its YANG library inside it.
	atf_check -o match:'"label":"vrf-root","module":"ietf-network-instance","shared-schema":\{"parent-reference":\["/if:interfaces"\]\}' \
	    -o match:'"namespace":\[\{"prefix":"if","uri":"urn:ietf:params:xml:ns:yang:ietf-interfaces"\}\]' \
	    "$JGC" -c "$SOCK" get schema-mounts
	atf_check -o match:'"vrf-root":\{.*"ietf-yang-library:yang-library":\{"content-id":"[0-9a-f]{16}"' \
	    "$JGC" -c "$SOCK" get network-instances
	"$JGC" -c "$SOCK" get -d running network-instances > run.json
	atf_check -o match:'"name":"fib1"' cat run.json
	atf_check -o not-match:'yang-library' cat run.json
	sed -e 's|"name":"fib1"|"description":"the lab'"'"'s","name":"blue"|' \
	    run.json > blue.json
	atf_check "$JGC" -c "$SOCK" edit network-instances @blue.json
	atf_check "$JGC" -c "$SOCK" commit
	atf_check -o match:'"name":"blue"' -o not-match:'"name":"fib1"' \
	    "$JGC" -c "$SOCK" get -d running network-instances
	# One past the last FIB.
	"$JGC" -c "$SOCK" get -d running network-instances |
	    sed -e "s|\"network-instance\":\[|\"network-instance\":[{\"name\":\"red\",\"vrf-root\":{},\"arcana-network-instance:fib\":$n},|" \
	    > red.json
	atf_check "$JGC" -c "$SOCK" edit network-instances @red.json
	atf_check -s exit:1 -e match:"net.fibs to go from $n to $((n + 1)).*-a net-fibs" \
	    "$JGC" -c "$SOCK" commit
	atf_check -o match:'after-reboot.*next boot' \
	    "$JGC" -c "$SOCK" commit -a net-fibs
	atf_check -o match:"^net.fibs=\"?$((n + 1))\"?" \
	    cat root/boot/loader.conf.d/arcana.conf
	atf_check -o match:"\"$((n + 0))\"|$n" sysctl -n net.fibs
}
datastores_instances_cleanup()
{
	stop_daemon
}

# Router advertisements (RFC 8349's submodule) in running, rtadvd.conf's
# record of an interface; a commit changes it, has the interface send
# (rtadvd_interfaces, rtadvd_enable in Arcana's file) and restarts
# rtadvd.
atf_test_case datastores_ra cleanup
datastores_ra_head()
{
	atf_set "descr" "Router advertisements read from rtadvd.conf and" \
	    "committed: rtadvd restarted where its interfaces change," \
	    "rtadvctl reload where not; other records kept; the" \
	    "operational datastore has what rtadvctl show says"
}
datastores_ra_body()
{
	mkdir -p root/etc/defaults root/usr/local/etc
	cp /etc/defaults/rc.conf root/etc/defaults/
	printf 'hostname="lab"\n' > root/etc/rc.conf
	cat > rtadvd.conf <<'EOF'
# Kept as it is: a comment, and another interface's record.
em7:\
	:rltime#0:unheardof="x":
lo0:\
	:maxinterval#300:chlim#64:
EOF
	# rtadvctl(8) stood in for: its calls logged, and show's text given.
	cat > fake-rtadvctl <<EOF
#!/bin/sh
echo "rtadvctl \$*" >> $(pwd)/rtadvctl.log
[ "\$1" = -v ] && [ "\$2" = show ] && cat $(pwd)/show.txt 2>/dev/null
exit 0
EOF
	chmod +x fake-rtadvctl
	DAEMON_ARGS="--root $(pwd)/root"
	start_daemon
	"$JGC" -c "$SOCK" get -d running interfaces > run.json
	atf_check -o match:'"max-rtr-adv-interval":300' \
	    -o match:'"send-advertisements":false' cat run.json
	sed -e 's|"max-rtr-adv-interval":300|"max-rtr-adv-interval":400|' \
	    -e 's|"send-advertisements":false|"send-advertisements":true|' \
	    run.json > new.json
	atf_check "$JGC" -c "$SOCK" edit interfaces @new.json
	atf_check "$JGC" -c "$SOCK" commit -a rc-conf-files
	atf_check -o match:'maxinterval#400' -o match:'chlim#64' cat rtadvd.conf
	atf_check -o match:'^rtadvd_interfaces="lo0"' \
	    -o match:'^rtadvd_enable="YES"' \
	    cat root/usr/local/etc/rc.conf.d/arcana
	# lo0 added to the interfaces rtadvd runs on: restarted, not reloaded.
	atf_check test -f running.rtadvd
	atf_check test ! -f rtadvctl.log
	atf_check -o match:'"max-rtr-adv-interval":400' \
	    -o match:'"send-advertisements":true' \
	    "$JGC" -c "$SOCK" get -d running interfaces
	# The other record and the comment as they were.
	atf_check -o match:'^# Kept as it is' \
	    -o match:'^	:rltime#0:unheardof="x":$' cat rtadvd.conf
	# Every capability of arcana-ra committed: the record written whole.
	"$JGC" -c "$SOCK" get -d running interfaces > run.json
	sed -e 's|"max-rtr-adv-interval":400|"max-rtr-adv-interval":400,"min-rtr-adv-interval":200,"managed-flag":true,"arcana-ra:router-preference":"high","link-mtu":1280,"arcana-ra:interface-prefixes":false,"arcana-ra:source-link-layer-address":false,"arcana-ra:clock-skew":10,"prefix-list":{"prefix":[{"prefix-spec":"2001:db8:57::/64","valid-lifetime":3600,"preferred-lifetime":1800,"on-link-flag":true,"autonomous-flag":false,"arcana-ra:valid-lifetime-decrements":true}]},"arcana-ra:route":[{"prefix":"2001:db8:100::/48","preference":"low","lifetime":900}],"arcana-ra:rdnss":[{"address":"2001:db8::53","lifetime":600},{"address":"2001:db8::54","lifetime":600}],"arcana-ra:dnssl":[{"domain":"example.com"}],"arcana-ra:pref64":[{"prefix":"64:ff9b::/96","lifetime":3600}],"arcana-ra:other-capability":["hatime#5"]|' \
	    run.json > new.json
	atf_check "$JGC" -c "$SOCK" edit interfaces @new.json
	atf_check "$JGC" -c "$SOCK" commit
	atf_check -o inline:"lo0:\\\\
	:maxinterval#400:mininterval#200:chlim#64:raflags=\"mh\":\\\\
	:noifprefix:clockskew#10:addr=\"2001:db8:57::\":prefixlen#64:\\\\
	:pinfoflags=\"l\":vltime#3600:vltimedecr:pltime#1800:mtu#1280:\\\\
	:nolladdr:rtprefix=\"2001:db8:100::\":rtplen#48:rtflags=\"l\":\\\\
	:rtltime#900:rdnss=\"2001:db8::53,2001:db8::54\":rdnssltime#600:\\\\
	:dnssl=\"example.com\":pref64=\"64:ff9b::\":pref64lifetime#3600:\\\\
	:hatime#5:
" sed -n '/^lo0:/,$p' rtadvd.conf
	# The same interfaces as before: rtadvd reloaded for lo0, not
	# restarted.
	atf_check -o match:'^rtadvctl reload lo0$' cat rtadvctl.log
	"$JGC" -c "$SOCK" get -d running interfaces > run.json
	atf_check -o match:'"arcana-ra:router-preference":"high"' \
	    -o match:'"arcana-ra:valid-lifetime-decrements":true' \
	    -o match:'"arcana-ra:rdnss":\[\{"address":"2001:db8::53","lifetime":600\},\{"address":"2001:db8::54","lifetime":600\}\]' \
	    -o match:'"arcana-ra:pref64":\[\{"lifetime":3600,"prefix":"64:ff9b::/96"\}\]' \
	    -o match:'"arcana-ra:other-capability":\["hatime#5"\]' \
	    -o not-match:'arcana-ra:rtadvd' cat run.json
	# Operational: what rtadvd(8) sends, from rtadvctl -v show.
	cat > show.txt <<'EOF'
lo0: flags=<UP,CONFIGURED,PERSIST> status=<RA_SEND> mtu 16384
	DefaultLifetime: 30m
	MinAdvInterval/MaxAdvInterval: 3m20s/6m40s
	AdvLinkMTU: 1280, Flags: M, Preference: high
	ReachableTime: 0s, RetransTimer: 0s, CurHopLimit: 64
	AdvIfPrefixes: no
	Next RA send: Tue Oct 27 10:11:12 2026
	Last RA send: never
	Clock skew: 10sec
	Route Info:
	  2001:db8:100::/48 (pref: low, ltime: 15m)
	Prefixes (1):
	  2001:db8:57::/64 (CONFIG, vltime=1h(expire: 59m), pltime=30m(expire 29m), flags=L)
	RDNSS entries:
	  2001:db8::53 (ltime=10m)
	  2001:db8::54 (ltime=10m)
	DNSSL entries:
	  example.com (ltime=10m)
	PREF64:
	  64:ff9b::/96 (ltime: 1h)
em7: flags=<DOWN,CONFIGURED> status=<INACTIVE>
EOF
	"$JGC" -c "$SOCK" get -d operational interfaces > oper.json
	atf_check -o match:'"arcana-ra:rtadvd":\{"clock-skew":10,"cur-hop-limit":64,"default-lifetime":1800,"dnssl":\[\{"domain":"example.com","lifetime":600\}\],"flags":"UP,CONFIGURED,PERSIST","interface-prefixes":false,"link-mtu":1280,"managed-flag":true,"max-rtr-adv-interval":400,"min-rtr-adv-interval":200,"next-send":"2026-10-27T[0-9:]*Z","other-config-flag":false,"pref64":\[\{"lifetime":3600,"prefix":"64:ff9b::/96"\}\],"prefix":\[\{"autonomous-flag":false,"on-link-flag":true,"origin":"config","preferred-expires":1740,"preferred-lifetime":1800,"prefix":"2001:db8:57::/64","valid-expires":3540,"valid-lifetime":3600\}\],"rdnss":\[\{"address":"2001:db8::53","lifetime":600\},\{"address":"2001:db8::54","lifetime":600\}\],"reachable-time":0,"retrans-timer":0,"route":\[\{"lifetime":900,"preference":"low","prefix":"2001:db8:100::/48"\}\],"router-preference":"high","status":"RA_SEND"\}' \
	    cat oper.json
	# Taken out of the advertising interfaces: rtadvd stopped.
	"$JGC" -c "$SOCK" get -d running interfaces > run.json
	sed -e 's|"send-advertisements":true|"send-advertisements":false|' \
	    run.json > new.json
	atf_check "$JGC" -c "$SOCK" edit interfaces @new.json
	atf_check "$JGC" -c "$SOCK" commit
	atf_check -o match:'^rtadvd_interfaces=""' \
	    cat root/usr/local/etc/rc.conf.d/arcana
	atf_check test ! -f running.rtadvd
}
datastores_ra_cleanup()
{
	stop_daemon
}

# arcana-sysctl (PLAN-SDN-YANG 3.1.6): running is what sysctl.conf sets
# at boot; a commit writes the file in place and sets the kernel to each
# value changed, a value refused puts the file back, a tunable the
# loader alone sets is refused for loader.conf, one taken out is said to
# keep its value.
atf_test_case datastores_sysctl cleanup
datastores_sysctl_head()
{
	atf_set "descr" "sysctl.conf as running, committed and applied"
}
datastores_sysctl_body()
{
	mkdir -p root/etc/defaults root/usr/local/etc
	cp /etc/defaults/rc.conf root/etc/defaults/
	printf 'hostname="lab"\n' > root/etc/rc.conf
	printf '# Kept.\nkern.ipc.somaxconn=1024\nnet.inet.ip.forwarding = 1 # routes\n' \
	    > root/etc/sysctl.conf
	cat > fake-sysctl <<EOS
#!/bin/sh
echo "sysctl \$*" >> $(pwd)/kld.log
[ "\$1" = "kern.nosuch=1" ] && { echo "sysctl: unknown oid 'kern.nosuch'" >&2; exit 1; }
exit 0
EOS
	chmod +x fake-sysctl
	DAEMON_ARGS="--root $(pwd)/root -Q $(pwd)/fake-sysctl"
	start_daemon
	# Running: the file's settings, nothing of the kernel's.
	atf_check -o inline:'{"arcana-sysctl:sysctl":{"kept":[{"name":"kern.ipc.somaxconn","value":"1024"},{"name":"net.inet.ip.forwarding","value":"1"}]}}\n' \
	    "$JGC" -c "$SOCK" get -d running sysctl
	# A commit: one changed in place, one new at the end, one taken out
	# (said); the kernel set to the two, as sysctl(8).
	atf_check "$JGC" -c "$SOCK" edit sysctl \
	    '{"kept":[{"name":"kern.ipc.somaxconn","value":"4096"},{"name":"kern.corefile","value":"/var/cores/%N core"}]}'
	atf_check -o match:'sysctl-unset: net.inet.ip.forwarding is no longer set at boot' \
	    "$JGC" -c "$SOCK" commit
	atf_check -o match:'^# Kept.$' -o match:'^kern.ipc.somaxconn=4096$' \
	    -o match:'^kern.corefile=/var/cores/%N core$' \
	    -o not-match:'forwarding' -o not-match:'1024' cat root/etc/sysctl.conf
	atf_check -o inline:'sysctl kern.ipc.somaxconn=4096\nsysctl kern.corefile=/var/cores/%N core\n' \
	    cat kld.log
	atf_check -o match:'"name":"kern.corefile","value":"/var/cores/%N core"' \
	    -o not-match:'forwarding' "$JGC" -c "$SOCK" get -d running sysctl
	# The kernel refuses one: the file as it was.
	cp root/etc/sysctl.conf before
	atf_check "$JGC" -c "$SOCK" edit sysctl \
	    '{"kept":[{"name":"kern.ipc.somaxconn","value":"4096"},{"name":"kern.corefile","value":"/var/cores/%N core"},{"name":"kern.nosuch","value":"1"}]}'
	atf_check -s exit:1 -e match:'kern.nosuch: .*unknown oid' \
	    "$JGC" -c "$SOCK" commit
	atf_check cmp before root/etc/sysctl.conf
	atf_check "$JGC" -c "$SOCK" discard
	# A tunable the loader alone sets: not from here.
	atf_check "$JGC" -c "$SOCK" edit sysctl \
	    '{"kept":[{"name":"kern.maxusers","value":"512"}]}'
	atf_check -s exit:1 -e match:'kern.maxusers is a tunable the loader sets' \
	    "$JGC" -c "$SOCK" commit
	atf_check cmp before root/etc/sysctl.conf
	atf_check "$JGC" -c "$SOCK" discard
	# The same again: nothing to do, nothing set.
	: > kld.log
	atf_check "$JGC" -c "$SOCK" edit sysctl \
	    '{"kept":[{"name":"kern.ipc.somaxconn","value":"4096"},{"name":"kern.corefile","value":"/var/cores/%N core"}]}'
	atf_check "$JGC" -c "$SOCK" commit
	atf_check cmp before root/etc/sysctl.conf
	atf_check -o empty cat kld.log
}
datastores_sysctl_cleanup()
{
	stop_daemon
}

# arcana-services (PLAN-SDN-YANG 3.1.2): running is each script with
# its rcvar and rc.conf variables from the files rc(8) reads; a commit
# writes what differs to Arcana's rc.conf file by rcarcana.c's rules,
# a service at a time; a variable not the service's own, or its rcvar
# as a variable, is refused.  A variable of the user's that Arcana's
# file takes is commented out where it is, never removed, and put back
# where the commit fails; the convert action moves a service's
# variables under Arcana deliberately, said first with dry-run.
atf_test_case datastores_services cleanup
datastores_services_head()
{
	atf_set "descr" "Services' rcvars and variables as running, committed; the user's lines commented out, put back; the convert action"
}
datastores_services_body()
{
	mkdir -p root/etc/defaults root/etc/rc.conf.d root/usr/local/etc
	cp /etc/defaults/rc.conf root/etc/defaults/
	printf 'hostname="lab"\nsshd_enable="YES"\nsshd_flags="-4"\nntpd_enable="NO"\nntpd_sync_on_start="$x"\n' \
	    > root/etc/rc.conf
	printf 'ntpd_flags="-g"\n' > root/etc/rc.conf.d/ntpd
	DAEMON_ARGS="--root $(pwd)/root"
	start_daemon
	# A script whose name is no variable's stem (rc(8)'s own
	# ftp-proxy): converting every script passes it by.
	printf '#!/bin/sh\n' > rc.d/ftp-proxy
	chmod +x rc.d/ftp-proxy
	# Running: the scripts, with what the files rc(8) reads set.
	atf_check -o save:run.json "$JGC" -c "$SOCK" get -d running services
	atf_check -o match:'\{"enabled":true,"name":"sshd","variable":\[\{"name":"sshd_flags","value":"-4"\}\]\}' \
	    -o match:'\{"enabled":false,"name":"ntpd","variable":\[\{"name":"ntpd_flags","value":"-g"\}\]\}' \
	    -o not-match:'"path"' cat run.json
	# The operational datastore: enabled as sysrc -A says, the
	# variables beside.
	atf_check -o match:'"name":"ntpd"' -o match:'"path":"' \
	    -o match:'"name":"sshd_flags","value":"-4"' "$JGC" -c "$SOCK" get services
	# A commit: disabled, a variable changed, one new; rc_conf_files
	# first, then the user's variables, then Arcana's file has them.
	atf_check "$JGC" -c "$SOCK" edit services \
	    '{"service":[{"name":"sshd","enabled":false,"variable":[{"name":"sshd_flags","value":"-6"},{"name":"sshd_program","value":"/usr/local/sbin/sshd"}]}]}'
	atf_check -s exit:1 -e match:'-a rc-conf-files' "$JGC" -c "$SOCK" commit
	atf_check -s exit:1 -e match:'sshd_enable .*rc.conf line 2.*-a rc-conf-conflict' \
	    "$JGC" -c "$SOCK" commit -a rc-conf-files
	atf_check "$JGC" -c "$SOCK" commit -a rc-conf-files -a rc-conf-conflict
	atf_check -o match:'^sshd_enable="NO"$' -o match:'^sshd_flags="-6"$' \
	    -o match:'^sshd_program="/usr/local/sbin/sshd"$' \
	    cat root/usr/local/etc/rc.conf.d/arcana
	# The user's lines commented out where they are, never removed.
	atf_check -o match:'^#sshd_enable="YES"  # taken by Arcana$' \
	    -o match:'^#sshd_flags="-4"  # taken by Arcana$' \
	    -o match:'^hostname="lab"$' -o match:'^ntpd_enable="NO"$' \
	    -o not-match:'^sshd_' cat root/etc/rc.conf
	atf_check -o match:'\{"enabled":false,"name":"sshd","variable":\[\{"name":"sshd_flags","value":"-6"\},\{"name":"sshd_program","value":"/usr/local/sbin/sshd"\}\]\}' \
	    "$JGC" -c "$SOCK" get -d running services
	# A later service's failure puts every file back: the user's line
	# as it was, Arcana's file without the change.
	cp root/etc/rc.conf rc.conf.before
	cp root/usr/local/etc/rc.conf.d/arcana arcana.before
	atf_check "$JGC" -c "$SOCK" edit services \
	    '{"service":[{"name":"ntpd","enabled":true},{"name":"zfs","variable":[{"name":"ntpd_flags","value":"x"}]}]}'
	atf_check -s exit:1 -e match:"'ntpd_flags' is not a variable of zfs" \
	    "$JGC" -c "$SOCK" commit -a rc-conf-conflict
	atf_check cmp rc.conf.before root/etc/rc.conf
	atf_check cmp arcana.before root/usr/local/etc/rc.conf.d/arcana
	atf_check "$JGC" -c "$SOCK" discard
	# Not its own variable; its rcvar is enabled's alone.
	atf_check "$JGC" -c "$SOCK" edit services \
	    '{"service":[{"name":"sshd","variable":[{"name":"ntpd_flags","value":"x"}]}]}'
	atf_check -s exit:1 -e match:"'ntpd_flags' is not a variable of sshd" \
	    "$JGC" -c "$SOCK" commit
	atf_check "$JGC" -c "$SOCK" discard
	atf_check "$JGC" -c "$SOCK" edit services \
	    '{"service":[{"name":"sshd","variable":[{"name":"sshd_enable","value":"YES"}]}]}'
	atf_check -s exit:1 -e match:"'sshd_enable' is not a variable of sshd" \
	    "$JGC" -c "$SOCK" commit
	atf_check "$JGC" -c "$SOCK" discard
	# One taken out: gone from Arcana's file; the rest as it was.
	atf_check "$JGC" -c "$SOCK" edit services \
	    '{"service":[{"name":"sshd","enabled":false,"variable":[{"name":"sshd_flags","value":"-6"}]}]}'
	atf_check "$JGC" -c "$SOCK" commit
	atf_check -o match:'^sshd_enable="NO"$' -o match:'^sshd_flags="-6"$' \
	    -o not-match:'sshd_program' cat root/usr/local/etc/rc.conf.d/arcana
	# The convert action: a service's variables of the user's files
	# moved under Arcana, each said with its file and line; a dry run
	# first, the files as they are; one not a literal left, said why.
	cp root/etc/rc.conf rc.conf.before
	atf_check -o match:'^ntpd +ntpd_enable +NO +/etc/rc.conf:4$' \
	    -o match:'^ +ntpd_sync_on_start +/etc/rc.conf:5  left: its value is not a literal' \
	    -o match:'^ +ntpd_flags +-g +/etc/rc.conf.d/ntpd:1$' \
	    "$JGC" -c "$SOCK" services convert -n ntpd
	atf_check cmp rc.conf.before root/etc/rc.conf
	atf_check -o inline:'ntpd_flags="-g"\n' cat root/etc/rc.conf.d/ntpd
	atf_check -s exit:1 -e match:'no such service' \
	    "$JGC" -c "$SOCK" services convert -n nosuch
	# Real: a change like a commit's, refused until accepted.
	atf_check -s exit:1 -e match:'ntpd_enable .*rc.conf line 4.*-a rc-conf-conflict' \
	    "$JGC" -c "$SOCK" services convert ntpd
	atf_check cmp rc.conf.before root/etc/rc.conf
	atf_check -o match:'^ntpd +ntpd_enable +NO +/etc/rc.conf:4$' \
	    -o match:'^ +ntpd_flags +-g +/etc/rc.conf.d/ntpd:1$' \
	    "$JGC" -c "$SOCK" services convert -a rc-conf-conflict ntpd
	atf_check -o match:'^ntpd_enable="NO"$' -o match:'^ntpd_flags="-g"$' \
	    -o match:'^sshd_flags="-6"$' -o not-match:'ntpd_sync_on_start' \
	    cat root/usr/local/etc/rc.conf.d/arcana
	atf_check -o match:'^#ntpd_enable="NO"  # taken by Arcana$' \
	    -o match:'^ntpd_sync_on_start="\$x"$' -o not-match:'^ntpd_enable' \
	    cat root/etc/rc.conf
	atf_check -o inline:'#ntpd_flags="-g"  # taken by Arcana\n' cat root/etc/rc.conf.d/ntpd
	atf_check -o match:'\{"enabled":false,"name":"ntpd","variable":\[\{"name":"ntpd_flags","value":"-g"\}\]\}' \
	    "$JGC" -c "$SOCK" get -d running services
	# Every script: nothing of the user's left but what cannot be taken.
	atf_check -o match:'ntpd_sync_on_start' -o not-match:'sshd' \
	    -o not-match:'ntpd_flags' "$JGC" -c "$SOCK" services convert -n
	# As the action, its output RFC 7951's JSON.
	atf_check -o match:'"service":\[\{"name":"ntpd","variable":\[\{"file":"/etc/rc.conf","left":"its value is not a literal[^"]*","line":5,"name":"ntpd_sync_on_start"\}\]\}\]' \
	    "$JGC" -c "$SOCK" action services convert dry-run=true
}
datastores_services_cleanup()
{
	stop_daemon
}

# arcana-jails (PLAN-SDN-YANG 3.1.1): running is each jail's parameters
# as jail(8) -e resolves them, and what starts at boot from the files
# rc(8) reads; a commit edits the jail's own block in place, makes a
# new jail a file of its own in jail.conf.d and takes one away with
# its file, and writes jail_list to Arcana's rc.conf file by
# rcarcana.c's rules.  What jail(8) would not read as asked is refused,
# every file put back.
atf_test_case datastores_jails cleanup
datastores_jails_head()
{
	atf_set "descr" "jail.conf as running, committed in place; boot by Arcana's rc.conf file; a jail made and taken away; refusals put every file back"
}
datastores_jails_body()
{
	mkdir -p root/etc/defaults root/usr/local/etc
	cp /etc/defaults/rc.conf root/etc/defaults/
	printf 'hostname="lab"\njail_enable="YES"\njail_list="db"\n' \
	    > root/etc/rc.conf
	DAEMON_ARGS="--root $(pwd)/root"
	start_daemon
	# Running: each jail's parameters as jail(8) -e has them, and what
	# starts at boot from the files rc(8) reads; nothing of its state.
	atf_check -o save:run.json "$JGC" -c "$SOCK" get -d running jails
	atf_check -o match:'"name":"db","param":.*"scope":"[^"]*/etc/jail.conf","boot":true\},\{"name":"mail"' \
	    -o match:'"name":"ip4.addr","value":\["10.0.0.10","10.0.0.11"\]' \
	    -o not-match:'"state"' -o not-match:'"conf-error"' cat run.json
	atf_check -o match:'"name":"web".*"state":"stopped"' \
	    "$JGC" -c "$SOCK" get jails
	# A list changed in its block, its first statement's place kept,
	# every other line as it was.
	cp etc/jail.conf before
	sed -e 's/"10\.0\.0\.11"/"10.0.0.12","10.0.0.13"/' run.json > e1.json
	atf_check "$JGC" -c "$SOCK" edit jails @e1.json
	atf_check "$JGC" -c "$SOCK" commit
	atf_check -o match:'^	ip4.addr = 10.0.0.10, "10.0.0.12", "10.0.0.13";$' \
	    -o match:'^# Lab jails$' cat etc/jail.conf
	atf_check -o inline:'2\n' sh -c "diff before etc/jail.conf | grep -c '^[<>]'"
	# Started at boot: jail_list and jail_enable in Arcana's rc.conf
	# file, the user's lines commented out where accepted.
	atf_check -s exit:1 -e match:'-a rc-conf-files' \
	    "$JGC" -c "$SOCK" enable web
	atf_check -s exit:1 -e match:'jail_list .*rc.conf line 3.*-a rc-conf-conflict' \
	    "$JGC" -c "$SOCK" enable -a rc-conf-files web
	atf_check -o match:'^At boot: +started$' "$JGC" -c "$SOCK" \
	    enable -a rc-conf-files -a rc-conf-conflict web
	atf_check -o match:'^jail_list="db web"$' -o match:'^jail_enable="YES"$' \
	    cat root/usr/local/etc/rc.conf.d/arcana
	atf_check -o match:'^#jail_list="db"  # taken by Arcana$' \
	    -o match:'^hostname="lab"$' cat root/etc/rc.conf
	# The last one taken out: jail_enable off, never an empty list,
	# which starts every jail.
	atf_check -o ignore "$JGC" -c "$SOCK" disable db
	atf_check -o match:'^At boot: +not started$' "$JGC" -c "$SOCK" \
	    disable web
	atf_check -o match:'^jail_enable="NO"$' -o not-match:'jail_list' \
	    cat root/usr/local/etc/rc.conf.d/arcana
	# A jail made: a file of its own in jail.conf.d; taken away with it.
	atf_check -o save:run2.json "$JGC" -c "$SOCK" get -d running jails
	sed -e 's|"jail":\[|"jail":[{"name":"cache","param":[{"name":"path","value":["/jails/cache"]},{"name":"persist"}]},|' \
	    run2.json > e2.json
	atf_check "$JGC" -c "$SOCK" edit jails @e2.json
	atf_check "$JGC" -c "$SOCK" commit
	atf_check -o inline:'cache {\n\tpath = /jails/cache;\n\tpersist;\n}\n' \
	    cat etc/jail.conf.d/cache.conf
	atf_check -o match:'^cache +stopped' "$JGC" -c "$SOCK" list -c
	atf_check "$JGC" -c "$SOCK" edit jails @run2.json
	atf_check "$JGC" -c "$SOCK" commit
	atf_check -s exit:1 test -e etc/jail.conf.d/cache.conf
	# Refused, every file as it was: a parameter the file's defaults
	# give, not the jail's own; a name jail(8) would not take.
	cp etc/jail.conf before
	sed -e 's|{"name":"path","value":\["/jails/web"\]},||' run2.json > e3.json
	atf_check "$JGC" -c "$SOCK" edit jails @e3.json
	atf_check -s exit:1 -e match:"web: path is inherited from the file's defaults" \
	    "$JGC" -c "$SOCK" commit
	atf_check cmp before etc/jail.conf
	atf_check "$JGC" -c "$SOCK" discard
	sed -e 's/"name":"vpn"/"name":"a;b"/' run2.json > e4.json
	atf_check "$JGC" -c "$SOCK" edit jails @e4.json
	atf_check -s exit:1 -e match:'invalid jail name' "$JGC" -c "$SOCK" commit
	atf_check -o match:'^vpn \{$' cat etc/jail.conf.d/vpn.conf
	atf_check "$JGC" -c "$SOCK" discard
}
datastores_jails_cleanup()
{
	stop_daemon
}

# arcana-kernel (3.1.6): kld_list as running, from the files rc(8)
# reads; a commit writes it to Arcana's rc.conf file by rcarcana.c's
# rules, the kernel as it is, said where the two differ.
atf_test_case datastores_kernel cleanup
datastores_kernel_head()
{
	atf_set "descr" "kld_list as running, committed to Arcana's rc.conf file"
}
datastores_kernel_body()
{
	mkdir -p root/etc/defaults root/usr/local/etc
	cp /etc/defaults/rc.conf root/etc/defaults/
	printf 'hostname="lab"\nkld_list="if_bridge"\n' > root/etc/rc.conf
	DAEMON_ARGS="--root $(pwd)/root"
	start_daemon
	atf_check -o inline:'{"arcana-kernel:kernel":{"kept":["if_bridge"]}}\n' \
	    "$JGC" -c "$SOCK" get -d running kernel
	# The operational state's kept is sysrc(8)'s word (./rc.conf here,
	# the jobs' file), running's the files under the root.
	printf 'kld_list="if_bridge"\n' >> rc.conf
	atf_check -o match:'"kept":\["if_bridge"\]' -o match:'"file":\[\{"address"' \
	    "$JGC" -c "$SOCK" get kernel
	# rc_conf_files first, then the user's variable; then Arcana's
	# file has it, the user's commented out, and a module not loaded
	# is said.
	atf_check "$JGC" -c "$SOCK" edit kernel '{"kept":["if_bridge","if_nosuch"]}'
	atf_check -s exit:1 -e match:'-a rc-conf-files' "$JGC" -c "$SOCK" commit
	atf_check -s exit:1 -e match:'kld_list .*rc.conf line 2.*-a rc-conf-conflict' \
	    "$JGC" -c "$SOCK" commit -a rc-conf-files
	atf_check -o match:'kld-list: if_nosuch is not loaded: kld_list loads it at the next boot' \
	    "$JGC" -c "$SOCK" commit -a rc-conf-files -a rc-conf-conflict
	atf_check -o match:'^kld_list="if_bridge if_nosuch"$' \
	    cat root/usr/local/etc/rc.conf.d/arcana
	atf_check -o match:'^rc_conf_files=".*/usr/local/etc/rc.conf.d/arcana"$' \
	    -o match:'^#kld_list="if_bridge"  # taken by Arcana$' \
	    -o not-match:'^kld_list' cat root/etc/rc.conf
	atf_check -o inline:'{"arcana-kernel:kernel":{"kept":["if_bridge","if_nosuch"]}}\n' \
	    "$JGC" -c "$SOCK" get -d running kernel
	# A name is a name.
	atf_check "$JGC" -c "$SOCK" edit kernel '{"kept":["/tmp/evil.ko"]}'
	atf_check -s exit:1 -e match:'without a path' "$JGC" -c "$SOCK" commit
	atf_check "$JGC" -c "$SOCK" discard
	# None: the variable taken out.
	atf_check "$JGC" -c "$SOCK" edit kernel '{}'
	atf_check -o ignore "$JGC" -c "$SOCK" commit
	atf_check -o not-match:'kld_list' cat root/usr/local/etc/rc.conf.d/arcana
	atf_check -o inline:'{"arcana-kernel:kernel":{}}\n' \
	    "$JGC" -c "$SOCK" get -d running kernel
}
datastores_kernel_cleanup()
{
	stop_daemon
}

# ietf-syslog (RFC 9742) in running, syslog.conf and newsyslog.conf as
# syslogd and newsyslog read them; a commit writes Arcana's own files,
# included by theirs, and takes the user's lines of what it changes
# only where accepted; syslogd not told again, every file as it was.
atf_test_case datastores_syslog cleanup
datastores_syslog_head()
{
	atf_set "descr" "syslog.conf and newsyslog.conf read and committed"
}
datastores_syslog_body()
{
	mkdir -p root/etc/defaults root/etc/syslog.d root/usr/local/etc \
	    root/var/log
	cp /etc/defaults/rc.conf root/etc/defaults/
	printf 'hostname="lab"\n' > root/etc/rc.conf
	cat > root/etc/syslog.conf <<'EOF'
*.err;kern.warning;auth.notice;mail.crit		/dev/console
*.notice;authpriv.none;kern.debug;lpr.info;mail.crit;news.err	/var/log/messages
security.*					/var/log/security
cron.*						-/var/log/cron
!-devd
*.=debug					/var/log/debug.log
!*
include						/etc/syslog.d
EOF
	echo 'local7.*	/var/log/messages' > root/etc/syslog.d/l7.conf
	cat > root/etc/newsyslog.conf <<'EOF'
/var/log/messages	644  5	1000	@0101T JC
/var/log/security	600  10	1000	*	JC
/var/log/cron		600  3	1000	*	JC
<include> /usr/local/etc/newsyslog.conf.d/[!.]*.conf
EOF
	touch root/var/log/messages root/var/log/security root/var/log/cron
	cp root/etc/syslog.conf syslog.conf.before
	cp root/etc/newsyslog.conf newsyslog.conf.before
	DAEMON_ARGS="--root $(pwd)/root"
	start_daemon
	touch running.syslogd
	"$JGC" -c "$SOCK" get -d running syslog > run.json
	atf_check -o match:'"name":"file:/var/log/messages"' \
	    -o match:'"facility":"ietf-syslog:local7"' cat run.json
	# A file of its own, rotated, and a remote: Arcana's files,
	# syslog.conf's include accepted first.
	sed -e 's|"log-file":\[|"log-file":[{"name":"file:/var/log/arcana.log","filter":{"facility-list":[{"facility":"ietf-syslog:local3","severity":"info"}]},"file-rotation":{"number-of-files":4,"max-file-size":2,"rollover":1440}},|' \
	    -e 's|\]}}}}$|]},"remote":{"destination":[{"name":"192.0.2.10","udp":{"udp":[{"address":"192.0.2.10","port":5514}]},"filter":{"facility-list":[{"facility":"ietf-syslog:local4","severity":"all"}]}}]}}}}|' \
	    run.json > new.json
	atf_check "$JGC" -c "$SOCK" edit syslog @new.json
	atf_check -s exit:1 -e match:'include them.*/etc/syslog.conf.*-a syslog-include' \
	    "$JGC" -c "$SOCK" commit
	atf_check cmp syslog.conf.before root/etc/syslog.conf
	atf_check -o ignore "$JGC" -c "$SOCK" commit -a syslog-include
	atf_check -o file:syslog.conf.before head -n 8 root/etc/syslog.conf
	atf_check -o match:'^include[[:space:]]+/usr/local/etc/syslog.d$' \
	    tail -n 1 root/etc/syslog.conf
	atf_check cmp newsyslog.conf.before root/etc/newsyslog.conf
	printf 'local3.info\t/var/log/arcana.log\nlocal4.*\t@192.0.2.10:5514\n' \
	    > want
	atf_check -o file:want grep -v '^#' \
	    root/usr/local/etc/syslog.d/arcana.conf
	printf '/var/log/arcana.log\t600  4\t2048\t24\tJC\n' > want
	atf_check -o file:want grep -v '^#' \
	    root/usr/local/etc/newsyslog.conf.d/arcana.conf
	atf_check test -f root/var/log/arcana.log
	atf_check -o inline:'reloaded\n' cat reloads.syslogd
	"$JGC" -c "$SOCK" get -d running syslog > run2.json
	atf_check -o match:'"max-file-size":2,"number-of-files":4,"rollover":1440' \
	    -o match:'"address":"192.0.2.10","port":5514' cat run2.json
	# One of the user's: their lines of it taken over where accepted.
	sed -e 's|{"facility":"ietf-syslog:lpr","severity":"info"},||' \
	    run2.json > lpr.json
	atf_check "$JGC" -c "$SOCK" edit syslog @lpr.json
	atf_check -s exit:1 \
	    -e match:'/etc/syslog.conf:2, /etc/syslog.d/l7.conf:1.*-a syslog-conf-conflict' \
	    "$JGC" -c "$SOCK" commit
	atf_check -o ignore "$JGC" -c "$SOCK" commit -a syslog-conf-conflict
	atf_check -o match:'^# taken by Arcana: \*\.notice;authpriv.none;kern.debug;lpr.info' \
	    sed -n 2p root/etc/syslog.conf
	atf_check -o match:'^# taken by Arcana: local7' cat root/etc/syslog.d/l7.conf
	atf_check -o match:'^\*\.notice;authpriv\.none;kern\.debug;mail\.crit;news\.err;local7\.\*	/var/log/messages$' \
	    cat root/usr/local/etc/syslog.d/arcana.conf
	atf_check cmp newsyslog.conf.before root/etc/newsyslog.conf
	"$JGC" -c "$SOCK" get -d running syslog > run3.json
	atf_check -o not-match:'ietf-syslog:lpr' \
	    -o match:'"facility":"ietf-syslog:local7"' cat run3.json
	# A rotation the files cannot hold, a remote named otherwise than
	# by its address: refused, said.
	sed -e 's|"rollover":1440|"rollover":1440,"retention":600|' \
	    run3.json > ret.json
	atf_check "$JGC" -c "$SOCK" edit syslog @ret.json
	atf_check -s exit:1 -e match:'retention: newsyslog keeps a number of files' \
	    "$JGC" -c "$SOCK" commit
	atf_check "$JGC" -c "$SOCK" discard
	sed -e 's|"name":"192.0.2.10"|"name":"loghost"|' run3.json > name.json
	atf_check "$JGC" -c "$SOCK" edit syslog @name.json
	atf_check -s exit:1 -e match:'loghost: a destination is named by its address' \
	    "$JGC" -c "$SOCK" commit
	atf_check "$JGC" -c "$SOCK" discard
	# syslogd will not read them again: every file as it was.
	for f in etc/syslog.conf etc/newsyslog.conf etc/syslog.d/l7.conf \
	    usr/local/etc/syslog.d/arcana.conf \
	    usr/local/etc/newsyslog.conf.d/arcana.conf; do
		cp "root/$f" "$(echo "$f" | tr / _).was"
	done
	sed -e 's|"number-of-files":3}|"number-of-files":6}|' run3.json > cron.json
	atf_check "$JGC" -c "$SOCK" edit syslog @cron.json
	touch noreload.syslogd
	atf_check -s exit:1 -e match:'syslogd: not reloaded' \
	    "$JGC" -c "$SOCK" commit -a syslog-conf-conflict
	for f in etc/syslog.conf etc/newsyslog.conf etc/syslog.d/l7.conf \
	    usr/local/etc/syslog.d/arcana.conf \
	    usr/local/etc/newsyslog.conf.d/arcana.conf; do
		atf_check cmp "$(echo "$f" | tr / _).was" "root/$f"
	done
	atf_check "$JGC" -c "$SOCK" discard
	rm noreload.syslogd
	# Taken away, syslogd not running: said, read when it starts.
	rm running.syslogd
	sed -e 's|,"remote":.*$|}}}|' run3.json > gone.json
	atf_check -o not-match:'192.0.2.10' cat gone.json
	atf_check "$JGC" -c "$SOCK" edit syslog @gone.json
	atf_check -o match:'syslogd-stopped.*when it starts' \
	    "$JGC" -c "$SOCK" commit
	atf_check -o not-match:'@192.0.2.10' \
	    cat root/usr/local/etc/syslog.d/arcana.conf
	atf_check -o not-match:'192.0.2.10' \
	    "$JGC" -c "$SOCK" get -d running syslog
}
datastores_syslog_cleanup()
{
	stop_daemon
}

atf_init_test_cases()
{
	atf_add_test_case datastores_syslog
	atf_add_test_case datastores_ra
	atf_add_test_case datastores_sysctl
	atf_add_test_case datastores_services
	atf_add_test_case datastores_jails
	atf_add_test_case datastores_kernel
	atf_add_test_case datastores_instances
	atf_add_test_case datastores_interfaces
	atf_add_test_case datastores
	atf_add_test_case reboot
	atf_add_test_case jail_boot
	atf_add_test_case bird_watch
	atf_add_test_case poudriere
	atf_add_test_case host_watch
	atf_add_test_case fw_walk
	atf_add_test_case crash_fault
	atf_add_test_case firewall_aliases
	atf_add_test_case firewall_long
	atf_add_test_case config_bundle
	atf_add_test_case ntp
	atf_add_test_case rtadvd
	atf_add_test_case ipsec_sa
	atf_add_test_case interfaces
	atf_add_test_case network_more
	atf_add_test_case sdwan
	atf_add_test_case sdwan_forms
	atf_add_test_case netstore
	atf_add_test_case smtpd
	atf_add_test_case speeder
	atf_add_test_case relay_rc
	atf_add_test_case monitors
	atf_add_test_case sysfiles
	atf_add_test_case sdwan_jail
	atf_add_test_case jail_conf
	atf_add_test_case jail_allow
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
	atf_add_test_case safe_sysctl
	atf_add_test_case safe_route_delete
	atf_add_test_case safe_bird
	atf_add_test_case safe_wireguard
	atf_add_test_case safe_ipsec
	atf_add_test_case safe_ipsec_sa
	atf_add_test_case safe_sysfile
	atf_add_test_case safe_if_destroy
	atf_add_test_case safe_l2
	atf_add_test_case agent_update
	atf_add_test_case agent_update_gzip
	atf_add_test_case agent_update_old
	atf_add_test_case agent_restart
	atf_add_test_case agent_build
	atf_add_test_case stop
	atf_add_test_case hello
	atf_add_test_case yang_get
	atf_add_test_case yang_actions
	atf_add_test_case yang_subscribe
	atf_add_test_case yang_interfaces
	atf_add_test_case yang_routes
	atf_add_test_case yang_origins
	atf_add_test_case yang_pmd
	atf_add_test_case yang_rc_routes
	atf_add_test_case yang_rtadv_conf
	atf_add_test_case yang_lne
	atf_add_test_case yang_ni_conf
	atf_add_test_case yang_ni_rc
	atf_add_test_case yang_ni_grow
	atf_add_test_case yang_active_route
	atf_add_test_case yang_jails
	atf_add_test_case yang_hardware
	atf_add_test_case yang_system
	atf_add_test_case yang_processes
	atf_add_test_case yang_log
	atf_add_test_case yang_firewall
	atf_add_test_case yang_troubleshoot
	atf_add_test_case yang_history
	atf_add_test_case yang_events
	atf_add_test_case yang_plugins
	atf_add_test_case yang_host_agent
	atf_add_test_case yang_sdwan
	atf_add_test_case yang_storage
	atf_add_test_case yang_packages
	atf_add_test_case yang_services
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
	atf_add_test_case jail_base
	atf_add_test_case jobs
}
