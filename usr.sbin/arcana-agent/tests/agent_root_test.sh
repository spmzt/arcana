#
# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
#
# arcana-agent(8) as root, on a throwaway jail it defines itself:
# "arcana-test", path "/", no mounts, exec hooks that only echo, and
# addresses on lo0 in 127.0.10.0/24.  Each case removes the jail and its
# addresses when it is done, and refuses to run if a jail of that name
# already exists.
#

JAIL=arcana-test

programs()
{
	JGD="$(atf_get_srcdir)/../arcana-agent"
	[ -f "$JGD" -a -x "$JGD" ] ||
	    JGD=$(atf_config_get arcana-agent /usr/local/sbin/arcana-agent)
	JGC="$(atf_get_srcdir)/../../arcanactl/arcanactl"
	[ -f "$JGC" -a -x "$JGC" ] ||
	    JGC=$(atf_config_get arcanactl /usr/local/sbin/arcanactl)
}

start_daemon()
{
	local i

	if jls -j "$JAIL" >/dev/null 2>&1; then
		atf_skip "a jail named $JAIL already exists"
	fi
	programs
	mkdir etc etc/jail.conf.d
	cat > etc/jail.conf <<EOF2
$JAIL {
	path = "/";
	host.hostname = "$JAIL.local";
	interface = lo0;
	ip4.addr = 127.0.10.1;
	persist;
	exec.start = "/bin/echo $JAIL: exec.start ran";
	exec.stop = "/bin/echo $JAIL: exec.stop ran";
}
EOF2
	SOCK="unix:$(pwd)/s.sock"
	# What it keeps (probes, rules, faults) in the work directory, not
	# the host's /usr/local/etc/arcana, where the next case would find it.
	"$JGD" -F -l "$SOCK" -f "$(pwd)/etc/jail.conf" \
	    -D "$(pwd)/etc/jail.conf.d" -1 "$(pwd)/history.conf" \
	    ${DAEMON_ARGS:-} > daemon.out 2>&1 &
	echo $! > daemon.pid
	for i in $(seq 1 100); do
		grep -q 'ready' daemon.out 2>/dev/null && return
		sleep 0.05
	done
	atf_fail "arcana-agent did not start: $(cat daemon.out)"
}

# Whatever happened, leave no jail, address or daemon behind.
cleanup()
{
	[ -f daemon.pid ] && kill "$(cat daemon.pid)" 2>/dev/null
	[ -f etc/jail.conf ] && jail -f etc/jail.conf -r "$JAIL" >/dev/null 2>&1
	for a in 127.0.10.1 127.0.10.2 127.0.10.3; do
		ifconfig lo0 inet "$a" -alias 2>/dev/null
	done
	true
}

lo0_has()
{
	ifconfig lo0 inet | grep -q "inet $1 "
}

atf_test_case lifecycle cleanup
lifecycle_head()
{
	atf_set "descr" "start, restart, stop and kill a real jail"
	atf_set "require.user" "root"
	# One jail and one name for all of them: never side by side.
	atf_set "is.exclusive" "true"
}
lifecycle_body()
{
	start_daemon
	atf_check -o save:start.out "$JGC" -t -c "$SOCK" start "$JAIL"
	atf_check -o match:'^State: running \(jid [0-9]+\)$' cat start.out
	atf_check -o match:"\\| $JAIL: exec.start ran" cat start.out
	atf_check -o ignore jls -j "$JAIL"
	lo0_has 127.0.10.1 || atf_fail "jail(8) did not add 127.0.10.1"
	atf_check -o match:"^$JAIL +running +[0-9]+ +127.0.10.1 " \
	    "$JGC" -c "$SOCK" list
	atf_check -s exit:1 -o ignore -e match:'already running' \
	    "$JGC" -c "$SOCK" start "$JAIL"

	atf_check -o save:restart.out "$JGC" -t -c "$SOCK" restart "$JAIL"
	atf_check -o match:"jail -f .* -rc $JAIL: exit status 0" \
	    -o match:'exec.stop ran' -o match:'exec.start ran' cat restart.out

	atf_check -o match:'^State: stopped$' "$JGC" -c "$SOCK" stop "$JAIL"
	atf_check -s exit:1 -o ignore -e ignore jls -j "$JAIL"
	lo0_has 127.0.10.1 && atf_fail "127.0.10.1 left on lo0"

	atf_check -o ignore "$JGC" -c "$SOCK" start "$JAIL"
	atf_check -o save:kill.out "$JGC" -t -c "$SOCK" kill "$JAIL"
	atf_check -o match:'\[syscall\] jail_remove\(2\)' cat kill.out
	atf_check -s exit:1 sh -c "grep '\[exec\]' kill.out | grep -v ' -e '"
	# Each coming and going was an event as it happened (EVFILT_JAIL).
	sleep 0.5
	atf_check -o save:ev.json "$JGC" -c "$SOCK" events
	atf_check -o match:"\"kind\":\"jail-state\",\"data\":\\{\"jail\":\"$JAIL\",\"state\":\"running\",\"jid\":[0-9]+\\}" \
	    -o match:"\"kind\":\"jail-state\",\"data\":\\{\"jail\":\"$JAIL\",\"state\":\"stopped\"" \
	    cat ev.json
	# Four starts (start, restart, start again) and as many ends.
	atf_check -o inline:'3\n' sh -c "grep -o '\"state\":\"running\"' ev.json | wc -l | tr -d ' '"
	atf_check -o inline:'3\n' sh -c "grep -o '\"state\":\"stopped\"' ev.json | wc -l | tr -d ' '"
}
lifecycle_cleanup()
{
	cleanup
}

atf_test_case jail_events_nested cleanup
jail_events_nested_head()
{
	atf_set "descr" "a jail made inside another, an LNE in an LNE, is an" \
	    "event when made and when removed (EVFILT_JAIL; PLAN-SDN-YANG" \
	    "2.7.5)"
	atf_set "require.user" "root"
	atf_set "is.exclusive" "true"
}
jail_events_nested_body()
{
	start_daemon
	jls -j "$YJAIL" >/dev/null 2>&1 && atf_skip "a jail named $YJAIL exists"
	atf_check -o ignore jail -c name="$YJAIL" path=/ vnet persist \
	    children.max=1
	atf_check -o ignore jexec "$YJAIL" jail -c name=inner path=/ persist
	atf_check -o ignore jls -j "$YJAIL.inner"
	atf_check -o ignore jexec "$YJAIL" jail -r inner
	atf_check -o ignore jail -r "$YJAIL"
	sleep 0.5
	atf_check -o save:ev.json "$JGC" -c "$SOCK" events
	for j in "$YJAIL" "$YJAIL.inner"; do
		for st in running stopped; do
			atf_check -o inline:"$j $st 1\n" sh -c "echo $j $st \$(grep -o '\"jail\":\"$j\",\"state\":\"$st\"' ev.json | wc -l | tr -d ' ')"
		done
	done
}
jail_events_nested_cleanup()
{
	jail -r "$YJAIL" >/dev/null 2>&1
	cleanup
}

atf_test_case live_address cleanup
live_address_head()
{
	atf_set "descr" "Live address changes use jail_setv(3) and ioctls only"
	atf_set "require.user" "root"
	# One jail and one name for all of them: never side by side.
	atf_set "is.exclusive" "true"
}
live_address_body()
{
	start_daemon
	cp etc/jail.conf before
	atf_check -o ignore "$JGC" -c "$SOCK" start "$JAIL"
	atf_check -o save:add.out "$JGC" -t -c "$SOCK" address add -l "$JAIL" \
	    127.0.10.2
	atf_check -o match:'^IPv4: 127.0.10.1,127.0.10.2$' \
	    -o match:'\[syscall\] ioctl\(SIOCAIFADDR\)' \
	    -o match:'\[lib\] jailparam_set\(3\)' cat add.out
	# Only jail(8) -e, reading the configuration, runs a program.
	atf_check -s exit:1 sh -c "grep '\[exec\]' add.out | grep -v ' -e '"
	lo0_has 127.0.10.2 || atf_fail "alias not added"
	atf_check -o inline:'127.0.10.1,127.0.10.2\n' \
	    jls -j "$JAIL" ip4.addr
	atf_check cmp -s before etc/jail.conf

	atf_check -o match:'^IPv4: 127.0.10.1$' \
	    "$JGC" -c "$SOCK" address remove -l "$JAIL" 127.0.10.2
	lo0_has 127.0.10.2 && atf_fail "alias not removed"

	atf_check -o match:'^IPv4: 127.0.10.1,127.0.10.3$' \
	    "$JGC" -c "$SOCK" address add -lp "$JAIL" 127.0.10.3
	atf_check -o match:'ip4.addr = 127.0.10.1, "127.0.10.3";' \
	    cat etc/jail.conf
	atf_check -o ignore "$JGC" -c "$SOCK" restart "$JAIL"
	atf_check -o inline:'127.0.10.1,127.0.10.3\n' \
	    jls -j "$JAIL" ip4.addr
}
live_address_cleanup()
{
	cleanup
}

atf_test_case aliases cleanup
aliases_head()
{
	atf_set "descr" "Aliases jail(8) does not know about go with the jail"
	atf_set "require.user" "root"
	# One jail and one name for all of them: never side by side.
	atf_set "is.exclusive" "true"
}
aliases_body()
{
	start_daemon
	atf_check -o ignore "$JGC" -c "$SOCK" start "$JAIL"
	atf_check -o ignore "$JGC" -c "$SOCK" address add -l "$JAIL" 127.0.10.2
	lo0_has 127.0.10.2 || atf_fail "alias not added"
	# jail(8) -r removes the configured alias; arcana-agent the live one.
	atf_check -o save:stop.out "$JGC" -t -c "$SOCK" stop "$JAIL"
	atf_check -o match:'\[syscall\] ioctl\(SIOCDIFADDR\)' cat stop.out
	lo0_has 127.0.10.2 && atf_fail "live alias 127.0.10.2 left on lo0"
	lo0_has 127.0.10.1 && atf_fail "configured alias 127.0.10.1 left on lo0"

	# jail_remove(2) removes no aliases at all; arcana-agent does.
	atf_check -o ignore "$JGC" -c "$SOCK" start "$JAIL"
	lo0_has 127.0.10.1 || atf_fail "jail(8) did not add 127.0.10.1"
	atf_check -o ignore "$JGC" -c "$SOCK" kill "$JAIL"
	lo0_has 127.0.10.1 && atf_fail "alias 127.0.10.1 left after kill"
	true
}
aliases_cleanup()
{
	cleanup
}

atf_test_case routes cleanup
routes_head()
{
	atf_set "descr" "the real routing table through netlink: read, a route added with its cost and share, looked up, deleted; and each told by the kernel as an event, as an interface and its address are"
	atf_set "require.user" "root"
	atf_set "is.exclusive" "true"
}
routes_body()
{
	if ifconfig lo7 >/dev/null 2>&1 || route -n get 198.51.100.9 2>/dev/null | grep -q 'destination: 198.51.100.0'; then
		atf_skip "lo7 or a route to 198.51.100.0/24 is there already"
	fi
	touch mine
	start_daemon
	atf_check -o match:'"interface-name":"lo0"' -o match:'"metric":[0-9]+,"weight":[0-9]+,"fib":0,"prefixlen":[0-9]+' \
	    "$JGC" -c "$SOCK" net routes
	last=$("$JGC" -c "$SOCK" events | sed -E 's/^\{"last":([0-9]+).*/\1/')
	# Read by the daemon itself, from the kernel's own lists, as
	# netstat and sockstat would list them: what sockstat has, this has,
	# and in parts too.
	atf_check -o match:'"statistics":\{"socket":\[' "$JGC" -c "$SOCK" net connections
	pid=$(sockstat -46w | awk 'NR > 1 && $3 ~ /^[0-9]+$/ { print $3; exit }')
	atf_check -o match:"\"pid\":$pid," -o match:'"user":"' \
	    "$JGC" -c "$SOCK" net sockets
	atf_check -o match:'"command":"' "$JGC" -c "$SOCK" net sockets parts
	atf_check -o match:'netlink\(4\)' "$JGC" -t -c "$SOCK" net routes

	atf_check -o match:'done +route add 198.51.100.0/24 via 127.0.0.1' \
	    "$JGC" -c "$SOCK" route add 198.51.100.0/24 127.0.0.1 metric 7 weight 3
	atf_check -o match:'"destination":"198.51.100.0/24","gateway":"127.0.0.1","flags":"UGS",[^}]*"interface-name":"lo0","metric":7,"weight":3' \
	    "$JGC" -c "$SOCK" net routes -4 198.51.100.
	atf_check -o match:'"best":\{"to":"198.51.100.9","destination":"198.51.100.0","prefixlen":24,"gateway":"127.0.0.1"' \
	    -o match:'"candidates":\[.*"destination":"198.51.100.0/24"' \
	    "$JGC" -c "$SOCK" route get 198.51.100.9
	atf_check -o match:'198.51.100.0/24 +127.0.0.1' netstat -rn4
	# The kernel told the agent of it, without being asked.
	atf_check -o match:'"kind":"route-add","data":\{"destination":"198.51.100.0/24","gateway":"127.0.0.1"' \
	    "$JGC" -c "$SOCK" events "$last"
	atf_check -o match:'done +route delete 198.51.100.0/24' \
	    "$JGC" -c "$SOCK" route delete 198.51.100.0/24 127.0.0.1 metric 7
	atf_check -o not-match:'198.51.100.0/24' netstat -rn4
	atf_check -o match:'"kind":"route-del","data":\{"destination":"198.51.100.0/24"' \
	    "$JGC" -c "$SOCK" events "$last"
	atf_check -s exit:1 -o match:'there is no such route' \
	    "$JGC" -c "$SOCK" route delete 198.51.100.0/24 127.0.0.1

	# Followed as they happen, the same events told to a subscriber.
	"$JGC" -c "$SOCK" events -f > follow.out 2>&1 &
	echo $! > follow.pid
	sleep 0.5
	# An interface that comes, and its address.
	atf_check ifconfig lo7 create
	atf_check ifconfig lo7 inet 127.0.77.1/24
	sleep 0.5
	atf_check -o match:'"kind":"link","data":\{"interface":"lo7"' \
	    -o match:'"kind":"address-add","data":\{"interface":"lo7","address":"127.0.77.1","prefixlen":24\}' \
	    "$JGC" -c "$SOCK" events "$last"
	# A route of two next hops, each with its share: two rows of one
	# route, and a nexthop group in the kernel.
	atf_check -o match:'done +route add 198.51.100.0/24 via 127.0.77.2@2,127.0.77.3' \
	    "$JGC" -c "$SOCK" route add 198.51.100.0/24 127.0.77.2@2,127.0.77.3
	atf_check -o save:ecmp.json "$JGC" -c "$SOCK" net routes -4 198.51.100.
	atf_check -o match:'"gateway":"127.0.77.2",[^}]*"weight":2,[^}]*"path":[12],"paths":2' \
	    -o match:'"gateway":"127.0.77.3",[^}]*"weight":1,[^}]*"path":[12],"paths":2' \
	    cat ecmp.json
	atf_check -o match:'"nh-gw":"127.0.77.[23]"' "$JGC" -c "$SOCK" net nhgroups
	# One of its ways deleted by its gateway: the other stays.
	atf_check -o match:'done' "$JGC" -c "$SOCK" route delete 198.51.100.0/24 127.0.77.3
	atf_check -o match:'"gateway":"127.0.77.2"' -o not-match:'127.0.77.3' \
	    "$JGC" -c "$SOCK" net routes -4 198.51.100.
	atf_check -o match:'done' "$JGC" -c "$SOCK" route delete 198.51.100.0/24
	# A neighbour, as ARP has it: listed by the kernel, and told as an
	# event when it comes and when it goes.
	ep=$(ifconfig epair create)
	echo "$ep" > epair
	atf_check ifconfig "$ep" inet 192.0.2.201/24 up
	atf_check arp -s 192.0.2.202 02:00:00:77:02:02
	sleep 0.5
	atf_check -o match:"\"address\":\"192.0.2.202\",\"lladdr\":\"02:00:00:77:02:02\",\"interface-name\":\"$ep\",\"state\":\"permanent\"" \
	    -o match:'"total":[1-9]' "$JGC" -c "$SOCK" net neighbours -4 192.0.2.202
	atf_check -o match:'"kind":"neigh","data":\{"family":"inet","address":"192.0.2.202"' \
	    "$JGC" -c "$SOCK" events "$last"
	atf_check -o ignore arp -d 192.0.2.202
	sleep 0.5
	atf_check -o match:'"kind":"neigh-del","data":\{"family":"inet","address":"192.0.2.202"' \
	    "$JGC" -c "$SOCK" events "$last"
	atf_check ifconfig "$ep" destroy
	rm epair
	atf_check ifconfig lo7 destroy
	sleep 0.5
	atf_check -o match:'"kind":"link-del","data":\{"interface":"lo7"' \
	    "$JGC" -c "$SOCK" events "$last"
	kill "$(cat follow.pid)"
	atf_check -o match:'"kind":"link","data":\{"interface":"lo7"' \
	    -o match:'"kind":"route-add","data":\{[^}]*"destination":"198.51.100.0' \
	    -o match:'"kind":"neigh","data":\{"family":"inet","address":"192.0.2.202"' \
	    -o match:'"kind":"link-del","data":\{"interface":"lo7"' cat follow.out
}
routes_cleanup()
{
	[ -f daemon.pid ] && kill "$(cat daemon.pid)" 2>/dev/null
	[ -f follow.pid ] && kill "$(cat follow.pid)" 2>/dev/null
	if [ -f mine ]; then
		route -q delete 198.51.100.0/24 >/dev/null 2>&1
		ifconfig lo7 destroy >/dev/null 2>&1
		[ -f epair ] && ifconfig "$(cat epair)" destroy >/dev/null 2>&1
	fi
	true
}

atf_test_case jail_network cleanup
jail_network_head()
{
	atf_set "descr" "a jail's own network (vnet) watched as the host's is: its interfaces, addresses and routes are events with its name, whether it was there before the agent or came after; and removed, it goes at once, not held"
	atf_set "require.user" "root"
	atf_set "is.exclusive" "true"
}
jail_network_body()
{
	if jls -j arcw_n1 >/dev/null 2>&1 || jls -j arcw_n2 >/dev/null 2>&1; then
		atf_skip "a jail arcw_n1 or arcw_n2 is there already"
	fi
	touch mine
	atf_check -o ignore jail -c name=arcw_n1 vnet persist path=/
	start_daemon
	sleep 0.5
	atf_check -o match:'watching the network of jail arcw_n1' cat daemon.out
	last=$("$JGC" -c "$SOCK" events | sed -E 's/^\{"last":([0-9]+).*/\1/')
	atf_check -o ignore jail -c name=arcw_n2 vnet persist path=/
	sleep 0.5
	atf_check -o match:'watching the network of jail arcw_n2' cat daemon.out
	# An interface given to each, with an address and a route there:
	# told with the jail's name, the interface by the jail's own index.
	for n in 1 2; do
		ep=$(ifconfig epair create)
		echo "${ep%a}" >> epairs
		atf_check ifconfig "${ep%a}b" vnet "arcw_n$n"
		atf_check jexec "arcw_n$n" ifconfig "${ep%a}b" inet "192.0.2.2$n/24" up
		atf_check -o ignore jexec "arcw_n$n" route -q add 198.51.100.0/24 "192.0.2.3$n"
	done
	sleep 0.5
	atf_check -o save:ev.json "$JGC" -c "$SOCK" events "$last"
	for n in 1 2; do
		b=$(sed -n "${n}p" epairs)b
		atf_check -o match:"\"kind\":\"link\",\"jail\":\"arcw_n$n\",\"data\":\\{\"interface\":\"$b\"" \
		    -o match:"\"kind\":\"address-add\",\"jail\":\"arcw_n$n\",\"data\":\\{\"interface\":\"$b\",\"address\":\"192.0.2.2$n\",\"prefixlen\":24\\}" \
		    -o match:"\"kind\":\"route-add\",\"jail\":\"arcw_n$n\",\"data\":\\{\"destination\":\"198.51.100.0/24\",\"gateway\":\"192.0.2.3$n\",[^}]*\"interface-name\":\"$b\"" \
		    cat ev.json
	done
	# The host's own were not told as the jail's.
	atf_check -o not-match:'"kind":"route-add","data":\{"destination":"198.51.100.0/24"' cat ev.json
	# Its firewall on or off as the jail's own network has it, not
	# as the host's.
	if kldstat -q -m ipfw; then
		atf_check -o ignore jexec arcw_n1 sysctl net.inet.ip.fw.enable=0
		atf_check -o match:'"enabled":false' "$JGC" -j arcw_n1 -c "$SOCK" net ipfw
		atf_check -o ignore jexec arcw_n1 sysctl net.inet.ip.fw.enable=1
		atf_check -o match:'"enabled":true' "$JGC" -j arcw_n1 -c "$SOCK" net ipfw
	fi
	# Removed: no longer watched, and gone, not held dying by it.  A
	# vnet torn down with an address on an interface in it panics a
	# debug kernel: the epairs go first.
	while read -r e; do
		atf_check ifconfig "${e}a" destroy
	done < epairs
	atf_check -o ignore jail -r arcw_n1
	sleep 0.5
	atf_check -o match:'the network of jail arcw_n1 is not watched' cat daemon.out
	atf_check -s not-exit:0 -e match:"not found" jls -d -j arcw_n1 jid
	atf_check -o ignore jail -r arcw_n2
	sleep 0.5
	atf_check -s not-exit:0 -e match:"not found" jls -d -j arcw_n2 jid
}
jail_network_cleanup()
{
	[ -f daemon.pid ] && kill "$(cat daemon.pid)" 2>/dev/null
	if [ -f mine ]; then
		[ -f epairs ] && while read -r e; do
			ifconfig "${e}a" destroy >/dev/null 2>&1
		done < epairs
		jail -r arcw_n1 >/dev/null 2>&1
		jail -r arcw_n2 >/dev/null 2>&1
	fi
	true
}

atf_test_case jail_plugins cleanup
jail_plugins_head()
{
	atf_set "descr" "a vnet jail's plugins are looked for as the jail sees its files: a program behind a link inside it is found, though the host has none; wg(8) of the base system counts"
	atf_set "require.user" "root"
	atf_set "is.exclusive" "true"
}
jail_plugins_body()
{
	if jls -j arcw_p1 >/dev/null 2>&1; then
		atf_skip "a jail arcw_p1 is there already"
	fi
	[ -e /opt/local/sbin/squid ] &&
	    atf_skip "the host has /opt/local/sbin/squid: the link would lead to it"
	touch mine
	# Squid behind the jail's own /usr/local, a link to /opt/local
	# inside it: from the host, that link leads to the host's /opt.
	mkdir -p root/opt/local/sbin root/usr/bin
	printf '#!/bin/sh\n' > root/opt/local/sbin/squid
	printf '#!/bin/sh\n' > root/usr/bin/wg
	chmod +x root/opt/local/sbin/squid root/usr/bin/wg
	ln -s /opt/local root/usr/local
	atf_check -o ignore jail -c name=arcw_p1 vnet persist path="$(pwd)/root"
	start_daemon
	atf_check -o save:list.json "$JGC" --libxo json -c "$SOCK" list
	atf_check -o match:'"name":"arcw_p1"' cat list.json
	sed -n 's/.*"name":"arcw_p1"\(.*\)/\1/p' list.json > jail.json
	atf_check -o match:'"plugins": ?\[[^]]*"squid"' \
	    -o match:'"plugins": ?\[[^]]*"wireguard"' cat jail.json
	# The host's own: wg(8) of the base system is WireGuard's there too.
	if [ -x /usr/bin/wg ] && [ ! -e /usr/local/bin/wg ]; then
		atf_check -o match:'Plugins:.*wireguard' "$JGC" -c "$SOCK" hello
	fi
	atf_check -o ignore jail -r arcw_p1
}
jail_plugins_cleanup()
{
	[ -f daemon.pid ] && kill "$(cat daemon.pid)" 2>/dev/null
	[ -f mine ] && jail -r arcw_p1 >/dev/null 2>&1
	true
}

atf_test_case fw_trace cleanup
fw_trace_head()
{
	atf_set "descr" "packets followed through the real firewall by the kernel: pings to an address, each with the rule that passed it"
	atf_set "require.user" "root"
	atf_set "is.exclusive" "true"
}
fw_trace_body()
{
	kldstat -q -m ipfw || atf_skip "ipfw(4) is not loaded"
	kldload -n dtraceall || atf_skip "no dtrace(4)"
	start_daemon
	ping -c 6 -i 0.3 127.0.0.1 >/dev/null 2>&1 &
	atf_check -o save:trace.json "$JGC" -c "$SOCK" ipfw trace 127.0.0.1 3 4
	atf_check -o match:'"verdict":"pass","family":"inet","source":"127.0.0.1","destination":"127.0.0.1","proto":1,"sport":0,"dport":0,"rule":[0-9]+,"interface":"lo0","direction":"(in|out)"' \
	    -o match:'"seconds":3,"limit":4' cat trace.json
	# No more than asked for.
	atf_check -o inline:'4\n' sh -c "grep -o '\"ms\"' trace.json | wc -l | tr -d ' '"
}
fw_trace_cleanup()
{
	[ -f daemon.pid ] && kill "$(cat daemon.pid)" 2>/dev/null
	true
}

atf_test_case kmsg cleanup
kmsg_head()
{
	atf_set "descr" "the kernel's messages, numbered as they come and followed by their number, none twice"
	atf_set "require.user" "root"
}
kmsg_body()
{
	start_daemon
	atf_check -o save:k1.json "$JGC" -c "$SOCK" log @dmesg
	atf_check -o match:'"name":"@dmesg","lines":\[\{' \
	    -o match:'"seq":[0-9]+' -o match:'"position":[1-9][0-9]*' cat k1.json
	pos=$(sed -n 's/.*"position":\([0-9]*\).*/\1/p' k1.json)
	# After the newest: none of what was read again (the kernel may
	# have said more since).
	atf_check -o not-match:"\"seq\":$pos[,}]" -o match:'"position":[0-9]+' \
	    "$JGC" -c "$SOCK" log -f "$pos" @dmesg
	# The last lines, by their number, in order.
	atf_check -o save:k3.json "$JGC" -c "$SOCK" log -o 3 @dmesg
	atf_check -o inline:'3\n' sh -c "grep -o '\"seq\":' k3.json | wc -l | tr -d ' '"
	# A number from before the agent began: read anew.
	atf_check -o match:'"rotated":true' "$JGC" -c "$SOCK" log -f 99999999 @dmesg
}
kmsg_cleanup()
{
	[ -f daemon.pid ] && kill "$(cat daemon.pid)" 2>/dev/null
	true
}

atf_test_case crash_event cleanup
crash_event_head()
{
	atf_set "descr" "a process the kernel ends by a signal that dumps" \
	    "core is an event, crash, with its name, jail and signal"
	atf_set "require.user" "root"
}
crash_event_body()
{
	[ "$(sysctl -n kern.logsigexit)" = 1 ] ||
	    atf_skip "kern.logsigexit is off: the kernel says no crash"
	start_daemon
	# The agent's first read of the buffer is what came before it.
	sleep 2
	# A stand-in of its own name crashes; no core is left (ulimit).
	cp /bin/sh ./arccrash
	./arccrash -c 'ulimit -c 0; kill -SEGV $$' || true
	for i in $(seq 1 50); do
		"$JGC" -c "$SOCK" events > ev.out 2>/dev/null
		grep -q '"process":"arccrash"' ev.out && break
		sleep 0.2
	done
	atf_check -o match:'"kind":"crash"' \
	    -o match:'"process":"arccrash","jid":0,"jail":"","uid":0,"signal":11,"core":false' \
	    cat ev.out
}
crash_event_cleanup()
{
	[ -f daemon.pid ] && kill "$(cat daemon.pid)" 2>/dev/null
	true
}

atf_test_case sdwan_probe cleanup
sdwan_probe_head()
{
	atf_set "descr" "a tunnel measured for real: the loopback pinged every 50 ms, up with its samples, and an address nothing routes to down, each an event"
	atf_set "require.user" "root"
	atf_set "is.exclusive" "true"
}
sdwan_probe_body()
{
	printf '#!/bin/sh\necho "ipfw $*" >> %s/ipfw.log\nexit 0\n' "$(pwd)" > fake-ipfw
	chmod +x fake-ipfw
	DAEMON_ARGS="-h $(pwd)/fake-ipfw"
	start_daemon
	last=$("$JGC" -c "$SOCK" events | sed -E 's/^\{"last":([0-9]+).*/\1/')
	atf_check -o empty "$JGC" -c "$SOCK" sdwan probes \
	    '[{"id":"lo","address":"127.0.0.1","interval":50,"eval":300,"down":2,"up":2,"timeout":200}]'
	sleep 2
	atf_check -o save:up.json "$JGC" -c "$SOCK" sdwan
	atf_check -o match:'"id":"lo","address":"127.0.0.1","family":"inet","fib":0,"state":"up"' \
	    -o match:'"samples":\[\[[0-9]+,[0-9.]+,[0-9.]+,0(\.0+)?,[0-9.]+,[0-9.]+,[1-9][0-9]*,[1-9][0-9]*\]' cat up.json
	atf_check -o match:'"kind":"sdwan-tunnel","data":\{"id":"lo","address":"127.0.0.1","state":"up"' \
	    "$JGC" -c "$SOCK" events "$last"
	# A table with no way to it: every probe lost, down in two.
	if setfib 2 route -n get 192.0.2.77 >/dev/null 2>&1; then
		atf_skip "fib 2 has a route to 192.0.2.77"
	fi
	# The steering follows the probes: the way through void first,
	# while nothing says it is down; once its probes do, the next one.
	atf_check -o empty "$JGC" -c "$SOCK" sdwan rules \
	    '{"set":30,"tables":[{"name":"swt_p_4","valtype":"ipv4"}],"rules":["12 fwd tablearg ip4 from any to table(swt_p_4)"]}'
	: > ipfw.log
	atf_check -o empty "$JGC" -c "$SOCK" sdwan steer \
	    '{"entries":[{"table":"swt_p_4","prefix":"10.20.0.0/24","candidates":[{"id":"void","via":"100.64.0.9"},{"id":"lo","via":"100.64.0.1"}]}]}'
	atf_check -o match:'atomic add 10.20.0.0/24 100.64.0.9' cat ipfw.log
	atf_check -o empty "$JGC" -c "$SOCK" sdwan probes \
	    '[{"id":"lo","address":"127.0.0.1","interval":50,"eval":300,"down":2,"up":2,"timeout":200},{"id":"void","address":"192.0.2.77","fib":2,"interval":50,"eval":300,"down":2,"timeout":100}]'
	sleep 1.5
	atf_check -o match:'atomic add 10.20.0.0/24 100.64.0.1' cat ipfw.log
	atf_check -o match:'"chosen":1,"candidates":\[\{"id":"void","via":"100.64.0.9","state":"down"\},\{"id":"lo","via":"100.64.0.1","state":"up"\}' \
	    "$JGC" -c "$SOCK" sdwan
	atf_check -o match:'"id":"void","address":"192.0.2.77","family":"inet","fib":2,"state":"down"' \
	    -o match:'"id":"lo",[^}]*"state":"up"' "$JGC" -c "$SOCK" sdwan
	atf_check -o match:'"data":\{"id":"void","address":"192.0.2.77","state":"down","misses":[0-9]+' \
	    "$JGC" -c "$SOCK" events "$last"
	atf_check -o empty "$JGC" -c "$SOCK" sdwan probes '[]'
}
sdwan_probe_cleanup()
{
	[ -f daemon.pid ] && kill "$(cat daemon.pid)" 2>/dev/null
	# Its rule and tables, which outlive the agent, gone from the
	# host's ipfw: only they, by their names.
	ipfw -S show 12 2>/dev/null | grep -q 'table(swt_p_4)' && \
	    ipfw -q delete 12
	ipfw -q table swt_p_4 destroy 2>/dev/null
	ipfw -q table swt_p_4_alt destroy 2>/dev/null
	true
}

atf_test_case sdwan_jail_edge cleanup
sdwan_jail_edge_head()
{
	atf_set "descr" "an SD-WAN edge that is a vnet jail, for real: its" \
	    "loopback probed from its own network (an ICMP socket the" \
	    "helper makes there), up, and a host's address the jail has no" \
	    "route to, down; its own ipfw given a set and steered"
	atf_set "require.user" "root"
	atf_set "is.exclusive" "true"
}
sdwan_jail_edge_body()
{
	atf_check -o ignore jail -c name=arcw_sdj vnet persist path=/
	atf_check jexec arcw_sdj ifconfig lo0 inet 127.0.0.1/8 up
	start_daemon
	# 127.0.0.1 in the jail's network; 192.0.2.66 is on no route of it.
	atf_check -o empty "$JGC" -c "$SOCK" sdwan probes \
	    '{"jail":"arcw_sdj","targets":[{"id":"jlo","address":"127.0.0.1","interval":50,"eval":300,"down":2,"up":2,"timeout":200},{"id":"jvoid","address":"192.0.2.66","interval":50,"eval":300,"down":2,"timeout":100}]}'
	sleep 2
	atf_check -o match:'"id":"jlo","address":"127.0.0.1","family":"inet","jail":"arcw_sdj","fib":0,"state":"up"' \
	    -o match:'"id":"jvoid","address":"192.0.2.66","family":"inet","jail":"arcw_sdj","fib":0,"state":"(down|error)"' \
	    "$JGC" -c "$SOCK" sdwan
	# Its own ipfw, where the kernel has one.
	if jexec arcw_sdj ipfw show >/dev/null 2>&1; then
		atf_check -o empty "$JGC" -c "$SOCK" sdwan rules \
		    '{"jail":"arcw_sdj","set":30,"tables":[{"name":"sj_p4","valtype":"ipv4","entries":[]}],"rules":["00500 count ip from any to table(sj_p4)"]}'
		atf_check -o match:'^00500 .*count ip from any to table\(sj_p4\)' \
		    jexec arcw_sdj ipfw show 500
		atf_check -o empty "$JGC" -c "$SOCK" sdwan steer \
		    '{"jail":"arcw_sdj","entries":[{"table":"sj_p4","prefix":"10.20.0.0/24","candidates":[{"id":"jvoid","via":"100.64.0.9"},{"id":"jlo","via":"100.64.0.1"}]}]}'
		atf_check -o match:'10.20.0.0/24 100.64.0.1' \
		    jexec arcw_sdj ipfw table sj_p4 list
		# The host's ipfw has none of it.
		atf_check -s not-exit:0 -e ignore -o ignore ipfw table sj_p4 list
		atf_check -o empty "$JGC" -c "$SOCK" sdwan rules \
		    '{"jail":"arcw_sdj","set":30,"tables":[],"rules":[]}'
	fi
	atf_check -o match:'"kind":"sdwan-tunnel","data":\{"id":"jlo","address":"127.0.0.1","state":"up","misses":0,"jail":"arcw_sdj"\}' \
	    "$JGC" -c "$SOCK" events
	atf_check -o empty "$JGC" -c "$SOCK" sdwan probes '{"jail":"arcw_sdj","targets":[]}'
	# Its network's multicast state, its own: lo0 alone, in 224.0.0.1.
	atf_check -o match:'"interfaces":\[\{"name":"lo0",.*"group":"224.0.0.1"' \
	    -o not-match:'"name":"(vtnet|em|igb|ix)[0-9]' \
	    -o match:'"settings":\[\{"name":"net.inet.igmp.default_version"' \
	    "$JGC" -c "$SOCK" -j arcw_sdj net multicast
}
sdwan_jail_edge_cleanup()
{
	[ -f daemon.pid ] && kill "$(cat daemon.pid)" 2>/dev/null
	sleep 0.5
	jail -r arcw_sdj 2>/dev/null
	true
}

atf_test_case sdwan_links cleanup
sdwan_links_head()
{
	atf_set "descr" "an SD-WAN edge's links watched for real: an epair's" \
	    "end down is an interface fault, up again cleared, as netlink" \
	    "tells the agent"
	atf_set "require.user" "root"
	atf_set "is.exclusive" "true"
}
sdwan_links_body()
{
	ep=$(ifconfig epair create) || atf_skip "no epair(4)"
	echo "$ep" > epair.name
	start_daemon
	atf_check -o empty "$JGC" -c "$SOCK" sdwan probes \
	    "{\"targets\":[],\"links\":[{\"interface\":\"$ep\",\"id\":\"uni-lab\",\"role\":\"uni\"}]}"
	# Made down: a fault at once.
	atf_check -o match:'"type":"interface","severity":"Major","was":"Major","object":"uni-lab","by":"link",[^}]*"cleared":false' \
	    "$JGC" -c "$SOCK" sdwan
	atf_check ifconfig "$ep" up
	atf_check ifconfig "${ep%a}b" up
	sleep 1
	atf_check -o match:'"object":"uni-lab","by":"link","description":"the UNI uni-lab has its link on '"$ep"' again","cleared":true' \
	    "$JGC" -c "$SOCK" sdwan
	atf_check ifconfig "$ep" down
	sleep 1
	atf_check -o match:'"object":"uni-lab","by":"link","description":"the UNI uni-lab has no link on '"$ep"'","cleared":false' \
	    "$JGC" -c "$SOCK" sdwan
	atf_check -o empty "$JGC" -c "$SOCK" sdwan probes '{"targets":[],"links":[]}'
}
sdwan_links_cleanup()
{
	[ -f daemon.pid ] && kill "$(cat daemon.pid)" 2>/dev/null
	[ -f epair.name ] && ifconfig "$(cat epair.name)" destroy 2>/dev/null
	true
}

atf_test_case sctp_multihome cleanup
sctp_multihome_head()
{
	atf_set "descr" "an SCTP association multi-homed between two network" \
	    "stacks: the agent in one vnet jail bound to two addresses" \
	    "(--sctp-also), arcanactl in another with two of its own, two" \
	    "epairs between them; the association has a path over each," \
	    "one cut goes on over the other, and the cut one comes back"
	atf_set "require.user" "root"
	atf_set "is.exclusive" "true"
	atf_set "timeout" "180"
}
sctp_multihome_body()
{
	local d="$(pwd)" port=24607 e0 e1 a b

	kldstat -q -m sctp || atf_skip "the kernel has no SCTP"
	command -v openssl >/dev/null || atf_skip "no openssl"
	programs
	for j in arcw_ma arcw_mb; do
		jls -j $j >/dev/null 2>&1 && atf_skip "a jail $j is there already"
	done
	# A CA, the agent's certificate for both its addresses, a client's.
	openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
	    -keyout ca.key -out ca.pem -days 2 -subj /CN=lab-ca \
	    -addext basicConstraints=critical,CA:true \
	    -addext keyUsage=critical,keyCertSign >/dev/null 2>&1
	for n in server client; do
		openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
		    -keyout $n.key -out $n.csr -subj /CN=$n >/dev/null 2>&1
		if [ $n = server ]; then
			printf 'subjectAltName=IP:10.91.0.1,IP:10.92.0.1\nextendedKeyUsage=serverAuth\n' > $n.ext
		else
			printf 'subjectAltName=DNS:console\nextendedKeyUsage=clientAuth\n' > $n.ext
		fi
		openssl x509 -req -in $n.csr -CA ca.pem -CAkey ca.key \
		    -CAcreateserial -out $n.pem -days 2 -extfile $n.ext \
		    >/dev/null 2>&1 || atf_fail "no $n certificate"
	done
	atf_check -o ignore jail -c name=arcw_ma vnet persist path=/
	atf_check -o ignore jail -c name=arcw_mb vnet persist path=/
	e0=$(ifconfig epair create); e1=$(ifconfig epair create)
	echo "${e0%a} ${e1%a}" > epairs
	atf_check ifconfig $e0 vnet arcw_ma
	atf_check ifconfig ${e0%a}b vnet arcw_mb
	atf_check ifconfig $e1 vnet arcw_ma
	atf_check ifconfig ${e1%a}b vnet arcw_mb
	atf_check jexec arcw_ma ifconfig $e0 inet 10.91.0.1/24 up
	atf_check jexec arcw_ma ifconfig $e1 inet 10.92.0.1/24 up
	atf_check jexec arcw_mb ifconfig ${e0%a}b inet 10.91.0.2/24 up
	atf_check jexec arcw_mb ifconfig ${e1%a}b inet 10.92.0.2/24 up
	for j in arcw_ma arcw_mb; do
		atf_check jexec $j ifconfig lo0 inet 127.0.0.1/8 up
		# A failed path found in about a second, not half a minute:
		# each stack's own (net.inet.sctp is per vnet).
		atf_check -o ignore jexec $j sysctl net.inet.sctp.rto_min=100 \
		    net.inet.sctp.rto_initial=300 net.inet.sctp.rto_max=500 \
		    net.inet.sctp.path_rtx_max=1 net.inet.sctp.heartbeat_interval=200
	done
	mkdir -p etc/jail.conf.d
	: > etc/jail.conf
	# The agent in arcw_ma: TCP and SCTP on 10.91.0.1, SCTP on
	# 10.92.0.1 too.
	jexec arcw_ma "$JGD" -F -l "tcp://10.91.0.1:$port" \
	    --sctp-also 10.92.0.1 -A "$d/ca.pem" -C "$d/server.pem" \
	    -K "$d/server.key" -f "$d/etc/jail.conf" -D "$d/etc/jail.conf.d" \
	    -1 "$d/history.conf" > daemon.out 2>&1 &
	echo $! > daemon.pid
	a="-A $d/ca.pem -C $d/client.pem -K $d/client.key"
	for i in 1 2 3 4 5 6 7 8 9 10; do
		jexec arcw_mb "$JGC" -c "sctp://10.91.0.1:$port" $a hello \
		    >/dev/null 2>&1 && break
		sleep 0.5
	done
	# One association kept open: what happens, as it happens.
	jexec arcw_mb "$JGC" -c "sctp://10.91.0.1:$port" $a events -f \
	    > follow.out 2>&1 &
	echo $! > follow.pid
	sleep 1
	# From the agent's end: the follower's association has a path to
	# each of the client's addresses, both taken up.
	atf_check -o save:t1.json jexec arcw_mb "$JGC" \
	    -c "sctp://10.92.0.1:$port" $a transport
	atf_check -o match:'"transport":"sctp","up":true,"addresses":\[("10.91.0.1","10.92.0.1"|"10.92.0.1","10.91.0.1")\]' cat t1.json
	atf_check -o match:'"paths":\[[^]]*"address":"10.91.0.2","state":"active"' \
	    -o match:'"paths":\[[^]]*"address":"10.92.0.2","state":"active"' cat t1.json
	# The first path cut, at the client's end: what happens after goes
	# on over the other, on the same association.
	atf_check jexec arcw_mb ifconfig ${e0%a}b down
	atf_check jexec arcw_ma ifconfig lo7 create
	for i in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do
		grep -q '"interface":"lo7"' follow.out && break
		sleep 0.5
	done
	atf_check -o match:'"kind":"link","data":\{"interface":"lo7"' cat follow.out
	kill -0 "$(cat follow.pid)" || atf_fail "the follower's association ended"
	atf_check -o save:t2.json jexec arcw_mb "$JGC" \
	    -c "sctp://10.92.0.1:$port" $a transport
	# The cut address no longer carries it: inactive, or taken out of
	# the association by the client itself (ASCONF, auto_asconf).
	atf_check -o match:'"address":"10.92.0.2","state":"active","srtt_ms":[0-9]+,"rto_ms":[0-9]+,"primary":true' \
	    -o not-match:'"address":"10.91.0.2","state":"active"' cat t2.json
	# The cut one back: added again (ASCONF) and taken up.
	atf_check jexec arcw_mb ifconfig ${e0%a}b up
	for i in 1 2 3 4 5 6 7 8 9 10; do
		jexec arcw_mb "$JGC" -c "sctp://10.92.0.1:$port" $a transport \
		    > t3.json 2>/dev/null
		grep -q '"address":"10.91.0.2","state":"active"' t3.json && break
		sleep 0.5
	done
	atf_check -o match:'"address":"10.91.0.2","state":"active"' cat t3.json
	atf_check jexec arcw_ma ifconfig lo7 destroy
}
sctp_multihome_cleanup()
{
	[ -f follow.pid ] && kill "$(cat follow.pid)" 2>/dev/null
	[ -f daemon.pid ] && kill "$(cat daemon.pid)" 2>/dev/null
	sleep 0.5
	# Each interface out of its jail before the jail goes: a vnet torn
	# down with them in it can panic.
	if [ -f epairs ]; then
		for e in $(cat epairs); do
			ifconfig ${e}a -vnet arcw_ma 2>/dev/null
			ifconfig ${e}b -vnet arcw_mb 2>/dev/null
			ifconfig ${e}a destroy 2>/dev/null
		done
	fi
	jexec arcw_ma ifconfig lo7 destroy 2>/dev/null
	jail -r arcw_ma 2>/dev/null
	jail -r arcw_mb 2>/dev/null
	true
}

atf_test_case snort_live cleanup
snort_live_head()
{
	atf_set "descr" "Snort for real: rules taken in and turned off, and" \
	    "local.rules, checked by the real snort -T (one it refuses kept" \
	    "out); arcana_snort starts it on an epair, a vnet jail's ping" \
	    "is an alert the agent reads, and with the rule turned off a" \
	    "reload makes the next ping none"
	atf_set "require.user" "root"
	atf_set "is.exclusive" "true"
	atf_set "timeout" "240"
}
snort_live_body()
{
	local d="$(pwd)" e sn env flags etc rc n0 n1 i

	# The program and where its own files are: the package's, or a
	# tree the configuration names (snort, snort_env, snort_flags,
	# snort_etc), its libraries and DAQ modules elsewhere.
	sn=$(atf_config_get snort /usr/local/bin/snort)
	env=$(atf_config_get snort_env "")
	flags=$(atf_config_get snort_flags "")
	etc=$(atf_config_get snort_etc /usr/local/etc/snort)
	[ -x "$sn" ] || atf_skip "no snort (security/snort3)"
	rc="$(atf_get_srcdir)/../arcana_snort.sh"
	[ -r "$rc" ] || rc=/usr/local/etc/rc.d/arcana_snort
	jls -j arcw_sn >/dev/null 2>&1 && atf_skip "a jail arcw_sn is there already"
	mkdir se sl
	cp "$etc"/*.lua "$etc"/*.rules se/
	printf '#!/bin/sh\nexec env %s %s %s "$@"\n' "$env" "$sn" "$flags" > snort-run
	chmod +x snort-run
	# rc.conf in the work directory, not the host's.
	cat > fake-sysrc <<EOS
#!/bin/sh
c=$d/rc.conf; touch \$c
[ "\$1" = -i ] && shift
case "\$1" in
-n) sed -n "s/^\$2=\"\(.*\)\"\\\$/\1/p" \$c | grep . ;;
-x) grep -v "^\$2=" \$c > \$c.n; mv \$c.n \$c ;;
*=*) grep -v "^\${1%%=*}=" \$c > \$c.n; printf '%s="%s"\n' "\${1%%=*}" "\${1#*=}" >> \$c.n; mv \$c.n \$c ;;
esac
EOS
	chmod +x fake-sysrc
	# Rules as an archive gives them, one to be seen and one to turn off.
	mkdir -p src/lab-rules
	cat > src/lab-rules/lab.rules <<'EOR'
alert icmp any any -> any any ( msg:"lab ping seen"; itype:8; classtype:misc-activity; sid:1000002; rev:1; )
alert tcp any any -> any 23 ( msg:"lab telnet"; flow:to_server; sid:1000003; rev:1; )
EOR
	tar -czf rules.tar.gz -C src lab-rules
	atf_check -o ignore jail -c name=arcw_sn vnet persist path=/
	e=$(ifconfig epair create)
	echo "$e" > epair.name
	atf_check ifconfig ${e%a}b vnet arcw_sn
	atf_check ifconfig $e inet 10.94.0.1/24 up
	atf_check jexec arcw_sn ifconfig ${e%a}b inet 10.94.0.2/24 up
	DAEMON_ARGS="--snort $d/snort-run --snort-etc $d/se --snort-log $d/sl -y $d/fake-sysrc"
	start_daemon
	atf_check -o match:'"installed":true' -o match:'"version":"3\.' \
	    "$JGC" -c "$SOCK" snort
	atf_check -o match:'done' "$JGC" -c "$SOCK" snort update \
	    "url=file://$d/rules.tar.gz"
	atf_check -o match:'"files":\[\{"name":"lab.rules","rules":2,"on":2\}\]' \
	    "$JGC" -c "$SOCK" snort
	# What the real snort refuses, kept out; its words in the error.
	printf 'alert icmp any any -> any any (msg:"bad"; nosuchopt:1; sid:1000009;)\n' > bad.rules
	atf_check -s exit:1 -o match:'snort does not take it: ERROR: .*unknown rule keyword: nosuchopt' \
	    -e ignore "$JGC" -c "$SOCK" snort conf local.rules bad.rules
	printf 'alert udp any any -> any 9 (msg:"lab discard"; sid:1000004; rev:1;)\n' > good.rules
	atf_check -o match:'done' "$JGC" -c "$SOCK" snort conf local.rules good.rules
	atf_check -o match:'done' "$JGC" -c "$SOCK" snort set enable=yes mode=ids \
	    interface=$e home_net=10.94.0.0/24
	atf_check -o match:"^arcana_snort_interfaces=\"$e\"\$" cat rc.conf
	# Started by arcana_snort, as rc(8) would, its settings given.
	atf_check -o ignore -e ignore env arcana_snort_enable=YES \
	    arcana_snort_interfaces=$e arcana_snort_conf=$d/se/snort.lua \
	    arcana_snort_rules=$d/se/arcana/arcana.rules arcana_snort_logdir=$d/sl \
	    arcana_snort_program="$sn" arcana_snort_env="$env" \
	    arcana_snort_flags="$flags" sh "$rc" onestart
	for i in $(seq 1 60); do
		[ -s sl/snort.pid ] && kill -0 $(cat sl/snort.pid) 2>/dev/null && break
		sleep 1
	done
	atf_check -o match:'"running":true' "$JGC" -c "$SOCK" snort
	sleep 3
	for i in $(seq 1 20); do
		jexec arcw_sn ping -c 1 -t 1 10.94.0.1 >/dev/null 2>&1
		grep -q 'lab ping seen' sl/alert_json.txt 2>/dev/null && break
		sleep 1
	done
	atf_check -o match:'"alerts":\[\{[^}]*"proto":"ICMP","src_addr":"10.94.0.2","dst_addr":"10.94.0.1","gid":1,"sid":1000002,"rev":1,"msg":"lab ping seen"' \
	    "$JGC" -c "$SOCK" snort
	# Turned off: the running Snort reloads, and pings are no alerts.
	atf_check -o match:'done' "$JGC" -c "$SOCK" snort rule off=1:1000002
	sleep 8
	n0=$(grep -c 'lab ping seen' sl/alert_json.txt)
	for i in 1 2 3; do jexec arcw_sn ping -c 1 -t 1 10.94.0.1 >/dev/null 2>&1; done
	sleep 3
	n1=$(grep -c 'lab ping seen' sl/alert_json.txt)
	[ "$n0" = "$n1" ] || atf_fail "alerts after the rule was turned off: $n0, then $n1"
	atf_check -o ignore -e ignore env arcana_snort_logdir=$d/sl \
	    arcana_snort_program="$sn" arcana_snort_interfaces=$e sh "$rc" onestop
}
snort_live_cleanup()
{
	[ -s sl/snort.pid ] && kill "$(cat sl/snort.pid)" 2>/dev/null
	[ -f epair.name ] && ifconfig "$(cat epair.name)" destroy 2>/dev/null
	jail -r arcw_sn >/dev/null 2>&1
	cleanup
}

atf_test_case bird_live cleanup
bird_live_head()
{
	atf_set "descr" "BIRD for real between two vnet jails: eBGP over an" \
	    "epair, written as the console's BGP form writes a session," \
	    "Established, a route of each learned by the other; the agent" \
	    "reads the session's state and the routes through the real birdc"
	atf_set "require.user" "root"
	atf_set "is.exclusive" "true"
	atf_set "timeout" "180"
}
bird_live_body()
{
	local d="$(pwd)" e j n

	[ -x /usr/local/sbin/bird ] || atf_skip "no BIRD (net/bird3)"
	for j in arcw_ba arcw_bb; do
		jls -j $j >/dev/null 2>&1 && atf_skip "a jail $j is there already"
	done
	atf_check -o ignore jail -c name=arcw_ba vnet persist path=/
	atf_check -o ignore jail -c name=arcw_bb vnet persist path=/
	e=$(ifconfig epair create)
	echo "${e%a}" > epair.name
	atf_check ifconfig $e vnet arcw_ba
	atf_check ifconfig ${e%a}b vnet arcw_bb
	atf_check jexec arcw_ba ifconfig $e inet 10.93.0.1/24 up
	atf_check jexec arcw_bb ifconfig ${e%a}b inet 10.93.0.2/24 up
	# Each as the BGP form writes a session (name, local AS, the
	# neighbour and its AS, a channel), and a route of its own to give.
	for n in a b; do
		if [ $n = a ]; then
			me=10.93.0.1 peer=10.93.0.2 las=65001 nas=65002 net=192.0.2.0/24
		else
			me=10.93.0.2 peer=10.93.0.1 las=65002 nas=65001 net=198.51.100.0/24
		fi
		cat > bird-$n.conf <<EOF
router id $me;

protocol device device1 {
}

protocol static own {
	ipv4;
	route $net blackhole;
}

protocol bgp peer_$n {
	description "the lab's other end";
	local as $las;
	neighbor $peer as $nas;
	ipv4 {
		import all;
		export where proto = "own";
	};
}
EOF
		atf_check /usr/local/sbin/bird -p -c bird-$n.conf
		jexec arcw_b$n /usr/local/sbin/bird -c "$d/bird-$n.conf" \
		    -s "$d/b$n.ctl" -P "$d/b$n.pid" || atf_fail "bird $n did not start"
	done
	# The agent's birdc: the real one, told jail a's socket.
	printf '#!/bin/sh\nexec /usr/local/sbin/birdc -s %s/ba.ctl "$@"\n' "$d" \
	    > birdc-a
	chmod +x birdc-a
	DAEMON_ARGS="-b $d/birdc-a"
	start_daemon
	for i in $(seq 1 60); do
		/usr/local/sbin/birdc -s ba.ctl show protocols peer_a 2>/dev/null |
		    grep -q Established && break
		sleep 1
	done
	atf_check -o match:'peer_a +BGP +--- +up .*Established' \
	    /usr/local/sbin/birdc -s ba.ctl show protocols peer_a
	# The agent's read of it, from the jail: up and Established.
	atf_check -o save:bird.json "$JGC" -c "$SOCK" -j arcw_ba net bird
	atf_check -o match:'"name":"peer_a","proto":"BGP"[^}]*"state":"up"[^}]*"info":"Established"' \
	    cat bird.json
	# The route b gave, learned by a, as the agent reads BIRD's table.
	for i in $(seq 1 20); do
		/usr/local/sbin/birdc -s ba.ctl show route 198.51.100.0/24 \
		    2>/dev/null | grep -q peer_a && break
		sleep 0.5
	done
	atf_check -o match:'198\.51\.100\.0/24' -o match:'peer_a' \
	    "$JGC" -c "$SOCK" -j arcw_ba bird routes
}
bird_live_cleanup()
{
	local d="$(pwd)"

	[ -f daemon.pid ] && kill "$(cat daemon.pid)" 2>/dev/null
	for n in a b; do
		[ -f b$n.pid ] && kill "$(cat b$n.pid)" 2>/dev/null
	done
	sleep 0.5
	# Its interfaces out of each jail before the jail goes.
	if [ -f epair.name ]; then
		e=$(cat epair.name)
		ifconfig ${e}a -vnet arcw_ba 2>/dev/null
		ifconfig ${e}b -vnet arcw_bb 2>/dev/null
		ifconfig ${e}a destroy 2>/dev/null
	fi
	jail -r arcw_ba 2>/dev/null
	jail -r arcw_bb 2>/dev/null
	true
}

atf_test_case sctp_loopback cleanup
sctp_loopback_head()
{
	atf_set "descr" "an SCTP listener on a router's loopback address alone" \
	    "(an address on lo0): FreeBSD's SCTP answers no peer elsewhere" \
	    "from it, which the transport read says; with --sctp-also an" \
	    "address of a real interface, SCTP by that one is answered"
	atf_set "require.user" "root"
	atf_set "is.exclusive" "true"
	atf_set "timeout" "120"
}
sctp_loopback_body()
{
	local d="$(pwd)" port=24611 e a

	kldstat -q -m sctp || atf_skip "the kernel has no SCTP"
	command -v openssl >/dev/null || atf_skip "no openssl"
	programs
	for j in arcw_la arcw_lb; do
		jls -j $j >/dev/null 2>&1 && atf_skip "a jail $j is there already"
	done
	openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
	    -keyout ca.key -out ca.pem -days 2 -subj /CN=lab-ca \
	    -addext basicConstraints=critical,CA:true \
	    -addext keyUsage=critical,keyCertSign >/dev/null 2>&1
	for n in server client; do
		openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
		    -keyout $n.key -out $n.csr -subj /CN=$n >/dev/null 2>&1
		if [ $n = server ]; then
			printf 'subjectAltName=IP:2001:db8:12::1,IP:2001:db8:99::1\nextendedKeyUsage=serverAuth\n' > $n.ext
		else
			printf 'subjectAltName=DNS:console\nextendedKeyUsage=clientAuth\n' > $n.ext
		fi
		openssl x509 -req -in $n.csr -CA ca.pem -CAkey ca.key \
		    -CAcreateserial -out $n.pem -days 2 -extfile $n.ext \
		    >/dev/null 2>&1 || atf_fail "no $n certificate"
	done
	atf_check -o ignore jail -c name=arcw_la vnet persist path=/
	atf_check -o ignore jail -c name=arcw_lb vnet persist path=/
	e=$(ifconfig epair create)
	echo "${e%a}" > epair.name
	atf_check ifconfig $e vnet arcw_la
	atf_check ifconfig ${e%a}b vnet arcw_lb
	# The router's loopback, 2001:db8:12::1 on lo0; its link to the
	# client, 2001:db8:99::1.
	atf_check jexec arcw_la ifconfig lo0 inet6 ::1/128 up
	atf_check jexec arcw_la ifconfig lo0 inet6 2001:db8:12::1/128 alias
	atf_check jexec arcw_la ifconfig $e inet6 2001:db8:99::1/64 up
	atf_check jexec arcw_lb ifconfig lo0 inet6 ::1/128 up
	atf_check jexec arcw_lb ifconfig ${e%a}b inet6 2001:db8:99::2/64 up
	atf_check jexec arcw_lb route -q -6 add 2001:db8:12::1 2001:db8:99::1
	sleep 2	# duplicate address detection
	mkdir -p etc/jail.conf.d
	: > etc/jail.conf
	a="-A $d/ca.pem -C $d/client.pem -K $d/client.key"
	for also in "" 2001:db8:99::1; do
		jexec arcw_la "$JGD" -F -l "tcp://[2001:db8:12::1]:$port" \
		    -l "unix:$d/s.sock" ${also:+--sctp-also $also} \
		    -A "$d/ca.pem" -C "$d/server.pem" -K "$d/server.key" \
		    -f "$d/etc/jail.conf" -D "$d/etc/jail.conf.d" \
		    -1 "$d/history.conf" > daemon.out 2>&1 &
		echo $! > daemon.pid
		for i in $(seq 1 50); do [ -S s.sock ] && break; sleep 0.1; done
		sleep 0.5
		atf_check -o save:t.json "$JGC" -c "unix:$d/s.sock" transport
		if [ -z "$also" ]; then
			# On lo0 alone: said, and why.
			atf_check -o match:'"transport":"sctp","up":true,[^}]*"warning":"its addresses are all on a loopback interface' \
			    cat t.json
			atf_check -o ignore jexec arcw_lb "$JGC" \
			    -c "tcp://[2001:db8:12::1]:$port" $a hello
		else
			# An address of a real interface too: no warning, and
			# SCTP by that address answered.
			atf_check -o not-match:'"warning"' cat t.json
			atf_check -o ignore jexec arcw_lb "$JGC" \
			    -c "sctp://[2001:db8:99::1]:$port" $a hello
		fi
		kill "$(cat daemon.pid)"
		for i in $(seq 1 50); do
			kill -0 "$(cat daemon.pid)" 2>/dev/null || break
			sleep 0.1
		done
		rm -f s.sock daemon.pid
	done
}
sctp_loopback_cleanup()
{
	[ -f daemon.pid ] && kill "$(cat daemon.pid)" 2>/dev/null
	sleep 0.5
	if [ -f epair.name ]; then
		e=$(cat epair.name)
		ifconfig ${e}a -vnet arcw_la 2>/dev/null
		ifconfig ${e}b -vnet arcw_lb 2>/dev/null
		ifconfig ${e}a destroy 2>/dev/null
	fi
	jail -r arcw_la 2>/dev/null
	jail -r arcw_lb 2>/dev/null
	true
}

atf_test_case sdwan_record cleanup
sdwan_record_head()
{
	atf_set "descr" "what a rule logs to the routing socket (ipfw logdst rtsock) is the agent's record: a count rule on the loopback, a ping, the entry with the rule's comment and an event"
	atf_set "require.user" "root"
	atf_set "is.exclusive" "true"
}
sdwan_record_body()
{
	ipfw list >/dev/null 2>&1 || atf_skip "no ipfw here"
	ipfw list 65010 >/dev/null 2>&1 && atf_skip "rule 65010 is taken"
	start_daemon
	last=$("$JGC" -c "$SOCK" events | sed -E 's/^\{"last":([0-9]+).*/\1/')
	atf_check -o ignore ipfw -q add 65010 count log logdst rtsock logamount 100 icmp from 127.0.0.1 to 127.0.0.1 // security lab guard dst
	atf_check -o ignore ping -c 1 -q 127.0.0.1
	sleep 1
	atf_check -o match:'"record":\{"count":[1-9][0-9]*,"seq":[0-9]+,"untold":0,"last":\[\{"t":[0-9]+,"seq":[0-9]+,"rule":65010,"action":"count","src":"127.0.0.1","dst":"127.0.0.1","iface":"lo0","comment":"security lab guard dst"\}' \
	    "$JGC" -c "$SOCK" sdwan
	atf_check -o match:'"kind":"sdwan-security","data":\{"seq":[0-9]+,"rule":65010,"action":"count","src":"127.0.0.1","dst":"127.0.0.1","iface":"lo0","comment":"security lab guard dst"\}' \
	    "$JGC" -c "$SOCK" events "$last"
	ipfw -q delete 65010
}
sdwan_record_cleanup()
{
	ipfw -q delete 65010 2>/dev/null
	[ -f daemon.pid ] && kill "$(cat daemon.pid)" 2>/dev/null
	true
}

atf_test_case resnapshot cleanup
resnapshot_head()
{
	atf_set "descr" "the newest snapshot of a dataset taken again under its name, on a pool of a memory disk made for it: newer, the same name, the older one untouched"
	atf_set "require.user" "root"
	atf_set "is.exclusive" "true"
}
resnapshot_body()
{
	zpool list arcw_rs >/dev/null 2>&1 && atf_skip "a pool arcw_rs is there already"
	md=$(mdconfig -a -t swap -s 128m) || atf_skip "no memory disk"
	echo "$md" > md
	atf_check zpool create -O mountpoint=none arcw_rs "$md"
	atf_check zfs create arcw_rs/d
	atf_check zfs snapshot arcw_rs/d@old
	atf_check zfs snapshot arcw_rs/d@last
	before=$(zfs get -Hp -o value createtxg arcw_rs/d@last)
	start_daemon
	atf_check -o match:'done +zfs resnapshot arcw_rs/d@last' \
	    "$JGC" -c "$SOCK" zfs resnapshot arcw_rs/d@last
	after=$(zfs get -Hp -o value createtxg arcw_rs/d@last)
	atf_check test "$after" -gt "$before"
	atf_check -o inline:'arcw_rs/d@old\narcw_rs/d@last\n' \
	    zfs list -H -o name -s createtxg -t snapshot -d 1 arcw_rs/d
	atf_check -s exit:1 -o match:'not the newest snapshot' \
	    "$JGC" -c "$SOCK" zfs resnapshot arcw_rs/d@old
	# Held, it stays as it was, and nothing is left beside it.
	atf_check zfs hold keep arcw_rs/d@last
	atf_check -s exit:1 -o match:'kept as it was' \
	    "$JGC" -c "$SOCK" zfs resnapshot arcw_rs/d@last
	atf_check -o inline:"$after\n" zfs get -Hp -o value createtxg arcw_rs/d@last
	atf_check -o not-match:'resnap' zfs list -H -o name -t snapshot -r arcw_rs
	atf_check zfs release keep arcw_rs/d@last
}
resnapshot_cleanup()
{
	[ -f daemon.pid ] && kill "$(cat daemon.pid)" 2>/dev/null
	if [ -f md ]; then
		zpool destroy -f arcw_rs >/dev/null 2>&1
		mdconfig -d -u "$(cat md)" >/dev/null 2>&1
	fi
	true
}

atf_test_case jail_make cleanup
jail_make_head()
{
	atf_set "descr" "jails made from a base snapshot on a pool of a memory disk made for it, by clone and by send, started, and taken away with their datasets"
	atf_set "require.user" "root"
	atf_set "is.exclusive" "true"
}
jail_make_body()
{
	zpool list arcw_jm >/dev/null 2>&1 && atf_skip "a pool arcw_jm is there already"
	for j in arcw-jm1 arcw-jm2; do
		jls -j "$j" >/dev/null 2>&1 && atf_skip "a jail $j is there already"
	done
	md=$(mdconfig -a -t swap -s 256m) || atf_skip "no memory disk"
	echo "$md" > md
	r=$(pwd)/jails
	atf_check zpool create -O mountpoint=none arcw_jm "$md"
	atf_check zfs create -o mountpoint=none arcw_jm/jails
	atf_check zfs create -o mountpoint="$r/base" arcw_jm/jails/base
	echo "the base" > "$r/base/marker"
	atf_check zfs snapshot arcw_jm/jails/base@1
	start_daemon
	d=$(pwd)/etc
	# The defaults: each jail's path under the test's own, a host name,
	# and kept running without a command.
	printf 'path = "%s/${name}";\nhost.hostname = "${name}.example.org";\npersist;\n' "$r" > defaults.conf
	atf_check -o match:'done +jail defaults' "$JGC" -c "$SOCK" jailconf defaults defaults.conf
	# One by clone, one by send, each started.
	for j in arcw-jm1 arcw-jm2; do
		printf '.include "%s/jail.conf";\n%s {\n\tdevfs_ruleset = 4;\n}\n' "$d" "$j" > "$j.conf"
	done
	atf_check -o match:'done +jail make arcw-jm1 from arcw_jm/jails/base@1' \
	    "$JGC" -c "$SOCK" jailconf make arcw-jm1 arcw-jm1.conf arcw_jm/jails/arcw-jm1 arcw_jm/jails/base@1 clone "$r/arcw-jm1" start
	atf_check -o match:'done +jail make arcw-jm2 from arcw_jm/jails/base@1' \
	    "$JGC" -c "$SOCK" jailconf make arcw-jm2 arcw-jm2.conf arcw_jm/jails/arcw-jm2 arcw_jm/jails/base@1 send "$r/arcw-jm2" start
	atf_check -o inline:"$r/arcw-jm1\n" zfs get -H -o value mountpoint arcw_jm/jails/arcw-jm1
	atf_check -o inline:"arcw_jm/jails/base@1\n" zfs get -H -o value origin arcw_jm/jails/arcw-jm1
	atf_check -o inline:"-\n" zfs get -H -o value origin arcw_jm/jails/arcw-jm2
	atf_check -o inline:"the base\n" cat "$r/arcw-jm1/marker"
	atf_check -o inline:"the base\n" cat "$r/arcw-jm2/marker"
	atf_check -o inline:"$r/arcw-jm1 arcw-jm1.example.org\n" jls -j arcw-jm1 path host.hostname
	atf_check -o inline:"$r/arcw-jm2 arcw-jm2.example.org\n" jls -j arcw-jm2 path host.hostname
	# A running jail's file changed: the rest taken, its path kept.
	printf '.include "%s/jail.conf";\narcw-jm1 {\n\tdevfs_ruleset = 4;\n\tallow.raw_sockets;\n}\n' "$d" > e1.conf
	atf_check -o match:'done +jail edit arcw-jm1$' \
	    "$JGC" -c "$SOCK" jailconf edit arcw-jm1 e1.conf
	atf_check cmp -s e1.conf "$d/jail.conf.d/arcw-jm1.conf"
	printf '.include "%s/jail.conf";\narcw-jm1 {\n\tpath = "/elsewhere";\n}\n' "$d" > e2.conf
	atf_check -s exit:1 -o match:"arcw-jm1 runs with its root at $r/arcw-jm1: stop it" \
	    "$JGC" -c "$SOCK" jailconf edit arcw-jm1 e2.conf
	atf_check cmp -s e1.conf "$d/jail.conf.d/arcw-jm1.conf"
	# A host with no dataset for its jails yet: the one above made, not
	# mounted of its own; a jail refused takes it away again.
	printf '.include "%s/jail.conf";\narcw-jm3 {\n}\n' "$d" > arcw-jm3.conf
	atf_check -o match:'done +jail make arcw-jm3' \
	    "$JGC" -c "$SOCK" jailconf make arcw-jm3 arcw-jm3.conf arcw_jm/more/jails/arcw-jm3 arcw_jm/jails/base@1 clone "$r/arcw-jm3"
	atf_check -o inline:"off\n" zfs get -H -o value canmount arcw_jm/more/jails
	atf_check -o inline:"the base\n" cat "$r/arcw-jm3/marker"
	atf_check -o match:'done +jail remove arcw-jm3' \
	    "$JGC" -c "$SOCK" jailconf remove arcw-jm3 arcw_jm/more/jails/arcw-jm3
	printf '.include "%s/jail.conf";\nother {\n}\n' "$d" > arcw-jm4.conf
	atf_check -s exit:1 -o match:'not the one jail arcw-jm4' \
	    "$JGC" -c "$SOCK" jailconf make arcw-jm4 arcw-jm4.conf arcw_jm/new/jails/arcw-jm4 arcw_jm/jails/base@1 clone "$r/arcw-jm4"
	atf_check -s exit:1 -e ignore zfs list arcw_jm/new
	# Taken away: not with a dataset that is not its; then with its own,
	# stopped and destroyed.
	atf_check -s exit:1 -o match:'is not mounted at the jail' \
	    "$JGC" -c "$SOCK" jailconf remove arcw-jm1 arcw_jm/jails/arcw-jm2
	atf_check -o ignore jls -j arcw-jm1
	atf_check -o match:'done +jail remove arcw-jm1' \
	    "$JGC" -c "$SOCK" jailconf remove arcw-jm1 arcw_jm/jails/arcw-jm1
	atf_check -s exit:1 -o ignore -e ignore jls -j arcw-jm1
	atf_check -s exit:1 -e ignore zfs list arcw_jm/jails/arcw-jm1
	atf_check -o match:'done +jail remove arcw-jm2' \
	    "$JGC" -c "$SOCK" jailconf remove arcw-jm2 arcw_jm/jails/arcw-jm2
	atf_check -s exit:1 -e ignore zfs list arcw_jm/jails/arcw-jm2
	# The base stays as it was.
	atf_check -o inline:"arcw_jm/jails/base@1\n" zfs list -H -o name -t snapshot -r arcw_jm
}
jail_make_cleanup()
{
	[ -f daemon.pid ] && kill "$(cat daemon.pid)" 2>/dev/null
	for j in arcw-jm1 arcw-jm2; do
		jail -r "$j" >/dev/null 2>&1
	done
	if [ -f md ]; then
		zpool destroy -f arcw_jm >/dev/null 2>&1
		mdconfig -d -u "$(cat md)" >/dev/null 2>&1
	fi
	true
}

atf_test_case carp cleanup
carp_head()
{
	atf_set "descr" "carp(4) between two vnet jails on one epair: a vhid made with its key by netlink, MASTER and BACKUP as their skews say, one told to step back, changed, and gone with its address; the key in no trace"
	atf_set "require.user" "root"
}
carp_body()
{
	kldstat -q -m carp || atf_skip "carp(4) is not loaded"
	if jls -j arcw_c1 >/dev/null 2>&1 || jls -j arcw_c2 >/dev/null 2>&1; then
		atf_skip "a jail arcw_c1 or arcw_c2 is there already"
	fi
	touch mine
	ep=$(ifconfig epair create)
	echo "${ep%a}" > epair
	atf_check -o ignore jail -c name=arcw_c1 vnet persist path=/ vnet.interface="${ep%a}a"
	atf_check -o ignore jail -c name=arcw_c2 vnet persist path=/ vnet.interface="${ep%a}b"
	atf_check jexec arcw_c1 ifconfig "${ep%a}a" inet 192.0.2.2/24 up
	atf_check jexec arcw_c2 ifconfig "${ep%a}b" inet 192.0.2.3/24 up
	start_daemon
	# Not kept (-p): these jails' rc.conf would be the host's.
	echo 'the-lab-key' | atf_check -o match:"done +arcw_c1: ${ep%a}a: carp add vhid 7 192.0.2.1/24" \
	    -o not-match:'the-lab-key' "$JGC" -t -c "$SOCK" -j arcw_c1 carp add "${ep%a}a" 192.0.2.1/24 vhid=7 key
	echo 'the-lab-key' | atf_check -o match:'done' \
	    "$JGC" -c "$SOCK" -j arcw_c2 carp add "${ep%a}b" 192.0.2.1/24 vhid=7 advskew=100 key
	sleep 4
	atf_check -o match:'"carp":true' -o match:'"carp":\[\{"vhid":7,"state":"MASTER","version":2,"advbase":1,"advskew":0' \
	    -o match:'"address":"192.0.2.1","prefixlen":24,"broadcast":"192.0.2.255","vhid":7' \
	    "$JGC" -c "$SOCK" -j arcw_c1 net interfaces
	atf_check -o match:'"state":"BACKUP","version":2,"advbase":1,"advskew":100' \
	    "$JGC" -c "$SOCK" -j arcw_c2 net interfaces
	# Told to step back: the other takes it.
	atf_check -o match:'done' "$JGC" -c "$SOCK" -j arcw_c1 carp set "${ep%a}a" vhid=7 state=backup
	sleep 5
	atf_check -o match:'"state":"BACKUP"' "$JGC" -c "$SOCK" -j arcw_c1 net interfaces
	atf_check -o match:'"state":"MASTER","version":2,"advbase":1,"advskew":100' \
	    "$JGC" -c "$SOCK" -j arcw_c2 net interfaces
	# Changed: what is not given stays.
	atf_check -o match:'done' "$JGC" -c "$SOCK" -j arcw_c2 carp set "${ep%a}b" vhid=7 advskew=50
	atf_check -o match:'"advbase":1,"advskew":50' "$JGC" -c "$SOCK" -j arcw_c2 net interfaces
	atf_check -s exit:1 -o match:'version is set when it is made' \
	    "$JGC" -c "$SOCK" -j arcw_c2 carp set "${ep%a}b" vhid=7 version=3
	# Gone with its address.
	atf_check -o match:'done' "$JGC" -c "$SOCK" -j arcw_c1 carp remove "${ep%a}a" 192.0.2.1 vhid=7
	atf_check -o not-match:'"vhid":7' "$JGC" -c "$SOCK" -j arcw_c1 net interfaces
	atf_check ifconfig "${ep%a}a" -vnet arcw_c1
	atf_check ifconfig "${ep%a}b" -vnet arcw_c2
	atf_check -o ignore jail -r arcw_c1
	atf_check -o ignore jail -r arcw_c2
	atf_check ifconfig "${ep%a}a" destroy
}
carp_cleanup()
{
	[ -f daemon.pid ] && kill "$(cat daemon.pid)" 2>/dev/null
	if [ -f mine ]; then
		e=$(cat epair 2>/dev/null)
		[ -n "$e" ] && ifconfig "${e}a" -vnet arcw_c1 >/dev/null 2>&1
		[ -n "$e" ] && ifconfig "${e}b" -vnet arcw_c2 >/dev/null 2>&1
		jail -r arcw_c1 >/dev/null 2>&1
		jail -r arcw_c2 >/dev/null 2>&1
		[ -n "$e" ] && ifconfig "${e}a" destroy >/dev/null 2>&1
	fi
	true
}

atf_test_case fwmatch_kernel cleanup
fwmatch_kernel_head()
{
	atf_set "descr" "path-check's ipfw walk (fwmatch.c) says what the" \
	    "kernel does: a ruleset in a vnet jail, packets sent at it from" \
	    "another, and the rule whose counter moved is the rule the walk" \
	    "names, for each"
	atf_set "require.user" "root"
}
fwmatch_kernel_body()
{
	local f="$(atf_get_srcdir)/fwmatch" ep a b

	kldstat -q -m ipfw || atf_skip "ipfw(4) is not loaded"
	if jls -j arcw_f1 >/dev/null 2>&1 || jls -j arcw_f2 >/dev/null 2>&1; then
		atf_skip "a jail arcw_f1 or arcw_f2 is there already"
	fi
	touch mine
	ep=$(ifconfig epair create)
	echo "${ep%a}" > epair
	a="${ep%a}a"
	b="${ep%a}b"
	atf_check -o ignore jail -c name=arcw_f1 vnet persist path=/ vnet.interface="$a"
	atf_check -o ignore jail -c name=arcw_f2 vnet persist path=/ vnet.interface="$b"
	atf_check jexec arcw_f1 ifconfig "$a" inet 192.0.2.2/24 up
	atf_check jexec arcw_f1 ifconfig "$a" inet 192.0.2.12/32 alias
	atf_check jexec arcw_f1 ifconfig lo0 up
	atf_check jexec arcw_f2 ifconfig "$b" inet 192.0.2.3/24 up
	atf_check jexec arcw_f2 ifconfig lo0 up
	# 198.51.100.0/24 is routed back elsewhere: verrevpath fails.
	atf_check -o ignore jexec arcw_f2 route add -net 198.51.100.0/24 -iface lo0
	atf_check jexec arcw_f1 ifconfig "$a" inet 198.51.100.7/32 alias
	# Out goes out: only what comes in is walked here.
	cat > rules <<EOF
add 00050 allow ip from any to any out
add 00100 allow ip from any to any via lo0
add 00300 deny ip from any to any not verrevpath in
add 00400 check-state :default
add 00500 count ip from any to any in recv $b
add 00600 skipto 1000 ip from 192.0.2.12 to any
add 00700 deny ip from table(bad) to any in
add 00800 allow tcp from any to me 22 in recv $b setup keep-state :default
add 00900 deny tcp from any to any 23 in
add 00950 allow icmp from any to me icmptypes 8 in
add 01000 deny udp from any to any 5000 in
add 01100 allow udp from any to { 192.0.2.3 or 192.0.2.9 } 53,123 in
add 01200 deny tcp from any to me 1024-2000 in
add 01300 allow udp from any to any in
add 65000 deny ip from any to any
EOF
	atf_check -o ignore jexec arcw_f2 sysctl net.inet.ip.fw.enable=1
	atf_check -o ignore jexec arcw_f2 ipfw -q flush
	atf_check -o ignore jexec arcw_f2 ipfw -q table bad create
	atf_check -o ignore jexec arcw_f2 ipfw -q table bad add 192.0.2.66/32
	atf_check -o ignore jexec arcw_f2 ipfw -q "$(pwd)/rules"
	jexec arcw_f2 ipfw list > list
	jexec arcw_f2 ipfw table all list > tables
	awk '$2 == "count" || $2 == "skipto" || $1 == "00050" {print $1}' \
	    list > notdeciding
	atf_check jexec arcw_f1 ifconfig "$a" inet 192.0.2.66/32 alias

	# One probe: the packet sent, the in rules (not count) whose
	# counters moved, against the walk's verdict for it.
	probe() {
		local from=$1 what=$2 port=$3 words before after got want
		before=$(jexec arcw_f2 ipfw show | awk '{print $1, $2}')
		case $what in
		icmp) jexec arcw_f1 ping -c 1 -t 1 -S $from 192.0.2.3 >/dev/null 2>&1
		      words="proto=icmp icmp=8" ;;
		udp)  echo x | jexec arcw_f1 nc -u -w 1 -s $from 192.0.2.3 $port >/dev/null 2>&1
		      words="proto=udp sport=40000 dport=$port" ;;
		tcp)  jexec arcw_f1 nc -z -w 1 -s $from 192.0.2.3 $port >/dev/null 2>&1
		      words="proto=tcp sport=40000 dport=$port syn" ;;
		esac
		after=$(jexec arcw_f2 ipfw show | awk '{print $1, $2}')
		# The rule that decided: one whose count rose, not of those
		# that only count or jump, nor the out one.
		got=$(printf '%s\n' "$after" | while read n c; do
			old=$(printf '%s\n' "$before" | awk -v n=$n '$1==n{print $2; exit}')
			[ "$c" != "${old:-0}" ] && echo $n
		done | grep -v -x -F -f notdeciding | head -1)
		rpf=rpf
		[ "$from" = 198.51.100.7 ] && rpf=
		want=$("$f" list tables local=192.0.2.3@$b in rcv=$b src=$from dst=192.0.2.3 $words $rpf reach | awk '{print $2}')
		echo "$from $what $port: kernel $got, walk $want"
		[ "$(printf %05d $want 2>/dev/null)" = "$got" ] || [ "$want" = "$got" ]
	}
	for p in "192.0.2.2 icmp" "192.0.2.2 tcp 22" "192.0.2.2 tcp 23" \
	    "192.0.2.2 tcp 1500" "192.0.2.2 tcp 80" "192.0.2.2 udp 53" \
	    "192.0.2.2 udp 5000" "192.0.2.2 udp 7000" "192.0.2.12 udp 5000" \
	    "192.0.2.12 udp 53" "192.0.2.66 icmp" "198.51.100.7 icmp"; do
		probe $p > out || atf_fail "$(cat out)"
		cat out
	done
	atf_check ifconfig "$a" -vnet arcw_f1
	atf_check ifconfig "$b" -vnet arcw_f2
	atf_check -o ignore jail -r arcw_f1
	atf_check -o ignore jail -r arcw_f2
	atf_check ifconfig "$a" destroy
}
fwmatch_kernel_cleanup()
{
	if [ -f mine ]; then
		e=$(cat epair 2>/dev/null)
		[ -n "$e" ] && ifconfig "${e}a" -vnet arcw_f1 >/dev/null 2>&1
		[ -n "$e" ] && ifconfig "${e}b" -vnet arcw_f2 >/dev/null 2>&1
		jail -r arcw_f1 >/dev/null 2>&1
		jail -r arcw_f2 >/dev/null 2>&1
		[ -n "$e" ] && ifconfig "${e}a" destroy >/dev/null 2>&1
	fi
	true
}

atf_test_case path_check cleanup
path_check_head()
{
	atf_set "descr" "path-check in a vnet jail between two others: what" \
	    "the router does with a packet and its reply, and why one does" \
	    "not get through: forwarding off, no send route, the firewall," \
	    "an asymmetric return with uRPF, a reply with no state"
	atf_set "require.user" "root"
}
path_check_body()
{
	local e1 e2 r

	kldstat -q -m ipfw || atf_skip "ipfw(4) is not loaded"
	for j in arcw_pc arcw_pr arcw_ps; do
		jls -j $j >/dev/null 2>&1 && atf_skip "a jail $j is there already"
	done
	touch mine
	e1=$(ifconfig epair create); e1=${e1%a}
	e2=$(ifconfig epair create); e2=${e2%a}
	echo "$e1 $e2" > epairs
	atf_check -o ignore jail -c name=arcw_pc vnet persist path=/ vnet.interface="${e1}a"
	atf_check -o ignore jail -c name=arcw_pr vnet persist path=/ vnet.interface="${e1}b" vnet.interface="${e2}a"
	atf_check -o ignore jail -c name=arcw_ps vnet persist path=/ vnet.interface="${e2}b"
	atf_check jexec arcw_pc ifconfig "${e1}a" inet 10.1.0.2/24 up
	atf_check jexec arcw_pr ifconfig "${e1}b" inet 10.1.0.1/24 up
	atf_check jexec arcw_pr ifconfig "${e2}a" inet 10.3.0.1/24 up
	atf_check jexec arcw_ps ifconfig "${e2}b" inet 10.3.0.2/24 up
	atf_check -o ignore jexec arcw_pc route add default 10.1.0.1
	atf_check -o ignore jexec arcw_ps route add default 10.3.0.1
	atf_check -o ignore jexec arcw_pr sysctl net.inet.ip.forwarding=1
	atf_check -o ignore jexec arcw_pr sysctl net.inet.ip.fw.enable=1
	atf_check -o ignore jexec arcw_pr ipfw -q flush
	atf_check -o ignore jexec arcw_pr ipfw -q add 65000 allow ip from any to any
	# The neighbours known, as a packet that went before would leave
	# them.
	atf_check -o ignore jexec arcw_pc ping -c 1 -t 2 10.3.0.2
	start_daemon

	# Through: in on e1b by the route back, out on e2a, the next hop
	# known, the reply back the same way.
	atf_check -o match:"\"ingress\":\{\"interface\":\"${e1}b\",\"how\":\"by the route back to the source\"\}" \
	    -o match:"\"route\":\{[^}]*\"interface\":\"${e2}a\"" \
	    -o match:'"neighbor":\{"address":"10.3.0.2","state":"[a-z]+"\}' \
	    -o match:'"symmetric":true' -o match:'"forwarding":true' \
	    -o match:'"severity":"ok","what":"Nothing here stops it, nor its reply"' \
	    -o not-match:'"severity":"bad"' "$JGC" -c "$SOCK" -j arcw_pr path-check -p tcp -P 22 10.1.0.2 10.3.0.2
	# Forwarding off.
	atf_check -o ignore jexec arcw_pr sysctl net.inet.ip.forwarding=0
	atf_check -o match:'"severity":"bad","what":"This host does not forward IPv4: net.inet.ip.forwarding is 0' \
	    "$JGC" -c "$SOCK" -j arcw_pr path-check -p icmp 10.1.0.2 10.3.0.2
	atf_check -o ignore jexec arcw_pr sysctl net.inet.ip.forwarding=1
	# No send route.
	atf_check -o match:'"severity":"bad","what":"No route to 10.9.0.5 in FIB 0: the send route is missing' \
	    "$JGC" -c "$SOCK" -j arcw_pr path-check -p icmp 10.1.0.2 10.9.0.5
	# The firewall: dropped going out, by its rule.
	atf_check -o ignore jexec arcw_pr ipfw -q add 01000 deny tcp from any to 10.3.0.2 22 out
	atf_check -o match:"\"severity\":\"bad\",\"what\":\"The firewall drops it going out by ${e2}a: rule 1000 \(01000 deny tcp from any to 10.3.0.2 22 out\)\"" \
	    -o match:'"out":\{"verdict":"deny","rule":1000' \
	    "$JGC" -c "$SOCK" -j arcw_pr path-check -p tcp -P 22 10.1.0.2 10.3.0.2
	atf_check -o not-match:'"severity":"bad"' "$JGC" -c "$SOCK" -j arcw_pr path-check -p tcp -P 80 10.1.0.2 10.3.0.2
	atf_check -o ignore jexec arcw_pr ipfw -q delete 1000
	# Asymmetric: the route back to the client by the other side; a
	# uRPF rule then drops what comes in.
	atf_check -o ignore jexec arcw_pr route add -host 10.1.0.2 -iface "${e2}a"
	atf_check -o match:"\"severity\":\"warn\",\"what\":\"Asymmetric: the request comes in on ${e1}b, the reply goes back by ${e2}a" \
	    -o match:'"symmetric":false' "$JGC" -c "$SOCK" -j arcw_pr path-check -i "${e1}b" -p icmp 10.1.0.2 10.3.0.2
	atf_check -o ignore jexec arcw_pr ipfw -q add 00500 deny ip from any to any not verrevpath in
	atf_check -o match:"\"severity\":\"bad\",\"what\":\"The firewall drops it coming in on ${e1}b: rule 500 " \
	    "$JGC" -c "$SOCK" -j arcw_pr path-check -i "${e1}b" -p icmp 10.1.0.2 10.3.0.2
	atf_check -o ignore jexec arcw_pr ipfw -q delete 500
	atf_check -o ignore jexec arcw_pr route delete -host 10.1.0.2
	# A reply with no state: let in only by one the request made.
	atf_check -o ignore jexec arcw_pr ipfw -q add 00600 allow tcp from 10.1.0.0/24 to any 22 in
	atf_check -o ignore jexec arcw_pr ipfw -q add 00700 allow tcp from 10.1.0.0/24 to any 22 out
	atf_check -o ignore jexec arcw_pr ipfw -q add 00800 deny tcp from any 22 to any
	atf_check -o match:"The firewall drops the reply coming in on ${e2}a: rule 800 \(00800 deny tcp from any 22 to any\) \(no state of the request's here to let it in\)" \
	    "$JGC" -c "$SOCK" -j arcw_pr path-check -p tcp -P 22 10.1.0.2 10.3.0.2
	atf_check -o ignore jexec arcw_pr ipfw -q add 00590 check-state
	atf_check -o ignore jexec arcw_pr ipfw -q delete 600
	atf_check -o ignore jexec arcw_pr ipfw -q add 00600 allow tcp from 10.1.0.0/24 to any 22 in keep-state
	atf_check -o match:'"reply_in":\{"verdict":"allow","rule":590,"text":"00590 check-state :default","by_state":true' \
	    -o not-match:'"severity":"bad"' "$JGC" -c "$SOCK" -j arcw_pr path-check -p tcp -P 22 10.1.0.2 10.3.0.2

	for i in "${e1}a:arcw_pc" "${e1}b:arcw_pr" "${e2}a:arcw_pr" "${e2}b:arcw_ps"; do
		atf_check ifconfig "${i%%:*}" -vnet "${i##*:}"
	done
	for j in arcw_pc arcw_pr arcw_ps; do
		atf_check -o ignore jail -r $j
	done
	atf_check ifconfig "${e1}a" destroy
	atf_check ifconfig "${e2}a" destroy
}
path_check_cleanup()
{
	[ -f daemon.pid ] && kill "$(cat daemon.pid)" 2>/dev/null
	if [ -f mine ]; then
		read e1 e2 < epairs 2>/dev/null
		for i in "${e1}a:arcw_pc" "${e1}b:arcw_pr" "${e2}a:arcw_pr" "${e2}b:arcw_ps"; do
			[ -n "$e1" ] && ifconfig "${i%%:*}" -vnet "${i##*:}" >/dev/null 2>&1
		done
		for j in arcw_pc arcw_pr arcw_ps; do
			jail -r $j >/dev/null 2>&1
		done
		[ -n "$e1" ] && ifconfig "${e1}a" destroy >/dev/null 2>&1
		[ -n "$e2" ] && ifconfig "${e2}a" destroy >/dev/null 2>&1
	fi
	true
}

atf_test_case zfs_key cleanup
zfs_key_head()
{
	atf_set "descr" "A dataset's key typed: loaded, changed, kept nowhere, on a pool of a memory disk"
	atf_set "require.user" "root"
}
zfs_key_body()
{
	zpool list arcw_zk >/dev/null 2>&1 && atf_skip "a pool arcw_zk is there already"
	md=$(mdconfig -a -t swap -s 128m) || atf_skip "no memory disk"
	echo "$md" > md
	atf_check zpool create -O mountpoint=none arcw_zk "$md"
	echo 'first passphrase' | atf_check zfs create -o encryption=on \
	    -o keyformat=passphrase -o keylocation=prompt -o mountpoint=none \
	    arcw_zk/enc
	atf_check zfs unload-key arcw_zk/enc
	atf_check -o inline:'unavailable\n' zfs get -H -o value keystatus arcw_zk/enc
	start_daemon
	# A wrong one: zfs's own words, nothing loaded.
	echo 'not the key' | atf_check -s exit:1 -e match:'[Ii]ncorrect key' -o ignore \
	    "$JGC" -c "$SOCK" zfskey arcw_zk/enc
	echo 'first passphrase' | atf_check -o ignore "$JGC" -c "$SOCK" zfskey arcw_zk/enc
	atf_check -o inline:'available\n' zfs get -H -o value keystatus arcw_zk/enc
	echo 'first passphrase' | atf_check -s exit:1 -e match:'loaded already' -o ignore \
	    "$JGC" -c "$SOCK" zfskey arcw_zk/enc
	# Changed, and asked for at a prompt again.
	printf '\nsecond passphrase\n' | atf_check -o ignore "$JGC" -c "$SOCK" zfskey -n arcw_zk/enc
	atf_check -o inline:'prompt\n' zfs get -H -o value keylocation arcw_zk/enc
	atf_check zfs unload-key arcw_zk/enc
	echo 'first passphrase' | atf_check -s exit:1 -e match:'[Ii]ncorrect key' -o ignore \
	    "$JGC" -c "$SOCK" zfskey arcw_zk/enc
	# Not loaded: the key now first, then the new one.
	printf 'second passphrase\nthird passphrase\n' | atf_check -o ignore \
	    "$JGC" -c "$SOCK" zfskey -n arcw_zk/enc
	atf_check zfs unload-key arcw_zk/enc
	echo 'third passphrase' | atf_check -o ignore "$JGC" -c "$SOCK" zfskey arcw_zk/enc
	# Too short; and no key left anywhere, nor in what was said.
	printf '\nshort\n' | atf_check -s exit:1 -e match:'8 characters at least' -o ignore \
	    "$JGC" -c "$SOCK" zfskey -n arcw_zk/enc
	ls -a /tmp | grep -q '^\.arcana-key\.' && atf_fail "a key file was left"
	grep -Eq '(first|second|third) passphrase' daemon.out && atf_fail "a key in the log"
	true
}
zfs_key_cleanup()
{
	[ -f daemon.pid ] && kill "$(cat daemon.pid)" 2>/dev/null
	if [ -f md ]; then
		zpool destroy -f arcw_zk >/dev/null 2>&1
		mdconfig -d -u "$(cat md)" >/dev/null 2>&1
	fi
	true
}

# ietf-interfaces' layers (PLAN-SDN-YANG 1.9.2): a vlan on a lagg of two
# ports, a bridge of two members, all made here of epairs and destroyed.
atf_test_case yang_layers cleanup
yang_layers_head()
{
	atf_set "descr" "ietf-interfaces' layers: a vlan on a lagg on two" \
	    "ports, a bridge on two members"
	atf_set "require.user" "root"
}
yang_layers_body()
{
	e1=$(ifconfig epair create) && echo "$e1" >> made
	e2=$(ifconfig epair create) && echo "$e2" >> made
	p1=${e1%a}b
	p2=${e2%a}b
	lg=$(ifconfig lagg create) && echo "$lg" >> made
	atf_check ifconfig "$lg" laggproto failover laggport "$e1" \
	    laggport "$e2" up
	vl=$(ifconfig vlan create vlan 42 vlandev "$lg") && echo "$vl" >> made
	br=$(ifconfig bridge create) && echo "$br" >> made
	atf_check ifconfig "$br" addm "$p1" addm "$p2" up
	atf_check -o save:y "$(atf_get_srcdir)/ycollect" interfaces
	atf_check -o match:" lower=$lg higher=- *\$" grep "^$vl " y
	# A leaf-list the system orders: the members in either order.
	atf_check -o match:" lower=($e1,$e2|$e2,$e1) higher=$vl *\$" \
	    grep "^$lg " y
	atf_check -o match:" lower=- higher=$lg *\$" grep "^$e1 " y
	atf_check -o match:" lower=- higher=$lg *\$" grep "^$e2 " y
	atf_check -o match:" lower=($p1,$p2|$p2,$p1) higher=- *\$" \
	    grep "^$br " y
	atf_check -o match:" lower=- higher=$br *\$" grep "^$p1 " y
	atf_check -o match:" lower=- higher=$br *\$" grep "^$p2 " y
	# A lagg's port is the Ethernet it was; the lagg the aggregate.
	atf_check -o match:" type=ethernetCsmacd " grep "^$e1 " y
	atf_check -o match:" type=ieee8023adLag " grep "^$lg " y
	atf_check -o match:" type=l2vlan " grep "^$vl " y
	atf_check -o match:'^yang-cbor [0-9]+ bytes, the same back$' tail -1 y
}
yang_layers_cleanup()
{
	# What was made, the last first: the vlan and bridge, the lagg,
	# then the epairs (destroying an a end takes its b end too).
	[ -f made ] && tail -r made | while read -r i; do
		ifconfig "$i" destroy >/dev/null 2>&1
	done
	true
}

# arcana-interfaces (PLAN-SDN-YANG 1.9.3): each kind of interface the
# agent's jobs make, read back.  What no job sets (a lagg's ports, a
# vlan's priority, STP on a bridge's member) ifconfig does.
YJAIL=arcana-ytest
atf_test_case yang_kinds cleanup
yang_kinds_head()
{
	atf_set "descr" "arcana-interfaces reads back what the agent's jobs" \
	    "made: a vlan on a lagg, a bridge, a gif's tunnel FIB, an MTU" \
	    "and a FIB, an epair whose other end is in a vnet jail"
	atf_set "require.user" "root"
}
yang_kinds_body()
{
	local y="$(atf_get_srcdir)/ycollect"

	[ "$(sysctl -n net.fibs)" -ge 2 ] || atf_skip "net.fibs is 1"
	for i in epair77a epair78a epair79a epair80a vlan77 vlan78 lagg77 lagg78 \
	    bridge77 gif77; do
		ifconfig "$i" >/dev/null 2>&1 && atf_skip "$i exists"
	done
	jls -j "$YJAIL" >/dev/null 2>&1 && atf_skip "a jail named $YJAIL exists"
	start_daemon
	touch made
	for e in epair77 epair78 epair79; do
		atf_check -o ignore "$JGC" -c "$SOCK" interface "$e" create
		echo "${e}a" >> made
	done
	atf_check -o ignore "$JGC" -c "$SOCK" interface epair77a mtu 1400
	atf_check -o ignore "$JGC" -c "$SOCK" interface epair77a fib 1
	atf_check -o ignore "$JGC" -c "$SOCK" interface lagg77 create
	echo lagg77 >> made
	atf_check ifconfig lagg77 laggproto loadbalance lagghash l3,l4 \
	    laggport epair78a
	atf_check -o ignore ifconfig epair80 create
	echo epair80a >> made
	atf_check -o ignore ifconfig lagg78 create
	echo lagg78 >> made
	atf_check ifconfig lagg78 laggproto lacp laggport epair80a
	atf_check -o ignore "$JGC" -c "$SOCK" interface vlan77 create id 77 \
	    parent lagg77
	echo vlan77 >> made
	atf_check ifconfig vlan77 vlanpcp 5
	atf_check -o ignore ifconfig vlan78 create vlan 78 vlandev epair79a \
	    vlanproto 802.1ad
	echo vlan78 >> made
	atf_check -o ignore "$JGC" -c "$SOCK" interface bridge77 create \
	    parent epair77b
	echo bridge77 >> made
	atf_check ifconfig bridge77 stp epair77b
	atf_check -o ignore "$JGC" -c "$SOCK" interface gif77 create tunnel \
	    192.0.2.77 192.0.2.78 tunnelfib 1
	echo gif77 >> made
	atf_check -o ignore jail -c name="$YJAIL" path=/ vnet persist
	atf_check -o ignore "$JGC" -c "$SOCK" interface epair79b give "$YJAIL"

	atf_check -o save:a "$y" arcif
	atf_check -o save:i "$y" interfaces
	atf_check -o match:'^yang-cbor [0-9]+ bytes, the same back$' tail -1 a
	# The MTU as ietf-if-extensions' max-frame-size: 1400, an Ethernet
	# header and FCS, and a tag (epair has VLAN_MTU); the other end as
	# its peer-interface; the FIB as RFC 8529's bind-ni-name.
	atf_check -o match:' frame=1422 .* peer=epair77b( |$)' \
	    grep '^epair77a ' a
	atf_check -o match:' peer=epair77a( |$)' grep '^epair77b ' a
	atf_check -o match:' peer=vnet( |$)' grep '^epair79a ' a
	atf_check -o match:'^epair77a 1 fib1 ' "$(atf_get_srcdir)/yni" -i -
	atf_check -o match:' tunnelfib=1 ' grep '^gif77 ' a
	atf_check -o match:' type=tunnel ' grep '^gif77 ' i
	# IEEE 802.1AX's: each lagg a key group and system of its name, its
	# lag and its port's aggport naming it; FreeBSD's loadbalance,
	# hashing l3 and l4 (bits 1 and 2); with LACP the port's number and
	# state, the system's priority.
	atf_check -o match:' lagg=loadbalance,6,[0-9A-F-]{17}( |$)' \
	    grep '^lagg77 ' a
	atf_check -o match:' aggport=lagg77,[0-9]+:[0-9a-f]+( |$)' \
	    grep '^epair78a ' a
	atf_check -o match:' lagg=lacp,[0-9a-f]+,[0-9A-F-]{17},key=[0-9]+' \
	    grep '^lagg78 ' a
	# The port's actor state: ifconfig's, LACP_STATE_* bits one
	# position on in IEEE's lacp-state (lacp-activity is position 1).
	st=$(ifconfig -v lagg78 | sed -n 's/.*laggport: epair80a .*state=\([0-9a-f]*\)<.*/\1/p')
	[ -n "$st" ] || atf_fail "ifconfig shows no LACP state for epair80a"
	st=$(printf '%x' $((0x$st << 1)))
	atf_check -o match:" aggport=lagg78,[0-9]+:[0-9a-f]+,port=[0-9]+,state=$st( |\$)" \
	    grep '^epair80a ' a
	atf_check -o save:la "$y" linkagg
	atf_check -o match:'^yang-cbor [0-9]+ bytes, the same back$' tail -1 la
	atf_check -o match:'^lagg77 system=lagg77,[0-9A-F-]{17},- lags=lagg77 aggports=epair78a$' \
	    grep '^lagg77 ' la
	atf_check -o match:'^lagg78 system=lagg78,[0-9A-F-]{17},[0-9]+ lags=lagg78 aggports=epair80a$' \
	    grep '^lagg78 ' la
	# ietf-if-vlan-encapsulation's outer tag, an 802.1Q one c-vlan; the
	# parent ietf-if-extensions'; the priority arcana-interfaces'.
	atf_check -o match:' vlan=77,lagg77,c-vlan,5' grep '^vlan77 ' a
	atf_check -o match:' vlan=78,epair79a,s-vlan,0' grep '^vlan78 ' a
	# IEEE 802.1Q's: the bridge, its one VLAN-unaware component and its
	# port; the member's bridge-port and, its STP on, RSTP's port, each
	# as ifconfig shows the member: flags (FreeBSD's own the learn,
	# discover, span, sticky, private and qinq ones), port, priority
	# (IEEE's a sixteenth of it), path cost, role and state (RSTP's:
	# disabled, listening and blocking discarding).
	atf_check -o save:br "$y" bridges
	atf_check -o match:'^yang-cbor [0-9]+ bytes, the same back$' tail -1 br
	atf_check -o match:'^bridge77 address=[0-9A-F-]{17} type=customer-vlan-bridge component=bridge77,d-bridge-component ports=epair77b$' \
	    grep '^bridge77 ' br
	ifconfig bridge77 | awk '
	$1 == "member:" { m = $2 == "epair77b"; if (m) { f = $3; sub(/^flags=/, "", f); sub(/<.*/, "", f) } next }
	!m { next }
	{ for (i = 1; i < NF; i++) {
		if ($i == "port") port = $(i + 1)
		if ($i == "priority") prio = $(i + 1)
		if ($i == "cost") cost = $(i + 1)
		if ($i == "role") role = $(i + 1)
		if ($i == "state") state = $(i + 1)
	} }
	END { print f, port, prio, cost, role, state }' > member
	read -r f port prio cost role state < member
	[ -n "$f" ] || atf_fail "ifconfig shows no member epair77b"
	f=$((0x$f))
	[ $((f & 0x100)) -ne 0 ] && p2p=auto ||
	    { [ $((f & 0x80)) -ne 0 ] && p2p=force-true || p2p=force-false; }
	[ $((f & 0x80)) -ne 0 ] && ptp=on || ptp=off
	own=$(printf '%x' $((f & 0x181b)))
	atf_check -o match:" bport=bridge77,$port,$p2p/$ptp,$own( |\$)" \
	    grep '^epair77b ' a
	[ $((f & 0x4)) -ne 0 ] || atf_fail "ifconfig stp did not turn STP on"
	case "$state" in learning|forwarding) ;; *) state=discarding ;; esac
	[ $((f & 0x400)) -ne 0 ] && fixed=fixed || fixed=auto
	atf_check -o match:" rstp=$state,$role,$((prio >> 4))/$port/$(((prio >> 4) << 12 | port)),$cost/$fixed,edge=$(((f >> 9) & 1))/$(((f >> 5) & 1))/$(((f >> 6) & 1))( |\$)" \
	    grep '^epair77b ' a
}
yang_kinds_cleanup()
{
	cleanup
	# Out of the vnet jail first: it is not removed with one inside.
	ifconfig epair79b -vnet "$YJAIL" >/dev/null 2>&1
	[ -f made ] && tail -r made | while read -r i; do
		ifconfig "$i" destroy >/dev/null 2>&1
	done
	jail -r "$YJAIL" >/dev/null 2>&1
	true
}

# The events ietf-interfaces' list changes by (PLAN-SDN-YANG 1.9.4),
# netlink(4)'s RTNLGRP_LINK as the agent watches it: an interface made,
# changed, renamed (gone by its old name, come by its new one) and
# destroyed, the collector's list agreeing after each.
atf_test_case yang_events cleanup
yang_events_head()
{
	atf_set "descr" "an interface made, changed, renamed and destroyed:" \
	    "each a link event, and the collector's list as it says"
	atf_set "require.user" "root"
}
yang_events_body()
{
	local y="$(atf_get_srcdir)/ycollect"

	for i in epair76a epair76b yev76; do
		ifconfig "$i" >/dev/null 2>&1 && atf_skip "$i exists"
	done
	start_daemon
	last=$("$JGC" -c "$SOCK" events | sed -E 's/^\{"last":([0-9]+).*/\1/')
	atf_check -o ignore ifconfig epair76 create
	echo epair76a > made
	atf_check ifconfig epair76a mtu 1400 up
	echo yev76 >> made
	atf_check -o inline:'yev76\n' ifconfig epair76a name yev76
	atf_check -o save:y "$y" interfaces
	atf_check -o match:'^yev76 index=[0-9]+ admin=up ' grep '^yev76 ' y
	atf_check -s exit:1 grep '^epair76a ' y
	atf_check ifconfig yev76 destroy
	atf_check -o save:y2 "$y" interfaces
	atf_check -s exit:1 grep -E '^(yev76|epair76b) ' y2
	sleep 0.5
	atf_check -o save:ev "$JGC" -c "$SOCK" events "$last"
	atf_check -o match:'"kind":"link","data":\{"interface":"epair76a","up":false' \
	    -o match:'"kind":"link","data":\{"interface":"epair76a","up":true,"carrier":true,"mtu":1400' \
	    -o match:'"kind":"link-del","data":\{"interface":"epair76a"' \
	    -o match:'"kind":"link","data":\{"interface":"yev76"' \
	    -o match:'"kind":"link-del","data":\{"interface":"yev76"' \
	    -o match:'"kind":"link-del","data":\{"interface":"epair76b"' cat ev
}
yang_events_cleanup()
{
	cleanup
	# By either name: renamed or not when the case stopped.
	[ -f made ] && while read -r i; do
		ifconfig "$i" destroy >/dev/null 2>&1
	done < made
	true
}

# ietf-ip's origins and statuses (PLAN-SDN-YANG 1.10.1) on a lab epair:
# deprecated, autoconfigured from the link address or not, link-local,
# IPv4 link-local, a duplicate DAD finds against the other end in a vnet
# jail, and IPv6 turned off.  (dhcp needs a server base has not.)
atf_test_case yang_ip cleanup
yang_ip_head()
{
	atf_set "descr" "ietf-ip's origins and statuses: deprecated," \
	    "autoconf by EUI-64 or not, link-local, 169.254/16, duplicate," \
	    "IPv6 off"
	atf_set "require.user" "root"
}
yang_ip_body()
{
	local y="$(atf_get_srcdir)/ycollect" e=epair75a b=epair75b

	ifconfig "$e" >/dev/null 2>&1 && atf_skip "$e exists"
	jls -j "$YJAIL" >/dev/null 2>&1 && atf_skip "a jail named $YJAIL exists"
	atf_check -o ignore ifconfig epair75 create
	echo "$e" > made
	atf_check -o ignore jail -c name="$YJAIL" path=/ vnet persist
	atf_check ifconfig "$b" vnet "$YJAIL"
	atf_check ifconfig "$e" up
	atf_check jexec "$YJAIL" ifconfig "$b" inet6 2001:db8:78::1/64 up
	atf_check ifconfig "$e" inet6 2001:db8:75::1/64 deprecated
	atf_check ifconfig "$e" inet6 2001:db8:76::/64 eui64 autoconf
	atf_check ifconfig "$e" inet6 2001:db8:77::5/64 autoconf
	atf_check ifconfig "$e" inet 169.254.7.5/16
	sleep 1
	atf_check ifconfig "$e" inet6 2001:db8:78::1/64
	# DAD: a probe a second (net.inet6.ip6.dad_count), then its verdict.
	for i in 1 2 3 4 5 6; do
		ifconfig "$e" | grep -q '2001:db8:78::1 .*duplicated' && break
		sleep 1
	done
	atf_check -o save:ip "$y" ip
	atf_check -o save:addrs sh -c "grep '^$e ' ip | tr '+ ' '\n\n'"
	atf_check -o match:'^v4=169\.254\.7\.5/16:random$' \
	    -o match:'^v6=2001:db8:75::1/64:static:deprecated$' \
	    -o match:'^fe80::[0-9a-f:]+/64:link-layer:preferred$' \
	    -o match:'^2001:db8:76:0:[0-9a-f:]+/64:link-layer:preferred$' \
	    -o match:'^2001:db8:77::5/64:random:preferred$' \
	    -o match:'^2001:db8:78::1/64:static:duplicate$' \
	    -o match:'^ipv6=on,1500$' cat addrs
	# Neighbours (1.10.2): set by hand, static, no state; one learnt,
	# dynamic, its link address the other end's; the host's own, none.
	atf_check arp -s 169.254.7.9 02:00:00:00:75:09
	atf_check -o ignore ndp -s 2001:db8:75::9 02:00:00:00:75:0a
	atf_check jexec "$YJAIL" ifconfig "$b" inet6 2001:db8:79::2/64
	atf_check ifconfig "$e" inet6 2001:db8:79::1/64
	sleep 2
	atf_check -o ignore ping6 -c 1 -t 5 2001:db8:79::2
	bll=$(jexec "$YJAIL" ifconfig "$b" ether | awk '$1 == "ether" { print $2 }')
	atf_check -o save:nb "$y" nb
	atf_check -o match:"^$e inet 169\.254\.7\.9 02:00:00:00:75:09 static\$" \
	    -o match:"^$e inet6 2001:db8:75::9 02:00:00:00:75:0a static - -\$" \
	    -o match:"^$e inet6 2001:db8:79::2 $bll dynamic - (reachable|stale|delay|probe)\$" \
	    -o not-match:"^$e inet 169\.254\.7\.5 " \
	    -o not-match:"^$e inet6 2001:db8:79::1 " cat nb
	# RAs' addresses are the interface's own to make.
	atf_check ifconfig "$e" inet6 accept_rtadv
	atf_check -o match:" global=1\$" sh -c "\"$y\" ipsys | grep '^$e '"
	atf_check ifconfig "$e" inet6 ifdisabled
	atf_check -o match:" ipv6=off,1500\$" sh -c "\"$y\" ip | grep '^$e '"
}
atf_test_case yang_ecmp cleanup
yang_ecmp_head()
{
	atf_set "descr" "ietf-routing's next-hop-list (PLAN-SDN-YANG" \
	    "2.4.2): a prefix with two gateways, IPv4 and IPv6, in a vnet" \
	    "jail's FIB"
	atf_set "require.user" "root"
}
yang_ecmp_body()
{
	local y="$(atf_get_srcdir)/ycollect" e=epair74a b=epair74b

	[ "$(sysctl -n net.route.multipath 2>/dev/null)" = 1 ] ||
	    atf_skip "no multipath routes (net.route.multipath)"
	ifconfig "$e" >/dev/null 2>&1 && atf_skip "$e exists"
	jls -j "$YJAIL" >/dev/null 2>&1 && atf_skip "a jail named $YJAIL exists"
	atf_check -o ignore ifconfig epair74 create
	echo "$e" > made
	atf_check -o ignore jail -c name="$YJAIL" path=/ vnet persist
	atf_check ifconfig "$b" vnet "$YJAIL"
	atf_check jexec "$YJAIL" ifconfig "$b" inet 192.0.2.10/24 up
	atf_check jexec "$YJAIL" ifconfig "$b" inet6 2001:db8:74::10/64 \
	    no_dad
	for g in 1 2; do
		atf_check -o ignore jexec "$YJAIL" route add -net \
		    198.51.100.0/24 192.0.2.$g
		atf_check -o ignore jexec "$YJAIL" route add -inet6 -net \
		    2001:db8:75::/48 2001:db8:74::$g
	done
	atf_check -o save:r jexec "$YJAIL" "$y" routes 0
	atf_check -o match:'^yang-cbor [0-9]+ bytes, the same back$' \
	    tail -1 r
	# One route, two next hops of its next-hop-list, the interface and
	# the gateway each; a static route's.
	atf_check -o inline:"inet 198.51.100.0/24 192.0.2.1 $b - static multipath
inet 198.51.100.0/24 192.0.2.2 $b - static multipath
inet6 2001:db8:75::/48 2001:db8:74::1 $b - static multipath
inet6 2001:db8:75::/48 2001:db8:74::2 $b - static multipath
" sh -c "grep ' multipath\$' r | sort"
	# One gateway left: a simple next hop again.
	atf_check -o ignore jexec "$YJAIL" route delete -net 198.51.100.0/24 \
	    192.0.2.2
	atf_check -o save:r2 jexec "$YJAIL" "$y" routes 0
	atf_check -o inline:"inet 198.51.100.0/24 192.0.2.1 $b - static -
" sh -c "grep '^inet 198\.51\.100\.0/24 ' r2"
}
atf_test_case yang_static_apply cleanup
yang_static_apply_head()
{
	atf_set "descr" "rc.conf's static routes made a vnet jail's FIBs'" \
	    "by netlink (PLAN-SDN-YANG 2.4.4), undone, and undone on a" \
	    "failure"
	atf_set "require.user" "root"
}
yang_static_apply_body()
{
	local y="$(atf_get_srcdir)/yrcroutes" c="$(atf_get_srcdir)/ycollect"
	local e=epair73a b=epair73b

	ifconfig "$e" >/dev/null 2>&1 && atf_skip "$e exists"
	jls -j "$YJAIL" >/dev/null 2>&1 && atf_skip "a jail named $YJAIL exists"
	atf_check -o ignore ifconfig epair73 create
	echo "$e" > made
	atf_check -o ignore jail -c name="$YJAIL" path=/ vnet persist
	atf_check ifconfig "$b" vnet "$YJAIL"
	# A host's loopback, which a blackhole or reject route goes by.
	atf_check jexec "$YJAIL" ifconfig lo0 inet 127.0.0.1/8 up
	atf_check jexec "$YJAIL" ifconfig lo0 inet6 ::1/128
	atf_check jexec "$YJAIL" ifconfig "$b" inet 192.0.2.5/24 up
	atf_check jexec "$YJAIL" ifconfig "$b" inet6 2001:db8:73::5/64 no_dad
	: > "$PWD/none.conf"
	cat > routes.conf <<EOF
defaultrouter="192.0.2.254"
static_routes="a e1 e2 bh rj ifr"
route_a="-net 10.2.0.0/16 192.0.2.10"
route_e1="-net 10.8.0.0/24 192.0.2.21"
route_e2="-net 10.8.0.0/24 192.0.2.22"
route_bh="-net 203.0.113.0/24 127.0.0.1 -blackhole"
route_rj="-host 203.0.113.9 127.0.0.1 -reject"
route_ifr="-net 10.9.0.0/24 -iface $b"
ipv6_static_routes="v6a"
ipv6_route_v6a="2001:db8:1::/48 2001:db8:73::1"
ipv6_defaultrouter="fe80::1%$b"
EOF
	atf_check jexec "$YJAIL" "$y" -a 0 "$PWD/none.conf" "$PWD/routes.conf"
	atf_check -o save:r jexec "$YJAIL" "$c" routes 0
	atf_check -o inline:"inet 0.0.0.0/0 192.0.2.254 $b - static -
inet 10.2.0.0/16 192.0.2.10 $b - static -
inet 10.8.0.0/24 192.0.2.21 $b - static multipath
inet 10.8.0.0/24 192.0.2.22 $b - static multipath
inet 10.9.0.0/24 - $b - static -
inet 203.0.113.0/24 - - blackhole static -
inet 203.0.113.9/32 - - unreachable static -
inet6 2001:db8:1::/48 2001:db8:73::1 $b - static -
inet6 ::/0 fe80::1%$b $b - static -
" sh -c "grep ' static ' r | grep -v ' receive ' | LC_ALL=C sort"
	# route(8)'s own word on two of them.
	atf_check -o match:'gateway: 192\.0\.2\.10' \
	    -o match:'flags: <UP,GATEWAY,DONE,STATIC>' \
	    jexec "$YJAIL" route -n get 10.2.3.4
	atf_check -o match:'flags: <UP,DONE,STATIC,BLACKHOLE>' \
	    jexec "$YJAIL" route -n get 203.0.113.1
	# A route changed: only it.
	sed 's/192\.0\.2\.10"/192.0.2.11"/' routes.conf > "$PWD/routes2.conf"
	atf_check jexec "$YJAIL" "$y" -a 0 "$PWD/routes.conf" "$PWD/routes2.conf"
	atf_check -o match:'gateway: 192\.0\.2\.11' \
	    jexec "$YJAIL" route -n get 10.2.3.4
	# All taken away: none left.
	atf_check jexec "$YJAIL" "$y" -a 0 "$PWD/routes2.conf" "$PWD/none.conf"
	atf_check -o empty sh -c "jexec '$YJAIL' '$c' routes 0 | \
	    grep ' static ' | grep -v ' receive ' || true"
	# One that fails, its interface not there: none of them stays.
	printf 'static_routes="a z"\nroute_a="-net 10.2.0.0/16 192.0.2.10"\nroute_z="-net 10.3.0.0/16 -iface nosuch0"\n' > "$PWD/bad.conf"
	atf_check -s exit:1 -e match:'no interface nosuch0' \
	    jexec "$YJAIL" "$y" -a 0 "$PWD/none.conf" "$PWD/bad.conf"
	atf_check -s not-exit:0 -o ignore -e ignore \
	    jexec "$YJAIL" route -n get 10.2.3.4
	# Another FIB's, with -fib: there, not in FIB 0.  net.fibs is the
	# jail's own (its vnet's), raised for it there.
	if jexec "$YJAIL" sysctl net.fibs=2 >/dev/null 2>&1; then
		# By the interface: 192.0.2.0/24 is FIB 0's alone
		# (net.add_addr_allfibs), no gateway in it reached from 1.
		printf 'static_routes="f"\nroute_f="-net 10.5.0.0/24 -iface %s -fib 1"\n' "$b" > fib.conf
		atf_check jexec "$YJAIL" "$y" -a 1 "$PWD/none.conf" "$PWD/fib.conf"
		atf_check -o match:"interface: $b" \
		    jexec "$YJAIL" route -n get -fib 1 10.5.0.1
		atf_check -s not-exit:0 -o ignore -e ignore \
		    jexec "$YJAIL" route -n get 10.5.0.1
		atf_check jexec "$YJAIL" "$y" -a 1 "$PWD/fib.conf" "$PWD/none.conf"
	fi
}
atf_test_case yang_route_times cleanup
yang_route_times_head()
{
	atf_set "descr" "ietf-routing's last-updated (PLAN-SDN-YANG 2.4.6):" \
	    "a route added while route events are heard has the time, one" \
	    "not seen to change none"
	atf_set "require.user" "root"
}
yang_route_times_body()
{
	local c="$(atf_get_srcdir)/ycollect" e=epair72a b=epair72b

	ifconfig "$e" >/dev/null 2>&1 && atf_skip "$e exists"
	jls -j "$YJAIL" >/dev/null 2>&1 && atf_skip "a jail named $YJAIL exists"
	atf_check -o ignore ifconfig epair72 create
	echo "$e" > made
	atf_check -o ignore jail -c name="$YJAIL" path=/ vnet persist
	atf_check ifconfig "$b" vnet "$YJAIL"
	atf_check jexec "$YJAIL" ifconfig "$b" inet 192.0.2.5/24 up
	jexec "$YJAIL" "$c" watch 0 4 > out &
	for i in 1 2 3 4 5 6 7 8 9 10; do
		grep -q '^watching$' out 2>/dev/null && break
		sleep 0.2
	done
	before=$(date -u +%Y-%m-%dT%H:%M:%SZ)
	atf_check -o ignore jexec "$YJAIL" route add -net 198.51.100.0/24 \
	    192.0.2.1
	after=$(date -u +%Y-%m-%dT%H:%M:%SZ)
	wait
	t=$(awk '$2 == "198.51.100.0/24" { print $8 }' out)
	[ -n "$t" ] && [ "$t" != - ] || { cat out; atf_fail \
	    "198.51.100.0/24: no last-updated"; }
	# The same format sorts as the times do: within the add.
	[ ! "$t" \< "$before" ] && [ ! "$t" \> "$after" ] ||
	    atf_fail "last-updated $t, not between $before and $after"
	atf_check -o inline:"-\n" awk '$2 == "192.0.2.0/24" { print $8 }' out
}
yang_route_times_cleanup()
{
	ifconfig epair72b -vnet "$YJAIL" >/dev/null 2>&1
	[ -f made ] && ifconfig "$(cat made)" destroy >/dev/null 2>&1
	jail -r "$YJAIL" >/dev/null 2>&1
	true
}

atf_test_case yang_lne cleanup
yang_lne_head()
{
	atf_set "descr" "logical network elements (PLAN-SDN-YANG 2.7.1): a" \
	    "vnet jail is one, a jail sharing the host's stack is not; as" \
	    "jls says"
	atf_set "require.user" "root"
}
yang_lne_body()
{
	local c="$(atf_get_srcdir)/ycollect"

	jls -j "$YJAIL" >/dev/null 2>&1 && atf_skip "a jail named $YJAIL exists"
	jls -j "${YJAIL}2" >/dev/null 2>&1 &&
	    atf_skip "a jail named ${YJAIL}2 exists"
	atf_check -o ignore jail -c name="$YJAIL" path=/ vnet persist
	atf_check -o ignore jail -c name="${YJAIL}2" path=/ persist
	atf_check -o match:"^$YJAIL managed\$" -o not-match:"^${YJAIL}2 " \
	    "$c" lne
	# jls's vnet parameter: new for a stack of its own.
	jls -n name vnet | sed -n 's/^name=\(.*\) vnet=new$/\1 managed/p' | \
	    sort > want
	"$c" lne | grep -v '^yang-cbor' | sort > got
	atf_check -o inline:"$YJAIL managed\n" grep "^$YJAIL " want
	atf_check cmp want got
}
yang_lne_cleanup()
{
	jail -r "${YJAIL}2" >/dev/null 2>&1
	jail -r "$YJAIL" >/dev/null 2>&1
	true
}

atf_test_case yang_ni cleanup
yang_ni_head()
{
	atf_set "descr" "network instances on a host with net.fibs=4" \
	    "(PLAN-SDN-YANG 2.6.1): a vnet jail's, raised to 4"
	atf_set "require.user" "root"
}
yang_ni_body()
{
	local y="$(atf_get_srcdir)/yni"

	jls -j "$YJAIL" >/dev/null 2>&1 && atf_skip "a jail named $YJAIL exists"
	atf_check -o ignore jail -c name="$YJAIL" path=/ vnet persist
	atf_check -o ignore jexec "$YJAIL" sysctl net.fibs=4
	printf 'fib2_name="blue"\nfib2_description="the blue one"\n' > \
	    fibs.conf
	atf_check -o inline:"fib1 1 -
blue 2 the blue one
fib3 3 -
yang-cbor 59 bytes, the same back
" jexec "$YJAIL" "$y" "$PWD/fibs.conf"
}
atf_test_case yang_ni_grow cleanup
yang_ni_grow_head()
{
	atf_set "descr" "an instance past the last FIB (PLAN-SDN-YANG 2.6.4):" \
	    "net.fibs raised live and kept in loader.conf; a vnet jail's"
	atf_set "require.user" "root"
}
yang_ni_grow_body()
{
	local y="$(atf_get_srcdir)/yni" n

	jls -j "$YJAIL" >/dev/null 2>&1 && atf_skip "a jail named $YJAIL exists"
	atf_check -o ignore jail -c name="$YJAIL" path=/ vnet persist
	# A new vnet has the boot's; the instance asked for is past it.
	n=$(jexec "$YJAIL" sysctl -n net.fibs)
	: > loader.conf
	: > fibs.conf
	echo "$((n + 2)) far" > in
	atf_check -o inline:"net.fibs $((n + 3)) live\n" \
	    jexec "$YJAIL" sh -c "'$y' -w -l '$PWD/loader.conf' '$PWD/fibs.conf' < '$PWD/in'"
	atf_check -o inline:"$((n + 3))\n" jexec "$YJAIL" sysctl -n net.fibs
	atf_check -o inline:"net.fibs=\"$((n + 3))\"\n" cat loader.conf
	atf_check -o match:"^far $((n + 2)) -$" \
	    jexec "$YJAIL" "$y" "$PWD/fibs.conf"
}
yang_ni_grow_cleanup()
{
	jail -r "$YJAIL" >/dev/null 2>&1
	true
}

yang_ni_cleanup()
{
	jail -r "$YJAIL" >/dev/null 2>&1
	true
}

atf_test_case yang_ni_bind cleanup
yang_ni_bind_head()
{
	atf_set "descr" "bind-ni-name (PLAN-SDN-YANG 2.6.3): ifconfig's fib" \
	    "read back as the instance's name, a name applied by SIOCSIFFIB" \
	    "and kept in rc.conf, bind-ni-name-failed; a vnet jail's epair"
	atf_set "require.user" "root"
}
yang_ni_bind_body()
{
	local y="$(atf_get_srcdir)/yni" e=epair72a b=epair72b

	ifconfig "$e" >/dev/null 2>&1 && atf_skip "$e exists"
	jls -j "$YJAIL" >/dev/null 2>&1 && atf_skip "a jail named $YJAIL exists"
	atf_check -o ignore ifconfig epair72 create
	echo "$e" > made
	atf_check -o ignore jail -c name="$YJAIL" path=/ vnet persist
	atf_check ifconfig "$b" vnet "$YJAIL"
	atf_check -o ignore jexec "$YJAIL" sysctl net.fibs=4
	atf_check jexec "$YJAIL" ifconfig "$b" inet 192.0.2.5/24 up
	printf 'fib2_name="blue"\n' > fibs.conf
	printf 'ifconfig_%s="inet 192.0.2.5/24"\n' "$b" > rc.conf
	# ifconfig fib 2, read back: FIB 2's name, its families' too.
	atf_check jexec "$YJAIL" ifconfig "$b" fib 2
	atf_check -o inline:"$b 2 blue blue blue
back $b blue
yang-cbor the same back
" jexec "$YJAIL" "$y" -i "$PWD/fibs.conf"
	# A name applied: the kernel's, rc.conf's.
	atf_check jexec "$YJAIL" "$y" -b "$b" fib3 "$PWD/fibs.conf" \
	    "$PWD/rc.conf"
	atf_check -o match:'fib: 3$' jexec "$YJAIL" ifconfig "$b"
	atf_check -o inline:"ifconfig_$b=\"inet 192.0.2.5/24 fib 3\"\n" \
	    cat rc.conf
	# Refused, nothing changed: no such instance, a family apart.
	atf_check -s exit:1 \
	    -o inline:"failed $b: nosuch: no such network instance\n" \
	    jexec "$YJAIL" "$y" -b "$b" nosuch "$PWD/fibs.conf" "$PWD/rc.conf"
	atf_check -s exit:1 -o inline:"failed $b: blue: FreeBSD binds an interface, both its address families, not one alone\n" \
	    jexec "$YJAIL" "$y" -b "$b" -4 fib1 blue "$PWD/fibs.conf"
	atf_check -o match:'fib: 3$' jexec "$YJAIL" ifconfig "$b"
	atf_check -o match:'fib 3' cat rc.conf
	# None: FIB 0, the word out.
	atf_check jexec "$YJAIL" "$y" -b "$b" - "$PWD/fibs.conf" \
	    "$PWD/rc.conf"
	atf_check -o not-match:'fib:' jexec "$YJAIL" ifconfig "$b"
	atf_check -o inline:"ifconfig_$b=\"inet 192.0.2.5/24\"\n" cat rc.conf
}
yang_ni_bind_cleanup()
{
	ifconfig epair72b -vnet "$YJAIL" >/dev/null 2>&1
	[ -f made ] && ifconfig "$(cat made)" destroy >/dev/null 2>&1
	jail -r "$YJAIL" >/dev/null 2>&1
	true
}

atf_test_case yang_rtadv cleanup
yang_rtadv_head()
{
	atf_set "descr" "rtadvd.conf edited as the router advertisement" \
	    "submodule, rtadvctl reload, rtadvctl show (PLAN-SDN-YANG 2.5.1)," \
	    "a lab rtadvd in a vnet jail"
	atf_set "require.user" "root"
}
yang_rtadv_body()
{
	local y="$(atf_get_srcdir)/yrtadv" e=epair71a b=epair71b

	# rtadvctl(8) has its socket at one place: none of the host's.
	pgrep -x rtadvd >/dev/null && atf_skip "rtadvd runs here"
	ifconfig "$e" >/dev/null 2>&1 && atf_skip "$e exists"
	jls -j "$YJAIL" >/dev/null 2>&1 && atf_skip "a jail named $YJAIL exists"
	atf_check -o ignore ifconfig epair71 create
	echo "$e" > made
	atf_check -o ignore jail -c name="$YJAIL" path=/ vnet persist
	atf_check ifconfig "$b" vnet "$YJAIL"
	atf_check jexec "$YJAIL" ifconfig "$b" inet6 2001:db8:71::1/64 up \
	    no_dad
	atf_check -o ignore jexec "$YJAIL" sysctl net.inet6.ip6.forwarding=1
	cat > rtadvd.conf <<EOF
$b:\\
	:maxinterval#600:mininterval#200:rltime#1800:\\
	:addr="2001:db8:71::":prefixlen#64:
EOF
	atf_check jexec "$YJAIL" rtadvd -c "$PWD/rtadvd.conf" \
	    -p "$PWD/rtadvd.pid" -s "$b"
	for i in 1 2 3 4 5 6 7 8 9 10; do
		jexec "$YJAIL" rtadvctl show "$b" 2>/dev/null | \
		    grep -q 'MaxAdvInterval' && break
		sleep 0.5
	done
	atf_check -o match:'MinAdvInterval/MaxAdvInterval: 3m20s/10m' \
	    jexec "$YJAIL" rtadvctl show "$b"
	# Edited as the submodule's max-rtr-adv-interval, reloaded: rtadvd
	# advertises by it.
	atf_check "$y" -m rtadvd.conf "$b" 300
	atf_check -o match:'maxinterval#300' cat rtadvd.conf
	atf_check jexec "$YJAIL" rtadvctl reload "$b"
	for i in 1 2 3 4 5 6 7 8 9 10; do
		jexec "$YJAIL" rtadvctl show "$b" | grep -q '/5m$' && break
		sleep 0.5
	done
	atf_check -o match:'MinAdvInterval/MaxAdvInterval: 3m20s/5m' \
	    jexec "$YJAIL" rtadvctl show "$b"
}
yang_rtadv_cleanup()
{
	[ -f rtadvd.pid ] && kill "$(cat rtadvd.pid)" >/dev/null 2>&1
	sleep 0.5
	ifconfig epair71b -vnet "$YJAIL" >/dev/null 2>&1
	[ -f made ] && ifconfig "$(cat made)" destroy >/dev/null 2>&1
	jail -r "$YJAIL" >/dev/null 2>&1
	true
}

yang_static_apply_cleanup()
{
	ifconfig epair73b -vnet "$YJAIL" >/dev/null 2>&1
	[ -f made ] && ifconfig "$(cat made)" destroy >/dev/null 2>&1
	jail -r "$YJAIL" >/dev/null 2>&1
	true
}

yang_ecmp_cleanup()
{
	# Out of the vnet jail first: it is not removed with one inside.
	ifconfig epair74b -vnet "$YJAIL" >/dev/null 2>&1
	[ -f made ] && ifconfig "$(cat made)" destroy >/dev/null 2>&1
	jail -r "$YJAIL" >/dev/null 2>&1
	true
}

yang_ip_cleanup()
{
	# Out of the vnet jail first: it is not removed with one inside.
	ifconfig epair75b -vnet "$YJAIL" >/dev/null 2>&1
	[ -f made ] && ifconfig "$(cat made)" destroy >/dev/null 2>&1
	jail -r "$YJAIL" >/dev/null 2>&1
	true
}

# devd(8)'s notifications, as events (gula/hostwatch.c): a disk's node
# made and destroyed, and ZFS's of a pool, on a memory disk of the lab.
atf_test_case devd_watch cleanup
devd_watch_head()
{
	atf_set "descr" "a memory disk made and destroyed, a pool made on it" \
	    "and exported: each told by devd(8), each an event"
	atf_set "require.user" "root"
}
devd_watch_body()
{
	[ -S /var/run/devd.seqpacket.pipe ] || atf_skip "devd(8) is not running"
	zpool list arcw_hw >/dev/null 2>&1 && atf_skip "a pool arcw_hw is there already"
	start_daemon
	"$JGC" -c "$SOCK" events -f > follow.out 2>&1 &
	echo $! > follow.pid
	sleep 1.2
	md=$(mdconfig -a -t swap -s 128m) || atf_skip "no memory disk"
	echo "$md" > md
	atf_check zpool create -O mountpoint=none arcw_hw "$md"
	sleep 1.5
	atf_check zpool export arcw_hw
	atf_check mdconfig -d -u "$md"
	rm md
	sleep 1.5
	kill "$(cat follow.pid)"
	atf_check -o match:"\"kind\":\"device\",\"data\":\\{\"cdev\":\"$md\",\"state\":\"created\"\\}" \
	    -o match:"\"kind\":\"device\",\"data\":\\{\"cdev\":\"$md\",\"state\":\"destroyed\"\\}" \
	    -o match:'"kind":"zfs","data":\{"type":"[a-z_]+","pool":"arcw_hw"\}' \
	    cat follow.out
}
devd_watch_cleanup()
{
	[ -f follow.pid ] && kill "$(cat follow.pid)" 2>/dev/null
	cleanup
	if [ -f md ]; then
		zpool destroy -f arcw_hw >/dev/null 2>&1
		mdconfig -d -u "$(cat md)" >/dev/null 2>&1
	fi
	true
}

atf_init_test_cases()
{
	atf_add_test_case yang_layers
	atf_add_test_case devd_watch
	atf_add_test_case yang_kinds
	atf_add_test_case yang_events
	atf_add_test_case yang_ip
	atf_add_test_case yang_ecmp
	atf_add_test_case yang_static_apply
	atf_add_test_case yang_route_times
	atf_add_test_case yang_rtadv
	atf_add_test_case yang_lne
	atf_add_test_case yang_ni
	atf_add_test_case yang_ni_bind
	atf_add_test_case yang_ni_grow
	atf_add_test_case lifecycle
	atf_add_test_case jail_events_nested
	atf_add_test_case live_address
	atf_add_test_case aliases
	atf_add_test_case routes
	atf_add_test_case jail_network
	atf_add_test_case jail_plugins
	atf_add_test_case fw_trace
	atf_add_test_case resnapshot
	atf_add_test_case kmsg
	atf_add_test_case fwmatch_kernel
	atf_add_test_case path_check
	atf_add_test_case crash_event
	atf_add_test_case sdwan_probe
	atf_add_test_case sdwan_jail_edge
	atf_add_test_case sdwan_links
	atf_add_test_case bird_live
	atf_add_test_case snort_live
	atf_add_test_case sctp_multihome
	atf_add_test_case sctp_loopback
	atf_add_test_case sdwan_record
	atf_add_test_case jail_make
	atf_add_test_case zfs_key
	atf_add_test_case carp
}
