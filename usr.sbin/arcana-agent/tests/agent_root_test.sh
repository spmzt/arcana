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

# Does the kernel have SCTP: compiled in (kern.features.sctp) or the
# module loaded.
has_sctp()
{
	[ "$(sysctl -n kern.features.sctp 2>/dev/null)" = 1 ] ||
	    kldstat -q -m sctp 2>/dev/null
}

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
	    "event when made and when removed (EVFILT_JAIL)"
	atf_set "require.user" "root"
	atf_set "is.exclusive" "true"
}
# The jail the nested events are made in, its own name.
NJAIL=arcana-nested

jail_events_nested_body()
{
	start_daemon
	jls -j "$NJAIL" >/dev/null 2>&1 && atf_skip "a jail named $NJAIL exists"
	atf_check -o ignore jail -c name="$NJAIL" path=/ vnet persist \
	    children.max=1
	atf_check -o ignore jexec "$NJAIL" jail -c name=inner path=/ persist
	atf_check -o ignore jls -j "$NJAIL.inner"
	atf_check -o ignore jexec "$NJAIL" jail -r inner
	atf_check -o ignore jail -r "$NJAIL"
	sleep 0.5
	atf_check -o save:ev.json "$JGC" -c "$SOCK" events
	for j in "$NJAIL" "$NJAIL.inner"; do
		for st in running stopped; do
			atf_check -o inline:"$j $st 1\n" sh -c "echo $j $st \$(grep -o '\"jail\":\"$j\",\"state\":\"$st\"' ev.json | wc -l | tr -d ' ')"
		done
	done
}
jail_events_nested_cleanup()
{
	jail -r "$NJAIL" >/dev/null 2>&1
	cleanup
}

atf_test_case jail_allow_live cleanup
jail_allow_live_head()
{
	atf_set "descr" "jail-allow on a running jail: a parameter set with JAIL_UPDATE as jail -m does, read back by jls and in the list; in safe mode and not confirmed, set back as it was"
	atf_set "require.user" "root"
	atf_set "is.exclusive" "true"
}
jail_allow_live_body()
{
	DAEMON_ARGS="-w 2"
	start_daemon
	AJ=arcana-allow-test
	jls -j "$AJ" >/dev/null 2>&1 && atf_skip "a jail named $AJ exists"
	atf_check -o ignore jail -c name="$AJ" path=/ persist allow.raw_sockets=0
	atf_check -o match:'jailparam_set\(3\)' -o match:'JAIL_UPDATE, 2 parameters' "$JGC" -t -c "$SOCK" allow "$AJ" allow.raw_sockets=1 allow.sysvipc=1
	atf_check -o match:'^(1|true)$' jls -j "$AJ" allow.raw_sockets
	atf_check -o match:'^(1|true)$' jls -j "$AJ" allow.sysvipc
	# Safe mode: set to 0 and not confirmed, back to 1.
	atf_check -o match:'queued' "$JGC" -q -s -c "$SOCK" allow "$AJ" allow.raw_sockets=0
	sleep 0.5
	atf_check -o match:'^(0|false)$' jls -j "$AJ" allow.raw_sockets
	for i in $(seq 1 200); do
		"$JGC" -c "$SOCK" jobs | grep -q 'unconfirmed\|queued\|running' ||
		    break
		sleep 0.1
	done
	atf_check -s exit:1 -o match:'not confirmed within 2 s: undone' -o match:'undo' "$JGC" -c "$SOCK" job $("$JGC" -c "$SOCK" jobs | awk '$1 ~ /^[0-9]+$/ {print $1}' | sort -n | tail -1)
	atf_check -o match:'^(1|true)$' jls -j "$AJ" allow.raw_sockets
	atf_check -o ignore jail -r "$AJ"
}
jail_allow_live_cleanup()
{
	jail -r arcana-allow-test >/dev/null 2>&1
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
	# A route by a link-local gateway with its zone, as a router
	# advertisement gives one.
	atf_check -o match:'done +route add 2001:db8:79::/48 via fe80::1%lo0' \
	    "$JGC" -c "$SOCK" route add 2001:db8:79::/48 fe80::1%lo0
	atf_check -o match:'2001:db8:79::/48 +fe80::1%lo0' netstat -rn6
	atf_check -o match:'done' "$JGC" -c "$SOCK" route delete 2001:db8:79::/48
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
	atf_set "descr" "a vnet jail's plugins are looked for as the jail sees its files: a program behind a link inside it is found, though the host has none; wg(8), the base system's, is no plugin"
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
	    -o not-match:'"plugins": ?\[[^]]*"wireguard"' cat jail.json
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

	has_sctp || atf_skip "the kernel has no SCTP"
	[ "$(sysctl -n net.inet.sctp.ignore_loopback_iftype 2>/dev/null)" = 1 ] ||
	    atf_skip "the kernel's SCTP scopes by the interface's type"
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

atf_test_case pkg_lanes cleanup
pkg_lanes_head()
{
	atf_set "descr" "jobs of pkg in jails run four at once, a jail's own" \
	    "one after another, and the next job of another kind after all" \
	    "of them; a pkg that says nothing is stopped with its child in" \
	    "the jail, and one cancelled at work is stopped"
	atf_set "require.user" "root"
	atf_set "is.exclusive" "true"
	atf_set "timeout" "120"
}
pkg_lanes_body()
{
	local d="$(pwd)" j id

	programs
	for j in arcw_p1 arcw_p2 arcw_p3 arcw_p4 arcw_ps arcw_pc; do
		jls -j $j >/dev/null 2>&1 && atf_skip "a jail $j is there already"
	done
	for j in arcw_p1 arcw_p2 arcw_p3 arcw_p4 arcw_ps arcw_pc; do
		atf_check -o ignore jail -c name=$j persist path=/
		echo $j >> jails.made
	done
	mkdir run etc etc/jail.conf.d
	: > etc/jail.conf
	# pkg, as the agent runs it: how many are at work when one starts,
	# a jail's twice at once said; arcw_ps silent with a child, as a
	# stalled download; arcw_pc silent until it is cancelled.
	cat > fake-pkg <<EOS
#!/bin/sh
jail=host
[ "\$1" = -j ] && { jail=\$2; shift 2; }
case "\$1" in
version) exit 1 ;;
-vv) exit 0 ;;
esac
[ -e $d/run/\$jail ] && echo "twice \$jail" >> $d/lanes.log
: > $d/run/\$jail
echo "\$jail \$(ls $d/run | wc -l | tr -d ' ')" >> $d/lanes.log
case "\$jail" in
arcw_ps|arcw_pc)
	# Stopped: no longer at work (its child is left to the agent).
	trap "rm -f $d/run/\$jail; exit 143" TERM
	sleep 300 &
	echo \$! > $d/\$jail.child
	wait ;;
*)	sleep 2
	echo "Your packages are up to date." ;;
esac
rm -f $d/run/\$jail
EOS
	chmod +x fake-pkg
	"$JGD" -F -l "unix:$d/s.sock" -P "$d/fake-pkg" --pkg-idle 5 \
	    -f "$d/etc/jail.conf" -D "$d/etc/jail.conf.d" \
	    -1 "$d/history.conf" > daemon.out 2>&1 &
	echo $! > daemon.pid
	for i in $(seq 1 50); do [ -S s.sock ] && break; sleep 0.1; done
	for j in arcw_ps arcw_pc arcw_p1 arcw_p1 arcw_p2 arcw_p3 arcw_p4; do
		"$JGC" -q -c "unix:$d/s.sock" pkg-upgrade -j $j >> queued.out ||
		    atf_fail "pkg-upgrade -j $j not queued"
	done
	# Then one of another kind: pkg on the host.
	"$JGC" -q -c "unix:$d/s.sock" pkg-upgrade >> queued.out
	id=$(awk '/in arcw_pc$/ { print $1 }' queued.out)
	for i in $(seq 1 50); do [ -s arcw_pc.child ] && break; sleep 0.1; done
	atf_check -o match:"^ *$id running" "$JGC" -c "unix:$d/s.sock" job-cancel $id
	for i in $(seq 1 300); do
		"$JGC" -c "unix:$d/s.sock" jobs | grep -q 'queued\|running' ||
		    break
		sleep 0.1
	done
	"$JGC" -c "unix:$d/s.sock" jobs > jobs.out
	cat lanes.log jobs.out
	atf_check -o not-match:'queued|running' cat jobs.out
	# Four at once at most, and four were.
	atf_check -o inline:'4\n' sh -c "awk '{ print \$2 }' lanes.log | sort -n | tail -1"
	atf_check -o not-match:twice cat lanes.log
	# The host's after every jail's, alone.
	atf_check -o match:'^host 1$' tail -1 lanes.log
	# The silent one stopped, its child with it; the cancelled one too.
	atf_check -o match:'failed +pkg upgrade in arcw_ps: pkg upgrade was killed: nothing came from it for 5 seconds' \
	    -o match:'failed +pkg upgrade in arcw_pc: cancelled while at work' \
	    -o match:'done +pkg upgrade in arcw_p1$' \
	    -o match:'done +pkg upgrade in arcw_p4$' \
	    -o match:'done +pkg upgrade$' cat jobs.out
	for j in arcw_ps arcw_pc; do
		atf_check -s not-exit:0 -e ignore kill -0 "$(cat $j.child)"
	done
}
pkg_lanes_cleanup()
{
	local j

	[ -f daemon.pid ] && kill "$(cat daemon.pid)" 2>/dev/null
	for j in arcw_ps arcw_pc; do
		[ -f $j.child ] && kill "$(cat $j.child)" 2>/dev/null
	done
	if [ -f jails.made ]; then
		for j in $(cat jails.made); do
			jail -r $j 2>/dev/null
		done
	fi
	true
}

atf_test_case sctp_loopback cleanup
sctp_loopback_head()
{
	atf_set "descr" "an SCTP listener on a router's loopback address alone" \
	    "(an address on lo0), with the kernel scoping by the address" \
	    "(net.inet.sctp.ignore_loopback_iftype): SCTP to that address" \
	    "from a peer elsewhere answered, and no warning said"
	atf_set "require.user" "root"
	atf_set "is.exclusive" "true"
	atf_set "timeout" "120"
}
sctp_loopback_body()
{
	local d="$(pwd)" port=24611 e a

	has_sctp || atf_skip "the kernel has no SCTP"
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
			printf 'subjectAltName=IP:2001:db8:12::1\nextendedKeyUsage=serverAuth\n' > $n.ext
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
	# The vnet's own value, as a new vnet takes it from the host's.
	atf_check -o inline:'1\n' jexec arcw_la sysctl -n net.inet.sctp.ignore_loopback_iftype
	jexec arcw_la "$JGD" -F -l "tcp://[2001:db8:12::1]:$port" \
	    -l "unix:$d/s.sock" \
	    -A "$d/ca.pem" -C "$d/server.pem" -K "$d/server.key" \
	    -f "$d/etc/jail.conf" -D "$d/etc/jail.conf.d" \
	    -1 "$d/history.conf" > daemon.out 2>&1 &
	echo $! > daemon.pid
	for i in $(seq 1 50); do [ -S s.sock ] && break; sleep 0.1; done
	sleep 0.5
	# The SCTP listener beside the TCP one, on lo0's address alone, up
	# and warned of nothing.
	atf_check -o save:t.json "$JGC" -c "unix:$d/s.sock" transport
	atf_check -o match:'"transport":"sctp","up":true' \
	    -o not-match:'"warning"' -o not-match:'loopback' cat t.json
	# Both answered from the other jail: TCP, and SCTP to the same
	# address on lo0.
	atf_check -o ignore jexec arcw_lb "$JGC" \
	    -c "tcp://[2001:db8:12::1]:$port" $a hello
	atf_check -o ignore jexec arcw_lb "$JGC" \
	    -c "sctp://[2001:db8:12::1]:$port" $a hello
	# Over SCTP the association's paths: the agent's lo0 address.
	atf_check -o match:'2001:db8:12::1' jexec arcw_lb "$JGC" \
	    -c "sctp://[2001:db8:12::1]:$port" $a transport
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
	atf_add_test_case devd_watch
	atf_add_test_case lifecycle
	atf_add_test_case jail_events_nested
	atf_add_test_case jail_allow_live
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
	atf_add_test_case sctp_multihome
	atf_add_test_case pkg_lanes
	atf_add_test_case sctp_loopback
	atf_add_test_case sdwan_record
	atf_add_test_case jail_make
	atf_add_test_case zfs_key
	atf_add_test_case carp
}
