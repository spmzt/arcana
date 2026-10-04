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
	"$JGD" -F -l "$SOCK" -f "$(pwd)/etc/jail.conf" \
	    -D "$(pwd)/etc/jail.conf.d" > daemon.out 2>&1 &
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
}
lifecycle_cleanup()
{
	cleanup
}

atf_test_case live_address cleanup
live_address_head()
{
	atf_set "descr" "Live address changes use jail_setv(3) and ioctls only"
	atf_set "require.user" "root"
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

atf_init_test_cases()
{
	atf_add_test_case lifecycle
	atf_add_test_case live_address
	atf_add_test_case aliases
}
