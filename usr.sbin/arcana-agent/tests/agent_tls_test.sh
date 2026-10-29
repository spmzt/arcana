#
# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
#
# arcana-agent(8) over TCP with mutual TLS: certificates from a throwaway CA
# made here with openssl(1), a daemon on a free loopback port.
#

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

# ca NAME: a CA.  cert CA NAME SAN [EKU]: a key and certificate it signs.
ca()
{
	openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 \
	    -nodes -keyout "$1.key" -out "$1.pem" -days 2 \
	    -subj "/CN=$1" -addext basicConstraints=critical,CA:TRUE \
	    -addext keyUsage=critical,keyCertSign >/dev/null 2>&1 ||
	    atf_fail "openssl: cannot make CA $1"
}

cert()
{
	openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
	    -keyout "$2.key" -out "$2.csr" -subj "/CN=$2" \
	    >/dev/null 2>&1 || atf_fail "openssl: cannot make $2"
	printf 'subjectAltName=%s\nextendedKeyUsage=%s\n' "$3" "$4" > "$2.ext"
	openssl x509 -req -in "$2.csr" -CA "$1.pem" -CAkey "$1.key" \
	    -CAcreateserial -days 2 -extfile "$2.ext" -out "$2.pem" \
	    >/dev/null 2>&1 || atf_fail "openssl: cannot sign $2"
}

start_daemon()
{
	local i

	programs
	ca ca
	ca rogue
	# The agent's: a server's, and a client's to a receiver of its
	# configured subscriptions, as the console signs a host's.
	cert ca server "IP:127.0.0.1,DNS:localhost" "serverAuth,clientAuth"
	cert ca client "DNS:console" clientAuth
	cert rogue intruder "DNS:intruder" clientAuth
	cert ca elsewhere "DNS:elsewhere.example" serverAuth
	mkdir -p etc/jail.conf.d
	printf 'web {\n\tpath = /;\n\tip4.addr = 10.0.0.10;\n}\n' > \
	    etc/jail.conf
	# A port of its own: one another test holds (make check runs them
	# side by side) is given up for another, the port checked to be
	# this agent's by sockstat(1), not only that it said ready.
	local try pid
	for try in $(seq 1 20); do
		PORT=$(jot -r 1 20000 59999)
		"$JGD" -F -l "tcp://127.0.0.1:$PORT" -A ca.pem -C server.pem \
		    -K server.key -f "$(pwd)/etc/jail.conf" \
		    -D "$(pwd)/etc/jail.conf.d" -I /usr/bin/false \
		    --nacm "$(pwd)/nacm.cbor" \
		    --subscriptions "$(pwd)/subscriptions.cbor" $DAEMON_ARGS \
		    > daemon.out 2>&1 &
		pid=$!
		echo $pid > daemon.pid
		for i in $(seq 1 100); do
			grep -q ready daemon.out 2>/dev/null && break
			sleep 0.05
		done
		if grep -q ready daemon.out 2>/dev/null && sockstat -4l -P tcp \
		    -p "$PORT" | awk -v p="$pid" '$3 == p { f = 1 } END { exit !f }'
		then
			return
		fi
		kill "$pid" 2>/dev/null
		wait "$pid" 2>/dev/null
	done
	atf_fail "arcana-agent did not start: $(cat daemon.out)"
}

stop_daemon()
{
	[ -f daemon.pid ] && kill "$(cat daemon.pid)" 2>/dev/null
	true
}

atf_test_case mtls cleanup
mtls_head()
{
	atf_set "descr" "Only clients with a certificate from the CA get in"
	atf_set "require.progs" "openssl"
}
mtls_body()
{
	start_daemon
	URI="tcp://127.0.0.1:$PORT"
	atf_check -o match:'^web +stopped +- +10.0.0.10 ' \
	    "$JGC" -c "$URI" -A ca.pem -C client.pem -K client.key list -c
	# Beside the TCP listener there is an SCTP one at the same address
	# and port: up where the kernel has SCTP, and reached there; said
	# to be missing, with why, where it has not.  Who is connected is
	# named by the certificate.
	atf_check -o save:t.json \
	    "$JGC" -c "$URI" -A ca.pem -C client.pem -K client.key transport
	atf_check -o match:"\"uri\":\"tcp://127.0.0.1:$PORT\",\"transport\":\"tcp\",\"up\":true" \
	    -o match:"\"uri\":\"sctp://127.0.0.1:$PORT\",\"transport\":\"sctp\"" \
	    -o match:'"sessions":\[\{"transport":"tcp","address":"127.0.0.1:[0-9]+","subject":"[^"]+"' \
	    cat t.json
	if has_sctp; then
		atf_check -o match:'"transport":"sctp","up":true' cat t.json
		atf_check -o match:'"sessions":\[\{"transport":"sctp"' \
		    "$JGC" -c "sctp://127.0.0.1:$PORT" -A ca.pem -C client.pem \
		    -K client.key transport
	else
		atf_check -o match:'"transport":"sctp","up":false,"error":"the kernel has no SCTP' \
		    cat t.json
		atf_check -s exit:1 -e match:'load the sctp module first' -o ignore \
		    "$JGC" -c "$URI" -A ca.pem -C client.pem -K client.key \
		    transport retry
	fi
	# A client certificate from another CA.
	atf_check -s exit:1 -e not-empty -o ignore \
	    "$JGC" -c "$URI" -A ca.pem -C intruder.pem -K intruder.key hello
	# Another host's, from the same CA: it may reach this one, but asks
	# nothing as the console does.
	cert ca otherhost "IP:127.0.0.2,URI:urn:arcana:role:agent" \
	    "serverAuth,clientAuth"
	atf_check -s exit:1 -e match:'[Pp]ermission denied' -o ignore \
	    "$JGC" -c "$URI" -A ca.pem -C otherhost.pem -K otherhost.key hello
	atf_check -o match:"a host's certificate asked: refused" \
	    cat daemon.out
	# Nor of the standard models (cblink's YANG family).
	atf_check -s exit:1 -e not-empty -o ignore \
	    "$JGC" -c "$URI" -A ca.pem -C otherhost.pem -K otherhost.key get
	# NACM's (RFC 8341) default: the console, which asks for nobody,
	# and its admin may do anything; another user reads, and asks what
	# changes nothing, but what changes the host is denied, counted.
	atf_check -o match:'"group":\[\{"name":"admin","user-name":\["admin","console"\]\}\]' \
	    -o match:'"write-default":"deny"' \
	    "$JGC" -c "$URI" -A ca.pem -C client.pem -K client.key get nacm
	atf_check -o match:'^Host:' "$JGC" -c "$URI" -A ca.pem -C client.pem \
	    -K client.key -u bob hello
	atf_check -s exit:1 -e match:'access denied' \
	    -o ignore "$JGC" -c "$URI" -A ca.pem -C client.pem \
	    -K client.key -u bob sysctl kern.hostname=x
	# The rules themselves are the admin's (default-deny-all): left out
	# of what another user reads.
	atf_check -o not-match:'"group"' -o not-match:'"rule-list"' \
	    "$JGC" -c "$URI" -A ca.pem -C client.pem -K client.key -u bob \
	    get nacm
	atf_check -s ignore -e not-match:'access denied' -o ignore \
	    "$JGC" -c "$URI" -A ca.pem -C client.pem -K client.key \
	    -u admin sysctl kern.hostname=x
	# A YANG action that changes the host is default-deny-all too: a
	# job's cancel (of none) denied to bob, asked for the admin.
	atf_check -s exit:1 -e match:'access denied' -o ignore \
	    "$JGC" -c "$URI" -A ca.pem -C client.pem -K client.key -u bob \
	    action jobs/job 99999 cancel
	atf_check -s ignore -e not-match:'access denied' -o ignore \
	    "$JGC" -c "$URI" -A ca.pem -C client.pem -K client.key \
	    -u admin action jobs/job 99999 cancel
	atf_check -o match:'"denied-operations":2,' -o match:'"denied-data-writes":0' \
	    "$JGC" -c "$URI" -A ca.pem -C client.pem -K client.key get nacm
	atf_check -o match:'^Host:' \
	    "$JGC" -c "$URI" -A ca.pem -C client.pem -K client.key hello
	# No TLS configuration at all is refused before connecting.
	atf_check -s exit:1 -e match:'needs -A, -C and -K' -o ignore \
	    "$JGC" -c "$URI" hello
	# The server's certificate must name the host the client asked for.
	atf_check -s exit:1 -e not-empty -o ignore \
	    "$JGC" -c "$URI" -N elsewhere.example -A ca.pem -C client.pem \
	    -K client.key hello
	atf_check -o match:'^Host:' \
	    "$JGC" -c "$URI" -N localhost -A ca.pem -C client.pem \
	    -K client.key hello
	# A client that trusts another CA does not trust this server.
	atf_check -s exit:1 -e not-empty -o ignore \
	    "$JGC" -c "$URI" -A rogue.pem -C client.pem -K client.key hello
	# Taking away the address the request came in by would cut the
	# client off: refused, unless in safe mode; another address is not.
	atf_check -s exit:1 -e match:'would cut you off' -o ignore \
	    "$JGC" -c "$URI" -A ca.pem -C client.pem -K client.key \
	    interface lo0 remove 127.0.0.1
	atf_check -s exit:1 -e match:'would cut you off' -o ignore \
	    "$JGC" -c "$URI" -A ca.pem -C client.pem -K client.key \
	    interface lo0 down
	atf_check -s exit:1 -o match:'failed' -o not-match:'cut you off' \
	    "$JGC" -c "$URI" -A ca.pem -C client.pem -K client.key \
	    interface lo0 remove 127.0.0.9
	# So would moving that interface to another table, a route over
	# the client's address in the table it is in, forwarding or the
	# tables turned over, the firewall's rules swapped in or turned
	# on: refused unless in safe mode.  A route elsewhere, or in
	# another table, is not.
	for c in "interface lo0 fib 1" "interface lo0 tunnelfib 1" \
	    "route add 127.0.0.0/8 127.0.0.1" "route delete default" \
	    "route add default 127.0.0.1" "sysctl net.fibs=2" \
	    "sysctl net.inet.ip.forwarding=1" "ipfw enable" "ipfw apply"; do
		atf_check -s exit:1 -e match:'would cut you off' -o ignore \
		    "$JGC" -c "$URI" -A ca.pem -C client.pem -K client.key $c
	done
	for c in "route add 10.99.0.0/16 127.0.0.1" "sysctl kern.hostname=x" \
	    "interface lo0 mtu 16384"; do
		atf_check -s ignore -e not-match:'cut you off' -o ignore \
		    "$JGC" -c "$URI" -A ca.pem -C client.pem -K client.key $c
	done
	atf_check -s ignore -e not-match:'cut you off' -o ignore \
	    "$JGC" -c "$URI" -A ca.pem -C client.pem -K client.key -F 3 \
	    route add 127.0.0.0/8 127.0.0.1
}
mtls_cleanup()
{
	stop_daemon
}

# sign CA CSR OUT: a server certificate for 127.0.0.1 from the request.
sign()
{
	printf 'subjectAltName=IP:127.0.0.1\nextendedKeyUsage=serverAuth\n' \
	    > srv.ext
	openssl x509 -req -in "$2" -CA "$1.pem" -CAkey "$1.key" \
	    -CAcreateserial -days 2 -extfile srv.ext -out "$3" \
	    >/dev/null 2>&1 || atf_fail "openssl: cannot sign $2"
}

# The request of the agent's csr reply, as PEM.
csr_of()
{
	sed -E 's/.*"csr":"([^"]*)".*/\1/' "$1" | sed 's|\\/|/|g' |
	    awk '{ gsub(/\\n/, "\n"); printf "%s", $0 }'
}

atf_test_case renew cleanup
renew_head()
{
	atf_set "descr" "The agent's own TLS files renewed while it runs: a key made there, its certificate taken, the CAs changed over to another one and to an intermediate, never so that the console asking is locked out"
	atf_set "require.progs" "openssl"
}
renew_body()
{
	# A smtpd.conf that serves with the agent's own certificate: its
	# dates read with it, the new ones once it is renewed.
	printf 'pki arcana cert "%s/server.pem"\npki arcana key "%s/server.key"\n' \
	    "$(pwd)" "$(pwd)" > smtpd.conf
	# The host's own services out of reach: no rc.d script found, no
	# service(8) or sysrc(8) run.
	mkdir -p rc.d
	DAEMON_ARGS="--smtpd-conf $(pwd)/smtpd.conf --smtpd-watch 0 -R $(pwd)/rc.d -s /usr/bin/false -y /usr/bin/false"
	start_daemon
	URI="tcp://127.0.0.1:$PORT"
	C1="-A ca.pem -C client.pem -K client.key"
	sha() { openssl x509 -in "$1" -noout -fingerprint -sha256 | sed 's/.*=//'; }
	atf_check -o save:st.json "$JGC" -c "$URI" $C1 tls
	atf_check -o match:'"subject":"CN=server","issuer":"CN=ca"' \
	    -o match:'"pending":false' cat st.json
	# A key made there, never sent; the request for it signed here.
	atf_check -o save:csr.json "$JGC" -c "$URI" $C1 tls csr
	csr_of csr.json > new.csr
	atf_check -o match:'CN *= *server' openssl req -in new.csr -noout -subject
	test -f server.key.next || atf_fail "no key waiting"
	atf_check -o match:'^-rw------- ' ls -l server.key.next
	atf_check -o not-match:'PRIVATE' cat csr.json
	# A second on, so that its dates are not the first one's.
	sleep 1
	sign ca new.csr new.pem
	# One not for that key is refused, the files as they were.
	atf_check -s exit:1 -e match:'not for the key that waits' -o ignore \
	    "$JGC" -c "$URI" $C1 tls install server.pem
	atf_check -o save:m1.json "$JGC" -c "$URI" $C1 smtpd
	atf_check -o match:'"pki_cert":\{"not_before":[0-9]+,"not_after":[0-9]+\}' \
	    cat m1.json
	atf_check -o save:st2.json "$JGC" -c "$URI" $C1 tls install new.pem
	grep -q "\"sha256\":\"$(sha new.pem)\"" st2.json || atf_fail "not installed"
	atf_check -o save:m2.json "$JGC" -c "$URI" $C1 smtpd
	cmp -s m1.json m2.json && atf_fail "the certificate's dates are the old ones"
	test -f server.pem.before || atf_fail "the certificate before was not kept"
	test -f server.key.next && atf_fail "the waiting key stayed"
	# New connections are served with it.
	echo | openssl s_client -connect "127.0.0.1:$PORT" -CAfile ca.pem \
	    -cert client.pem -key client.key 2>/dev/null |
	    openssl x509 -noout -fingerprint -sha256 | sed 's/.*=//' > served
	atf_check -o inline:"$(sha new.pem)\n" cat served
	# Another CA: not trusted alone while the console's is of the first.
	ca ca2
	cert ca2 client2 "DNS:console" clientAuth
	atf_check -s exit:1 -e match:'would not be trusted any more' -o ignore \
	    "$JGC" -c "$URI" $C1 tls install - ca2.pem
	atf_check -o match:'Host:' "$JGC" -c "$URI" $C1 hello
	# Both, then the new one's console, then the new one alone.
	cat ca.pem ca2.pem > both.pem
	atf_check -o match:'"subject":"CN=ca2"' "$JGC" -c "$URI" $C1 tls install - both.pem
	C2="-A ca.pem -C client2.pem -K client2.key"
	atf_check -o match:'Host:' "$JGC" -c "$URI" $C2 hello
	atf_check -o save:csr2.json "$JGC" -c "$URI" $C2 tls csr
	csr_of csr2.json > new2.csr
	sign ca2 new2.csr new2.pem
	atf_check -o ignore "$JGC" -c "$URI" $C2 tls install new2.pem ca2.pem
	atf_check -o match:'Host:' "$JGC" -c "$URI" -A ca2.pem -C client2.pem -K client2.key hello
	atf_check -s exit:1 -e not-empty -o ignore "$JGC" -c "$URI" $C1 hello
	# Under an intermediate: the chain sent after the certificate.
	openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
	    -keyout inter.key -out inter.csr -subj /CN=inter >/dev/null 2>&1
	printf 'basicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign\n' > inter.ext
	openssl x509 -req -in inter.csr -CA ca2.pem -CAkey ca2.key \
	    -CAcreateserial -days 2 -extfile inter.ext -out inter.pem >/dev/null 2>&1
	C3="-A ca2.pem -C client2.pem -K client2.key"
	atf_check -o save:csr3.json "$JGC" -c "$URI" $C3 tls csr
	csr_of csr3.json > new3.csr
	sign inter new3.csr leaf3.pem
	cat leaf3.pem inter.pem > new3.pem
	atf_check -o match:'"chain":\[\{"subject":"CN=inter","issuer":"CN=ca2"' \
	    "$JGC" -c "$URI" $C3 tls install new3.pem
	atf_check -o match:'Host:' "$JGC" -c "$URI" $C3 hello
	# Leaf alone, for the key that waits but without its intermediate:
	# does not verify, refused.
	atf_check -o save:csr4.json "$JGC" -c "$URI" $C3 tls csr
	csr_of csr4.json > new4.csr
	sign inter new4.csr leaf4.pem
	atf_check -s exit:1 -e match:'does not verify' -o ignore \
	    "$JGC" -c "$URI" $C3 tls install leaf4.pem
	atf_check -o match:'Host:' "$JGC" -c "$URI" $C3 hello
}
renew_cleanup()
{
	stop_daemon
}

atf_test_case tls_files
tls_files_head()
{
	atf_set "descr" "Bad TLS files are named at startup, before detaching"
	atf_set "require.progs" "openssl"
}
tls_files_body()
{
	programs
	ca ca
	cert ca server "IP:127.0.0.1" serverAuth
	cert ca other "IP:127.0.0.1" serverAuth
	URI="tcp://127.0.0.1:$(( 20000 + $$ % 20000 ))"
	atf_check -s exit:1 -e match:'-C missing.pem: No such file' \
	    "$JGD" -l "$URI" -A ca.pem -C missing.pem -K server.key
	atf_check -s exit:1 -e match:'-K ca.pem: not a PEM private key' \
	    "$JGD" -l "$URI" -A ca.pem -C server.pem -K ca.pem
	atf_check -s exit:1 -e match:'not the key of the certificate' \
	    "$JGD" -l "$URI" -A ca.pem -C server.pem -K other.key
}

# The stand-in HTTPS-notif receiver, on a free port, its log recv.log.
start_receiver()
{
	local try i

	for try in $(seq 1 20); do
		[ -n "$RPORT" ] || RPORT=$(jot -r 1 20000 59999)
		"$(atf_get_srcdir)/notifrecv" recv.pem recv.key ca.pem "$RPORT" \
		    "$(pwd)/recv.log" > recv.out 2>&1 &
		echo $! > recv.pid
		for i in $(seq 1 100); do
			grep -q ready recv.out 2>/dev/null && return
			kill -0 "$(cat recv.pid)" 2>/dev/null || break
			sleep 0.05
		done
		kill "$(cat recv.pid)" 2>/dev/null
		wait "$(cat recv.pid)" 2>/dev/null
		RPORT=
	done
	atf_fail "notifrecv did not start: $(cat recv.out)"
}

# wait_log PATTERN COUNT SECONDS: until the log has COUNT lines of it.
wait_log()
{
	local i

	for i in $(seq 1 $(( $3 * 10 ))); do
		[ "$(grep -c -- "$1" recv.log 2>/dev/null)" -ge "$2" ] && return
		sleep 0.1
	done
	atf_fail "no $2 of '$1' in $3 s: $(cat recv.log 2>/dev/null); the agent: $(grep subscription daemon.out | tail -5)"
}

atf_test_case configured cleanup
configured_head()
{
	atf_set "descr" "A configured subscription (RFC 8639 section 2.5)" \
	    "to an HTTPS-notif receiver: its capabilities read, each record" \
	    "POSTed as RFC 8040's JSON, what it missed while away replayed" \
	    "when it is back; listed with its receiver's state; ended by the" \
	    "configuration"
	atf_set "require.progs" "openssl"
}
configured_body()
{
	start_daemon
	URI="tcp://127.0.0.1:$PORT"
	JC="$JGC -c $URI -A ca.pem -C client.pem -K client.key"
	cert ca recv "IP:127.0.0.1" serverAuth
	RPORT=
	start_receiver
	# Refused: a receiver names no instance; an instance that is no
	# https-receiver.
	cat > bad.json <<EOF
{"ietf-subscribed-notifications:subscriptions":{"subscription":[{"id":7,
"stream":"NETCONF","receivers":{"receiver":[{"name":"console"}]}}]}}
EOF
	atf_check $JC edit subscriptions @bad.json
	atf_check -s exit:1 -e match:'names a receiver instance' $JC commit
	cat > subs.json <<EOF
{"ietf-subscribed-notifications:subscriptions":{"subscription":[{"id":7,
"stream":"NETCONF","stream-xpath-filter":"/arcana-events:event",
"configured-replay":[null],"receivers":{"receiver":[{"name":"console",
"ietf-subscribed-notif-receivers:receiver-instance-ref":"lab"}]}}],
"ietf-subscribed-notif-receivers:receiver-instances":{"receiver-instance":[
{"name":"lab","ietf-https-notif-transport:https-receiver":{
"capabilities-endpoint":{"uri":"https://127.0.0.1:$RPORT/notif/capabilities"},
"relay-notification-endpoint":{"uri":"https://127.0.0.1:$RPORT/notif/relay-notification"},
"arcana-notif:token":"lab-token-7"}}]}}}
EOF
	atf_check $JC edit subscriptions @subs.json
	atf_check $JC commit
	# Connected: the capabilities asked, subscription-started and (a
	# replay from its making, of nothing) replay-completed POSTed, the
	# instance's token sent with each as Authorization: Bearer.
	wait_log '^POST ' 2 5
	atf_check -o match:'^GET /notif/capabilities$' \
	    -o match:'^POST /notif/relay-notification$' \
	    -o match:'^Authorization: Bearer lab-token-7$' \
	    -o match:'"ietf-restconf:notification":\{"eventTime":"[0-9T:-]+Z","ietf-subscribed-notifications:subscription-started":\{"id":7,"stream":"NETCONF","stream-xpath-filter":"/arcana-events:event"\}\}' \
	    -o match:'"ietf-subscribed-notifications:replay-completed":\{"id":7\}' \
	    cat recv.log
	atf_check -o match:'"id":7,' \
	    -o match:'"ietf-subscribed-notif-receivers:receiver-instance-ref":"lab"' \
	    -o match:'"state":"active"' -o match:'"configured-subscription-state":"valid"' \
	    -o match:'"capabilities-endpoint":\{"uri":"https://127.0.0.1' \
	    $JC get subscriptions
	# An event: a record.
	atf_check -s ignore -o ignore -e ignore $JC interface lo0 mtu 16384
	wait_log '"arcana-events:event":{' 1 5
	# The receiver gone: the next record fails, what follows is missed;
	# back, it is told subscription-started with the time of the last
	# record it had, what it missed replayed, then replay-completed.
	kill "$(cat recv.pid)"
	wait "$(cat recv.pid)" 2>/dev/null
	atf_check -s ignore -o ignore -e ignore $JC interface lo0 mtu 1500
	sleep 0.5
	atf_check -s ignore -o ignore -e ignore $JC interface lo0 mtu 16384
	sleep 0.5
	start_receiver
	wait_log 'subscription-started' 2 20
	wait_log 'replay-completed' 2 20
	atf_check -o match:'subscription-started":\{"id":7,"replay-previous-event-time":"[0-9T:-]+Z"' \
	    cat recv.log
	atf_check -o match:'^3$' \
	    sh -c 'grep -c "ifconfig exited with status 1" recv.log'
	atf_check -o match:'"excluded-event-records":"[1-9]' $JC get subscriptions
	# Out of the configuration: told subscription-terminated, gone from
	# the list; its file gone too.
	atf_check $JC edit subscriptions null
	atf_check $JC commit
	wait_log 'subscription-terminated' 1 5
	atf_check -o match:'reason":"ietf-subscribed-notifications:no-such-subscription"' \
	    cat recv.log
	atf_check -o not-match:'"id":7,' $JC get subscriptions
	atf_check -s exit:1 -o ignore test -f subscriptions.cbor
}
configured_cleanup()
{
	stop_daemon
	[ -f recv.pid ] && kill "$(cat recv.pid)" 2>/dev/null
	true
}

atf_init_test_cases()
{
	atf_add_test_case tls_files
	atf_add_test_case mtls
	atf_add_test_case renew
	atf_add_test_case configured
}
