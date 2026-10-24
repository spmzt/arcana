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
	cert ca server "IP:127.0.0.1,DNS:localhost" serverAuth
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
	atf_check -o match:"a host's certificate asked for hello: refused" \
	    cat daemon.out
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
	sign ca new.csr new.pem
	# One not for that key is refused, the files as they were.
	atf_check -s exit:1 -e match:'not for the key that waits' -o ignore \
	    "$JGC" -c "$URI" $C1 tls install server.pem
	atf_check -o save:st2.json "$JGC" -c "$URI" $C1 tls install new.pem
	grep -q "\"sha256\":\"$(sha new.pem)\"" st2.json || atf_fail "not installed"
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

atf_init_test_cases()
{
	atf_add_test_case tls_files
	atf_add_test_case mtls
	atf_add_test_case renew
}
