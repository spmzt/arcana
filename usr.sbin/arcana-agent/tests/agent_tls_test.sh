#
# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
#
# arcana-agent(8) over TCP with mutual TLS: certificates from a throwaway CA
# made here with openssl(1), a daemon on a free loopback port.
#

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
	PORT=$(( 20000 + $$ % 20000 ))
	"$JGD" -F -l "tcp://127.0.0.1:$PORT" -A ca.pem -C server.pem \
	    -K server.key -f "$(pwd)/etc/jail.conf" \
	    -D "$(pwd)/etc/jail.conf.d" -I /usr/bin/false \
	    > daemon.out 2>&1 &
	echo $! > daemon.pid
	for i in $(seq 1 100); do
		grep -q ready daemon.out 2>/dev/null && return
		sleep 0.05
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
	# A client certificate from another CA.
	atf_check -s exit:1 -e not-empty -o ignore \
	    "$JGC" -c "$URI" -A ca.pem -C intruder.pem -K intruder.key hello
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
}
mtls_cleanup()
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
}
