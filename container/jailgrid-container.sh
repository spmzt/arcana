#!/bin/sh
#
# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
#
# The jailgrid console in a container: kore(1) with jailgrid.so, in the
# foreground, logging to standard output, as the unprivileged user the
# container runs as.
#
# A web.conf or kore.conf in /usr/local/etc/jailgrid is used as it is.
# A missing one is written to /var/run/jailgrid from the environment:
#
# JAILGRID_RP_ID	The console's host name, as the browser sees it.
#			Required without a web.conf.
# JAILGRID_ORIGIN	The exact origin the browser uses.
#			Default: https://${JAILGRID_RP_ID}
# JAILGRID_PORT		The port to listen on.  Default: 8443
#
# and from the files in /usr/local/etc/jailgrid:
#
# console.pem, console.key	Kore serves HTTPS with these.  The key
#				must be RSA: Kore's key manager signs
#				nothing else.  Without them, plain HTTP,
#				for a reverse proxy that terminates TLS;
#				WebAuthn needs HTTPS but on localhost.
# ca.pem, client.pem,		The console's certificates for jailgridd
# client.key			over TCP (mutual TLS).
#
# All of them must be readable by the user the container runs as.

set -eu

etc=/usr/local/etc/jailgrid
run=/var/run/jailgrid

die()
{
	echo "jailgrid-container: $*" >&2
	exit 1
}

web=${etc}/web.conf
if [ ! -f "${web}" ]; then
	[ -n "${JAILGRID_RP_ID:-}" ] ||
	    die "set JAILGRID_RP_ID, or mount a web.conf in ${etc}"
	origin=${JAILGRID_ORIGIN:-https://${JAILGRID_RP_ID}}
	case "${JAILGRID_RP_ID}" in
	*[!A-Za-z0-9.-]*)	die "JAILGRID_RP_ID: not a host name" ;;
	esac
	case "${origin}" in
	http://*|https://*)	;;
	*)			die "JAILGRID_ORIGIN: not an http(s) origin" ;;
	esac
	case "${origin#*://}" in
	*[!A-Za-z0-9.:\[\]-]*)	die "JAILGRID_ORIGIN: not an http(s) origin" ;;
	esac
	web=${run}/web.conf
	{
		printf 'rp_id = "%s";\n' "${JAILGRID_RP_ID}"
		printf 'origin = "%s";\n' "${origin}"
		printf 'datadir = "/var/db/jailgrid";\n'
		if [ -f ${etc}/client.pem ]; then
			printf 'tls {\n'
			printf '\tca = "%s/ca.pem";\n' ${etc}
			printf '\tcert = "%s/client.pem";\n' ${etc}
			printf '\tkey = "%s/client.key";\n' ${etc}
			printf '}\n'
		fi
	} > "${web}"
fi

conf=${etc}/kore.conf
if [ ! -f "${conf}" ]; then
	port=${JAILGRID_PORT:-8443}
	case "${port}" in
	''|*[!0-9]*)	die "JAILGRID_PORT: not a port number" ;;
	esac
	if [ -f ${etc}/console.pem -a -f ${etc}/console.key ]; then
		openssl x509 -in ${etc}/console.pem -noout -text |
		    grep -q 'Public Key Algorithm: rsaEncryption$' ||
		    die "console.pem: Kore needs an RSA certificate"
		tls=yes
		certs=$(printf '\tcertfile\t%s\n\tcertkey\t\t%s\n' \
		    ${etc}/console.pem ${etc}/console.key)
	else
		tls=no
		certs=
	fi
	conf=${run}/kore.conf
	cat > "${conf}" <<EOF
server console {
	bind		0.0.0.0 ${port}
	tls		${tls}
}

load		/usr/local/lib/jailgrid/jailgrid.so jgw_onload
pidfile		${run}/kore.pid
tls_dhparam	/usr/local/share/kore/ffdhe4096.pem

workers			1
task_threads		8
http_body_max		65536
http_media_type		application/wasm wasm
http_media_type		application/manifest+json webmanifest
http_media_type		image/svg+xml svg
http_media_type		font/woff2 woff2
http_media_type		image/x-icon ico
filemap_index		index.html

domain * {
	attach		console${certs:+
${certs}}
	include		${etc}/routes.conf
	filemap		/ /usr/local/www/jailgrid
}
EOF
	echo "jailgrid-container: serving $([ ${tls} = yes ] &&
	    echo HTTPS || echo HTTP) on port ${port}"
fi

export JAILGRID_WEB_CONF="${web}"
# -n and -r: no chroot and no change of user; the container already
# runs as the console's user.
exec /usr/local/bin/kore -f -n -r -c "${conf}"
