#!/bin/sh
#
# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
#
# The arcana console in a container: kore(1) with arcana-console.so, in the
# foreground, logging to standard output, as the unprivileged user the
# container runs as.
#
# A web.conf or kore.conf in /usr/local/etc/arcana is used as it is.
# A missing one is written to /var/run/arcana from the environment:
#
# ARCANA_RP_ID	The console's host name, as the browser sees it.
#			Required without a web.conf.
# ARCANA_ORIGIN	The exact origin the browser uses.
#			Default: https://${ARCANA_RP_ID}
# ARCANA_PORT		The port to listen on.  Default: 8443
# ARCANA_AGENT_SOURCE	A git repository a host can be asked to build
#			arcana-agent from, and ARCANA_AGENT_REF, a
#			branch or tag of it.  Default: none; the console
#			sends the arcana-agent in the image.
#
# and from the files in /usr/local/etc/arcana:
#
# console.pem, console.key	Kore serves HTTPS with these.  The key
#				must be RSA: Kore's key manager signs
#				nothing else.  Without them, plain HTTP,
#				for a reverse proxy that terminates TLS;
#				WebAuthn needs HTTPS but on localhost.
# ca.pem, client.pem,		The console's certificates for arcana-agent
# client.key			over TCP (mutual TLS).
#
# All of them must be readable by the user the container runs as.

set -eu

etc=/usr/local/etc/arcana
run=/var/run/arcana

die()
{
	echo "arcana-container: $*" >&2
	exit 1
}

web=${etc}/web.conf
if [ ! -f "${web}" ]; then
	[ -n "${ARCANA_RP_ID:-}" ] ||
	    die "set ARCANA_RP_ID, or mount a web.conf in ${etc}"
	origin=${ARCANA_ORIGIN:-https://${ARCANA_RP_ID}}
	case "${ARCANA_RP_ID}" in
	*[!A-Za-z0-9.-]*)	die "ARCANA_RP_ID: not a host name" ;;
	esac
	case "${origin}" in
	http://*|https://*)	;;
	*)			die "ARCANA_ORIGIN: not an http(s) origin" ;;
	esac
	case "${origin#*://}" in
	*[!A-Za-z0-9.:\[\]-]*)	die "ARCANA_ORIGIN: not an http(s) origin" ;;
	esac
	case "${ARCANA_AGENT_SOURCE:-}${ARCANA_AGENT_REF:-}" in
	*[!A-Za-z0-9._:/@~+-]*)	die "ARCANA_AGENT_SOURCE or ARCANA_AGENT_REF: "\
"not a repository and a branch" ;;
	esac
	web=${run}/web.conf
	{
		printf 'rp_id = "%s";\n' "${ARCANA_RP_ID}"
		printf 'origin = "%s";\n' "${origin}"
		printf 'datadir = "/var/db/arcana";\n'
		[ -z "${ARCANA_AGENT_SOURCE:-}" ] ||
		    printf 'agent_source = "%s";\n' "${ARCANA_AGENT_SOURCE}"
		[ -z "${ARCANA_AGENT_REF:-}" ] ||
		    printf 'agent_ref = "%s";\n' "${ARCANA_AGENT_REF}"
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
	port=${ARCANA_PORT:-8443}
	case "${port}" in
	''|*[!0-9]*)	die "ARCANA_PORT: not a port number" ;;
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
	bind		:: ${port}
	tls		${tls}
}

load		/usr/local/lib/arcana/arcana-console.so arcw_onload
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
	filemap		/ /usr/local/www/arcana-console
}
EOF
	echo "arcana-container: serving $([ ${tls} = yes ] &&
	    echo HTTPS || echo HTTP) on port ${port}"
fi

export ARCANA_WEB_CONF="${web}"
# -n and -r: no chroot and no change of user; the container already
# runs as the console's user.
exec /usr/local/bin/kore -f -n -r -c "${conf}"
