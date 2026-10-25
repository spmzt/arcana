#!/bin/sh
#
# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
#
# The arcana console in a container: arcana-console(8), in the foreground,
# logging to standard error, as the unprivileged user the container runs
# as.
#
# A web.conf in /usr/local/etc/arcana is used as it is (its server { }
# says where to listen, with user = "").  A missing one is written to
# /var/run/arcana from the environment:
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
# console.pem, console.key	The console serves HTTPS with these, RSA
#				or EC.  Without them, plain HTTP,
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
	port=${ARCANA_PORT:-8443}
	case "${port}" in
	''|*[!0-9]*)	die "ARCANA_PORT: not a port number" ;;
	esac
	web=${run}/web.conf
	{
		# The container runs as the console's user already.
		printf 'server {\n'
		printf '\tlisten = [ "0.0.0.0:%s", "[::]:%s" ];\n' \
		    "${port}" "${port}"
		if [ -f ${etc}/console.pem -a -f ${etc}/console.key ]; then
			printf '\tcertfile = "%s/console.pem";\n' ${etc}
			printf '\tcertkey = "%s/console.key";\n' ${etc}
			tls=HTTPS
		else
			tls=HTTP
		fi
		printf '\tuser = "";\n\ttask_threads = 8;\n}\n'
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
	echo "arcana-container: serving ${tls} on port ${port}"
fi

exec /usr/local/sbin/arcana-console -c "${web}"
