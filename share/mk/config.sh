#!/bin/sh
#
# The build's options, as the ports' "make config" has them:
#
#	config.sh config	choose them with bsddialog(1) and keep them
#				in config.mk
#	config.sh show		say each and how it is set
#
# Told by the environment (the top Makefile sets it): ARC_TOP, and
# CONSOLE and WEBGPU (yes, no), each option as the build sees it now.
# What config writes is a block of config.mk of its own, between the
# two lines below; the rest of the file (LDFLAGS, LWS_*, EMDAWN, ...) is
# kept as it is, but a WITH_ or WITHOUT_ line of these options outside
# the block is taken out, so that the block alone says.

set -u

mode=${1:-config}
conf=${ARC_TOP:?}/config.mk
begin="# make config: begin (written by make config; make config to change)"
end="# make config: end"

# An option: its name, its default, and what it is.
options="CONSOLE yes The_web_console:_its_server_and_the_page
WEBGPU no The_network_map_drawn_with_WebGPU_(Dawn's_emdawnwebgpu)"

now()
{
	eval echo "\${$1:-$2}"
}

if [ "$mode" = show ]; then
	echo "Arcana's build options (make config to change them):"
	echo "$options" | while read -r name def desc; do
		v=$(now "$name" "$def")
		printf '  %-8s %-3s %s\n' "$name" "$([ "$v" = yes ] && echo on ||
		    echo off)" "$(echo "$desc" | tr _ ' ')"
	done
	exit 0
fi

if [ ! -t 0 ] || [ ! -t 1 ]; then
	echo "make config needs a terminal; set the options in $conf:" >&2
	echo "  WITHOUT_CONSOLE=yes, WITH_WEBGPU=yes" >&2
	exit 1
fi

set --
for o in $(echo "$options" | awk '{ print $1 }'); do
	line=$(echo "$options" | awk -v o="$o" '$1 == o')
	def=$(echo "$line" | awk '{ print $2 }')
	desc=$(echo "$line" | awk '{ print $3 }' | tr _ ' ')
	v=$(now "$o" "$def")
	set -- "$@" "$o" "$desc" "$([ "$v" = yes ] && echo on || echo off)"
done
chosen=$(bsddialog --backtitle "Arcana" --title "Build options" \
    --separate-output --output-fd 3 --checklist \
    "The options Arcana is built with, kept in config.mk:" \
    0 0 0 "$@" 3>&1 1>/dev/tty 2>/dev/tty) || {
	clear
	echo "make config: nothing changed"
	exit 0
}
clear

on()
{
	echo "$chosen" | grep -qx "$1"
}

tmp=$(mktemp "$conf.XXXXXX") || exit 1
trap 'rm -f "$tmp"' EXIT
{
	if [ -f "$conf" ]; then
		awk -v b="$begin" -v e="$end" '
		    $0 == b { skip = 1; next }
		    $0 == e { skip = 0; next }
		    skip { next }
		    /^[ \t]*WITH(OUT)?_(CONSOLE|WEBGPU)[ \t]*[?:!+]?=/ { next }
		    { print }' "$conf"
	fi
	echo "$begin"
	echo "$options" | while read -r name def desc; do
		if on "$name"; then
			[ "$def" = no ] && echo "WITH_${name}=	yes"
		else
			[ "$def" = yes ] && echo "WITHOUT_${name}=	yes"
		fi
	done
	echo "$end"
} > "$tmp" && mv "$tmp" "$conf" || exit 1
trap - EXIT

echo "make config: $conf"
ARC_TOP=$ARC_TOP CONSOLE=$(on CONSOLE && echo yes || echo no) \
    WEBGPU=$(on WEBGPU && echo yes || echo no) sh "$0" show
if on WEBGPU && on CONSOLE; then
	echo "WEBGPU needs Dawn's emdawnwebgpu: make depends fetches it."
fi
