#!/bin/sh
#
# What building Arcana needs, and whether this host has it:
#
#	deps.sh check		say each, and fail when one the build needs
#				is missing
#	deps.sh install		pkg install the packages missing
#
# Told by the environment (the top Makefile sets it): CONSOLE and TESTS
# (yes, no), LOCALBASE, LIBUCL_SRC, LIBYAML_SRC, EMDAWN, EMDAWN_DEFAULT,
# EMDAWN_ZIP.  What is
# installed is pkg(8)'s to say; a copy built by hand in a package's place
# (a file it would install, a command) counts too.

set -u

mode=${1:-check}
LOCALBASE=${LOCALBASE:-/usr/local}
CONSOLE=${CONSOLE:-yes}
TESTS=${TESTS:-no}

pkgs=""		# the packages missing, to install
other=""	# what is missing and is no package: what to do
fatal=0

say()
{
	printf '  %-9s %-16s %s\n' "$1" "$2" "$3"
}

# A package: its name, a file or a command it gives, what it is for, and
# whether the build stops without it (yes) or only some tests (no).
want()
{
	# pkg(8) says; a copy built by hand in its place counts too.
	if pkg info -e "$1" 2>/dev/null || [ -e "$2" ] || { case "$2" in
	    /*) false ;; *) command -v "$2" >/dev/null 2>&1 ;; esac; }; then
		say ok "$1" "$3"
		return
	fi
	say missing "$1" "$3"
	pkgs="$pkgs $1"
	[ "$4" = yes ] && fatal=1
}

# A library's source the page compiles to wasm: the system's, which
# pkgbase's FreeBSD-src installs, or a tree LIBUCL_SRC or LIBYAML_SRC
# names.
src()
{
	if [ -e "$2/$3" ]; then
		say ok "$1 source" "$2"
	elif [ "$2" = "/usr/src/contrib/$1" ]; then
		say missing "$1 source" "the system's: pkgbase's FreeBSD-src"
		case "$pkgs" in *FreeBSD-src*) ;; *) pkgs="$pkgs FreeBSD-src" ;; esac
		fatal=1
	else
		say missing "$1 source" "$2 is not $1's source tree"
		other="$other\n  $(echo "$1" | tr a-z A-Z)_SRC names no source tree: $2"
		fatal=1
	fi
}

# Dawn's emdawnwebgpu package, the map's WebGPU: a port file, the one
# "make depends" unpacks or one EMDAWN names, or emcc's own remote port,
# which fetches it.
emdawn()
{
	case "${EMDAWN:-}" in
	emdawnwebgpu)
		say ok emdawnwebgpu "fetched by emcc: needs the network"
		;;
	*)
		if [ -f "${EMDAWN:-}" ]; then
			say ok emdawnwebgpu "${EMDAWN}"
			return
		fi
		say missing emdawnwebgpu "the map's WebGPU (Dawn's package)"
		if [ "${EMDAWN:-}" = "${EMDAWN_DEFAULT:-}" ]; then
			other="$other\n  emdawnwebgpu: make depends fetches it (without the network, copy its zip to ${EMDAWN_ZIP:-} first)"
		else
			other="$other\n  EMDAWN names no port file: ${EMDAWN:-}"
		fi
		fatal=1
		;;
	esac
}

echo "Arcana's build needs, for the host's programs:"
want libcbor "$LOCALBASE/include/cbor.h" "CBOR for libcblink (devel/libcbor)" yes
want libyang3 "$LOCALBASE/include/libyang/libyang.h" \
    "YANG for cblink-gen, to build only (net/libyang3)" yes
if [ "$CONSOLE" = yes ]; then
	echo "for the console (WITHOUT_CONSOLE=yes builds without it):"
	want emscripten emcc "the page, C to WebAssembly (devel/emscripten)" yes
	want libwebsockets "$LOCALBASE/include/libwebsockets.h" \
	    "its HTTP server (net/libwebsockets)" yes
	src libucl "${LIBUCL_SRC:-}" src/ucl_parser.c
	src libyaml "${LIBYAML_SRC:-}" src/parser.c
	emdawn
fi
if [ "$TESTS" = yes ]; then
	echo "for make check (a test without its tool is skipped or fails):"
	want git git "the builds' and updates' tests (devel/git)" no
	want curl curl "the console's HTTP tests (ftp/curl)" no
	want python3 python3 "strict JSON checks (lang/python3)" no
	if [ "$CONSOLE" = yes ]; then
		want chromium chromedriver "the browser test (www/chromium)" no
	fi
fi

if [ "$mode" = install ]; then
	if [ -z "$pkgs" ]; then
		echo "No package is missing."
	elif [ "$(id -u)" != 0 ]; then
		echo "Installing packages takes root: run as root" \
		    "make install-missing-packages, or:"
		echo "  pkg install$pkgs"
		exit 1
	else
		# shellcheck disable=SC2086
		pkg install -y $pkgs || exit 1
		pkgs=""
	fi
fi
if [ -n "$pkgs" ]; then
	echo "Missing packages:$pkgs"
	echo "  pkg install$pkgs, or as root: make install-missing-packages"
fi
if [ -n "$other" ]; then
	printf 'Not packages:%b\n' "$other"
fi
if [ "$fatal" = 1 ] && [ "$mode" = check ]; then
	exit 1
fi
exit 0
