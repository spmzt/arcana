#!/bin/sh
#
# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
#
# Compile the YANG corpus with yanglint(1) of net/libyang3: every module
# on its own, its imports made implemented (-i), then all of them in one
# context.  A developer's check: building Arcana needs no libyang.

set -eu

cd "$(dirname "$0")"
command -v yanglint >/dev/null || { echo "lint.sh: no yanglint (net/libyang3)" >&2; exit 2; }
mains=$(grep -l '^module ' *.yang)
n=0
for f in $mains; do
	yanglint -i -p . "$f" || { echo "lint.sh: $f does not compile" >&2; exit 1; }
	n=$((n + 1))
done
yanglint -i -p . $mains
# Arcana's deviations hold: what FreeBSD sets for the whole host is no
# configuration of one interface.
d=$(mktemp -d)
trap 'rm -rf "$d"' EXIT
t=$d/ip.json
echo '{"ietf-interfaces:interfaces":{"interface":[{"name":"em0","type":"iana-if-type:ethernetCsmacd","ietf-ip:ipv4":{"forwarding":true}}]}}' > "$t"
yanglint -i -p . -t config ietf-interfaces@2018-02-20.yang \
    iana-if-type@2026-03-17.yang ietf-ip@2018-02-22.yang "$t" >/dev/null ||
    { echo "lint.sh: ietf-ip refuses its own forwarding" >&2; exit 1; }
if yanglint -i -p . -t config ietf-interfaces@2018-02-20.yang \
    iana-if-type@2026-03-17.yang ietf-ip@2018-02-22.yang \
    arcana-ip-deviations@2026-10-14.yang "$t" >/dev/null 2>&1; then
	echo "lint.sh: arcana-ip-deviations does not hold" >&2
	exit 1
fi
# arcana-network-instance's: a FIB cannot be disabled; an instance has no
# VSI root.  libyang keeps no empty mount point without schema-mount data,
# so each instance is refused for its root too: what is checked is the
# deviation's own word, there with the module and not without.
ni="ietf-interfaces@2018-02-20.yang ietf-ip@2018-02-22.yang ietf-network-instance@2019-01-21.yang"
echo '{"ietf-network-instance:network-instances":{"network-instance":[{"name":"blue","enabled":false,"vsi-root":{}}]}}' > "$d/ni.json"
with=$(yanglint -i -p . -t config $ni arcana-network-instance@2026-10-14.yang \
    "$d/ni.json" 2>&1 || true)
without=$(yanglint -i -p . -t config $ni "$d/ni.json" 2>&1 || true)
case $with in
*'"vsi-root" not found'*) ;;
*) echo "lint.sh: arcana-network-instance leaves vsi-root" >&2; exit 1 ;;
esac
case $without in
*'"vsi-root" not found'*) echo "lint.sh: no vsi-root without arcana-network-instance" >&2; exit 1 ;;
esac
echo '{"ietf-network-instance:network-instances":{"network-instance":[{"name":"blue","enabled":false,"vrf-root":{}}]}}' > "$d/ni.json"
case $(yanglint -i -p . -t config $ni arcana-network-instance@2026-10-14.yang \
    "$d/ni.json" 2>&1 || true) in
*'a FIB cannot be disabled'*) ;;
*) echo "lint.sh: arcana-network-instance lets a FIB be disabled" >&2; exit 1 ;;
esac
echo "$n modules compiled, alone and together ($(yanglint --version)); deviations hold"
