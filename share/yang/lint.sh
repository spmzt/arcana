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
echo "$n modules compiled, alone and together ($(yanglint --version))"
