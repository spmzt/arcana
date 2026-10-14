#!/bin/sh
#
# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
#
# The YANG model of each operation converted to YANG, as the console
# shows it beside the operation's CBOR schema:
#
#	{ "ops": { "<op>": { "module", "revision", "tree" } } }
#
# the tree the module's RFC 8340 diagram, as cblink-gen draws it.
#
#	yang.sh cblink-gen yang-dir yang-ops work-dir > yang.json

set -eu
gen=$1 dir=$2 map=$3 work=$4

mkdir -p "$work"
# Each module's tree, once.
for m in $(awk '!/^#/ && NF == 2 { print $2 }' "$map" | sort -u); do
	"$gen" -m tree -b "${m%@*}" -o "$work" -p "$dir" "$dir/$m.yang" \
	    >/dev/null
done
awk -v work="$work" '
function esc(s) {
	gsub(/\\/, "\\\\", s)
	gsub(/"/, "\\\"", s)
	gsub(/\t/, "        ", s)
	return s
}
!/^#/ && NF == 2 {
	mod = $2
	name = mod
	sub(/@.*/, "", name)
	rev = mod
	sub(/^[^@]*@/, "", rev)
	tree = ""
	f = work "/" name ".tree"
	while ((getline line < f) > 0)
		tree = tree esc(line) "\\n"
	close(f)
	ops[++n] = sprintf("\"%s\":{\"module\":\"%s\",\"revision\":\"%s\"," \
	    "\"tree\":\"%s\"}", esc($1), esc(name), esc(rev), tree)
}
END {
	printf "{\"ops\":{"
	for (i = 1; i <= n; i++)
		printf "%s%s", (i > 1 ? "," : ""), ops[i]
	printf "}}\n"
}' "$map"
