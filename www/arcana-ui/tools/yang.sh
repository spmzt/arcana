#!/bin/sh
#
# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
#
# The YANG model of each operation converted to YANG (share/arcana/
# yang-ops), as the console shows it beside the operation's CBOR schema.
#
#	yang.sh trees cblink-gen yang-dir yang-ops tree-dir
#		each module's RFC 8340 tree, as cblink-gen draws it, into
#		tree-dir/<module>.tree (make regen-yang: cblink-gen built
#		with libyang)
#	yang.sh json yang-ops tree-dir > yang.json
#		{ "ops": { "<op>": { "module", "revision", "tree" } } },
#		from the trees committed (the build: no libyang needed)

set -eu

case ${1:-} in
trees)
	gen=$2 dir=$3 map=$4 out=$5
	mkdir -p "$out"
	for m in $(awk '!/^#/ && NF == 2 { print $2 }' "$map" | sort -u); do
		"$gen" -m tree -b "${m%@*}" -o "$out" -p "$dir" \
		    "$dir/$m.yang" >/dev/null
	done
	;;
json)
	map=$2 trees=$3
	awk -v trees="$trees" '
	function esc(s) {
		gsub(/\\/, "\\\\", s)
		gsub(/"/, "\\\"", s)
		gsub(/\t/, "        ", s)
		return s
	}
	!/^#/ && NF == 2 {
		name = $2
		sub(/@.*/, "", name)
		rev = $2
		sub(/^[^@]*@/, "", rev)
		tree = ""
		f = trees "/" name ".tree"
		if ((getline line < f) <= 0) {
			print "yang.sh: no " f ": make regen-yang" > "/dev/stderr"
			exit 1
		}
		do
			tree = tree esc(line) "\\n"
		while ((getline line < f) > 0)
		close(f)
		ops[++n] = sprintf("\"%s\":{\"module\":\"%s\"," \
		    "\"revision\":\"%s\",\"tree\":\"%s\"}", esc($1),
		    esc(name), esc(rev), tree)
	}
	END {
		printf "{\"ops\":{"
		for (i = 1; i <= n; i++)
			printf "%s%s", (i > 1 ? "," : ""), ops[i]
		printf "}}\n"
	}' "$map"
	;;
*)
	echo "usage: yang.sh trees cblink-gen yang-dir yang-ops tree-dir" >&2
	echo "       yang.sh json yang-ops tree-dir" >&2
	exit 2
	;;
esac
