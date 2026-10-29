# A family spec (cluster.yaml) as its wire on cblink: the YANG module
# whose rpcs mirror the operations (out=yang), the C header that names
# the structs cblink-gen writes from that module as the programs call
# them (out=h), and the C glue between the programs' handlers and
# cblink (out=c).  A spec without operations (arcana.yaml) is no family:
# its module has the structures alone, its header their names and the
# definitions, and there is no glue.
#
#	awk -v out=yang -v rev=2026-10-22 -f wire.awk cluster.yaml > \
#	    arcana-cluster@2026-10-22.yang
#	awk -v out=h -v base=arcana_v2 -f wire.awk cluster.yaml > cluster.h
#	awk -v out=c -v side=both -f wire.awk cluster.yaml > cluster_wire.c
#
# side is server, client or both (out=c); base the name cblink-gen wrote
# the module's header and tables under (out=h, out=c: base.h).  The
# spec's own c-prefix (arc, acl) names what the programs call.
#
# Every attribute set of the spec is a grouping, and one used as a
# nested attribute carries cg:struct, so that cblink-gen writes one
# struct for it wherever it is used (step, job, host...); each
# operation is an rpc whose input and output use the family set's
# attributes one grouping each; a dump's forms are an rpc of their own;
# an event is a structure of its multicast group; a stream's payload is
# a structure, and so is a set with "structure: true" that no operation
# carries, kept for the programs' own use (the agent's jobs).  Enums
# travel as uint8 with their names in the description, so that the C
# member stays a uint8_t.

function die(msg) {
	printf "wire.awk: %s\n", msg > "/dev/stderr"
	exit 1
}

function ystr(s) {
	gsub(/\\/, "\\\\", s)
	gsub(/"/, "\\\"", s)
	return "\"" s "\""
}

# A spec name (net-kind) as C (net_kind), upper too.
function cname(s) {
	gsub(/[-.]/, "_", s)
	return s
}

function uname(s) {
	return toupper(cname(s))
}

# The struct a set is, by its name: the name, but where the module
# arcana-<name>'s data struct is struct arcana_<name> already (the
# standard models' tables, share/mk/arcana.yang.mk, are built in the
# same programs): host is struct arcana_host_info.
function sname(s) {
	return s == "host" ? "host-info" : s
}

function value(line) {
	sub(/^[^:]*:[ \t]*/, "", line)
	sub(/[ \t]+$/, "", line)
	return line
}

function indent(line,    i) {
	match(line, /^ */)
	return RLENGTH
}

# A YANG description from a doc, at indent ind: the text as it is,
# quoted, lines joined.
function ydesc(doc, ind,    n, i, a, out) {
	if (doc == "")
		return
	n = split(doc, a, "\n")
	out = ""
	for (i = 1; i <= n; i++) {
		if (a[i] == "" && i == n)
			break
		out = out (i > 1 ? "\n" ind "   " : "") a[i]
	}
	gsub(/\\/, "\\\\", out)
	gsub(/"/, "\\\"", out)
	printf "%sdescription\n%s  \"%s\";\n", ind, ind, out
}

# ---- The spec, read ------------------------------------------------

# Sections: definitions, attribute-sets, operations, mcast-groups,
# streams.  Lists at indent 2 ("  - name:"); what is under an item at
# 4; the attributes of a set at 6 with their properties at 8; an
# operation's do/dump/event at 4, request/reply at 6, their lists at 8,
# the names at 10.
{
	line = $0
	sub(/\r$/, "", line)
	if (docind >= 0) {
		if (line == "" || indent(line) > docind) {
			t = line
			if (t != "")
				t = substr(t, docind + 3)
			doc = doc (doc == "" && t == "" ? "" : t "\n")
			next
		}
		docind = -1
		docs[dockey] = doc
	}
	if (line ~ /^[ \t]*#/ || line ~ /^---/ || line ~ /^[ \t]*$/)
		next
	ind = indent(line)
	key = line
	sub(/^ */, "", key)
	sub(/:.*/, "", key)
	if (ind == 0) {
		section = key
		if (key == "name")
			spec = value(line)
		else if (key == "version")
			specver = value(line)
		else if (key == "c-prefix")
			pfx = value(line)
		else if (key == "doc") {
			docind = 0
			dockey = "spec"
			doc = ""
		}
		next
	}
	if (section == "definitions") {
		if (ind == 2 && key == "- name") {
			defcur = value(line)
			ndef++
			defname[ndef] = defcur
		} else if (ind == 4 && key == "type")
			deftype[defcur] = value(line)
		else if (ind == 4 && key == "value")
			defval[defcur] = value(line)
		else if (ind == 4 && key == "doc") {
			if (line ~ /\|[ \t]*$/) {
				docind = 4
				dockey = "def:" defcur
				doc = ""
			} else
				docs["def:" defcur] = value(line)
		} else if (ind == 6 && line ~ /^      - name:/) {
			entcur = value(line)
			nent[defcur]++
			ent[defcur, nent[defcur]] = entcur
		} else if (ind == 6 && line ~ /^      - /) {
			entcur = line
			sub(/^      - /, "", entcur)
			nent[defcur]++
			ent[defcur, nent[defcur]] = entcur
		} else if (ind == 8 && key == "doc") {
			if (line ~ /\|[ \t]*$/) {
				docind = 8
				dockey = "ent:" defcur ":" entcur
				doc = ""
			} else
				docs["ent:" defcur ":" entcur] = value(line)
		}
		next
	}
	if (section == "attribute-sets") {
		if (ind == 2 && key == "- name") {
			setcur = value(line)
			nset++
			setname[nset] = setcur
			nattr[setcur] = 0
		} else if (ind == 4 && key == "structure")
			setkept[setcur] = value(line) == "true"
		else if (ind == 4 && key == "doc") {
			if (line ~ /\|[ \t]*$/) {
				docind = 4
				dockey = "set:" setcur
				doc = ""
			} else
				docs["set:" setcur] = value(line)
		} else if (ind == 6 && key == "- name") {
			acur = value(line)
			nattr[setcur]++
			attr[setcur, nattr[setcur]] = acur
			ak = setcur ":" acur
			atype[ak] = ""
			aenum[ak] = ""
			anest[ak] = ""
			amulti[ak] = 0
		} else if (ind == 8 && key == "type")
			atype[ak] = value(line)
		else if (ind == 8 && key == "enum")
			aenum[ak] = value(line)
		else if (ind == 8 && key == "nested-attributes")
			anest[ak] = value(line)
		else if (ind == 8 && key == "multi-attr")
			amulti[ak] = value(line) == "true"
		else if (ind == 8 && key == "doc") {
			if (line ~ /\|[ \t]*$/) {
				docind = 8
				dockey = "attr:" ak
				doc = ""
			} else
				docs["attr:" ak] = value(line)
		} else if (ind == 10)
			achk[ak, key] = value(line)
		next
	}
	if (section == "operations") {
		if (ind == 2 && key == "- name") {
			opcur = value(line)
			nop++
			opname[nop] = opcur
			opform = ""
			opauth[opcur] = 0
		} else if (ind == 4 && key == "retired")
			opretired[opcur] = value(line) == "true"
		else if (ind == 4 && key == "auth")
			opauth[opcur] = value(line) == "true"
		else if (ind == 4 && key == "mcgrp")
			opgrp[opcur] = value(line)
		else if (ind == 4 && key == "attribute-set")
			opset[opcur] = value(line)
		else if (ind == 4 && key == "doc") {
			if (line ~ /\|[ \t]*$/) {
				docind = 4
				dockey = "op:" opcur
				doc = ""
			} else
				docs["op:" opcur] = value(line)
		} else if (ind == 4 && (key == "do" || key == "dump" ||
		    key == "event")) {
			opform = key
			opforms[opcur, key] = 1
			if (key == "event")
				opdir = "event"
		} else if (ind == 6 && (key == "request" || key == "reply"))
			opdir = key
		else if (ind == 6 && key == "attributes" && opform == "event")
			oplist = "attrs"
		else if (ind == 8 && key == "attributes")
			oplist = "attrs"
		else if (ind == 8 && key == "required")
			oplist = "req"
		else if ((ind == 10 || (ind == 8 && opform == "event")) &&
		    line ~ /^ *- /) {
			v = line
			sub(/^ *- /, "", v)
			k = opcur ":" opform ":" opdir ":" oplist
			n = ++opn[k]
			opa[k, n] = v
		}
		next
	}
	if (section == "mcast-groups") {
		if (ind == 2 && key == "- name") {
			grpcur = value(line)
			ngrp++
			grpname[ngrp] = grpcur
		} else if (ind == 4 && key == "auth")
			grpauth[grpcur] = value(line) == "true"
		next
	}
	if (section == "streams") {
		if (ind == 2 && key == "- name") {
			stcur = value(line)
			nst++
			stname[nst] = stcur
		} else if (ind == 4)
			stprop[stcur, key] = value(line)
		next
	}
}

# ---- What the spec comes to ----------------------------------------

# The value a check names: a number, or a const's.
function cval(v) {
	if (v ~ /^[0-9]+$/)
		return v
	if (deftype[v] == "const")
		return defval[v]
	die("no such const: " v)
}

# The command number of an operation: its place among the operations,
# from 1, events counted (an event's is its notification's command).  A
# retired one keeps its place, nothing made of it, so that no command
# after it moves: an agent and a console of different releases then
# still agree on every command both have (agent-update among them).
function cmd_of(op,    i) {
	for (i = 1; i <= nop; i++)
		if (opname[i] == op)
			return i
	die("no command for " op)
}

# The set's attributes used as nests, and the sets used as stream
# payloads: those with a struct.
function mark_structs(    i, j, s, ak) {
	for (i = 1; i <= nset; i++) {
		s = setname[i]
		for (j = 1; j <= nattr[s]; j++) {
			ak = s ":" attr[s, j]
			if (atype[ak] == "nest")
				isstruct[anest[ak]] = 1
		}
	}
	for (i = 1; i <= nst; i++)
		isstruct[stprop[stname[i], "payload"]] = 1
	for (i = 1; i <= nset; i++)
		if (setkept[setname[i]])
			isstruct[setname[i]] = 1
}

# Has the spec a dump form of any operation?
function has_dumps(    i) {
	for (i = 1; i <= nop; i++)
		if (opforms[opname[i], "dump"])
			return 1
	return 0
}

# The operation a stream opens, by its name, or "".
function stream_of(op,    i) {
	for (i = 1; i <= nst; i++)
		if (stprop[stname[i], "open"] == op)
			return stname[i]
	return ""
}

# ---- out=yang --------------------------------------------------------

# One attribute as a YANG node at indent ind.
function ynode(s, a, ind,    ak, t, e, n, i, desc, lo, hi, yt) {
	ak = s ":" a
	t = atype[ak]
	desc = docs["attr:" ak]
	if (t == "nest") {
		if (amulti[ak]) {
			printf "%slist %s {\n", ind, a
			printf "%s  cg:struct %s;\n", ind, ystr(sname(anest[ak]))
			if ((ak, "max-count") in achk)
				printf "%s  max-elements %s;\n", ind,
				    cval(achk[ak, "max-count"])
			if ((ak, "min-count") in achk)
				printf "%s  min-elements %s;\n", ind,
				    cval(achk[ak, "min-count"])
		} else {
			printf "%scontainer %s {\n", ind, a
			printf "%s  cg:struct %s;\n", ind, ystr(sname(anest[ak]))
		}
		ydesc(desc, ind "  ")
		printf "%s  uses set-%s;\n", ind, anest[ak]
		printf "%s}\n", ind
		return
	}
	printf "%s%s %s {\n", ind, amulti[ak] ? "leaf-list" : "leaf", a
	if (t == "text") {
		lo = (ak, "min-len") in achk ? cval(achk[ak, "min-len"]) : 0
		hi = (ak, "max-len") in achk ? cval(achk[ak, "max-len"]) : ""
		if (hi != "")
			printf "%s  type string {\n%s    length \"%s..%s\";\n%s  }\n",
			    ind, ind, lo, hi, ind
		else if (lo > 0)
			printf "%s  type string {\n%s    length \"%s..max\";\n%s  }\n",
			    ind, ind, lo, ind
		else
			printf "%s  type string;\n", ind
	} else if (t == "bytes") {
		if ((ak, "max-len") in achk)
			printf "%s  type binary {\n%s    length \"0..%s\";\n%s  }\n",
			    ind, ind, cval(achk[ak, "max-len"]), ind
		else
			printf "%s  type binary;\n", ind
	} else if (t == "flag")
		printf "%s  type empty;\n", ind
	else if (t == "bool")
		printf "%s  type boolean;\n", ind
	else if (t == "float")
		printf "%s  type decimal64 {\n%s    fraction-digits 2;\n%s  }\n",
		    ind, ind, ind
	else if (t == "u8" || t == "u32" || t == "u64" || t == "s32" ||
	    t == "s64") {
		if (aenum[ak] != "") {
			e = aenum[ak]
			printf "%s  type uint8 {\n%s    range \"0..%d\";\n%s  }\n",
			    ind, ind, nent[e] - 1, ind
			desc = desc (desc == "" ? "" : "\n") "One of " e ":"
			for (i = 1; i <= nent[e]; i++)
				desc = desc " " (i - 1) " " ent[e, i]
			desc = desc "."
		} else {
			lo = (ak, "min") in achk ? cval(achk[ak, "min"]) : ""
			hi = (ak, "max") in achk ? cval(achk[ak, "max"]) : ""
			yt = t == "u8" ? "uint8" : t == "u32" ? "uint32" : t == "u64" ? "uint64" : t == "s32" ? "int32" : "int64"
			if (lo == "" && hi == "")
				printf "%s  type %s;\n", ind, yt
			else
				printf "%s  type %s {\n%s    range \"%s..%s\";\n%s  }\n",
				    ind, yt, ind, (lo == "" ? "min" : lo), (hi == "" ? "max" : hi),
				    ind
		}
	} else
		die("attribute " ak ": type " t)
	if (amulti[ak] && (ak, "max-count") in achk)
		printf "%s  max-elements %s;\n", ind, cval(achk[ak, "max-count"])
	if (amulti[ak] && (ak, "min-count") in achk)
		printf "%s  min-elements %s;\n", ind, cval(achk[ak, "min-count"])
	ydesc(desc, ind "  ")
	printf "%s}\n", ind
}

# An rpc's input or output: the family set's attributes, one grouping
# each, the required ones refined.
function yio(op, form, dir, what,    k, rk, n, i, j, a, req, ak) {
	k = op ":" form ":" dir ":attrs"
	rk = op ":" form ":" dir ":req"
	if (opn[k] == 0)
		return
	printf "    %s {\n", what
	for (i = 1; i <= opn[k]; i++) {
		a = opa[k, i]
		req = 0
		for (j = 1; j <= opn[rk]; j++)
			if (opa[rk, j] == a)
				req = 1
		ak = opset[op] ":" a
		if (!(ak in atype))
			die(op ": no attribute " a " in set " opset[op])
		if (!req)
			printf "      uses attr-%s;\n", a
		else if (atype[ak] == "nest" && amulti[ak])
			printf "      uses attr-%s {\n        refine %s {\n          min-elements 1;\n        }\n      }\n",
			    a, a
		else if (atype[ak] == "nest")
			printf "      uses attr-%s;\n", a
		else if (amulti[ak])
			printf "      uses attr-%s {\n        refine %s {\n          min-elements 1;\n        }\n      }\n",
			    a, a
		else
			printf "      uses attr-%s {\n        refine %s {\n          mandatory true;\n        }\n      }\n",
			    a, a
	}
	printf "    }\n"
}

function out_yang(    i, j, s, op, famset, st, cmd) {
	mark_structs()
	printf "module %s {\n", spec
	printf "  yang-version 1.1;\n"
	printf "  namespace \"urn:arcana:yang:%s\";\n", spec
	printf "  prefix %s;\n\n", pfx
	printf "  import cblink-gen {\n    prefix cg;\n  }\n"
	printf "  import ietf-yang-structure-ext {\n    prefix sx;\n  }\n"
	if (nop > 0)
		printf "  import arcana-family {\n    prefix fam;\n  }\n"
	printf "\n"
	printf "  organization\n    \"Arcana\";\n"
	printf "  contact\n    \"Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>\";\n"
	ydesc(docs["spec"] "\nWritten by share/arcana/wire.awk from share/arcana/" \
	    spec ".yaml: " (nop > 0 ? "the operations of the family spec as " \
	    "rpcs, on wire version 2" : "the structures the programs keep") \
	    ".  Do not edit.", "  ")
	printf "\n  revision %s {\n    description\n      \"From the spec as of this day.\";\n  }\n\n",
	    rev
	if (nop > 0)
		printf "  fam:family %s;\n  fam:version 2;\n\n", ystr(spec)
	# The consts, said.
	for (i = 1; i <= ndef; i++)
		if (deftype[defname[i]] == "const")
			printf "  // %s = %s\n", defname[i], defval[defname[i]]
	printf "\n"
	# The sets: a grouping each, the family set's attributes one each.
	for (i = 1; i <= nset; i++) {
		s = setname[i]
		printf "  grouping set-%s {\n", s
		ydesc(docs["set:" s], "    ")
		for (j = 1; j <= nattr[s]; j++)
			ynode(s, attr[s, j], "    ")
		printf "  }\n\n"
	}
	famset = ""
	for (i = 1; i <= nop; i++)
		if (opset[opname[i]] != "")
			famset = opset[opname[i]]
	if (famset == "" && nop > 0)
		die("no family set: no operation names an attribute set")
	for (j = 1; j <= nattr[famset]; j++) {
		printf "  grouping attr-%s {\n", attr[famset, j]
		ynode(famset, attr[famset, j], "    ")
		printf "  }\n\n"
	}
	# The operations.
	for (i = 1; i <= nop; i++) {
		op = opname[i]
		if (opretired[op])
			continue
		if (opforms[op, "event"]) {
			printf "  sx:structure %s-ntf {\n", op
			printf "    fam:command %d;\n", cmd_of(op)
			printf "    fam:group %s;\n", ystr(opgrp[op])
			ydesc(docs["op:" op], "    ")
			for (j = 1; j <= opn[op ":event:event:attrs"]; j++)
				printf "    uses attr-%s;\n", opa[op ":event:event:attrs", j]
			printf "  }\n\n"
			continue
		}
		cmd = cmd_of(op)
		if (opforms[op, "do"]) {
			printf "  rpc %s {\n", op
			printf "    fam:command %d;\n", cmd
			if (opauth[op])
				printf "    fam:auth;\n"
			st = stream_of(op)
			if (st != "") {
				printf "    fam:stream %s;\n", ystr(stprop[st, "payload"])
				printf "    fam:credit %s;\n", stprop[st, "initial-credit"]
			}
			ydesc(docs["op:" op], "    ")
			yio(op, "do", "request", "input")
			yio(op, "do", "reply", "output")
			printf "  }\n\n"
		}
		if (opforms[op, "dump"]) {
			printf "  rpc %s-dump {\n", op
			printf "    fam:command %d;\n", cmd
			if (opauth[op])
				printf "    fam:auth;\n"
			printf "    fam:dump %s;\n", ystr(op)
			ydesc("The dump form of " op ": each item of the dump is one output.", "    ")
			yio(op, "dump", "request", "input")
			yio(op, "dump", "reply", "output")
			printf "  }\n\n"
		}
	}
	# The streams' payloads.
	for (i = 1; i <= nst; i++) {
		s = stprop[stname[i], "payload"]
		if (done[s])
			continue
		done[s] = 1
		printf "  sx:structure %s {\n", s
		printf "    cg:struct %s;\n", ystr(sname(s))
		ydesc("A data message of a stream of " s "s.", "    ")
		printf "    uses set-%s;\n", s
		printf "  }\n\n"
	}
	# The sets kept for the programs' own use.
	for (i = 1; i <= nset; i++) {
		s = setname[i]
		if (!setkept[s] || done[s])
			continue
		done[s] = 1
		printf "  sx:structure %s {\n", s
		printf "    cg:struct %s;\n", ystr(sname(s))
		ydesc(docs["set:" s], "    ")
		printf "    uses set-%s;\n", s
		printf "  }\n\n"
	}
	printf "}\n"
}

# ---- out=h: the programs' names over the generated structs ----------

function out_h(    i, j, s, op, e, u, d, famset, st) {
	mark_structs()
	u = uname(pfx)
	printf "/*\n * Written by share/arcana/wire.awk from share/arcana/%s.yaml: the\n * names the programs use over the structs cblink-gen writes from the\n * module (%s.h).  Do not edit.\n */\n\n",
	    spec, base
	printf "#ifndef _%s_WIRE_H_\n#define\t_%s_WIRE_H_\n\n", u, u
	printf "#include <cbl_schema.h>\n#include <cblink.h>\n\n#include \"%s.h\"\n\n", base
	if (nop > 0)
		printf "#define\t%s_FAMILY_NAME\t%s\n#define\t%s_FAMILY_VERSION\t2\n\n",
		    u, ystr(spec), u
	for (i = 1; i <= ndef; i++) {
		d = defname[i]
		if (deftype[d] == "const")
			printf "#define\t%s_%s\t%s\n", u, uname(d), defval[d]
	}
	printf "\n"
	for (i = 1; i <= ndef; i++) {
		d = defname[i]
		if (deftype[d] != "enum")
			continue
		printf "/* %s */\n", d
		for (j = 1; j <= nent[d]; j++)
			printf "#define\t%s_%s_%s\t%d\n", u, uname(d), uname(ent[d, j]),
			    j - 1
		printf "#define\t%s_%s_COUNT\t%d\n\n", u, uname(d), nent[d]
	}
	if (nop > 0) {
		printf "/* The commands, as the frames carry them; an event's is its\n * notification's. */\n"
		for (i = 1; i <= nop; i++) {
			op = opname[i]
			if (opretired[op])
				continue
			printf "#define\t%s_CMD_%s\t%d\n", u, uname(op), cmd_of(op)
		}
		printf "\n/* The multicast groups, by their place in the family. */\n"
		printf "enum {\n"
		for (i = 1; i <= ngrp; i++)
			printf "\t%s_MCGRP_%s%s,\n", u, uname(grpname[i]), (i == 1 ? " = 0" : "")
		printf "\t%s_MCGRP_COUNT\n};\n\n", u
	}
	printf "/* The structs, by the programs' names. */\n"
	for (i = 1; i <= nset; i++) {
		s = setname[i]
		if (!isstruct[s])
			continue
		printf "#define\t%s_%s\t%s_%s\n", pfx, cname(s), cname(spec),
		    cname(sname(s))
		printf "#define\t%s_%s_put_fields\t%s_%s_put\n", pfx, cname(s),
		    cname(spec), cname(sname(s))
	}
	for (i = 1; i <= nop; i++) {
		op = opname[i]
		if (opretired[op])
			continue
		if (opforms[op, "event"]) {
			printf "#define\t%s_%s_ntf\t%s_%s_ntf\n", pfx, cname(op),
			    cname(spec), cname(op)
			printf "#define\t%s_%s_ntf_put_fields\t%s_%s_ntf_put\n", pfx,
			    cname(op), cname(spec), cname(op)
			continue
		}
		if (opforms[op, "do"]) {
			if (opn[op ":do:request:attrs"] > 0) {
				printf "#define\t%s_%s_req\t%s_%s_input\n", pfx, cname(op),
				    cname(spec), cname(op)
				printf "#define\t%s_%s_req_put_fields\t%s_%s_input_put\n",
				    pfx, cname(op), cname(spec), cname(op)
			}
			printf "#define\t%s_%s_rsp\t%s_%s_output\n", pfx, cname(op),
			    cname(spec), cname(op)
			printf "#define\t%s_%s_rsp_put_fields\t%s_%s_output_put\n", pfx,
			    cname(op), cname(spec), cname(op)
		}
		if (opforms[op, "dump"]) {
			printf "#define\t%s_%s_dump_req\t%s_%s_dump_input\n", pfx,
			    cname(op), cname(spec), cname(op)
			printf "#define\t%s_%s_dump_rsp\t%s_%s_dump_output\n", pfx,
			    cname(op), cname(spec), cname(op)
		}
	}
	if (nop == 0) {
		printf "\n#endif /* !_%s_WIRE_H_ */\n", u
		return
	}
	printf "\n/* ---- The server: the handlers the program defines, the replies ---- */\n\n"
	printf "extern const struct cbl_family_def %s_family_def;\n", pfx
	printf "int\t%s_register(cbl_ctx *, void *, cbl_family **);\n\n", pfx
	for (i = 1; i <= nop; i++) {
		op = opname[i]
		if (opretired[op])
			continue
		if (opforms[op, "event"]) {
			printf "int\t%s_%s_notify(cbl_family *, const struct %s_%s_ntf *);\n",
			    pfx, cname(op), pfx, cname(op)
			continue
		}
		if (opforms[op, "do"]) {
			st = stream_of(op)
			if (st != "") {
				printf "int\t%s_%s_stream_open(cbl_req *, const struct %s_%s_req *,\n\t    cbl_stream *, void *);\n",
				    pfx, cname(op), pfx, cname(op)
				printf "struct %s_%s_server_cbs {\n", pfx, cname(op)
				printf "\tvoid\t(*on_data)(cbl_stream *, const struct %s_%s *, void *);\n",
				    pfx, cname(stprop[st, "payload"])
				printf "\tvoid\t(*on_hclose)(cbl_stream *, void *);\n"
				printf "\tvoid\t(*on_close)(cbl_stream *, int, const char *, void *);\n"
				printf "\tvoid\t(*on_writable)(cbl_stream *, size_t, void *);\n};\n"
				printf "int\t%s_%s_accept(cbl_stream *, const struct %s_%s_rsp *,\n\t    const struct %s_%s_server_cbs *, void *);\n",
				    pfx, cname(op), pfx, cname(op), pfx, cname(op)
				printf "int\t%s_%s_server_send(cbl_stream *, const struct %s_%s *);\n",
				    pfx, cname(op), pfx, cname(stprop[st, "payload"])
			} else if (opn[op ":do:request:attrs"] > 0)
				printf "int\t%s_%s_doit(cbl_req *, const struct %s_%s_req *, void *);\n",
				    pfx, cname(op), pfx, cname(op)
			else
				printf "int\t%s_%s_doit(cbl_req *, void *);\n", pfx, cname(op)
			printf "int\t%s_%s_reply(cbl_req *, const struct %s_%s_rsp *);\n",
			    pfx, cname(op), pfx, cname(op)
		}
		if (opforms[op, "dump"]) {
			printf "int\t%s_%s_dumpit(cbl_req *, const struct %s_%s_dump_req *,\n\t    struct cbl_dump_state *, void *);\n",
			    pfx, cname(op), pfx, cname(op)
			printf "int\t%s_%s_dump_reply(cbl_req *, const struct %s_%s_dump_rsp *);\n",
			    pfx, cname(op), pfx, cname(op)
		}
	}
	printf "\n/* ---- The client ---------------------------------------------- */\n\n"
	printf "struct %s_client {\n\tcbl_conn\t*conn;\n\tuint16_t\t family;\n\tuint32_t\t version;\n\tuint32_t\t groups[%s_MCGRP_COUNT > 0 ? %s_MCGRP_COUNT : 1];\n\tcbl_msg\t\t*err;\t/* ERROR of the last failed call */\n\tint\t\t timeout_ms;\t/* a call's longest wait; 0 none */\n};\n\n",
	    pfx, u, u
	printf "int\t%s_client_init(struct %s_client *, cbl_conn *);\n", pfx, pfx
	printf "int\t%s_client_init_info(struct %s_client *, cbl_conn *,\n\t    const cbl_family_info *);\n",
	    pfx, pfx
	printf "void\t%s_client_fini(struct %s_client *);\n\n", pfx, pfx
	for (i = 1; i <= nop; i++) {
		op = opname[i]
		if (opretired[op])
			continue
		if (opforms[op, "event"]) {
			printf "struct %s_%s_handlers {\n\tvoid\t(*%s)(const struct %s_%s_ntf *, void *);\n};\n",
			    pfx, cname(opgrp[op]), cname(op), pfx, cname(op)
			printf "int\t%s_%s_subscribe(struct %s_client *,\n\t    const struct %s_%s_handlers *, void *, cbl_sub **);\n",
			    pfx, cname(opgrp[op]), pfx, pfx, cname(opgrp[op])
			printf "int\t%s_%s_unsubscribe(cbl_sub *);\n", pfx, cname(opgrp[op])
			continue
		}
		if (opforms[op, "do"] && stream_of(op) != "")
			printf "int\t%s_%s_send(cbl_stream *, const struct %s_%s *);\n", pfx,
			    cname(op), pfx, cname(stprop[stream_of(op), "payload"])
		if (opforms[op, "do"] && stream_of(op) == "") {
			if (opn[op ":do:request:attrs"] > 0)
				printf "int\t%s_%s(struct %s_client *, const struct %s_%s_req *,\n\t    struct %s_%s_rsp **);\n",
				    pfx, cname(op), pfx, pfx, cname(op), pfx, cname(op)
			else
				printf "int\t%s_%s(struct %s_client *, struct %s_%s_rsp **);\n",
				    pfx, cname(op), pfx, pfx, cname(op)
			printf "void\t%s_%s_rsp_free(struct %s_%s_rsp *);\n", pfx, cname(op),
			    pfx, cname(op)
		}
		if (opforms[op, "dump"]) {
			printf "int\t%s_%s_dump(struct %s_client *, const struct %s_%s_dump_req *,\n\t    cbl_dump **);\n",
			    pfx, cname(op), pfx, pfx, cname(op)
			printf "int\t%s_%s_dump_next(cbl_dump *, struct %s_%s_dump_rsp **);\n",
			    pfx, cname(op), pfx, cname(op)
		}
	}
	if (has_dumps())
		printf "/* The items a dump gave, forgotten with it. */\nvoid\t%s_dump_free(cbl_dump *);\n\n",
		    pfx
	printf "#endif /* !_%s_WIRE_H_ */\n", u
}

# ---- out=c: the glue --------------------------------------------------

function out_c_server(    i, op, u, st, pl, n) {
	u = uname(pfx)
	printf "/* ---- The server ----------------------------------------------- */\n\n"
	for (i = 1; i <= nop; i++) {
		op = opname[i]
		if (opretired[op])
			continue
		if (opforms[op, "event"]) {
			printf "int\n%s_%s_notify(cbl_family *fam, const struct %s_%s_ntf *ntf)\n{\n\tcbl_msg *msg;\n\tint error;\n\n",
			    pfx, cname(op), pfx, cname(op)
			printf "\tif ((error = cbl_notify_msg_new(fam, %s_CMD_%s, &msg)) != 0)\n\t\treturn (error);\n",
			    u, uname(op)
			printf "\tif ((error = %s_%s_ntf_put(msg, ntf)) != 0) {\n\t\tcbl_msg_free(msg);\n\t\treturn (error);\n\t}\n",
			    cname(spec), cname(op)
			printf "\treturn (cbl_notify(fam, %s_MCGRP_%s, msg));\n}\n\n", u,
			    uname(opgrp[op])
			continue
		}
		if (opforms[op, "do"]) {
			st = stream_of(op)
			if (st == "") {
				printf "static int\n%s__%s_doit(cbl_req *req, const cbl_msg *msg, void *arg)\n{\n",
				    pfx, cname(op)
				if (opn[op ":do:request:attrs"] > 0) {
					printf "\tstruct %s_%s_req in;\n\tcbl_yarena *a;\n\tchar why[256];\n\tint error;\n\n",
					    pfx, cname(op)
					printf "\tif ((a = cbl_yarena_new()) == NULL)\n\t\treturn (ENOMEM);\n"
					printf "\tif (%s_%s_input_parse(msg, &in, a, CBL_YD_STRICT, why,\n\t    sizeof(why)) != 0) {\n\t\t(void)cbl_req_set_err(req, why, NULL, 0, -1);\n\t\tcbl_yarena_free(a);\n\t\treturn (EINVAL);\n\t}\n",
					    cname(spec), cname(op)
					printf "\terror = %s_%s_doit(req, &in, arg);\n\tcbl_yarena_free(a);\n\treturn (error);\n}\n\n",
					    pfx, cname(op)
				} else
					printf "\n\t(void)msg;\n\treturn (%s_%s_doit(req, arg));\n}\n\n",
					    pfx, cname(op)
			} else {
				pl = stprop[st, "payload"]
				printf "static int\n%s__%s_sopen(cbl_req *req, const cbl_msg *msg, cbl_stream *s,\n    void *arg)\n{\n",
				    pfx, cname(op)
				printf "\tstruct %s_%s_req in;\n\tcbl_yarena *a;\n\tchar why[256];\n\tint error;\n\n",
				    pfx, cname(op)
				printf "\tif ((a = cbl_yarena_new()) == NULL)\n\t\treturn (ENOMEM);\n"
				printf "\tif (%s_%s_input_parse(msg, &in, a, CBL_YD_STRICT, why,\n\t    sizeof(why)) != 0) {\n\t\t(void)cbl_req_set_err(req, why, NULL, 0, -1);\n\t\tcbl_yarena_free(a);\n\t\treturn (EINVAL);\n\t}\n",
				    cname(spec), cname(op)
				printf "\terror = %s_%s_stream_open(req, &in, s, arg);\n\tcbl_yarena_free(a);\n\treturn (error);\n}\n\n",
				    pfx, cname(op)
				# The accept, and the data callbacks typed.
				printf "struct %s__%s_sctx {\n\tstruct %s_%s_server_cbs cbs;\n\tvoid\t*arg;\n};\n\n",
				    pfx, cname(op), pfx, cname(op)
				printf "static void\n%s__%s_s_on_data(cbl_stream *s, cbl_msg *data, void *arg)\n{\n\tstruct %s__%s_sctx *c = arg;\n\tstruct %s_%s d;\n\tcbl_yarena *a;\n\n",
				    pfx, cname(op), pfx, cname(op), pfx, cname(pl)
				printf "\tif ((a = cbl_yarena_new()) == NULL) {\n\t\t(void)cbl_stream_reset(s, ENOMEM);\n\t\treturn;\n\t}\n"
				printf "\tif (%s_%s_parse(data, &d, a, CBL_YD_STRICT, NULL, 0) != 0) {\n\t\tcbl_yarena_free(a);\n\t\t(void)cbl_stream_reset(s, EBADMSG);\n\t\treturn;\n\t}\n",
				    cname(spec), cname(pl)
				printf "\tif (c->cbs.on_data != NULL)\n\t\tc->cbs.on_data(s, &d, c->arg);\n\tcbl_yarena_free(a);\n}\n\n"
				printf "static void\n%s__%s_s_on_hclose(cbl_stream *s, void *arg)\n{\n\tstruct %s__%s_sctx *c = arg;\n\n\tif (c->cbs.on_hclose != NULL)\n\t\tc->cbs.on_hclose(s, c->arg);\n}\n\n",
				    pfx, cname(op), pfx, cname(op)
				printf "static void\n%s__%s_s_on_close(cbl_stream *s, int code, const char *text,\n    void *arg)\n{\n\tstruct %s__%s_sctx *c = arg;\n\n\tif (c->cbs.on_close != NULL)\n\t\tc->cbs.on_close(s, code, text, c->arg);\n\tfree(c);\n}\n\n",
				    pfx, cname(op), pfx, cname(op)
				printf "static void\n%s__%s_s_on_writable(cbl_stream *s, size_t credit, void *arg)\n{\n\tstruct %s__%s_sctx *c = arg;\n\n\tif (c->cbs.on_writable != NULL)\n\t\tc->cbs.on_writable(s, credit, c->arg);\n}\n\n",
				    pfx, cname(op), pfx, cname(op)
				printf "static const struct cbl_stream_cbs %s__%s_stramp = {\n\t.on_data = %s__%s_s_on_data,\n\t.on_hclose = %s__%s_s_on_hclose,\n\t.on_close = %s__%s_s_on_close,\n\t.on_writable = %s__%s_s_on_writable,\n};\n\n",
				    pfx, cname(op), pfx, cname(op), pfx, cname(op), pfx,
				    cname(op), pfx, cname(op)
				printf "int\n%s_%s_accept(cbl_stream *s, const struct %s_%s_rsp *accept,\n    const struct %s_%s_server_cbs *cbs, void *arg)\n{\n\tstruct %s__%s_sctx *c;\n\tcbl_msg *msg;\n\tint error;\n\n",
				    pfx, cname(op), pfx, cname(op), pfx, cname(op), pfx,
				    cname(op)
				printf "\tif ((error = cbl_stream_msg_new(s, &msg)) != 0)\n\t\treturn (error);\n"
				printf "\tif (accept != NULL && (error = %s_%s_output_put(msg, accept)) !=\n\t    0) {\n\t\tcbl_msg_free(msg);\n\t\treturn (error);\n\t}\n",
				    cname(spec), cname(op)
				printf "\t(void)cbl_msg_set_window(msg, %s);\n", stprop[st, "initial-credit"]
				printf "\tif ((c = calloc(1, sizeof(*c))) == NULL) {\n\t\tcbl_msg_free(msg);\n\t\treturn (ENOMEM);\n\t}\n\tc->cbs = *cbs;\n\tc->arg = arg;\n"
				printf "\tif ((error = cbl_stream_accept(s, msg, 0, &%s__%s_stramp, c)) != 0)\n\t\tfree(c);\n\treturn (error);\n}\n\n",
				    pfx, cname(op)
				printf "int\n%s_%s_server_send(cbl_stream *s, const struct %s_%s *data)\n{\n\tcbl_msg *msg;\n\tint error;\n\n",
				    pfx, cname(op), pfx, cname(pl)
				printf "\tif ((error = cbl_stream_msg_new(s, &msg)) != 0)\n\t\treturn (error);\n"
				printf "\tif ((error = %s_%s_put(msg, data)) != 0) {\n\t\tcbl_msg_free(msg);\n\t\treturn (error);\n\t}\n\t/* EAGAIN (no credit) leaves the message the caller's. */\n\tif ((error = cbl_stream_send(s, msg)) == EAGAIN)\n\t\tcbl_msg_free(msg);\n\treturn (error);\n}\n\n",
				    cname(spec), cname(pl)
			}
			printf "int\n%s_%s_reply(cbl_req *req, const struct %s_%s_rsp *rsp)\n{\n\tcbl_msg *msg;\n\tint error;\n\n",
			    pfx, cname(op), pfx, cname(op)
			printf "\tif ((error = cbl_req_reply_new(req, %s_CMD_%s, &msg)) != 0)\n\t\treturn (error);\n",
			    u, uname(op)
			printf "\tif ((error = %s_%s_output_put(msg, rsp)) != 0) {\n\t\tcbl_msg_free(msg);\n\t\treturn (error);\n\t}\n\treturn (cbl_req_send(req, msg));\n}\n\n",
			    cname(spec), cname(op)
		}
		if (opforms[op, "dump"]) {
			printf "static int\n%s__%s_dumpit(cbl_req *req, const cbl_msg *msg,\n    struct cbl_dump_state *st, void *arg)\n{\n",
			    pfx, cname(op)
			printf "\tstruct %s_%s_dump_req in;\n\tcbl_yarena *a;\n\tchar why[256];\n\tint error;\n\n",
			    pfx, cname(op)
			printf "\tif ((a = cbl_yarena_new()) == NULL)\n\t\treturn (ENOMEM);\n"
			printf "\tif (%s_%s_dump_input_parse(msg, &in, a, CBL_YD_STRICT, why,\n\t    sizeof(why)) != 0) {\n\t\t(void)cbl_req_set_err(req, why, NULL, 0, -1);\n\t\tcbl_yarena_free(a);\n\t\treturn (EINVAL);\n\t}\n",
			    cname(spec), cname(op)
			printf "\terror = %s_%s_dumpit(req, &in, st, arg);\n\tcbl_yarena_free(a);\n\treturn (error);\n}\n\n",
			    pfx, cname(op)
			printf "int\n%s_%s_dump_reply(cbl_req *req, const struct %s_%s_dump_rsp *rsp)\n{\n\tcbl_msg *msg;\n\tint error;\n\n",
			    pfx, cname(op), pfx, cname(op)
			printf "\tif ((error = cbl_req_dump_item(req, &msg)) != 0)\n\t\treturn (error);\n"
			printf "\tif ((error = %s_%s_dump_output_put(msg, rsp)) != 0) {\n\t\tcbl_msg_free(msg);\n\t\treturn (error);\n\t}\n\treturn (cbl_req_send(req, msg));\n}\n\n",
			    cname(spec), cname(op)
		}
	}
	# The family: its operations by command, its groups.
	printf "static const struct cbl_op %s__ops[] = {\n", pfx
	n = 0
	for (i = 1; i <= nop; i++) {
		op = opname[i]
		if (opretired[op])
			continue
		if (opforms[op, "event"])
			continue
		st = stream_of(op)
		printf "\t{\n\t\t.cmd = %s_CMD_%s,\n\t\t.name = %s,\n\t\t.flags = 0%s%s%s%s,\n",
		    u, uname(op), ystr(op), (opforms[op, "do"] && st == "") ? " | CBL_OPF_DO" : "",
		    opforms[op, "dump"] ? " | CBL_OPF_DUMP" : "",
		    (st != "" ? " | CBL_OPF_STREAM" : ""),
		    opauth[op] ? " | CBL_OPF_AUTH" : ""
		if (opforms[op, "do"] && st == "")
			printf "\t\t.doit = %s__%s_doit,\n", pfx, cname(op)
		if (opforms[op, "dump"])
			printf "\t\t.dumpit = %s__%s_dumpit,\n", pfx, cname(op)
		if (st != "")
			printf "\t\t.stream_open = %s__%s_sopen,\n", pfx, cname(op)
		printf "\t},\n"
	}
	printf "};\n\n"
	printf "static const struct cbl_mcgrp %s__mcgrps[] = {\n", pfx
	for (i = 1; i <= ngrp; i++)
		printf "\t{ .name = %s, .flags = %s },\n", ystr(grpname[i]),
		    grpauth[grpname[i]] ? "CBL_MCF_AUTH" : "0"
	printf "};\n\n"
	printf "const struct cbl_family_def %s_family_def = {\n\t.abi = CBL_FAMILY_ABI,\n\t.name = %s_FAMILY_NAME,\n\t.version = %s_FAMILY_VERSION,\n\t.ops = %s__ops,\n\t.nops = nitems(%s__ops),\n\t.mcgrps = %s__mcgrps,\n\t.nmcgrps = nitems(%s__mcgrps),\n};\n\n",
	    pfx, u, u, pfx, pfx, pfx, pfx
	printf "int\n%s_register(cbl_ctx *ctx, void *arg, cbl_family **famp)\n{\n\n\treturn (cbl_family_register(ctx, &%s_family_def, arg, famp));\n}\n\n",
	    pfx, pfx
}

function out_c_client(    i, op, u, st) {
	u = uname(pfx)
	printf "/* ---- The client ----------------------------------------------- */\n\n"
	printf "/* The ERROR of the last failed call, kept until the next. */\nstatic void\n%s__err(struct %s_client *cl, cbl_msg *rsp)\n{\n\n\tcbl_msg_free(cl->err);\n\tcl->err = rsp;\n}\n\n",
	    pfx, pfx
	printf "int\n%s_client_init(struct %s_client *cl, cbl_conn *conn)\n{\n\tcbl_family_info *info;\n\tint error;\n\n\tif ((error = cbl_resolve(conn, %s_FAMILY_NAME, &info)) != 0)\n\t\treturn (error);\n\terror = %s_client_init_info(cl, conn, info);\n\tcbl_family_info_free(info);\n\treturn (error);\n}\n\n",
	    pfx, pfx, u, pfx
	printf "int\n%s_client_init_info(struct %s_client *cl, cbl_conn *conn,\n    const cbl_family_info *info)\n{\n\n\tmemset(cl, 0, sizeof(*cl));\n\tcl->conn = conn;\n\tcl->family = cbl_family_info_id(info);\n\tcl->version = cbl_family_info_version(info);\n",
	    pfx, pfx
	for (i = 1; i <= ngrp; i++)
		printf "\t(void)cbl_family_info_group(info, %s,\n\t    &cl->groups[%s_MCGRP_%s]);\n",
		    ystr(grpname[i]), u, uname(grpname[i])
	printf "\treturn (0);\n}\n\n"
	printf "void\n%s_client_fini(struct %s_client *cl)\n{\n\n\tcbl_msg_free(cl->err);\n\tcl->err = NULL;\n}\n\n",
	    pfx, pfx
	# A reply as the caller keeps it: the output in an arena of its own,
	# the message with it, freed together.
	printf "struct %s__box {\n\tcbl_yarena\t*a;\n\tcbl_msg\t\t*m;\n\tchar\t\t out[] __aligned(16);\n};\n\n", pfx
	printf "static void *\n%s__box_new(cbl_msg *m, size_t size)\n{\n\tstruct %s__box *b;\n\n\tif ((b = calloc(1, sizeof(*b) + size)) == NULL)\n\t\treturn (NULL);\n\tif ((b->a = cbl_yarena_new()) == NULL) {\n\t\tfree(b);\n\t\treturn (NULL);\n\t}\n\tb->m = m;\n\treturn (b);\n}\n\n",
	    pfx, pfx
	printf "static void\n%s__box_free(void *out)\n{\n\tstruct %s__box *b;\n\n\tif (out == NULL)\n\t\treturn;\n\tb = (struct %s__box *)(void *)((char *)out - offsetof(struct %s__box,\n\t    out));\n\tcbl_yarena_free(b->a);\n\tcbl_msg_free(b->m);\n\tfree(b);\n}\n\n",
	    pfx, pfx, pfx, pfx
	for (i = 1; i <= nop; i++) {
		op = opname[i]
		if (opretired[op])
			continue
		if (opforms[op, "event"]) {
			printf "struct %s__%s_sub {\n\tstruct %s_%s_handlers h;\n\tvoid\t*arg;\n};\n\n",
			    pfx, cname(opgrp[op]), pfx, cname(opgrp[op])
			printf "static void\n%s__%s_ntf_cb(cbl_conn *conn __unused, cbl_msg *msg, void *arg)\n{\n\tstruct %s__%s_sub *ctx = arg;\n\tstruct %s_%s_ntf n;\n\tcbl_yarena *a;\n\n",
			    pfx, cname(opgrp[op]), pfx, cname(opgrp[op]), pfx, cname(op)
			printf "\tif (cbl_msg_cmd(msg) != %s_CMD_%s || ctx->h.%s == NULL)\n\t\treturn;\n",
			    u, uname(op), cname(op)
			printf "\tif ((a = cbl_yarena_new()) == NULL)\n\t\treturn;\n"
			printf "\tif (%s_%s_ntf_parse(msg, &n, a, CBL_YD_STRICT, NULL, 0) == 0)\n\t\tctx->h.%s(&n, ctx->arg);\n\tcbl_yarena_free(a);\n}\n\n",
			    cname(spec), cname(op), cname(op)
			printf "int\n%s_%s_subscribe(struct %s_client *cl,\n    const struct %s_%s_handlers *h, void *arg, cbl_sub **subp)\n{\n\tstruct %s__%s_sub *ctx;\n\tint error;\n\n",
			    pfx, cname(opgrp[op]), pfx, pfx, cname(opgrp[op]), pfx,
			    cname(opgrp[op])
			printf "\tif ((ctx = calloc(1, sizeof(*ctx))) == NULL)\n\t\treturn (ENOMEM);\n\tctx->h = *h;\n\tctx->arg = arg;\n"
			printf "\terror = cbl_subscribe_id(cl->conn, cl->family,\n\t    cl->groups[%s_MCGRP_%s], %s__%s_ntf_cb, ctx, subp);\n\tif (error != 0)\n\t\tfree(ctx);\n\treturn (error);\n}\n\n",
			    u, uname(opgrp[op]), pfx, cname(opgrp[op])
			printf "int\n%s_%s_unsubscribe(cbl_sub *sub)\n{\n\tvoid *ctx = cbl_sub_arg(sub);\n\tint error;\n\n\terror = cbl_unsubscribe(sub);\n\tfree(ctx);\n\treturn (error);\n}\n\n",
			    pfx, cname(opgrp[op])
			continue
		}
		if (opforms[op, "do"] && stream_of(op) != "") {
			# What a client sends on a stream it opened.
			printf "int\n%s_%s_send(cbl_stream *s, const struct %s_%s *data)\n{\n\tcbl_msg *msg;\n\tint error;\n\n",
			    pfx, cname(op), pfx, cname(stprop[stream_of(op), "payload"])
			printf "\tif ((error = cbl_stream_msg_new(s, &msg)) != 0)\n\t\treturn (error);\n"
			printf "\tif ((error = %s_%s_put(msg, data)) != 0) {\n\t\tcbl_msg_free(msg);\n\t\treturn (error);\n\t}\n\t/* EAGAIN (no credit) leaves the message the caller's. */\n\tif ((error = cbl_stream_send(s, msg)) == EAGAIN)\n\t\tcbl_msg_free(msg);\n\treturn (error);\n}\n\n",
			    cname(spec), cname(stprop[stream_of(op), "payload"])
		}
		if (opforms[op, "do"] && stream_of(op) == "") {
			if (opn[op ":do:request:attrs"] > 0)
				printf "int\n%s_%s(struct %s_client *cl, const struct %s_%s_req *req,\n    struct %s_%s_rsp **rspp)\n{\n",
				    pfx, cname(op), pfx, pfx, cname(op), pfx, cname(op)
			else
				printf "int\n%s_%s(struct %s_client *cl, struct %s_%s_rsp **rspp)\n{\n",
				    pfx, cname(op), pfx, pfx, cname(op)
			printf "\tstruct %s__box *b;\n\tcbl_msg *msg, *rsp = NULL;\n\tint error;\n\n\t*rspp = NULL;\n",
			    pfx
			printf "\tif ((error = cbl_msg_new(cbl_conn_ctx(cl->conn), cl->family,\n\t    %s_CMD_%s, 0, &msg)) != 0)\n\t\treturn (error);\n",
			    u, uname(op)
			if (opn[op ":do:request:attrs"] > 0)
				printf "\tif (req != NULL && (error = %s_%s_input_put(msg, req)) != 0) {\n\t\tcbl_msg_free(msg);\n\t\treturn (error);\n\t}\n",
				    cname(spec), cname(op)
			printf "\terror = cbl_request(cl->conn, msg, &rsp, cl->timeout_ms > 0 ?\n\t    cl->timeout_ms : -1);\n\tif (error != 0) {\n\t\t%s__err(cl, rsp);\n\t\treturn (error);\n\t}\n\t%s__err(cl, NULL);\n\tif (rsp == NULL)\n\t\treturn (EPROTO);\n",
			    pfx, pfx
			printf "\tif ((b = %s__box_new(rsp, sizeof(struct %s_%s_rsp))) == NULL) {\n\t\tcbl_msg_free(rsp);\n\t\treturn (ENOMEM);\n\t}\n",
			    pfx, pfx, cname(op)
			printf "\tif ((error = %s_%s_output_parse(rsp, (struct %s_%s_rsp *)(void *)b->out,\n\t    b->a, CBL_YD_STRICT, NULL, 0)) != 0) {\n\t\t%s__box_free(b->out);\n\t\treturn (error);\n\t}\n",
			    cname(spec), cname(op), pfx, cname(op), pfx
			printf "\t*rspp = (struct %s_%s_rsp *)(void *)b->out;\n\treturn (0);\n}\n\n", pfx,
			    cname(op)
			printf "void\n%s_%s_rsp_free(struct %s_%s_rsp *rsp)\n{\n\n\t%s__box_free(rsp);\n}\n\n",
			    pfx, cname(op), pfx, cname(op), pfx
		}
		if (opforms[op, "dump"]) {
			printf "int\n%s_%s_dump(struct %s_client *cl, const struct %s_%s_dump_req *req,\n    cbl_dump **dp)\n{\n\tcbl_msg *msg;\n\tint error;\n\n",
			    pfx, cname(op), pfx, pfx, cname(op)
			printf "\tif ((error = cbl_msg_new(cbl_conn_ctx(cl->conn), cl->family,\n\t    %s_CMD_%s, CBL_F_DUMP, &msg)) != 0)\n\t\treturn (error);\n",
			    u, uname(op)
			printf "\tif (req != NULL && (error = %s_%s_dump_input_put(msg, req)) != 0) {\n\t\tcbl_msg_free(msg);\n\t\treturn (error);\n\t}\n\treturn (cbl_dump_start(cl->conn, msg, dp));\n}\n\n",
			    cname(spec), cname(op)
			printf "int\n%s_%s_dump_next(cbl_dump *d, struct %s_%s_dump_rsp **itemp)\n{\n\tstruct %s__box *b;\n\tcbl_msg *m;\n\tint error;\n\n\t*itemp = NULL;\n",
			    pfx, cname(op), pfx, cname(op), pfx
			printf "\tif ((error = cbl_dump_next(d, &m)) != 0 || m == NULL)\n\t\treturn (error);\n"
			printf "\tif ((b = %s__box_new(NULL, sizeof(struct %s_%s_dump_rsp))) == NULL)\n\t\treturn (ENOMEM);\n",
			    pfx, pfx, cname(op)
			printf "\tif ((error = %s_%s_dump_output_parse(m, (struct %s_%s_dump_rsp *)(void *)\n\t    b->out, b->a, CBL_YD_STRICT, NULL, 0)) != 0) {\n\t\t%s__box_free(b->out);\n\t\treturn (error);\n\t}\n",
			    cname(spec), cname(op), pfx, cname(op), pfx
			printf "\t%s__dump_keep(d, b);\n\t*itemp = (struct %s_%s_dump_rsp *)(void *)b->out;\n\treturn (0);\n}\n\n",
			    pfx, pfx, cname(op)
		}
	}
}

# The items of a dump live as long as the dump: kept by the dump, freed
# by pfx_dump_free().
function out_c_dumps(    u) {
	printf "struct %s__dumped {\n\tcbl_dump\t\t*d;\n\tstruct %s__box\t*b;\n\tstruct %s__dumped\t*next;\n};\n\nstatic struct %s__dumped *%s__dumped;\nstatic pthread_mutex_t %s__dumped_lock = PTHREAD_MUTEX_INITIALIZER;\n\n",
	    pfx, pfx, pfx, pfx, pfx, pfx
	printf "static void\n%s__dump_keep(cbl_dump *d, struct %s__box *b)\n{\n\tstruct %s__dumped *k;\n\n\tif ((k = calloc(1, sizeof(*k))) == NULL)\n\t\treturn;\n\tk->d = d;\n\tk->b = b;\n\tpthread_mutex_lock(&%s__dumped_lock);\n\tk->next = %s__dumped;\n\t%s__dumped = k;\n\tpthread_mutex_unlock(&%s__dumped_lock);\n}\n\n",
	    pfx, pfx, pfx, pfx, pfx, pfx, pfx
	printf "void\n%s_dump_free(cbl_dump *d)\n{\n\tstruct %s__dumped *k, **kp;\n\n\tpthread_mutex_lock(&%s__dumped_lock);\n\tfor (kp = &%s__dumped; (k = *kp) != NULL; ) {\n\t\tif (k->d != d) {\n\t\t\tkp = &k->next;\n\t\t\tcontinue;\n\t\t}\n\t\t*kp = k->next;\n\t\t%s__box_free(k->b->out);\n\t\tfree(k);\n\t}\n\tpthread_mutex_unlock(&%s__dumped_lock);\n\tcbl_dump_free(d);\n}\n\n",
	    pfx, pfx, pfx, pfx, pfx, pfx
}

function out_c(    hdr) {
	if (nop == 0)
		die("no operations: no family, no glue")
	mark_structs()
	hdr = base == "" ? spec : base
	printf "/*\n * Written by share/arcana/wire.awk from share/arcana/%s.yaml: the glue\n * between the program and cblink for the family, over the structs\n * cblink-gen writes from the module.  Do not edit.\n */\n\n",
	    spec
	printf "#include <sys/param.h>\n\n#include <errno.h>\n#include <pthread.h>\n#include <stddef.h>\n#include <stdlib.h>\n#include <string.h>\n\n#include \"%s.h\"\n\n",
	    hdrname
	if (side == "server" || side == "both")
		out_c_server()
	if (side == "client" || side == "both") {
		if (has_dumps())
			printf "struct %s__box;\nstatic void\t%s__dump_keep(cbl_dump *, struct %s__box *);\n\n",
			    pfx, pfx, pfx
		out_c_client()
		if (has_dumps())
			out_c_dumps()
	}
}

END {
	if (docind >= 0)
		docs[dockey] = doc
	if (out == "yang")
		out_yang()
	else if (out == "h")
		out_h()
	else if (out == "c")
		out_c()
	else
		die("out is yang, h or c")
}

BEGIN {
	docind = -1
	if (rev == "")
		rev = "2026-10-22"
	if (side == "")
		side = "both"
	if (hdrname == "")
		hdrname = "arcana"
}
