# SPDX-License-Identifier: BSD-2-Clause
#
# The family's reference, as cblink-gen writes it in Markdown, into the
# JSON the console shows beside an operation:
#
#	{ "family": "arcana",
#	  "sets": { "<set>": [ { "id", "name", "type", "checks", "doc" } ] },
#	  "ops": { "<op>": { "cmd", "set", "doc",
#	      "request": [ { "name", "required" } ], "reply": [ ... ] } } }
#
# cblink-gen's output is deterministic, so this reads its lines as they
# are: "### `name`" headings, attribute tables, "- Do request:" lists.

function esc(s) {
	gsub(/\\/, "\\\\", s)
	gsub(/"/, "\\\"", s)
	gsub(/\t/, " ", s)
	return s
}
function trim(s) {
	sub(/^[ \t]+/, "", s)
	sub(/[ \t]+$/, "", s)
	return s
}
function unquote(s) {
	gsub(/`/, "", s)
	return trim(s)
}
# "a (required), b" as [{"name":"a","required":true},...]
function attrs(list,    n, i, parts, a, req, out) {
	n = split(list, parts, /, */)
	out = ""
	for (i = 1; i <= n; i++) {
		a = parts[i]
		req = (a ~ /\(required\)/) ? "true" : "false"
		sub(/ *\(required\)/, "", a)
		a = unquote(a)
		if (a == "")
			continue
		out = out (out == "" ? "" : ",") \
		    "{\"name\":\"" esc(a) "\",\"required\":" req "}"
	}
	return "[" out "]"
}
function close_set() {
	if (inset) {
		sets = sets (sets == "" ? "" : ",") "\"" esc(setname) "\":[" \
		    rows "]"
		inset = 0
	}
}
function close_op() {
	if (inop) {
		ops = ops (ops == "" ? "" : ",") "\"" esc(opname) "\":{\"cmd\":" \
		    cmd ",\"set\":\"" esc(opset) "\",\"doc\":\"" esc(trim(doc)) \
		    "\",\"request\":" (request == "" ? "[]" : request) \
		    ",\"reply\":" (reply == "" ? "[]" : reply) "}"
		inop = 0
	}
}

/^# / && family == "" {
	family = $0
	sub(/^[^`]*`/, "", family)
	sub(/`.*/, "", family)
}
/^## / {
	close_set(); close_op()
	section = $0
	next
}
/^### / {
	close_set(); close_op()
	name = $2
	gsub(/`/, "", name)
	if (section ~ /Attribute sets/) {
		inset = 1; setname = name; rows = ""
	} else if (section ~ /Operations/) {
		inop = 1; opname = name; doc = ""; request = ""; reply = ""
		opset = ""
		cmd = $0
		sub(/.*\(command */, "", cmd)
		sub(/\).*/, "", cmd)
	}
	next
}
inset && /^\| *[0-9]+ *\|/ {
	n = split($0, f, /\|/)
	rows = rows (rows == "" ? "" : ",") "{\"id\":" trim(f[2]) \
	    ",\"name\":\"" esc(unquote(f[3])) "\",\"type\":\"" \
	    esc(unquote(f[4])) "\",\"checks\":\"" \
	    esc(trim(f[5]) == "—" ? "" : unquote(f[5])) "\",\"doc\":\"" \
	    esc(trim(f[6])) "\"}"
	next
}
inop && /^- Attribute set:/ {
	opset = $0; sub(/^- Attribute set: */, "", opset); opset = unquote(opset)
	next
}
inop && /^- Do request:/ {
	line = $0; sub(/^- Do request: */, "", line); request = attrs(line)
	next
}
inop && /^- Do reply:/ {
	line = $0; sub(/^- Do reply: */, "", line); reply = attrs(line)
	next
}
inop && !/^- / && !/^$/ {
	doc = doc " " $0
}
END {
	close_set(); close_op()
	printf "{\"family\":\"%s\",\"sets\":{%s},\"ops\":{%s}}\n", esc(family),
	    sets, ops
}
