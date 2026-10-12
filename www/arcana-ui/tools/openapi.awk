# SPDX-License-Identifier: BSD-2-Clause
#
# docs/openapi.yaml, the console's API as it is documented, into the
# JSON the console shows on its API page:
#
#	{ "title", "version", "about",
#	  "ops": [ { "path", "method", "tag", "summary", "about",
#	      "open", "params": [ "name (in)" ], "codes": [ "200" ] } ] }
#
# The document is written by hand in one style, and this reads its
# lines as they are: a path at two spaces, a method at four, what the
# method has at six.

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
function unq(s) {
	s = trim(s)
	if (s ~ /^".*"$/ || s ~ /^'.*'$/)
		s = substr(s, 2, length(s) - 2)
	return s
}
# The block of text being read is over: it goes where it belongs.
function endblock() {
	if (block == "")
		return
	sub(/(\\n)+$/, "", text)
	if (block == "info")
		info = text
	else
		A[n] = text
	block = ""
}
BEGIN { section = ""; n = 0; block = ""; path = "" }
{
	match($0, /^ */)
	ind = RLENGTH
	if (block != "") {
		if ($0 ~ /^[ \t]*$/) {
			text = text "\\n"
			next
		}
		if (ind > blockind) {
			# As written, or a sentence that ran on to the next
			# line.
			if (folded)
				text = text (text == "" ? "" : " ") \
				    esc(trim($0))
			else
				text = text (text == "" ? "" : "\\n") \
				    esc(substr($0, blockind + 3))
			next
		}
		endblock()
	}
}
/^[a-zA-Z]/ {
	section = $1
	sub(/:.*/, "", section)
	next
}
section == "info" && /^  title:/ { sub(/^  title: */, ""); title = unq($0) }
section == "info" && /^  version:/ {
	sub(/^  version: */, "")
	version = unq($0)
}
section == "info" && /^  description: \|/ {
	block = "info"; blockind = 2; text = ""; folded = 0
	next
}
section != "paths" { next }
/^  \/[^ ]*:$/ {
	path = trim($0)
	sub(/:$/, "", path)
	next
}
/^    (get|post|put|delete|patch):$/ {
	n++
	P[n] = path
	M[n] = trim($0)
	sub(/:$/, "", M[n])
	T[n] = S[n] = A[n] = PR[n] = C[n] = ""
	O[n] = "false"
	inparams = inresp = 0
	next
}
n == 0 { next }
/^      [a-zA-Z]/ {
	inparams = ($0 ~ /^      parameters:/)
	inresp = ($0 ~ /^      responses:/)
}
/^      tags: \[/ {
	t = $0
	sub(/^      tags: \[/, "", t)
	sub(/[,\]].*/, "", t)
	T[n] = trim(t)
}
/^      summary:/ {
	t = $0
	sub(/^      summary: */, "", t)
	S[n] = unq(t)
}
/^      description: \|/ {
	block = "op"; blockind = 6; text = ""; folded = 0
	next
}
# Folded, for a text with ": " in it, which a plain one cannot hold.
/^      description: >-?$/ {
	block = "op"; blockind = 6; text = ""; folded = 1
	next
}
/^      description: [^|]/ {
	t = $0
	sub(/^      description: */, "", t)
	block = "op"; blockind = 6; text = esc(unq(t)); folded = 1
	next
}
/^      security: \[\]/ { O[n] = "true" }
inparams && /^        - name:/ {
	t = $0
	sub(/^        - name: */, "", t)
	last = unq(t)
	PR[n] = PR[n] (PR[n] == "" ? "" : ",") "\"" esc(last)
	open = 1
}
inparams && open && /^          in:/ {
	t = $0
	sub(/^          in: */, "", t)
	PR[n] = PR[n] " (" esc(unq(t)) ")\""
	open = 0
}
inparams && /^        - \$ref:/ {
	t = $0
	sub(/.*\//, "", t)
	sub(/".*/, "", t)
	PR[n] = PR[n] (PR[n] == "" ? "" : ",") "\"" esc(t) "\""
}
inresp && /^        "[0-9]+":/ {
	t = $0
	sub(/^        "/, "", t)
	sub(/".*/, "", t)
	C[n] = C[n] (C[n] == "" ? "" : ",") "\"" t "\""
}
END {
	endblock()
	printf "{\"title\":\"%s\",\"version\":\"%s\",\"about\":\"%s\",\"ops\":[", \
	    esc(title), esc(version), info
	for (i = 1; i <= n; i++) {
		# A name whose "in" never came still closes its quote.
		if (PR[i] != "" && PR[i] !~ /"$/)
			PR[i] = PR[i] "\""
		printf "%s{\"path\":\"%s\",\"method\":\"%s\",", \
		    (i > 1 ? "," : ""), esc(P[i]), M[i]
		printf "\"tag\":\"%s\",\"summary\":\"%s\",\"about\":\"%s\",", \
		    esc(T[i]), esc(S[i]), A[i]
		printf "\"open\":%s,\"params\":[%s],\"codes\":[%s]}", O[i], \
		    PR[i], C[i]
	}
	printf "]}\n"
}
