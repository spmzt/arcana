# jobs.yaml as the console's table (out=c) or the page's (out=json).
#
#	awk -v out=c -f jobs.awk arcana.yaml jobs.yaml > jobs_table.h
#	awk -v out=json -f jobs.awk arcana.yaml jobs.yaml > jobs.json
#
# arcana.yaml first: its job-kind entries and job-spec attributes are
# what jobs.yaml must agree with.  A kind in the one and not the other,
# or a field that is no attribute of job-spec, stops the build with
# what differs, and nothing is written.

function jstr(s) {
	gsub(/\\/, "\\\\", s)
	gsub(/"/, "\\\"", s)
	return "\"" s "\""
}

function cstr(s) {
	gsub(/\\/, "\\\\", s)
	gsub(/"/, "\\\"", s)
	return "\"" s "\""
}

# "a b c" as a JSON array of strings.
function jlist(s,    n, i, a, r) {
	n = split(s, a, " ")
	r = "["
	for (i = 1; i <= n; i++)
		r = r (i > 1 ? "," : "") jstr(a[i])
	return r "]"
}

# "action=start|stop verb=a|b" as {"action":["start","stop"],...}.
function jvalues(s,    n, i, a, kv, r, m, j, w) {
	n = split(s, a, " ")
	r = "{"
	for (i = 1; i <= n; i++) {
		split(a[i], kv, "=")
		m = split(kv[2], w, "|")
		r = r (i > 1 ? "," : "") jstr(kv[1]) ":["
		for (j = 1; j <= m; j++)
			r = r (j > 1 ? "," : "") jstr(w[j])
		r = r "]"
	}
	return r "}"
}

function value(line) {
	sub(/^[^:]*:[ \t]*/, "", line)
	return line
}

function flush_field() {
	if (fname == "")
		return
	nf++
	ff[nf] = fname; ft[nf] = ftype; fl[nf] = flabel; fa[nf] = fattr
	fname = ftype = flabel = fattr = ""
}

function flush_kind() {
	if (kname == "")
		return
	nk++
	kk[nk] = kname; kt[nk] = ktitle; kn[nk] = kneeds; ku[nk] = kuses
	kv[nk] = kvalues; kd[nk] = kdestroys
	kname = ktitle = kneeds = kuses = kvalues = kdestroys = ""
}

# arcana.yaml: the entries of the job-kind enum, the attributes of the
# job-spec set; each a "      - name:" under its "  - name:".
FILENAME ~ /arcana\.yaml$/ {
	if ($0 ~ /^  - name:/)
		top = value($0)
	else if ($0 ~ /^      - name:/ && top == "job-kind")
		akind[value($0)] = 1
	else if ($0 ~ /^      - name:/ && top == "job-spec")
		aspec[value($0)] = 1
	next
}
/^#/ || /^[ \t]*$/ { next }
/^fields:/ { section = "f"; next }
/^kinds:/ { flush_field(); section = "k"; next }
section == "f" && /^  - field:/ { flush_field(); fname = value($0); next }
section == "f" && /^    type:/ { ftype = value($0); next }
section == "f" && /^    label:/ { flabel = value($0); next }
section == "f" && /^    attribute:/ { fattr = value($0); next }
section == "k" && /^  - kind:/ { flush_kind(); kname = value($0); next }
section == "k" && /^    title:/ { ktitle = value($0); next }
section == "k" && /^    needs:/ { kneeds = value($0); next }
section == "k" && /^    uses:/ { kuses = value($0); next }
section == "k" && /^    values:/ { kvalues = value($0); next }
section == "k" && /^    destroys:/ { kdestroys = value($0); next }

END {
	flush_field()
	flush_kind()
	bad = 0
	for (k in akind)
		seen_a[k] = 0
	for (i = 1; i <= nk; i++) {
		if (!(kk[i] in akind)) {
			printf "jobs.awk: kind %s is in jobs.yaml, not in arcana.yaml's job-kind\n", kk[i] > "/dev/stderr"
			bad = 1
		}
		seen_a[kk[i]] = 1
	}
	for (k in akind)
		if (!seen_a[k]) {
			printf "jobs.awk: kind %s is in arcana.yaml's job-kind, not in jobs.yaml\n", k > "/dev/stderr"
			bad = 1
		}
	for (i = 1; i <= nf; i++) {
		a = fa[i] != "" ? fa[i] : ff[i]
		gsub(/_/, "-", a)
		if (!(a in aspec)) {
			printf "jobs.awk: field %s is no attribute of arcana.yaml's job-spec\n", ff[i] > "/dev/stderr"
			bad = 1
		}
	}
	if (nk == 0 || length(akind) == 0) {
		print "jobs.awk: give arcana.yaml, then jobs.yaml" > "/dev/stderr"
		bad = 1
	}
	if (bad)
		exit 1
	if (out == "c") {
		print "/* Made from share/arcana/jobs.yaml by jobs.awk: not to be edited. */"
		print "struct jobfield {"
		print "\tconst char\t*field, *type, *label;"
		print "};"
		print "struct jobkind {"
		print "\tconst char\t*kind, *title, *needs, *uses, *values, *destroys;"
		print "};"
		print "static const struct jobfield jobfields[] = {"
		for (i = 1; i <= nf; i++)
			printf "\t{ %s, %s, %s },\n", cstr(ff[i]), cstr(ft[i]), cstr(fl[i])
		print "};"
		print "static const struct jobkind jobkinds[] = {"
		for (i = 1; i <= nk; i++)
			printf "\t{ %s, %s, %s, %s, %s, %s },\n", cstr(kk[i]), cstr(kt[i]), cstr(kn[i]), cstr(ku[i]), cstr(kv[i]), cstr(kd[i])
		print "};"
		exit
	}
	printf "{\"fields\":["
	for (i = 1; i <= nf; i++)
		printf "%s{\"field\":%s,\"type\":%s,\"label\":%s}", (i > 1 ? "," : ""), jstr(ff[i]), jstr(ft[i]), jstr(fl[i])
	printf "],\"kinds\":["
	for (i = 1; i <= nk; i++)
		printf "%s{\"kind\":%s,\"title\":%s,\"needs\":%s,\"uses\":%s,\"values\":%s,\"destroys\":%s}", (i > 1 ? "," : ""), jstr(kk[i]), jstr(kt[i]), jlist(kn[i]), jlist(ku[i]), jvalues(kv[i]), jstr(kd[i])
	printf "]}\n"
}
