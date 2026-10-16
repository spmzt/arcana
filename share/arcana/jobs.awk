# jobs.yaml as the console's table (out=c), the page's (out=json), or
# the YANG of a job's change (out=yang: share/yang's submodule
# arcana-jobs-kinds, which arcana-jobs includes).
#
#	awk -v out=c -f jobs.awk arcana.yaml jobs.yaml > jobs_table.h
#	awk -v out=json -f jobs.awk arcana.yaml jobs.yaml > jobs.json
#	awk -v out=yang -f jobs.awk arcana.yaml jobs.yaml > \
#	    arcana-jobs-kinds@2026-10-14.yang
#	awk -v out=yspec -f jobs.awk arcana.yaml jobs.yaml arcana.h > \
#	    yjobs_spec.c
#
# out=yspec writes yjobs_spec(), a change of that submodule (its C
# struct, as cblink-gen makes it) made the job-spec the agent's queue
# takes; arcana.h, the family's C header, says which of job-spec's
# members have a has_ beside them.
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

# A YANG string's text: in double quotes, escaped.
function ystr(s) {
	gsub(/\\/, "\\\\", s)
	gsub(/"/, "\\\"", s)
	return "\"" s "\""
}

# Field i of kind k as a YANG node, indented by ind; need: mandatory.
function yfield(k, i, need, ind,    name, n, a, j, w, m, vals) {
	name = ff[i]
	gsub(/_/, "-", name)
	vals = ""
	n = split(kv[k], a, " ")
	for (j = 1; j <= n; j++) {
		split(a[j], w, "=")
		if (w[1] == ff[i])
			vals = w[2]
	}
	if (ft[i] == "map") {
		printf "%slist %s {\n", ind, name
		printf "%s  key \"name\";\n", ind
		printf "%s  description\n%s    %s;\n", ind, ind, ystr(fl[i])
		printf "%s  leaf name {\n%s    type string;\n%s    description\n%s      \"The variable.\";\n%s  }\n", ind, ind, ind, ind, ind
		printf "%s  leaf value {\n%s    type string;\n%s    description\n%s      \"Its value.\";\n%s  }\n", ind, ind, ind, ind, ind
		printf "%s}\n", ind
		return
	}
	printf "%s%s %s {\n", ind, (ft[i] == "list" ? "leaf-list" : "leaf"), name
	if (vals != "") {
		m = split(vals, w, "|")
		printf "%s  type enumeration {\n", ind
		for (j = 1; j <= m; j++)
			printf "%s    enum %s;\n", ind, w[j]
		printf "%s  }\n", ind
	} else if (ft[i] == "number")
		printf "%s  type uint32;\n", ind
	else if (ft[i] == "bool")
		printf "%s  type boolean;\n", ind
	else
		printf "%s  type string;\n", ind
	if (ft[i] == "list")
		printf "%s  ordered-by user;\n", ind
	if (need && ft[i] != "list")
		printf "%s  mandatory true;\n", ind
	printf "%s  description\n%s    %s;\n", ind, ind, ystr(fl[i])
	printf "%s}\n", ind
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
	fh[nf] = fhelp; fc[nf] = fchoices; fp[nf] = fpicker
	fname = ftype = flabel = fattr = fhelp = fchoices = fpicker = ""
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
	else if ($0 ~ /^      - name:/ && top == "job-kind") {
		akind[value($0)] = 1
		aorder[nak++] = value($0)
	}
	else if ($0 ~ /^      - name:/ && top == "job-spec")
		aspec[value($0)] = 1
	next
}
# arcana.h: struct arc_job_spec's members.
FILENAME ~ /arcana\.h$/ {
	if ($0 ~ /^struct arc_job_spec \{/)
		inspec = 1
	else if (inspec && $0 ~ /^\};/)
		inspec = 0
	else if (inspec && match($0, /[*]?[a-z_0-9]+;$/)) {
		m = substr($0, RSTART, RLENGTH - 1)
		sub(/^[*]/, "", m)
		if (m ~ /^has_/)
			shas[substr(m, 5)] = 1
		else
			smem[m] = 1
	}
	next
}
/^#/ || /^[ \t]*$/ { next }
/^fields:/ { section = "f"; next }
/^kinds:/ { flush_field(); section = "k"; next }
section == "f" && /^  - field:/ { flush_field(); fname = value($0); next }
section == "f" && /^    type:/ { ftype = value($0); next }
section == "f" && /^    label:/ { flabel = value($0); next }
section == "f" && /^    attribute:/ { fattr = value($0); next }
section == "f" && /^    help:/ { fhelp = value($0); next }
section == "f" && /^    choices:/ { fchoices = value($0); next }
section == "f" && /^    picker:/ { fpicker = value($0); next }
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
	if (out == "yang") {
		yang()
		exit
	}
	if (out == "yspec") {
		yspec()
		exit
	}
	printf "{\"fields\":["
	for (i = 1; i <= nf; i++) {
		printf "%s{\"field\":%s,\"type\":%s,\"label\":%s", (i > 1 ? "," : ""), jstr(ff[i]), jstr(ft[i]), jstr(fl[i])
		# The page's: a line under the field, labelled values to
		# choose from (v=label|v=label), and what fills a list.
		if (fh[i] != "")
			printf ",\"help\":%s", jstr(fh[i])
		if (fp[i] != "")
			printf ",\"picker\":%s", jstr(fp[i])
		if (fc[i] != "") {
			m = split(fc[i], w, "|")
			printf ",\"choices\":["
			for (j = 1; j <= m; j++) {
				split(w[j], kvp, "=")
				printf "%s{\"value\":%s,\"label\":%s}", (j > 1 ? "," : ""), jstr(kvp[1]), jstr(kvp[2] != "" ? kvp[2] : kvp[1])
			}
			printf "]"
		}
		printf "}"
	}
	printf "],\"kinds\":["
	for (i = 1; i <= nk; i++)
		printf "%s{\"kind\":%s,\"title\":%s,\"needs\":%s,\"uses\":%s,\"values\":%s,\"destroys\":%s}", (i > 1 ? "," : ""), jstr(kk[i]), jstr(kt[i]), jlist(kn[i]), jlist(ku[i]), jvalues(kv[i]), jstr(kd[i])
	printf "]}\n"
}

function fidx(name,    i) {
	for (i = 1; i <= nf; i++)
		if (ff[i] == name)
			return i
	return 0
}

function yang(    i, j, n, a, k, ind) {
	print "submodule arcana-jobs-kinds {"
	print "  yang-version 1.1;"
	print "  belongs-to arcana-jobs {"
	print "    prefix arcjob;"
	print "  }"
	print ""
	print "  organization"
	print "    \"Arcana\";"
	print "  contact"
	print "    \"Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>\";"
	print "  description"
	print "    \"The kinds of job, a change each: made from share/arcana/jobs.yaml"
	print "     by share/arcana/jobs.awk (out=yang), not to be edited.  A kind"
	print "     is a case, its fields leaves: those it needs mandatory, those"
	print "     whose values jobs.yaml lists an enumeration.\";"
	print ""
	print "  revision 2026-10-14 {"
	print "    description"
	print "      \"Initial revision.\";"
	print "    reference"
	print "      \"Arcana docs/PLAN-SDN-YANG.md step 3.1.4.\";"
	print "  }"
	print ""
	print "  typedef job-kind {"
	print "    type enumeration {"
	for (j = 0; j < nak; j++) {
		print "      enum " aorder[j] " {"
		print "        value " j ";"
		print "      }"
	}
	print "    }"
	print "    description"
	print "      \"A kind of job, by its number in arcana.yaml's job-kind.\";"
	print "  }"
	print ""
	print "  grouping change {"
	print "    description"
	print "      \"A change: one kind of job, and what it is given.\";"
	print "    choice kind {"
	print "      mandatory true;"
	print "      description"
	print "        \"The kind of job.\";"
	for (k = 1; k <= nk; k++) {
		print "      case " kk[k] " {"
		print "        container " kk[k] " {"
		print "          presence"
		print "            \"This kind of job.\";"
		print "          description"
		printf "            %s;\n", ystr(kt[k] ((kd[k] != "") ? " (destroys: " kd[k] ")" : ""))
		ind = "          "
		n = split(kn[k], a, " ")
		for (j = 1; j <= n; j++)
			if ((i = fidx(a[j])) > 0)
				yfield(k, i, 1, ind)
		n = split(ku[k], a, " ")
		for (j = 1; j <= n; j++)
			if ((i = fidx(a[j])) > 0)
				yfield(k, i, 0, ind)
		print "        }"
		print "      }"
	}
	print "    }"
	print "  }"
	print "}"
}

function cname(s) {
	gsub(/-/, "_", s)
	return s
}

function uname(s) {
	s = cname(s)
	return toupper(s)
}

# The values field f of kind k is one of, or "".
function kvals(k, f,    n, a, j, w) {
	n = split(kv[k], a, " ")
	for (j = 1; j <= n; j++) {
		split(a[j], w, "=")
		if (w[1] == f)
			return w[2]
	}
	return ""
}

# Field i of kind k into the job-spec: the C to do it.
function yspec_field(k, i,    f, m, vals, nv, w, j, tab) {
	f = ff[i]
	m = fa[i] != "" ? cname(fa[i]) : f
	vals = kvals(k, f)
	if (f == "set") {
		print "\t\tfor (size_t i = 0; i < c->set.n; i++) {"
		print "\t\t\tvars[nv].key = c->set.v[i].name;"
		print "\t\t\tvars[nv++].value = c->set.v[i].value;"
		print "\t\t}"
		return
	}
	if (f == "unset") {
		print "\t\tfor (size_t i = 0; i < c->unset.n; i++) {"
		print "\t\t\tvars[nv].key = c->unset.v[i];"
		print "\t\t\tvars[nv++].remove = true;"
		print "\t\t}"
		return
	}
	if (ft[i] == "list") {
		printf "\t\tsp->%s.n = c->%s.n;\n", m, f
		printf "\t\tsp->%s.v = c->%s.v;\n", m, f
		return
	}
	if (vals != "") {
		# action: the job-spec's own enumeration, the same order.
		if (f == "action") {
			m = kk[k] == "service-action" ? "service_action" : "action"
			printf "\t\tif ((sp->has_%s = c->has_%s))\n", m, f
			printf "\t\t\tsp->%s = (uint8_t)c->%s;\n", m, f
			return
		}
		tab = cname(kk[k]) "_" f
		printf "\t\tif (c->has_%s)\n", f
		printf "\t\t\tsp->%s = %s[c->%s];\n", m, tab, f
		return
	}
	if (ft[i] == "number" || (ft[i] == "bool" && (m in shas))) {
		printf "\t\tif ((sp->has_%s = c->has_%s))\n", m, f
		printf "\t\t\tsp->%s = c->%s;\n", m, f
		return
	}
	if (ft[i] == "bool") {
		printf "\t\tsp->%s = c->has_%s && c->%s;\n", m, f, f
		return
	}
	printf "\t\tsp->%s = c->%s;\n", m, f
}

function yspec(    k, i, j, n, a, nv, w, f, vals, fields, nf2, seen, tab, line, w2) {
	print "/*"
	print " * Made from share/arcana/jobs.yaml by share/arcana/jobs.awk"
	print " * (out=yspec): not to be edited.  A change of arcana-jobs's submit"
	print " * (its struct, as cblink-gen makes it from arcana-jobs-kinds) made"
	print " * the job-spec the agent's queue takes, field by field as jobs.yaml"
	print " * names them."
	print " */"
	print ""
	print "#include <errno.h>"
	print "#include <string.h>"
	print ""
	print "#include <arcana.h>"
	print ""
	print "#include \"collect.h\""
	print ""
	# The enumerations whose words the job-spec takes as text.
	for (k = 1; k <= nk; k++) {
		n = split(kv[k], a, " ")
		for (j = 1; j <= n; j++) {
			split(a[j], w, "=")
			if (w[1] == "action")
				continue
			tab = cname(kk[k]) "_" w[1]
			nv = split(w[2], vals, "|")
			printf "static const char *const %s[] = {\n", tab
			line = "\t"
			for (i = 1; i <= nv; i++) {
				w2 = "\"" vals[i] "\","
				if (length(line) + length(w2) > 70) {
					print line
					line = "\t"
				}
				line = line (line == "\t" ? "" : " ") w2
			}
			print line
			print "};"
		}
	}
	print ""
	print "/*"
	print " * Change c made job-spec sp, its arrays a's.  0, or EINVAL: no kind,"
	print " * or one not given."
	print " */"
	print "int"
	print "yjobs_spec(const struct arcana_jobs_submit_input_change *in,"
	print "    cbl_yarena *a, struct arc_job_spec *sp)"
	print "{"
	print "\tstruct arc_variable *vars = NULL;"
	print "\tsize_t nv = 0;"
	print ""
	print "\tmemset(sp, 0, sizeof(*sp));"
	print "\tsp->has_kind = true;"
	print "\tswitch (in->kind) {"
	for (k = 1; k <= nk; k++) {
		printf "\tcase ARCANA_JOBS_SUBMIT_INPUT_CHANGE_KIND_%s: {\n", uname(kk[k])
		printf "\t\tconst struct arcana_jobs_submit_input_change_%s *c =\n", cname(kk[k])
		printf "\t\t    in->%s;\n\n", cname(kk[k])
		print "\t\tif (c == NULL)"
		print "\t\t\treturn (EINVAL);"
		printf "\t\tsp->kind = ARC_JOB_KIND_%s;\n", uname(kk[k])
		fields = kn[k] " " ku[k]
		if (fields ~ /(^| )(set|unset)( |$)/) {
			print "\t\tif ((vars = cbl_yarena_alloc(a, (c->set.n + c->unset.n +"
			print "\t\t    1) * sizeof(*vars))) == NULL)"
			print "\t\t\treturn (ENOMEM);"
			print "\t\tmemset(vars, 0, (c->set.n + c->unset.n + 1) *"
			print "\t\t    sizeof(*vars));"
		}
		nf2 = split(fields, a, " ")
		delete seen
		for (j = 1; j <= nf2; j++)
			if ((i = fidx(a[j])) > 0 && !(a[j] in seen)) {
				seen[a[j]] = 1
				yspec_field(k, i)
			}
		if (fields ~ /(^| )(set|unset)( |$)/) {
			print "\t\tsp->variables.n = nv;"
			print "\t\tsp->variables.v = vars;"
		}
		print "\t\treturn (0);"
		print "\t}"
	}
	print "\tdefault:"
	print "\t\treturn (EINVAL);"
	print "\t}"
	print "}"
}
