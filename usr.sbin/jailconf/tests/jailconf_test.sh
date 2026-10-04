#
# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
#
# jailconf(8) on files in the test's work directory.
#

# The program next to the tests in the build tree, else the "jailconf"
# configuration variable, else the installed one.
setup()
{
	JC="$(atf_get_srcdir)/../jailconf"
	[ -f "$JC" -a -x "$JC" ] ||
	    JC=$(atf_config_get jailconf /usr/local/sbin/jailconf)
}

conf()
{
	cat > jail.conf <<'CONF'
# Lab jails
exec.start = "/bin/sh /etc/rc";
path = "/jails/$name";

web {
	ip4.addr = 10.0.0.10, "10.0.0.11";
	persist;
}
CONF
}

atf_test_case add
add_head()
{
	atf_set "descr" "+= extends the list in place and prints nothing"
}
add_body()
{
	setup
	conf
	atf_check -s exit:0 -o empty -e empty \
	    "$JC" -f jail.conf web ip4.addr+=10.0.0.12
	atf_check -o match:'^	ip4.addr = 10.0.0.10, "10.0.0.11", "10.0.0.12";$' \
	    cat jail.conf
	atf_check -o match:'^# Lab jails$' cat jail.conf
}

atf_test_case remove
remove_head()
{
	atf_set "descr" "-= removes one value, then the statement"
}
remove_body()
{
	setup
	conf
	atf_check "$JC" -f jail.conf web ip4.addr-=10.0.0.10
	atf_check -o match:'^	ip4.addr = "10.0.0.11";$' cat jail.conf
	atf_check "$JC" -f jail.conf web ip4.addr-=10.0.0.11
	atf_check -s exit:1 -o empty grep ip4.addr jail.conf
	atf_check -o match:'^	persist;$' cat jail.conf
}

atf_test_case dry_run
dry_run_head()
{
	atf_set "descr" "-n prints a unified diff and writes nothing"
}
dry_run_body()
{
	setup
	conf
	cp jail.conf before
	cat > expected <<'EOF2'
--- jail.conf
+++ jail.conf
@@ -5,4 +5,5 @@
 web {
 	ip4.addr = 10.0.0.10, "10.0.0.11";
 	persist;
+	ip6.addr = "2001:db8::10";
 }
EOF2
	atf_check -o file:expected "$JC" -n -f jail.conf web \
	    ip6.addr+=2001:db8::10
	atf_check cmp -s before jail.conf
}

atf_test_case verbose
verbose_head()
{
	atf_set "descr" "-v writes and prints the diff"
}
verbose_body()
{
	setup
	conf
	atf_check -o match:'^\+	exec.start \+= "/usr/local/bin/app";$' \
	    "$JC" -v -f jail.conf web exec.start+=/usr/local/bin/app
	atf_check -o match:'exec.start \+= "/usr/local/bin/app"' cat jail.conf
}

atf_test_case included_file
included_file_head()
{
	atf_set "descr" "A jail defined in an included file is edited there"
}
included_file_body()
{
	setup
	mkdir inc
	printf 'mail {\n\tip4.addr = 10.0.0.30;\n}\n' > inc/mail.inc
	printf '.include "%s/inc/*.inc";\n' "$(pwd)" > jail.conf
	cp jail.conf before
	atf_check "$JC" -f jail.conf mail ip4.addr+=10.0.0.31
	atf_check -o inline:'mail {\n\tip4.addr = 10.0.0.30, "10.0.0.31";\n}\n' \
	    cat inc/mail.inc
	atf_check cmp -s before jail.conf
}

atf_test_case errors
errors_head()
{
	atf_set "descr" "Failures leave the file alone and say why"
}
errors_body()
{
	setup
	conf
	cp jail.conf before
	atf_check -s exit:1 -e match:"no jail 'db'" \
	    "$JC" -f jail.conf db ip4.addr+=10.0.0.1
	atf_check -s exit:1 -e match:'not a valid ip4.addr' \
	    "$JC" -f jail.conf web ip4.addr+=10.0.0.300
	atf_check -s exit:1 -e match:'not a valid ip6.addr' \
	    "$JC" -f jail.conf web ip6.addr+=10.0.0.1
	atf_check -s exit:1 -e match:'already in ip4.addr' \
	    "$JC" -f jail.conf web ip4.addr+=em0\|10.0.0.11/24
	atf_check -s exit:1 -e match:'shared by all jails' \
	    "$JC" -f jail.conf web exec.start-=/bin/sh\ /etc/rc
	atf_check -s exit:1 -e match:'No such file' \
	    "$JC" -f missing.conf web ip4.addr+=10.0.0.1
	atf_check -s exit:2 -e match:usage "$JC" -f jail.conf web ip4.addr
	atf_check -s exit:2 -e match:usage "$JC" web
	atf_check cmp -s before jail.conf
	printf 'web {\n\tip4.addr = "10.0.0.1;\n}\n' > jail.conf
	atf_check -s exit:1 -e match:'jail.conf line 2: unterminated string' \
	    "$JC" -f jail.conf web ip4.addr+=10.0.0.2
}

atf_init_test_cases()
{
	atf_add_test_case add
	atf_add_test_case remove
	atf_add_test_case dry_run
	atf_add_test_case verbose
	atf_add_test_case included_file
	atf_add_test_case errors
}
