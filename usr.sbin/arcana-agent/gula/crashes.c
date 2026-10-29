/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Gula: the cores the kernel dumped (core(5)), where kern.corefile
 * says: each with its program, pid, size and time, the largest a
 * measure of what the process held when it died.  Asked for one, its
 * backtrace, every thread's, as lldb(1) of the base system reads the
 * core with its program in batch; and the signal's code the core keeps,
 * which tells a SIGBUS of a fault the kernel could find no memory for
 * (BUS_OOMERR) from one of a bad address.  Nothing is changed: a core
 * is read, not moved nor taken away.
 */

#include <sys/param.h>
#include <sys/stat.h>
#include <sys/sysctl.h>

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <ucl.h>

#include "agent.h"

#define	CORES_MAX	200
#define	BT_MAX		(512 * 1024)	/* lldb's words kept */

/* Where cores go: kern.corefile's directory; NULL when it names none
 * (each in its process's own directory). */
static const char *
core_dir(struct work *w, char *pattern, size_t len)
{
	char	*slash;
	size_t	 n;

	n = len;
	if (sysctlbyname("kern.corefile", pattern, &n, NULL, 0) != 0)
		return (NULL);
	pattern[MIN(n, len - 1)] = '\0';
	if (pattern[0] != '/' || (slash = strrchr(pattern, '/')) == NULL)
		return (NULL);
	if (strchr(pattern, '%') != NULL && strchr(pattern, '%') < slash)
		return (NULL);
	return (wstrndup(w, pattern, slash == pattern ? 1 :
	    (size_t)(slash - pattern)));
}

/* A core's name as a directory entry: no slash, not hidden, a core. */
static bool
core_name_ok(const char *s)
{

	return (s != NULL && s[0] != '\0' && s[0] != '.' && strlen(s) < 200 &&
	    strchr(s, '/') == NULL && (strstr(s, ".core") != NULL ||
	    strcmp(s, "core") == 0));
}

/* The program a core is of, from its name (%N.%P.core, %N.core): its
 * first word; then the places a program of that name is. */
static const char *
core_program(struct work *w, const char *core)
{
	static const char *const dirs[] = { "/usr/local/sbin",
	    "/usr/local/bin", "/usr/sbin", "/usr/bin", "/sbin", "/bin",
	    "/usr/libexec", "/usr/local/libexec" };
	const char	*name, *p;
	size_t		 i;

	name = wstrndup(w, core, strcspn(core, "."));
	for (i = 0; i < nitems(dirs); i++) {
		p = wfmt(w, "%s/%s", dirs[i], name);
		if (access(p, X_OK) == 0)
			return (p);
	}
	return (NULL);
}

/*
 * The cores of dir into arr, each with where it is; *othersp counts
 * the directory's other files; false, with why in *errp, when the
 * directory cannot be read.
 */
static bool
cores_list(struct work *w, const char *dir, ucl_object_t *arr, int *othersp,
    ucl_object_t *others, const char **errp)
{
	ucl_object_t	*o;
	DIR		*d;
	struct dirent	*de;
	struct stat	 st;
	char		 pid[16];
	const char	*p;
	int		 n;

	if ((d = opendir(dir)) == NULL) {
		*errp = wfmt(w, "%s: %s", dir, strerror(errno));
		return (false);
	}
	n = 0;
	while ((de = readdir(d)) != NULL && n < CORES_MAX) {
		if (fstatat(dirfd(d), de->d_name, &st, AT_SYMLINK_NOFOLLOW) != 0
		    || !S_ISREG(st.st_mode))
			continue;
		if (!core_name_ok(de->d_name)) {
			if ((*othersp)++ < 20 && others != NULL)
				ucl_array_append(others, ucl_object_fromstring(wfmt(
				    w, "%s/%s (%jd bytes)", strcmp(dir, "/") == 0 ? "" :
				    dir, de->d_name, (intmax_t)st.st_size)));
			continue;
		}
		o = ucl_object_typed_new(UCL_OBJECT);
		ucl_object_insert_key(o, ucl_object_fromstring(de->d_name),
		    "name", 0, true);
		ucl_object_insert_key(o, ucl_object_fromstring(dir), "directory",
		    0, true);
		ucl_object_insert_key(o, ucl_object_fromlstring(de->d_name,
		    strcspn(de->d_name, ".")), "program", 0, false);
		/* %N.%P.core: its pid, when the name has one. */
		p = strchr(de->d_name, '.');
		if (p != NULL && sscanf(p + 1, "%15[0-9]", pid) == 1)
			ucl_object_insert_key(o, ucl_object_fromint(atoi(pid)),
			    "pid", 0, false);
		ucl_object_insert_key(o, ucl_object_fromint(st.st_size),
		    "size", 0, false);
		ucl_object_insert_key(o, ucl_object_fromint(st.st_mtime),
		    "time", 0, false);
		ucl_array_append(arr, o);
		n++;
	}
	closedir(d);
	return (true);
}

/* lldb's backtrace of every thread of a core, and the signal's code. */
static int
core_backtrace(struct work *w, const char *dir, const char *core,
    const char *program, ucl_object_t *top, const char **errp)
{
	struct execres	 res;
	const char	*lldb, *gdb, *path;
	char		*argv[20], *text;
	int		 n, step;

	if (!core_name_ok(core)) {
		*errp = "a core is named as the list has it";
		return (-1);
	}
	path = wfmt(w, "%s/%s", strcmp(dir, "/") == 0 ? "" : dir, core);
	if (program == NULL || program[0] == '\0')
		program = core_program(w, core);
	if (program == NULL || program[0] != '/' || access(program, X_OK) !=
	    0) {
		*errp = wfmt(w, "the program of %s is not found: name it", core);
		return (-1);
	}
	if ((lldb = tool(w, "lldb")) == NULL) {
		*errp = "the host has no lldb(1): its base system is built "
		    "without it";
		return (-1);
	}
	n = 0;
	argv[n++] = (char *)(uintptr_t)lldb;
	argv[n++] = (char *)(uintptr_t)"--batch";
	argv[n++] = (char *)(uintptr_t)"--no-lldbinit";
	/* The symbols a port keeps apart (WITH_DEBUG): beside the base
	 * system's. */
	argv[n++] = (char *)(uintptr_t)"-O";
	argv[n++] = (char *)(uintptr_t)"settings set target.debug-file-search-"
	    "paths /usr/local/lib/debug /usr/lib/debug";
	argv[n++] = (char *)(uintptr_t)"-c";
	argv[n++] = (char *)(uintptr_t)path;
	argv[n++] = (char *)(uintptr_t)"-o";
	argv[n++] = (char *)(uintptr_t)"thread list";
	argv[n++] = (char *)(uintptr_t)"-o";
	argv[n++] = (char *)(uintptr_t)"thread backtrace all";
	argv[n++] = (char *)(uintptr_t)"-o";
	argv[n++] = (char *)(uintptr_t)"thread siginfo";
	argv[n++] = (char *)(uintptr_t)"--";
	argv[n++] = (char *)(uintptr_t)program;
	argv[n] = NULL;
	step = step_begin(w, STEP_EXEC, "lldb", "%s of %s", core,
	    program);
	(void)run_exec_max(w, argv, &res, BT_MAX);
	text = wfmt(w, "%.*s%.*s", (int)res.outlen, res.out != NULL ? res.out :
	    "", (int)res.errlen, res.err != NULL ? res.err : "");
	step_end(w, step, strstr(text, "error:") == NULL, NULL);
	/* gdb too, when it is installed: it reads the signal's code from a
	 * FreeBSD core (si_code 100, BUS_OOMERR, is a page fault the kernel
	 * found no memory for), which lldb does not; and what lldb could
	 * not read. */
	if ((gdb = tool(w, "gdb")) != NULL) {
		n = 0;
		argv[n++] = (char *)(uintptr_t)gdb;
		argv[n++] = (char *)(uintptr_t)"-batch";
		argv[n++] = (char *)(uintptr_t)"-nx";
		argv[n++] = (char *)(uintptr_t)"-ex";
		argv[n++] = (char *)(uintptr_t)"set debug-file-directory "
		    "/usr/local/lib/debug:/usr/lib/debug";
		argv[n++] = (char *)(uintptr_t)"-ex";
		argv[n++] = (char *)(uintptr_t)"info threads";
		argv[n++] = (char *)(uintptr_t)"-ex";
		argv[n++] = (char *)(uintptr_t)"thread apply all bt";
		argv[n++] = (char *)(uintptr_t)"-ex";
		argv[n++] = (char *)(uintptr_t)"print $_siginfo";
		argv[n++] = (char *)(uintptr_t)program;
		argv[n++] = (char *)(uintptr_t)path;
		argv[n] = NULL;
		step = step_begin(w, STEP_EXEC, "gdb", "%s of %s",
		    core, program);
		(void)run_exec_max(w, argv, &res, BT_MAX);
		text = wfmt(w, "%s\n%.*s%.*s", text, (int)res.outlen, res.out !=
		    NULL ? res.out : "", (int)res.errlen, res.err != NULL ?
		    res.err : "");
		step_end(w, step, res.outlen > 0, NULL);
	}
	if (text[0] == '\0') {
		*errp = wtext(w, exec_error(w, &res, "lldb"));
		return (-1);
	}
	ucl_object_insert_key(top, ucl_object_fromstring(core), "core", 0,
	    false);
	ucl_object_insert_key(top, ucl_object_fromstring(program), "program",
	    0, false);
	ucl_object_insert_key(top, ucl_object_fromstring(text), "backtrace", 0,
	    false);
	if (res.truncated)
		ucl_object_insert_key(top, ucl_object_frombool(true),
		    "truncated", 0, false);
	return (0);
}

/*
 * The cores, or with names "backtrace" core [program] one's backtrace
 * besides.
 */
void
do_crashes(struct work *w, const char *const *names, size_t n,
    struct json_rsp *rsp)
{
	static const char *const elsewhere[] = { "/", "/root", "/tmp",
	    "/var/tmp", "/var/db/bird", "/usr/local/etc/bird" };
	ucl_object_t	*top, *cores, *notes, *onames;
	char		 pattern[MAXPATHLEN], *json;
	const char	*dir, *err;
	size_t		 i;
	int		 others;

	top = ucl_object_typed_new(UCL_OBJECT);
	notes = ucl_object_typed_new(UCL_ARRAY);
	dir = core_dir(w, pattern, sizeof(pattern));
	ucl_object_insert_key(top, ucl_object_fromstring(pattern),
	    "corefile", 0, false);
	cores = ucl_object_typed_new(UCL_ARRAY);
	others = 0;
	if (dir == NULL)
		ucl_array_append(notes, ucl_object_fromstring("kern.corefile "
		    "names no directory of its own: each core is where its "
		    "process ran"));
	else {
		ucl_object_insert_key(top, ucl_object_fromstring(dir),
		    "directory", 0, false);
		onames = ucl_object_typed_new(UCL_ARRAY);
		err = NULL;
		if (!cores_list(w, dir, cores, &others, onames, &err))
			ucl_array_append(notes, ucl_object_fromstring(err));
		else if (others > 0)
			ucl_array_append(notes, ucl_object_fromstring(wfmt(w,
			    "%s holds %d other file%s", dir, others, others == 1 ?
			    "" : "s")));
		ucl_object_insert_key(top, onames, "others", 0, false);
	}
	/* Where else a core may lie: a daemon's working directory, /,
	 * where a %N.core of an earlier setting went; and where a hand
	 * puts one aside. */
	for (i = 0; i < nitems(elsewhere); i++) {
		if (dir != NULL && strcmp(dir, elsewhere[i]) == 0)
			continue;
		err = NULL;
		others = 0;
		(void)cores_list(w, elsewhere[i], cores, &others, NULL, &err);
	}
	/* And each home directory. */
	{
		DIR		*d;
		struct dirent	*de;

		if ((d = opendir("/home")) != NULL) {
			while ((de = readdir(d)) != NULL) {
				if (de->d_name[0] == '.' || de->d_type != DT_DIR)
					continue;
				err = NULL;
				others = 0;
				(void)cores_list(w, wfmt(w, "/home/%s", de->d_name),
				    cores, &others, NULL, &err);
			}
			closedir(d);
		}
	}
	ucl_object_insert_key(top, cores, "cores", 0, false);
	ucl_object_insert_key(top, notes, "notes", 0, false);
	if (n >= 2 && strcmp(names[0], "backtrace") == 0) {
		const ucl_object_t	*c;
		ucl_object_iter_t	 it = NULL;
		const char		*where = dir;

		/* The core named, where the list found it. */
		while ((c = ucl_object_iterate(cores, &it, true)) != NULL)
			if (ucl_object_tostring(ucl_object_lookup(c, "name")) !=
			    NULL && strcmp(ucl_object_tostring(ucl_object_lookup(
			    c, "name")), names[1]) == 0)
				where = ucl_object_tostring(ucl_object_lookup(c,
				    "directory"));
		err = NULL;
		if (where == NULL || core_backtrace(w, where, names[1], n >= 3 ?
		    names[2] : NULL, top, &err) != 0) {
			ucl_object_unref(top);
			rsp->ok = false;
			rsp->error = err != NULL ? err : "no directory of cores";
			return;
		}
	}
	json = (char *)ucl_object_emit(top, UCL_EMIT_JSON_COMPACT);
	ucl_object_unref(top);
	if (json == NULL) {
		rsp->ok = false;
		rsp->error = "out of memory";
		return;
	}
	rsp->json = wstrdup(w, json);
	free(json);
	rsp->ok = true;
}
