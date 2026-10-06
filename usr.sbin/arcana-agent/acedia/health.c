/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Acedia: how the disks are, as they say themselves.  An NVMe disk is
 * asked with nvmecontrol(8), which the base system has; any other with
 * smartctl(8) of smartmontools, when the host has it.  And the swap
 * the host has, as swapinfo(8) lists it.
 */

#include <sys/param.h>
#include <sys/sysctl.h>
#include <sys/wait.h>

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ucl.h>
#include <unistd.h>

#include "agent.h"

/*
 * A program this daemon has no option for: in the directory it was
 * told to look in (-2), or where the system keeps such.  NULL when the
 * host has none.
 */
const char *
tool(struct work *w, const char *name)
{
	static const char *const dirs[] = { "/sbin", "/usr/sbin", "/bin",
	    "/usr/bin", "/usr/local/sbin", "/usr/local/bin" };
	char	*path;
	size_t	 i;

	if (opts.tools_dir != NULL) {
		path = wfmt(w, "%s/%s", opts.tools_dir, name);
		return (access(path, X_OK) == 0 ? path : NULL);
	}
	for (i = 0; i < nitems(dirs); i++) {
		path = wfmt(w, "%s/%s", dirs[i], name);
		if (access(path, X_OK) == 0)
			return (path);
	}
	return (NULL);
}

static void
put(ucl_object_t *o, const char *key, const char *v)
{

	ucl_object_insert_key(o, ucl_object_fromstring(v), key, 0, false);
}

static void
putn(ucl_object_t *o, const char *key, int64_t v)
{

	ucl_object_insert_key(o, ucl_object_fromint(v), key, 0, false);
}

/* "Temperature:  312 K, 38.85 C, ..." gives 312; -1 when not there. */
static int64_t
after(const char *text, const char *label)
{
	const char	*p;

	if ((p = strstr(text, label)) == NULL)
		return (-1);
	p += strlen(label);
	p += strspn(p, ": \t");
	if (!isdigit((unsigned char)*p))
		return (-1);
	return (strtoll(p, NULL, 0));
}

/* The SMART / Health Information log page of an NVMe disk. */
static void
nvme(struct work *w, ucl_object_t *o, const char *name)
{
	struct execres	 res;
	const char	*bin;
	char		*argv[6];
	int64_t		 v;

	if ((bin = tool(w, "nvmecontrol")) == NULL) {
		put(o, "note", "the host has no nvmecontrol");
		return;
	}
	argv[0] = (char *)(uintptr_t)bin;
	argv[1] = (char *)(uintptr_t)"logpage";
	argv[2] = (char *)(uintptr_t)"-p";
	argv[3] = (char *)(uintptr_t)"2";
	/* The log is the controller's: nda0 and nvd0 are of nvme0. */
	argv[4] = wfmt(w, "nvme%s", name + strcspn(name, "0123456789"));
	argv[5] = NULL;
	if (run_exec(w, argv, &res) != 0 || res.out == NULL) {
		put(o, "note", wtext(w, exec_error(w, &res, "nvmecontrol")));
		return;
	}
	put(o, "by", "nvmecontrol");
	/* Its flags are listed under it by the same names: a line's
	 * own begins the line. */
	v = after(res.out, "Critical Warning State");
	ucl_object_insert_key(o, ucl_object_frombool(v == 0), "ok", 0, false);
	if ((v = after(res.out, "\nTemperature")) > 0)
		putn(o, "temperature", v - 273);
	if ((v = after(res.out, "\nAvailable spare")) >= 0)
		putn(o, "spare_pct", v);
	if ((v = after(res.out, "Percentage used")) >= 0)
		putn(o, "used_pct", v);
	if ((v = after(res.out, "Power on hours")) >= 0)
		putn(o, "power_on_hours", v);
	if ((v = after(res.out, "Unsafe shutdowns")) >= 0)
		putn(o, "unsafe_shutdowns", v);
	if ((v = after(res.out, "Media errors")) >= 0)
		putn(o, "media_errors", v);
	if ((v = after(res.out, "Power cycles")) >= 0)
		putn(o, "power_cycles", v);
}

/* What smartctl(8) says of a disk, from its JSON. */
static void
smart(struct work *w, ucl_object_t *o, const char *name)
{
	static const struct {
		int		 id;
		const char	*key;
	} attrs[] = {
		{ 5, "reallocated" }, { 197, "pending" },
		{ 198, "uncorrectable" }, { 199, "crc_errors" },
		{ 177, "wear_level" }, { 231, "life_left" },
		{ 233, "media_wearout" },
	};
	struct execres		 res;
	struct ucl_parser	*p;
	const ucl_object_t	*top, *t, *a;
	ucl_object_iter_t	 it;
	const char		*bin;
	char			*argv[6];
	size_t			 i;

	if ((bin = tool(w, "smartctl")) == NULL) {
		put(o, "note", "the host has no smartctl: pkg install "
		    "smartmontools");
		return;
	}
	argv[0] = (char *)(uintptr_t)bin;
	argv[1] = (char *)(uintptr_t)"-H";
	argv[2] = (char *)(uintptr_t)"-A";
	argv[3] = (char *)(uintptr_t)"--json=c";
	argv[4] = wfmt(w, "/dev/%s", name);
	argv[5] = NULL;
	/* Its exit status is bits of what it found: the JSON says. */
	(void)run_exec(w, argv, &res);
	if (res.out == NULL || res.out[0] != '{') {
		put(o, "note", wtext(w, exec_error(w, &res, "smartctl")));
		return;
	}
	p = ucl_parser_new(UCL_PARSER_NO_IMPLICIT_ARRAYS |
	    UCL_PARSER_DISABLE_MACRO | UCL_PARSER_NO_TIME);
	top = ucl_parser_add_string(p, res.out, 0) ? ucl_parser_get_object(
	    p) : NULL;
	ucl_parser_free(p);
	if (top == NULL) {
		put(o, "note", "what smartctl said is not JSON");
		return;
	}
	put(o, "by", "smartctl");
	if ((t = ucl_object_lookup_path(top, "smart_status.passed")) != NULL)
		ucl_object_insert_key(o, ucl_object_frombool(
		    ucl_object_toboolean(t)), "ok", 0, false);
	else
		put(o, "note", "the disk does not say how it is (no SMART)");
	if ((t = ucl_object_lookup_path(top, "temperature.current")) != NULL)
		putn(o, "temperature", ucl_object_toint(t));
	if ((t = ucl_object_lookup_path(top, "power_on_time.hours")) != NULL)
		putn(o, "power_on_hours", ucl_object_toint(t));
	if ((t = ucl_object_lookup_path(top, "power_cycle_count")) != NULL)
		putn(o, "power_cycles", ucl_object_toint(t));
	it = NULL;
	while ((a = ucl_object_iterate(ucl_object_lookup_path(top,
	    "ata_smart_attributes.table"), &it, true)) != NULL)
		for (i = 0; i < nitems(attrs); i++)
			if (ucl_object_toint(ucl_object_lookup(a, "id")) ==
			    attrs[i].id && (t = ucl_object_lookup_path(a,
			    "raw.value")) != NULL)
				putn(o, attrs[i].key, ucl_object_toint(t));
	ucl_object_unref((ucl_object_t *)(uintptr_t)top);
}

/* {"disks":[{"name","by","ok","temperature",...}]}: each of kern.disks. */
int
do_health(struct work *w, struct arc_storage_rsp *rsp)
{
	ucl_object_t	*top, *arr, *o;
	unsigned char	*json;
	char		 names[4096], *it, *name;
	size_t		 len;

	rsp->has_ok = true;
	rsp->ok = false;
	len = sizeof(names) - 1;
	if (opts.tools_dir != NULL) {
		/* Stand-ins are of stand-in disks. */
		strlcpy(names, "nda0 ada0 da0", sizeof(names));
	} else if (sysctlbyname("kern.disks", names, &len, NULL, 0) == -1) {
		rsp->error = wfmt(w, "kern.disks: %s", strerror(errno));
		return (0);
	} else
		names[len] = '\0';
	top = ucl_object_typed_new(UCL_OBJECT);
	arr = ucl_object_typed_new(UCL_ARRAY);
	for (it = names; (name = strsep(&it, " ")) != NULL; ) {
		if (name[0] == '\0' || strlen(name) > 32 || strncmp(name, "cd",
		    2) == 0 || strncmp(name, "md", 2) == 0)
			continue;
		o = ucl_object_typed_new(UCL_OBJECT);
		put(o, "name", wtext(w, name));
		if (strncmp(name, "nda", 3) == 0 || strncmp(name, "nvd", 3) ==
		    0)
			nvme(w, o, name);
		else if (strncmp(name, "vtbd", 4) == 0 || strncmp(name, "zvol",
		    4) == 0)
			put(o, "note", "a virtual disk: it has no health of "
			    "its own");
		else
			smart(w, o, name);
		ucl_array_append(arr, o);
	}
	ucl_object_insert_key(top, arr, "disks", 0, false);
	json = ucl_object_emit(top, UCL_EMIT_JSON_COMPACT);
	ucl_object_unref(top);
	if (json == NULL) {
		rsp->error = "cannot build the reply";
		return (0);
	}
	rsp->json = wtext(w, wadopt(w, json));
	rsp->ok = true;
	return (0);
}

/* The swap devices, as swapinfo -k lists them: [{device,size,used}]. */
ucl_object_t *
swap_list(struct work *w)
{
	struct execres	 res;
	ucl_object_t	*arr, *o;
	char		*argv[3], *text, *line, *dev, *size, *used;

	arr = ucl_object_typed_new(UCL_ARRAY);
	argv[0] = (char *)(uintptr_t)opts.swapinfo_bin;
	argv[1] = (char *)(uintptr_t)"-k";
	argv[2] = NULL;
	if (run_exec(w, argv, &res) != 0 || res.out == NULL)
		return (arr);
	text = wstrdup(w, res.out);
	while ((line = strsep(&text, "\n")) != NULL) {
		if (strncmp(line, "/dev/", 5) != 0)
			continue;
		dev = strsep(&line, " \t");
		while (line != NULL && (size = strsep(&line, " \t")) != NULL &&
		    *size == '\0')
			;
		while (line != NULL && (used = strsep(&line, " \t")) != NULL &&
		    *used == '\0')
			;
		if (line == NULL)
			continue;
		o = ucl_object_typed_new(UCL_OBJECT);
		put(o, "device", wtext(w, dev));
		putn(o, "size", strtoll(size, NULL, 10) * 1024);
		putn(o, "used", strtoll(used, NULL, 10) * 1024);
		ucl_array_append(arr, o);
	}
	return (arr);
}

/*
 * The helper's "zfs-pipe zfs snapshot target from recursive": zfs send
 * of the snapshot into zfs receive of the target, which is not mounted
 * and must not be there.  from is the snapshot both have, for what
 * changed since, or "-"; recursive "r" for the datasets under it too.
 */
int
zfs_pipe(int argc, char **argv)
{
	const char	*sv[8], *rv[6];
	pid_t		 a, b;
	int		 fd[2], st, sa, n;

	if (argc != 6)
		return (2);
	n = 0;
	sv[n++] = argv[1];
	sv[n++] = "send";
	if (strcmp(argv[5], "r") == 0)
		sv[n++] = "-R";
	if (strcmp(argv[4], "-") != 0) {
		sv[n++] = "-i";
		sv[n++] = argv[4];
	}
	sv[n++] = argv[2];
	sv[n] = NULL;
	rv[0] = argv[1];
	rv[1] = "receive";
	rv[2] = "-u";
	rv[3] = argv[3];
	rv[4] = NULL;
	if (pipe(fd) == -1 || (a = fork()) == -1)
		return (1);
	if (a == 0) {
		dup2(fd[1], STDOUT_FILENO);
		close(fd[0]);
		close(fd[1]);
		execv(sv[0], (char *const *)(uintptr_t)sv);
		_exit(127);
	}
	if ((b = fork()) == -1)
		return (1);
	if (b == 0) {
		dup2(fd[0], STDIN_FILENO);
		close(fd[0]);
		close(fd[1]);
		execv(rv[0], (char *const *)(uintptr_t)rv);
		_exit(127);
	}
	close(fd[0]);
	close(fd[1]);
	sa = st = 0;
	(void)waitpid(a, &sa, 0);
	(void)waitpid(b, &st, 0);
	/* What receive refused it has said itself; send then only
	 * lost whom it wrote to. */
	if (!WIFEXITED(st) || WEXITSTATUS(st) != 0)
		return (1);
	if (!WIFEXITED(sa) || WEXITSTATUS(sa) != 0) {
		fprintf(stderr, "zfs send did not finish\n");
		return (1);
	}
	return (0);
}
