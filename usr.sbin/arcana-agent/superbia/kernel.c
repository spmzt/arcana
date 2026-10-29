/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * The kernel's modules and its memory.  What is loaded is read from the
 * kernel itself (kldnext(2), kldstat(2), modstat(2)), what its memory
 * went to from memstat(3), as vmstat -m and -z have it.  A module is
 * loaded and unloaded with kldload(8) and kldunload(8), and kept for
 * the next boot in rc.conf's kld_list.
 */

#include <sys/param.h>
#include <sys/linker.h>
#include <sys/module.h>
#include <sys/sysctl.h>

#include <ctype.h>
#include <dirent.h>
#include <memstat.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ucl.h>

#include "agent.h"

#define	KERNEL_TYPES	48	/* of malloc types and of zones: the largest */
#define	KERNEL_AVAIL	2000	/* module files offered, at most */
#define	KERNEL_MODS	4000	/* modules named of one file, at most */

struct use {
	const char	*name;
	uint64_t	 bytes, count, requests, size, free;
};

static void
put(ucl_object_t *o, const char *key, const char *v)
{

	if (v != NULL)
		ucl_object_insert_key(o, ucl_object_fromstring(v), key, 0,
		    false);
}

static void
putn(ucl_object_t *o, const char *key, uint64_t v)
{

	ucl_object_insert_key(o, ucl_object_fromint((int64_t)v), key, 0,
	    false);
}

static int
by_bytes(const void *a, const void *b)
{
	const struct use	*x = a, *y = b;

	return (x->bytes < y->bytes ? 1 : x->bytes > y->bytes ? -1 :
	    strcmp(x->name, y->name));
}

static int
by_name(const void *a, const void *b)
{

	return (strcmp(*(const char *const *)a, *(const char *const *)b));
}

/* A module's name is one kldload(8) finds by itself: no path. */
bool
kmod_name_ok(const char *s)
{

	if (s == NULL || s[0] == '\0' || s[0] == '-' || s[0] == '.' ||
	    strlen(s) > 64)
		return (false);
	for (; *s != '\0'; s++)
		if (!isalnum((unsigned char)*s) && strchr("_.-", *s) == NULL)
			return (false);
	return (true);
}

/*
 * Is the module in the kernel now: as a file, or as a module of one?
 * Built into a kernel, some register no module of their name (a kernel
 * with IPFIREWALL_NAT64 lists no ipfw_nat64; SCTP's MOD_LOAD fails with
 * EEXIST when it is built in, and the module goes): a sysctl that only
 * the feature's own code creates says it is there.
 */
bool
kmod_loaded(const char *name)
{
	static const struct {
		const char	*mod, *oid;
	} builtin[] = {
		/* netpfil/ipfw/nat64/ip_fw_nat64.c */
		{ "ipfw_nat64", "net.inet.ip.fw.nat64_direct_output" },
		/* netinet/sctp_sysctl.c, FEATURE(sctp) */
		{ "sctp", "kern.features.sctp" },
	};
	char	file[80];
	size_t	i, len;

	snprintf(file, sizeof(file), "%s%s", name, strstr(name, ".ko") ==
	    NULL ? ".ko" : "");
	if (kldfind(file) >= 0 || modfind(name) >= 0)
		return (true);
	for (i = 0; i < nitems(builtin); i++)
		if (strcmp(name, builtin[i].mod) == 0) {
			len = 0;
			return (sysctlbyname(builtin[i].oid, NULL, &len, NULL,
			    0) == 0);
		}
	return (false);
}

/*
 * What the kernel's memory went to: its malloc(9) types, or its uma(9)
 * zones, the largest first, and what all of them hold together.
 */
static ucl_object_t *
memory_of(struct work *w, bool zones, uint64_t *totalp)
{
	struct memory_type_list	*mtl;
	struct memory_type	*mt;
	struct use		*u;
	ucl_object_t		*arr, *o;
	size_t			 n, cap, i;

	arr = ucl_object_typed_new(UCL_ARRAY);
	*totalp = 0;
	if ((mtl = memstat_mtl_alloc()) == NULL)
		return (arr);
	if ((zones ? memstat_sysctl_uma(mtl, 0) : memstat_sysctl_malloc(mtl,
	    0)) < 0) {
		memstat_mtl_free(mtl);
		return (arr);
	}
	cap = 0;
	for (mt = memstat_mtl_first(mtl); mt != NULL; mt = memstat_mtl_next(mt))
		cap++;
	u = wcalloc(w, cap + 1, sizeof(*u));
	n = 0;
	for (mt = memstat_mtl_first(mtl); mt != NULL && n < cap;
	    mt = memstat_mtl_next(mt)) {
		u[n].name = wstrdup(w, memstat_get_name(mt));
		u[n].count = memstat_get_count(mt);
		u[n].requests = memstat_get_numallocs(mt);
		if (zones) {
			u[n].size = memstat_get_size(mt);
			u[n].free = memstat_get_free(mt);
			u[n].bytes = u[n].size * (u[n].count + u[n].free);
		} else
			u[n].bytes = memstat_get_bytes(mt);
		/*
		 * Counted on each CPU apart, a type freed on another CPU
		 * than it was allocated on can come out below nothing.
		 */
		if ((int64_t)u[n].bytes < 0)
			u[n].bytes = 0;
		if ((int64_t)u[n].count < 0)
			u[n].count = 0;
		*totalp += u[n].bytes;
		n++;
	}
	memstat_mtl_free(mtl);
	qsort(u, n, sizeof(*u), by_bytes);
	for (i = 0; i < n && i < KERNEL_TYPES && u[i].bytes > 0; i++) {
		o = ucl_object_typed_new(UCL_OBJECT);
		put(o, "name", u[i].name);
		putn(o, "bytes", u[i].bytes);
		putn(o, "count", u[i].count);
		putn(o, "requests", u[i].requests);
		if (zones) {
			putn(o, "size", u[i].size);
			putn(o, "free", u[i].free);
		}
		ucl_array_append(arr, o);
	}
	return (arr);
}

/*
 * {"files": [{"id", "name", "path", "refs", "size", "address",
 * "modules": [...]}], "available": [...], "memory":
 * {"files", "kmem_size", "kmem_map_size", "kmem_map_free", "malloc_total",
 * "malloc": [{"name", "bytes", "count", "requests"}],
 * "zones": [{"name", "bytes", "count", "free", "size", "requests"}]}},
 * in w's pool; NULL with *errp set.
 */
const char *
do_kernel(struct work *w, const char **errp)
{
	struct kld_file_stat	 st;
	struct module_stat	 ms;
	struct dirent		*de;
	ucl_object_t		*top, *files, *o, *mods, *arr, *mem;
	unsigned char		*json;
	const char		**loaded, **avail, *out;
	char			*path, *dir, *name, addr[32];
	u_long			 ul;
	uint64_t		 total, sum;
	size_t			 len, nloaded, navail, i, k;
	DIR			*d;
	int			 id, mid, step, n;

	top = ucl_object_typed_new(UCL_OBJECT);
	files = ucl_object_typed_new(UCL_ARRAY);
	loaded = wcalloc(w, 1024, sizeof(*loaded));
	nloaded = 0;
	sum = 0;
	step = step_begin(w, STEP_LIB, "kldstat(2)",
	    "every file linked into the kernel, and the modules of each");
	for (id = kldnext(0); id > 0; id = kldnext(id)) {
		memset(&st, 0, sizeof(st));
		st.version = sizeof(st);
		if (kldstat(id, &st) == -1)
			continue;
		o = ucl_object_typed_new(UCL_OBJECT);
		putn(o, "id", (uint64_t)st.id);
		put(o, "name", st.name);
		put(o, "path", st.pathname);
		putn(o, "refs", (uint64_t)st.refs);
		putn(o, "size", st.size);
		snprintf(addr, sizeof(addr), "%p", (void *)st.address);
		put(o, "address", addr);
		sum += st.size;
		if (nloaded < 1024)
			loaded[nloaded++] = wstrdup(w, st.name);
		mods = ucl_object_typed_new(UCL_ARRAY);
		n = 0;
		for (mid = kldfirstmod(id); mid > 0 && n < KERNEL_MODS;
		    mid = modfnext(mid)) {
			memset(&ms, 0, sizeof(ms));
			ms.version = sizeof(ms);
			if (modstat(mid, &ms) == -1)
				continue;
			ucl_array_append(mods, ucl_object_fromstring(ms.name));
			n++;
		}
		ucl_object_insert_key(o, mods, "modules", 0, false);
		ucl_array_append(files, o);
	}
	step_end(w, step, true, "%zu files", nloaded);
	ucl_object_insert_key(top, files, "files", 0, false);

	/* What could be loaded: the files of the module path not yet in. */
	avail = wcalloc(w, KERNEL_AVAIL, sizeof(*avail));
	navail = 0;
	len = 0;
	if (sysctlbyname("kern.module_path", NULL, &len, NULL, 0) == 0 &&
	    len > 0) {
		path = wcalloc(w, len + 1, 1);
		if (sysctlbyname("kern.module_path", path, &len, NULL, 0) != 0)
			path[0] = '\0';
		while ((dir = strsep(&path, ";")) != NULL) {
			if (dir[0] != '/' || (d = opendir(dir)) == NULL)
				continue;
			while ((de = readdir(d)) != NULL && navail <
			    KERNEL_AVAIL) {
				len = strlen(de->d_name);
				if (len < 4 || strcmp(de->d_name + len - 3,
				    ".ko") != 0)
					continue;
				for (i = 0; i < nloaded; i++)
					if (strcmp(loaded[i], de->d_name) == 0)
						break;
				name = wstrndup(w, de->d_name, len - 3);
				if (i == nloaded && kmod_name_ok(name))
					avail[navail++] = name;
			}
			closedir(d);
		}
	}
	qsort(avail, navail, sizeof(*avail), by_name);
	arr = ucl_object_typed_new(UCL_ARRAY);
	for (i = 0; i < navail; i++)
		if (i == 0 || strcmp(avail[i], avail[i - 1]) != 0)
			ucl_array_append(arr, ucl_object_fromstring(avail[i]));
	ucl_object_insert_key(top, arr, "available", 0, false);

	mem = ucl_object_typed_new(UCL_OBJECT);
	putn(mem, "files", sum);
	static const char *const ctl[] = { "kmem_size", "kmem_map_size",
	    "kmem_map_free" };
	for (k = 0; k < nitems(ctl); k++) {
		len = sizeof(ul);
		if (sysctlbyname(wfmt(w, "vm.%s", ctl[k]), &ul, &len, NULL,
		    0) == 0)
			putn(mem, ctl[k], ul);
	}
	step = step_begin(w, STEP_LIB, "memstat(3)",
	    "the kernel's malloc(9) types and uma(9) zones");
	arr = memory_of(w, false, &total);
	putn(mem, "malloc_total", total);
	ucl_object_insert_key(mem, arr, "malloc", 0, false);
	/*
	 * No sum of the zones: one is built on another's items, and the
	 * malloc(9) types are served from zones too, so their sizes
	 * together are more than the memory there is.
	 */
	arr = memory_of(w, true, &total);
	ucl_object_insert_key(mem, arr, "zones", 0, false);
	step_end(w, step, true, NULL);
	ucl_object_insert_key(top, mem, "memory", 0, false);

	json = ucl_object_emit(top, UCL_EMIT_JSON_COMPACT);
	ucl_object_unref(top);
	if (json == NULL || strlen((char *)json) > ARC_MAX_JSON) {
		free(json);
		*errp = "the kernel's modules are more than a reply carries";
		return (NULL);
	}
	out = wtext(w, wadopt(w, json));
	return (out);
}

/* Are the two the same module, with or without .ko? */
static bool
kld_same(const char *a, const char *b)
{
	size_t	n, m;

	n = strlen(a);
	if (n > 3 && strcmp(a + n - 3, ".ko") == 0)
		n -= 3;
	m = strlen(b);
	if (m > 3 && strcmp(b + m - 3, ".ko") == 0)
		m -= 3;
	return (n == m && strncmp(a, b, n) == 0);
}

/* Is the module named in rc.conf's kld_list, with or without its .ko? */
bool
kld_listed(struct work *w, const char *name)
{
	const char	*v;
	char		*words, *word, *rest;

	if ((v = rc_get(w, "kld_list")) == NULL)
		return (false);
	words = wstrdup(w, v);
	for (rest = words; (word = strsep(&rest, " \t")) != NULL; )
		if (word[0] != '\0' && kld_same(word, name))
			return (true);
	return (false);
}

/*
 * The module put in kld_list (keep) or taken out of it, however it is
 * spelt there: kept once, foo or foo.ko, and forgotten in every
 * spelling, the other words left as they were.
 */
static int
kld_list_set(struct work *w, const char *name, bool keep, const char **errp)
{
	const char	*v;
	char		*words, *word, *rest, out[1024];

	if (keep && kld_listed(w, name))
		return (0);
	out[0] = '\0';
	v = rc_get(w, "kld_list");
	words = wstrdup(w, v != NULL ? v : "");
	for (rest = words; (word = strsep(&rest, " \t")) != NULL; ) {
		if (word[0] == '\0' || (!keep && kld_same(word, name)))
			continue;
		if (strlen(out) + strlen(word) + 2 >= sizeof(out)) {
			*errp = "kld_list would be too long";
			return (-1);
		}
		snprintf(out + strlen(out), sizeof(out) - strlen(out), "%s%s",
		    out[0] != '\0' ? " " : "", word);
	}
	if (keep)
		snprintf(out + strlen(out), sizeof(out) - strlen(out), "%s%s",
		    out[0] != '\0' ? " " : "", name);
	if (out[0] == '\0') {
		rc_unset(w, "kld_list");
		return (0);
	}
	return (rc_set(w, "kld_list", "=", out, errp) != 0 ? -1 : 0);
}

/*
 * Load a module, or unload one.  Kept, it is in rc.conf's kld_list, or
 * out of it: what rc(8) loads when the host starts.  keep and forget
 * change kld_list alone, the kernel as it is.
 */
int
do_kmod(struct work *w, const char *verb, const char *name, bool persist,
    const char **errp)
{
	struct execres	 res;
	char		*argv[4];
	bool		 load;
	int		 n;

	load = strcmp(verb, "load") == 0;
	if (!load && strcmp(verb, "unload") != 0 && strcmp(verb, "keep") !=
	    0 && strcmp(verb, "forget") != 0) {
		*errp = "a module is loaded, unloaded, kept or forgotten: "
		    "load, unload, keep, forget";
		return (-1);
	}
	if (!kmod_name_ok(name)) {
		*errp = "a module is named as kldload(8) finds it, without a "
		    "path: letters, digits and . _ -";
		return (-1);
	}
	/* kld_list alone: loaded at the next boot, or not. */
	if (strcmp(verb, "keep") == 0 || strcmp(verb, "forget") == 0)
		return (kld_list_set(w, name, verb[0] == 'k', errp));
	if (!load && (strcmp(name, "kernel") == 0 || strcmp(name,
	    "kernel.ko") == 0)) {
		*errp = "the kernel itself is not unloaded";
		return (-1);
	}
	n = 0;
	argv[n++] = (char *)(uintptr_t)(load ? opts.kldload_bin :
	    opts.kldunload_bin);
	/* One that is there already is no failure. */
	if (load)
		argv[n++] = (char *)(uintptr_t)"-n";
	argv[n++] = (char *)(uintptr_t)name;
	argv[n] = NULL;
	if (run_exec(w, argv, &res) != 0) {
		*errp = wtext(w, exec_error(w, &res, load ? "kldload" :
		    "kldunload"));
		return (-1);
	}
	if (persist && rc_set(w, "kld_list", load ? "+=" : "-=", name,
	    errp) != 0)
		return (-1);
	return (0);
}
