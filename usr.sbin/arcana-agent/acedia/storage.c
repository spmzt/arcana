/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Acedia: what holds the host's data, and where it is put.
 *
 * Read: the disks and their partitions from GEOM itself (libgeom(3)),
 * with what camcontrol(8) says of each; the ZFS pools with their
 * devices from zpool(8), the datasets and the snapshots from zfs(8);
 * what is mounted from getfsstat(2), beside what fstab(5) says should
 * be.
 *
 * Changed, by a job: with zfs(8), zpool(8), mount(8), umount(8),
 * gpart(8) and camcontrol(8).  A job says a verb and its words; each
 * word is checked for being what the verb takes before a program sees
 * it, no word is an option, and the options a verb has are flags of
 * the job.  What cannot be taken back is not done in safe mode.
 */

#include <sys/param.h>
#include <sys/mount.h>
#include <sys/stat.h>

#include <ctype.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <fstab.h>
#include <libgeom.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ucl.h>
#include <unistd.h>

#include <openssl/sha.h>

#include "agent.h"

#define	STORAGE_ROWS	4000	/* datasets, or snapshots, in one reply */
#define	FSTAB_MAX	(256 * 1024)

/* getfsent(3) keeps its place in the file for the whole process. */
static pthread_mutex_t	fstab_lock = PTHREAD_MUTEX_INITIALIZER;

static void
put(ucl_object_t *o, const char *key, const char *v)
{

	if (v != NULL)
		ucl_object_insert_key(o, ucl_object_fromstring(v), key, 0,
		    false);
}

static void
putn(ucl_object_t *o, const char *key, int64_t v)
{

	ucl_object_insert_key(o, ucl_object_fromint(v), key, 0, false);
}

/* A number zfs(8) and zpool(8) print with -p; "-" is none. */
static void
putnum(ucl_object_t *o, const char *key, const char *v)
{

	if (v != NULL && isdigit((unsigned char)v[0]))
		putn(o, key, (int64_t)strtoull(v, NULL, 10));
}

static int
emit(struct work *w, ucl_object_t *top, struct arc_storage_rsp *rsp)
{
	unsigned char	*json;

	json = ucl_object_emit(top, UCL_EMIT_JSON_COMPACT);
	ucl_object_unref(top);
	if (json == NULL || strlen((char *)json) > ARC_MAX_JSON) {
		free(json);
		rsp->error = "more than a reply carries";
		return (0);
	}
	rsp->json = wtext(w, wadopt(w, json));
	rsp->ok = true;
	return (0);
}

/*
 * What is mounted, in memory of the request's own: getmntinfo(3) keeps
 * its answer in one place for the whole process, and requests run side
 * by side.
 */
static int
mnts(struct work *w, struct statfs **out)
{
	struct statfs	*buf;
	int		 n;

	*out = NULL;
	if ((n = getfsstat(NULL, 0, MNT_NOWAIT)) <= 0)
		return (0);
	buf = wcalloc(w, (size_t)n + 16, sizeof(*buf));
	n = getfsstat(buf, (long)((size_t)(n + 16) * sizeof(*buf)), MNT_NOWAIT);
	if (n <= 0)
		return (0);
	*out = buf;
	return (n);
}

/*
 * Is the path where the system itself lives?  The root, and what is
 * under the directories every FreeBSD has: a file system there is one
 * the host, or who works on it, may be standing on.
 */
static bool
system_path(const char *path)
{
	static const char *const dirs[] = { "bin", "boot", "compat", "dev",
	    "etc", "home", "lib", "libexec", "net", "proc", "rescue", "root",
	    "sbin", "tmp", "usr", "var" };
	size_t	i, n;

	if (path[0] != '/')
		return (false);
	if (path[1] == '\0')
		return (true);
	n = strcspn(path + 1, "/");
	for (i = 0; i < nitems(dirs); i++)
		if (strlen(dirs[i]) == n && strncmp(path + 1, dirs[i], n) == 0)
			return (true);
	return (false);
}

/*
 * A dataset of the pool that is mounted where the system lives: its
 * mount point, or NULL when the pool has none there.
 */
static const char *
pool_system_mount(struct work *w, const char *pool)
{
	struct statfs	*mnt;
	size_t		 len;
	int		 n, i;

	len = strlen(pool);
	n = mnts(w, &mnt);
	for (i = 0; i < n; i++)
		if (strcmp(mnt[i].f_fstypename, "zfs") == 0 && strncmp(
		    mnt[i].f_mntfromname, pool, len) == 0 &&
		    (mnt[i].f_mntfromname[len] == '/' ||
		    mnt[i].f_mntfromname[len] == '\0') && system_path(
		    mnt[i].f_mntonname))
			return (wstrdup(w, mnt[i].f_mntonname));
	return (NULL);
}

static const char *
conf(struct gconf *gc, const char *name)
{
	struct gconfig	*c;

	LIST_FOREACH(c, gc, lg_config)
		if (strcmp(c->lg_name, name) == 0)
			return (c->lg_val);
	return (NULL);
}

/*
 * {"disks": [{"name", "size", "sectorsize", "descr", "ident",
 * "rotation", "cam", "scheme", "first", "last", "parts": [{"name",
 * "index", "type", "label", "start", "end", "size", "mounted"}]}]}.
 * start, end, first and last are in sectors.
 */
static int
disks(struct work *w, struct arc_storage_rsp *rsp)
{
	struct gmesh	 mesh;
	struct gclass	*cls, *part;
	struct ggeom	*gp, *pg;
	struct gprovider *pp, *ppp;
	struct statfs	*mnt;
	struct execres	 res;
	ucl_object_t	*top, *arr, *o, *parts, *po;
	char		*argv[3], *text, *line, *names, *name, dev[80];
	const char	*v;
	int		 step, nmnt, i;

	step = step_begin(w, ARC_STEP_KIND_LIB, "geom_gettree(3)",
	    "the DISK and PART classes of GEOM");
	if (geom_gettree(&mesh) != 0) {
		rsp->error = wfmt(w, "geom_gettree: %s", strerror(errno));
		step_end(w, step, false, "%s", rsp->error);
		return (0);
	}
	step_end(w, step, true, NULL);
	/* What camcontrol(8) says each is; only root is told. */
	text = NULL;
	argv[0] = (char *)(uintptr_t)opts.camcontrol_bin;
	argv[1] = (char *)(uintptr_t)"devlist";
	argv[2] = NULL;
	if (run_exec(w, argv, &res) == 0 && res.out != NULL)
		text = wstrdup(w, res.out);
	nmnt = mnts(w, &mnt);

	part = NULL;
	LIST_FOREACH(cls, &mesh.lg_class, lg_class)
		if (strcmp(cls->lg_name, "PART") == 0)
			part = cls;
	top = ucl_object_typed_new(UCL_OBJECT);
	arr = ucl_object_typed_new(UCL_ARRAY);
	LIST_FOREACH(cls, &mesh.lg_class, lg_class) {
		/* Disks, and memory disks, which are partitioned alike. */
		if (strcmp(cls->lg_name, "DISK") != 0 && strcmp(cls->lg_name,
		    "MD") != 0)
			continue;
		LIST_FOREACH(gp, &cls->lg_geom, lg_geom) {
			if ((pp = LIST_FIRST(&gp->lg_provider)) == NULL)
				continue;
			o = ucl_object_typed_new(UCL_OBJECT);
			put(o, "name", pp->lg_name);
			putn(o, "size", pp->lg_mediasize);
			putn(o, "sectorsize", pp->lg_sectorsize);
			put(o, "descr", conf(&pp->lg_config, "descr"));
			put(o, "ident", conf(&pp->lg_config, "ident"));
			put(o, "rotation", conf(&pp->lg_config,
			    "rotationrate"));
			/* "<VENDOR MODEL REV>  at scbus0 ... (pass0,ada0)". */
			for (line = text; line != NULL && *line != '\0';
			    line = strchr(line, '\n'), line = line != NULL ?
			    line + 1 : NULL) {
				if ((names = strrchr(wstrndup(w, line,
				    strcspn(line, "\n")), '(')) == NULL)
					continue;
				names++;
				names[strcspn(names, ")")] = '\0';
				while ((name = strsep(&names, ",")) != NULL)
					if (strcmp(name, pp->lg_name) == 0)
						put(o, "cam", wstrndup(w, line,
						    strcspn(line, "(\n")));
			}
			parts = ucl_object_typed_new(UCL_ARRAY);
			pg = NULL;
			if (part != NULL)
				LIST_FOREACH(pg, &part->lg_geom, lg_geom)
					if (strcmp(pg->lg_name, pp->lg_name) ==
					    0)
						break;
			if (pg != NULL) {
				put(o, "scheme", conf(&pg->lg_config,
				    "scheme"));
				putnum(o, "first", conf(&pg->lg_config,
				    "first"));
				putnum(o, "last", conf(&pg->lg_config, "last"));
				LIST_FOREACH(ppp, &pg->lg_provider,
				    lg_provider) {
					po = ucl_object_typed_new(UCL_OBJECT);
					put(po, "name", ppp->lg_name);
					putn(po, "size", ppp->lg_mediasize);
					putnum(po, "index", conf(
					    &ppp->lg_config, "index"));
					put(po, "type", conf(&ppp->lg_config,
					    "type"));
					v = conf(&ppp->lg_config, "label");
					if (v != NULL && v[0] != '\0')
						put(po, "label", v);
					putnum(po, "start", conf(
					    &ppp->lg_config, "start"));
					putnum(po, "end", conf(&ppp->lg_config,
					    "end"));
					snprintf(dev, sizeof(dev), "/dev/%s",
					    ppp->lg_name);
					for (i = 0; i < nmnt; i++)
						if (strcmp(mnt[i].f_mntfromname,
						    dev) == 0)
							put(po, "mounted",
							    mnt[i].f_mntonname);
					ucl_array_append(parts, po);
				}
			}
			ucl_object_insert_key(o, parts, "parts", 0, false);
			ucl_array_append(arr, o);
		}
	}
	geom_deletetree(&mesh);
	ucl_object_insert_key(top, arr, "disks", 0, false);
	return (emit(w, top, rsp));
}

/* The fields of a line zfs(8) or zpool(8) printed with -H. */
static int
fields(char *line, char **f, int max)
{
	int	n;

	for (n = 0; n < max && (f[n] = strsep(&line, "\t")) != NULL; n++)
		;
	return (n);
}

/*
 * What zpool status says of each pool, into the pool's object: its
 * state, status, action, scan and errors lines, and under "vdevs" the
 * devices as they are nested: {"name", "state", "read", "write",
 * "cksum", "depth", "note"}.
 */
static void
pool_status(struct work *w, ucl_object_t *pools)
{
	static const char *const keys[] = { "state", "status", "action",
	    "scan", "errors", "see" };
	struct execres		 res;
	const ucl_object_t	*c;
	ucl_object_iter_t	 it;
	ucl_object_t		*cur, *vdevs, *v;
	char			*argv[3], *text, *line, *p, *f[6], *val;
	const char		*key, *last;
	size_t			 k;
	int			 n, depth;
	bool			 config;

	argv[0] = (char *)(uintptr_t)opts.zpool_bin;
	argv[1] = (char *)(uintptr_t)"status";
	argv[2] = NULL;
	if (run_exec(w, argv, &res) != 0 || res.out == NULL)
		return;
	cur = vdevs = NULL;
	config = false;
	last = NULL;
	text = wstrdup(w, res.out);
	while ((line = strsep(&text, "\n")) != NULL) {
		if (config && line[0] == '\t' && cur != NULL) {
			/* A device: nested by two spaces a level. */
			p = line + 1;
			depth = (int)(strspn(p, " ") / 2);
			p += strspn(p, " ");
			if (strncmp(p, "NAME ", 5) == 0)
				continue;
			for (n = 0; n < 5 && (f[n] = strsep(&p, " ")) != NULL; )
				if (f[n][0] != '\0')
					n++;
			if (n == 0)
				continue;
			v = ucl_object_typed_new(UCL_OBJECT);
			put(v, "name", f[0]);
			putn(v, "depth", depth);
			if (n > 1)
				put(v, "state", f[1]);
			if (n > 4) {
				put(v, "read", f[2]);
				put(v, "write", f[3]);
				put(v, "cksum", f[4]);
			}
			if (p != NULL && p[strspn(p, " ")] != '\0')
				put(v, "note", p + strspn(p, " "));
			ucl_array_append(vdevs, v);
			continue;
		}
		p = line + strspn(line, " ");
		if (strncmp(p, "pool: ", 6) == 0) {
			cur = NULL;
			it = NULL;
			while ((c = ucl_object_iterate(pools, &it, true)) !=
			    NULL)
				if (strcmp(ucl_object_tostring(
				    ucl_object_lookup(c, "name")), p + 6) == 0)
					cur = (ucl_object_t *)(uintptr_t)c;
			vdevs = ucl_object_typed_new(UCL_ARRAY);
			if (cur != NULL)
				ucl_object_insert_key(cur, vdevs, "vdevs", 0,
				    false);
			config = false;
			last = NULL;
			continue;
		}
		if (cur == NULL)
			continue;
		if (strncmp(p, "config:", 7) == 0) {
			config = true;
			continue;
		}
		key = NULL;
		for (k = 0; k < nitems(keys); k++)
			if (strncmp(p, keys[k], strlen(keys[k])) == 0 &&
			    p[strlen(keys[k])] == ':')
				key = keys[k];
		if (key != NULL) {
			config = false;
			last = key;
			put(cur, key, p + strlen(key) + 1 + strspn(p +
			    strlen(key) + 1, " "));
		} else if (last != NULL && line[0] != '\0' && (line[0] ==
		    '\t' || line[0] == ' ') && !config) {
			/* The line before, going on. */
			val = wfmt(w, "%s %s", ucl_object_tostring(
			    ucl_object_lookup(cur, last)), p + strspn(p,
			    "\t "));
			ucl_object_replace_key(cur, ucl_object_fromstring(val),
			    last, 0, false);
		}
	}
}

/*
 * {"pools": [{"name", "size", "alloc", "free", "frag", "cap", "dedup",
 * "health", and what pool_status() adds}]}.
 */
static int
pools(struct work *w, struct arc_storage_rsp *rsp)
{
	struct execres	 res;
	ucl_object_t	*top, *arr, *o;
	char		*argv[6], *text, *line, *f[8];

	argv[0] = (char *)(uintptr_t)opts.zpool_bin;
	argv[1] = (char *)(uintptr_t)"list";
	argv[2] = (char *)(uintptr_t)"-Hp";
	argv[3] = (char *)(uintptr_t)"-o";
	argv[4] = (char *)(uintptr_t)"name,size,allocated,free,fragmentation,"
	    "capacity,dedupratio,health";
	argv[5] = NULL;
	if (run_exec(w, argv, &res) != 0) {
		rsp->error = wtext(w, exec_error(w, &res, "zpool"));
		return (0);
	}
	top = ucl_object_typed_new(UCL_OBJECT);
	arr = ucl_object_typed_new(UCL_ARRAY);
	text = wstrdup(w, res.out != NULL ? res.out : "");
	while ((line = strsep(&text, "\n")) != NULL) {
		if (fields(line, f, 8) < 8)
			continue;
		o = ucl_object_typed_new(UCL_OBJECT);
		put(o, "name", f[0]);
		putnum(o, "size", f[1]);
		putnum(o, "alloc", f[2]);
		putnum(o, "free", f[3]);
		putnum(o, "frag", f[4]);
		putnum(o, "cap", f[5]);
		put(o, "dedup", f[6]);
		put(o, "health", f[7]);
		ucl_array_append(arr, o);
	}
	pool_status(w, arr);
	ucl_object_insert_key(top, arr, "pools", 0, false);
	return (emit(w, top, rsp));
}

/* A dataset's name, or a pool's: no option, no path out of it. */
static bool
dataset_ok(const char *s)
{

	if (s == NULL || s[0] == '\0' || s[0] == '-' || s[0] == '/' ||
	    strlen(s) > 255 || strstr(s, "//") != NULL || s[strlen(s) - 1] ==
	    '/')
		return (false);
	for (; *s != '\0'; s++)
		if (!isalnum((unsigned char)*s) && strchr("_.:/-", *s) == NULL)
			return (false);
	return (true);
}

/* dataset@snapshot. */
static bool
snapshot_ok(struct work *w, const char *s)
{
	const char	*at, *p;

	if (s == NULL || (at = strchr(s, '@')) == NULL || at[1] == '\0' ||
	    strlen(s) > 255 || !dataset_ok(wstrndup(w, s, (size_t)(at - s))))
		return (false);
	for (p = at + 1; *p != '\0'; p++)
		if (!isalnum((unsigned char)*p) && strchr("_.:-", *p) == NULL)
			return (false);
	return (true);
}

/*
 * {"datasets": [{"name", "type", "used", "avail", "refer",
 * "mountpoint", "compression", "ratio", "quota", "reservation",
 * "mounted", "canmount", "origin", "volsize", "readonly"}]} or
 * {"snapshots": [{"name", "used", "refer", "creation"}]}, the newest
 * first, of the dataset filter names and those under it, or of all.
 */
static int
datasets(struct work *w, bool snaps, const char *filter,
    struct arc_storage_rsp *rsp)
{
	static const char *const dcols[] = { "name", "type", "used", "avail",
	    "refer", "mountpoint", "compression", "ratio", "quota",
	    "reservation", "mounted", "canmount", "origin", "volsize",
	    "readonly", "encryption", "keystatus", "keylocation", "jailed" };
	static const char *const scols[] = { "name", "used", "refer",
	    "creation" };
	struct execres		 res;
	ucl_object_t		*top, *arr, *o;
	const char *const	*cols;
	char			*argv[12], *text, *line, *f[20];
	uint64_t		 total;
	int			 n, i, ncols;

	if (filter != NULL && filter[0] != '\0' && !dataset_ok(filter)) {
		rsp->error = "a dataset is named by letters, digits and "
		    "_ . : / -";
		return (0);
	}
	cols = snaps ? scols : dcols;
	ncols = snaps ? (int)nitems(scols) : (int)nitems(dcols);
	n = 0;
	argv[n++] = (char *)(uintptr_t)opts.zfs_bin;
	argv[n++] = (char *)(uintptr_t)"list";
	argv[n++] = (char *)(uintptr_t)"-Hp";
	argv[n++] = (char *)(uintptr_t)"-t";
	argv[n++] = (char *)(uintptr_t)(snaps ? "snapshot" :
	    "filesystem,volume");
	argv[n++] = (char *)(uintptr_t)"-o";
	argv[n++] = (char *)(uintptr_t)(snaps ? "name,used,referenced,"
	    "creation" : "name,type,used,available,referenced,mountpoint,"
	    "compression,compressratio,quota,reservation,mounted,canmount,"
	    "origin,volsize,readonly,encryption,keystatus,keylocation,"
	    "jailed");
	if (snaps) {
		argv[n++] = (char *)(uintptr_t)"-S";
		argv[n++] = (char *)(uintptr_t)"creation";
	}
	if (filter != NULL && filter[0] != '\0') {
		argv[n++] = (char *)(uintptr_t)"-r";
		argv[n++] = (char *)(uintptr_t)filter;
	}
	argv[n] = NULL;
	/* In a jail: its own zfs, which sees what was given to it. */
	if (run_exec_max(w, scope_jexec(w, argv), &res, ARC_MAX_JSON) != 0) {
		rsp->error = wtext(w, exec_error(w, &res, "zfs"));
		return (0);
	}
	top = ucl_object_typed_new(UCL_OBJECT);
	arr = ucl_object_typed_new(UCL_ARRAY);
	total = 0;
	text = wstrdup(w, res.out != NULL ? res.out : "");
	while ((line = strsep(&text, "\n")) != NULL) {
		if (fields(line, f, ncols) < ncols)
			continue;
		if (total++ >= STORAGE_ROWS)
			continue;
		o = ucl_object_typed_new(UCL_OBJECT);
		for (i = 0; i < ncols; i++) {
			if (strcmp(f[i], "-") == 0)
				continue;
			/* Sizes and times are numbers; the rest words. */
			if (isdigit((unsigned char)f[i][0]) && f[i][strspn(
			    f[i], "0123456789")] == '\0' && i != 0)
				putnum(o, cols[i], f[i]);
			else
				put(o, cols[i], f[i]);
		}
		ucl_array_append(arr, o);
	}
	ucl_object_insert_key(top, arr, snaps ? "snapshots" : "datasets", 0,
	    false);
	if (total > STORAGE_ROWS || res.truncated) {
		rsp->has_total = true;
		rsp->total = total;
		rsp->truncated = true;
	}
	return (emit(w, top, rsp));
}

/* What a mount's flags say, in mount(8)'s words. */
static const char *
mount_flags(struct work *w, uint64_t fl)
{
	static const struct {
		uint64_t	 flag;
		const char	*name;
	} names[] = {
		{ MNT_RDONLY, "read-only" }, { MNT_NOEXEC, "noexec" },
		{ MNT_NOSUID, "nosuid" }, { MNT_NOATIME, "noatime" },
		{ MNT_SYNCHRONOUS, "synchronous" }, { MNT_ASYNC, "async" },
		{ MNT_LOCAL, "local" }, { MNT_SOFTDEP, "soft-updates" },
		{ MNT_SUJ, "journaled" }, { MNT_NFS4ACLS, "nfsv4acls" },
		{ MNT_ACLS, "acls" }, { MNT_MULTILABEL, "multilabel" },
		{ MNT_EXPORTED, "exported" }, { MNT_UNION, "union" },
	};
	const char	*s;
	size_t		 i;

	s = "";
	for (i = 0; i < nitems(names); i++)
		if ((fl & names[i].flag) != 0)
			s = wfmt(w, "%s%s%s", s, s[0] != '\0' ? ", " : "",
			    names[i].name);
	return (s);
}

/*
 * {"mounts": [{"from", "on", "type", "options", "size", "used",
 * "avail"}], "fstab": [{"spec", "file", "vfstype", "mntops", "type",
 * "freq", "passno", "mounted"}]}.
 */
static int
mounts(struct work *w, struct arc_storage_rsp *rsp)
{
	struct statfs	*mnt;
	struct fstab	*fs;
	ucl_object_t	*top, *arr, *o;
	char		 real[MAXPATHLEN];
	int		 n, i, step;
	bool		 mounted;

	step = step_begin(w, ARC_STEP_KIND_LIB, "getfsstat(2)", NULL);
	n = mnts(w, &mnt);
	step_end(w, step, n > 0, "%d mounted", n);
	top = ucl_object_typed_new(UCL_OBJECT);
	arr = ucl_object_typed_new(UCL_ARRAY);
	for (i = 0; i < n; i++) {
		o = ucl_object_typed_new(UCL_OBJECT);
		put(o, "from", mnt[i].f_mntfromname);
		put(o, "on", mnt[i].f_mntonname);
		put(o, "type", mnt[i].f_fstypename);
		put(o, "options", mount_flags(w, mnt[i].f_flags));
		putn(o, "size", (int64_t)(mnt[i].f_blocks * mnt[i].f_bsize));
		putn(o, "used", (int64_t)((mnt[i].f_blocks - mnt[i].f_bfree) *
		    mnt[i].f_bsize));
		putn(o, "avail", mnt[i].f_bavail > 0 ? (int64_t)(
		    (uint64_t)mnt[i].f_bavail * mnt[i].f_bsize) : 0);
		ucl_array_append(arr, o);
	}
	ucl_object_insert_key(top, arr, "mounts", 0, false);

	arr = ucl_object_typed_new(UCL_ARRAY);
	pthread_mutex_lock(&fstab_lock);
	setfstab(opts.fstab_path);
	if (setfsent() != 0) {
		while ((fs = getfsent()) != NULL) {
			o = ucl_object_typed_new(UCL_OBJECT);
			put(o, "spec", fs->fs_spec);
			put(o, "file", fs->fs_file);
			put(o, "vfstype", fs->fs_vfstype);
			put(o, "mntops", fs->fs_mntops);
			put(o, "type", fs->fs_type);
			putn(o, "freq", fs->fs_freq);
			putn(o, "passno", fs->fs_passno);
			mounted = false;
			if (realpath(fs->fs_file, real) == NULL)
				strlcpy(real, fs->fs_file, sizeof(real));
			for (i = 0; i < n; i++)
				if (strcmp(mnt[i].f_mntonname, fs->fs_file) ==
				    0 || strcmp(mnt[i].f_mntonname, real) == 0)
					mounted = true;
			ucl_object_insert_key(o, ucl_object_frombool(mounted),
			    "mounted", 0, false);
			ucl_array_append(arr, o);
		}
		endfsent();
	}
	pthread_mutex_unlock(&fstab_lock);
	ucl_object_insert_key(top, arr, "fstab", 0, false);
	ucl_object_insert_key(top, swap_list(w), "swap", 0, false);
	return (emit(w, top, rsp));
}

static int	importable(struct work *, struct arc_storage_rsp *);

int
do_storage(struct work *w, uint8_t kind, const char *filter,
    struct arc_storage_rsp *rsp)
{

	rsp->has_ok = true;
	rsp->ok = false;
	switch (kind) {
	case ARC_STORAGE_KIND_DISKS:
		return (disks(w, rsp));
	case ARC_STORAGE_KIND_POOLS:
		return (pools(w, rsp));
	case ARC_STORAGE_KIND_DATASETS:
		return (datasets(w, false, filter, rsp));
	case ARC_STORAGE_KIND_SNAPSHOTS:
		return (datasets(w, true, filter, rsp));
	case ARC_STORAGE_KIND_MOUNTS:
		return (mounts(w, rsp));
	case ARC_STORAGE_KIND_IMPORTABLE:
		return (importable(w, rsp));
	case ARC_STORAGE_KIND_HEALTH:
		return (do_health(w, rsp));
	default:
		rsp->error = "no such kind of storage";
		return (0);
	}
}

/* Words a job's verb takes: each of a kind, checked before use. */
static bool
word_ok(const char *s, const char *more, size_t max)
{

	if (s == NULL || s[0] == '\0' || s[0] == '-' || strlen(s) > max)
		return (false);
	for (; *s != '\0'; s++)
		if (!isalnum((unsigned char)*s) && strchr(more, *s) == NULL)
			return (false);
	return (true);
}

static bool
size_ok(const char *s)
{
	size_t	n;

	if (s == NULL || (n = strspn(s, "0123456789")) == 0 || n > 18)
		return (false);
	return (s[n] == '\0' || (strchr("kKmMgGtT", s[n]) != NULL && s[n +
	    1] == '\0'));
}

/* name=value of a property zfs(8) may be given here. */
static bool
property_ok(struct work *w, const char *s)
{
	static const char *const props[] = { "atime", "canmount", "checksum",
	    "compression", "copies", "dedup", "exec", "mountpoint", "quota",
	    "readonly", "recordsize", "refquota", "refreservation",
	    "reservation", "setuid", "snapdir", "sync", "volsize", "xattr",
	    "primarycache", "secondarycache", "logbias", "relatime",
	    "acltype", "aclmode", "aclinherit", "utf8only", "normalization",
	    "casesensitivity", "volblocksize", "special_small_blocks",
	    "encryption", "keyformat", "keylocation", "pbkdf2iters",
	    "jailed" };
	const char	*eq;
	char		*name;
	size_t		 i;

	if (s == NULL || (eq = strchr(s, '=')) == NULL || eq == s)
		return (false);
	name = wstrndup(w, s, (size_t)(eq - s));
	/* One of the system's, or a user's own: module:name. */
	for (i = 0; i < nitems(props); i++)
		if (strcmp(name, props[i]) == 0)
			break;
	if (i == nitems(props) && (strchr(name, ':') == NULL || !word_ok(name,
	    "_.:-", 128)))
		return (false);
	return (eq[1] == '\0' || word_ok(eq + 1, "_.:/=,@+ -", 1024) ||
	    eq[1] == '/');
}

static const char *
property_name_ok(const char *s)
{

	return (word_ok(s, "_.:-", 128) ? NULL : "a property is named by "
	    "letters, digits and _ . : -");
}

/* Is path something fstab(5) says to mount? */
static bool
in_fstab(const char *path)
{
	struct fstab	*fs;
	bool		 found;

	found = false;
	pthread_mutex_lock(&fstab_lock);
	setfstab(opts.fstab_path);
	if (setfsent() != 0) {
		while ((fs = getfsent()) != NULL)
			if (strcmp(fs->fs_file, path) == 0)
				found = true;
		endfsent();
	}
	pthread_mutex_unlock(&fstab_lock);
	return (found);
}

/*
 * Is something mounted on path?  The kernel names a mount point by
 * where it really is: a path that leads there through a link is the
 * same place.
 */
static bool
is_mounted(struct work *w, const char *path)
{
	struct statfs	*mnt;
	char		 real[MAXPATHLEN];
	int		 n, i;

	if (realpath(path, real) == NULL)
		strlcpy(real, path, sizeof(real));
	n = mnts(w, &mnt);
	for (i = 0; i < n; i++)
		if (strcmp(mnt[i].f_mntonname, path) == 0 || strcmp(
		    mnt[i].f_mntonname, real) == 0)
			return (true);
	return (false);
}

/* How devices are put together in a pool, in zpool(8)'s words. */
static bool
vdev_word(const char *s)
{
	static const char *const words[] = { "mirror", "raidz", "raidz1",
	    "raidz2", "raidz3", "log", "cache", "spare", "special" };
	size_t	i;

	for (i = 0; i < nitems(words); i++)
		if (strcmp(s, words[i]) == 0)
			return (true);
	return (false);
}

/*
 * {"importable": [{"name", "id", "state", "status"}]}: the pools zpool
 * finds on the host's devices that are not imported.
 */
static int
importable(struct work *w, struct arc_storage_rsp *rsp)
{
	struct execres	 res;
	ucl_object_t	*top, *arr, *o;
	char		*argv[3], *text, *line, *p;

	argv[0] = (char *)(uintptr_t)opts.zpool_bin;
	argv[1] = (char *)(uintptr_t)"import";
	argv[2] = NULL;
	/* With nothing to import it says so and ends badly: none, then. */
	(void)run_exec(w, argv, &res);
	top = ucl_object_typed_new(UCL_OBJECT);
	arr = ucl_object_typed_new(UCL_ARRAY);
	o = NULL;
	text = wstrdup(w, res.out != NULL ? res.out : "");
	while ((line = strsep(&text, "\n")) != NULL) {
		p = line + strspn(line, " ");
		if (strncmp(p, "pool: ", 6) == 0) {
			o = ucl_object_typed_new(UCL_OBJECT);
			put(o, "name", p + 6);
			ucl_array_append(arr, o);
		} else if (o != NULL && strncmp(p, "id: ", 4) == 0)
			put(o, "id", p + 4);
		else if (o != NULL && strncmp(p, "state: ", 7) == 0)
			put(o, "state", p + 7);
		else if (o != NULL && strncmp(p, "status: ", 8) == 0)
			put(o, "status", p + 8);
	}
	ucl_object_insert_key(top, arr, "importable", 0, false);
	return (emit(w, top, rsp));
}

#define	ARG(s)	do { v[n++] = (char *)(uintptr_t)(s); } while (0)

/*
 * The program and its arguments for a job, each word checked: NULL and
 * why not in *errp when the job is not one to run.  What a verb needs
 * that is an option of the program comes from the job's flags, never
 * from its words.
 */
char **
storage_argv(struct work *w, const struct arc_job_spec *sp, const char **errp)
{
	const char *const	*a;
	const char		*verb, *sysmnt;
	char			**v;
	size_t			 na, i, n, devs;

	*errp = NULL;
	verb = sp->verb != NULL ? sp->verb : "";
	a = sp->names.v;
	na = sp->names.n;
	if (na > 24) {
		*errp = "too many words";
		return (NULL);
	}
	v = wcalloc(w, 2 * na + 12, sizeof(*v));
	n = 0;
	switch (sp->kind) {
	case ARC_JOB_KIND_ZFS:
		ARG(opts.zfs_bin);
		if (strcmp(verb, "snapshot") == 0 && na == 1) {
			if (!snapshot_ok(w, a[0]))
				goto name;
			ARG("snapshot");
			if (sp->recursive)
				ARG("-r");
			ARG(a[0]);
		} else if (strcmp(verb, "destroy") == 0 && na == 1) {
			/* A pool is not destroyed by its dataset's name. */
			if (!(snapshot_ok(w, a[0]) || (dataset_ok(a[0]) &&
			    strchr(a[0], '/') != NULL)))
				goto name;
			ARG("destroy");
			if (sp->recursive)
				ARG("-r");
			ARG(a[0]);
		} else if (strcmp(verb, "resnapshot") == 0 && na == 1) {
			/* Its newest snapshot made again: do_storage_job. */
			if (!snapshot_ok(w, a[0]) || strlen(a[0]) > 240)
				goto name;
			ARG("resnapshot");
			if (sp->recursive)
				ARG("-r");
			ARG(a[0]);
		} else if (strcmp(verb, "rollback") == 0 && na == 1) {
			if (!snapshot_ok(w, a[0]))
				goto name;
			ARG("rollback");
			/* To one that is not the latest: those after it go. */
			if (sp->recursive)
				ARG("-r");
			ARG(a[0]);
		} else if (strcmp(verb, "create") == 0 && na >= 1) {
			if (!dataset_ok(a[0]) || strchr(a[0], '/') == NULL)
				goto name;
			ARG("create");
			for (i = 1; i < na; i++) {
				if (!property_ok(w, a[i]))
					goto prop;
				/* A volume is one by its size. */
				if (strncmp(a[i], "volsize=", 8) == 0) {
					if (!size_ok(a[i] + 8))
						goto size;
					ARG("-V");
					ARG(a[i] + 8);
				} else {
					ARG("-o");
					ARG(a[i]);
				}
			}
			ARG(a[0]);
		} else if (strcmp(verb, "set") == 0 && na >= 2) {
			if (!dataset_ok(a[0]))
				goto name;
			ARG("set");
			for (i = 1; i < na; i++) {
				if (!property_ok(w, a[i]))
					goto prop;
				ARG(a[i]);
			}
			ARG(a[0]);
		} else if (strcmp(verb, "inherit") == 0 && na == 2) {
			if (!dataset_ok(a[0]))
				goto name;
			if ((*errp = property_name_ok(a[1])) != NULL)
				return (NULL);
			ARG("inherit");
			ARG(a[1]);
			ARG(a[0]);
		} else if ((strcmp(verb, "mount") == 0 || strcmp(verb,
		    "unmount") == 0 || strcmp(verb, "promote") == 0) && na ==
		    1) {
			if (!dataset_ok(a[0]))
				goto name;
			/* By force only what the system does not live on. */
			if (sp->force && verb[0] == 'u') {
				if ((sysmnt = pool_system_mount(w, wstrndup(w,
				    a[0], strcspn(a[0], "/")))) != NULL) {
					*errp = wfmt(w, "its pool has a "
					    "dataset mounted on %s, where the "
					    "system lives: nothing of it is "
					    "unmounted by force from here",
					    sysmnt);
					return (NULL);
				}
			}
			ARG(verb);
			if (sp->force && verb[0] == 'u')
				ARG("-f");
			ARG(a[0]);
		} else if ((strcmp(verb, "jail") == 0 || strcmp(verb,
		    "unjail") == 0) && na == 2) {
			/* A dataset given to a jail, to manage as its own. */
			if (!dataset_ok(a[0]) || strchr(a[0], '/') == NULL)
				goto name;
			if (!word_ok(a[1], "_.-", 255)) {
				*errp = "a jail is named by letters, digits "
				    "and _ . -";
				return (NULL);
			}
			ARG(verb);
			ARG(a[1]);
			ARG(a[0]);
		} else if ((strcmp(verb, "load-key") == 0 || strcmp(verb,
		    "unload-key") == 0) && na == 1) {
			/*
			 * The key of an encrypted dataset, read from where
			 * its keylocation says: one that is asked for at a
			 * prompt is not loaded from here.
			 */
			if (!dataset_ok(a[0]))
				goto name;
			ARG(verb);
			if (sp->recursive)
				ARG("-r");
			ARG(a[0]);
		} else if (strcmp(verb, "replicate") == 0 && (na == 2 || na ==
		    3)) {
			/*
			 * A snapshot sent into a dataset that is not there
			 * yet, on this host: zfs send into zfs receive, by
			 * the helper.  With a third word, only what changed
			 * since that snapshot, which both have.
			 */
			if (!snapshot_ok(w, a[0]) || !dataset_ok(a[1]) ||
			    strchr(a[1], '/') == NULL || (na == 3 &&
			    !snapshot_ok(w, a[2])))
				goto name;
			n = 0;
			ARG(opts.helper_bin);
			ARG("-Q");
			ARG("0");
			ARG("zfs-pipe");
			ARG(opts.zfs_bin);
			ARG(a[0]);
			ARG(a[1]);
			ARG(na == 3 ? a[2] : "-");
			ARG(sp->recursive ? "r" : "-");
		} else if (strcmp(verb, "clone") == 0 && na == 2) {
			if (!snapshot_ok(w, a[0]) || !dataset_ok(a[1]) ||
			    strchr(a[1], '/') == NULL)
				goto name;
			ARG("clone");
			ARG(a[0]);
			ARG(a[1]);
		} else if (strcmp(verb, "rename") == 0 && na == 2) {
			if (!((snapshot_ok(w, a[0]) && snapshot_ok(w, a[1])) ||
			    (dataset_ok(a[0]) && dataset_ok(a[1]) && strchr(
			    a[0], '/') != NULL && strchr(a[1], '/') != NULL)))
				goto name;
			ARG("rename");
			ARG(a[0]);
			ARG(a[1]);
		} else
			goto verb;
		break;
	case ARC_JOB_KIND_ZPOOL:
		ARG(opts.zpool_bin);
		if (na < 1 || !word_ok(a[0], "_.:-", 255))
			goto name;
		if (strcmp(verb, "create") == 0 || strcmp(verb, "add") == 0) {
			/*
			 * A pool, then how its devices are put together and
			 * the devices: mirror, raidz and the like among
			 * them, as zpool takes them; for create, also
			 * mountpoint=, altroot= and ashift=.
			 */
			ARG(verb);
			if (sp->force)
				ARG("-f");
			devs = 0;
			for (i = 1; i < na; i++) {
				if (verb[0] != 'c' || strchr(a[i], '=') == NULL)
					continue;
				if (strncmp(a[i], "mountpoint=/", 12) == 0 &&
				    word_ok(a[i] + 12, "_.:/@+-", MAXPATHLEN) &&
				    strstr(a[i], "/..") == NULL) {
					ARG("-m");
					ARG(a[i] + 11);
				} else if (strncmp(a[i], "altroot=/", 9) == 0 &&
				    word_ok(a[i] + 9, "_.:/@+-", MAXPATHLEN) &&
				    strstr(a[i], "/..") == NULL) {
					ARG("-R");
					ARG(a[i] + 8);
				} else if (strncmp(a[i], "ashift=", 7) == 0 &&
				    a[i][7] != '\0' && strlen(a[i]) <= 9 &&
				    a[i][7 + strspn(a[i] + 7, "0123456789")] ==
				    '\0') {
					ARG("-o");
					ARG(a[i]);
				} else
					goto pool;
			}
			ARG(a[0]);
			for (i = 1; i < na; i++) {
				if (strchr(a[i], '=') != NULL) {
					if (verb[0] != 'c')
						goto pool;
					continue;
				}
				if (!vdev_word(a[i]) && (!word_ok(a[i],
				    "_.:/-", 255) || strstr(a[i], "..") !=
				    NULL))
					goto pool;
				if (!vdev_word(a[i]))
					devs++;
				ARG(a[i]);
			}
			if (devs == 0)
				goto pool;
		} else if ((strcmp(verb, "destroy") == 0 || strcmp(verb,
		    "export") == 0) && na == 1) {
			/*
			 * Never a pool the system lives on: to destroy or
			 * export it unmounts what it can, and the host, or
			 * who is logged in to it, is left standing on
			 * nothing.  And never by force, which unmounts what
			 * is in use.
			 */
			if ((sysmnt = pool_system_mount(w, a[0])) != NULL) {
				*errp = wfmt(w, "%s has a dataset mounted on "
				    "%s, where the system lives: it is not "
				    "%sed from here", a[0], sysmnt, verb[0] ==
				    'd' ? "destroy" : "export");
				return (NULL);
			}
			if (sp->force) {
				*errp = "a pool is not destroyed or exported "
				    "by force from here: what uses it is "
				    "stopped first";
				return (NULL);
			}
			ARG(verb);
			ARG(a[0]);
		} else if (strcmp(verb, "import") == 0 && na <= 2) {
			ARG("import");
			if (sp->force)
				ARG("-f");
			if (na == 2) {
				if (strncmp(a[1], "altroot=/", 9) != 0 ||
				    !word_ok(a[1] + 9, "_.:/@+-", MAXPATHLEN) ||
				    strstr(a[1], "/..") != NULL)
					goto pool;
				ARG("-R");
				ARG(a[1] + 8);
			}
			ARG(a[0]);
		} else if (((strcmp(verb, "attach") == 0 || strcmp(verb,
		    "replace") == 0) && na == 3) || ((strcmp(verb, "detach") ==
		    0 || strcmp(verb, "remove") == 0 || strcmp(verb,
		    "replace") == 0) && na == 2)) {
			for (i = 1; i < na; i++)
				if (!word_ok(a[i], "_.:/-", 255) || strstr(a[i],
				    "..") != NULL)
					goto name;
			ARG(verb);
			if (sp->force && verb[0] != 'd' && verb[2] != 'm')
				ARG("-f");
			ARG(a[0]);
			for (i = 1; i < na; i++)
				ARG(a[i]);
		} else if ((strcmp(verb, "scrub") == 0 || strcmp(verb, "trim") ==
		    0) && na == 1) {
			ARG(verb);
			ARG(a[0]);
		} else if (strcmp(verb, "scrub-stop") == 0 && na == 1) {
			ARG("scrub");
			ARG("-s");
			ARG(a[0]);
		} else if (strcmp(verb, "clear") == 0 && na <= 2) {
			if (na == 2 && (!word_ok(a[1], "_.:/-", 255) || strstr(
			    a[1], "..") != NULL))
				goto name;
			ARG("clear");
			ARG(a[0]);
			if (na == 2)
				ARG(a[1]);
		} else if ((strcmp(verb, "online") == 0 || strcmp(verb,
		    "offline") == 0) && na == 2) {
			if (!word_ok(a[1], "_.:/-", 255) || strstr(a[1],
			    "..") != NULL)
				goto name;
			ARG(verb);
			ARG(a[0]);
			ARG(a[1]);
		} else
			goto verb;
		break;
	case ARC_JOB_KIND_MOUNT:
		if (na != 1 || a[0][0] != '/' || (a[0][1] != '\0' && (!word_ok(
		    a[0] + 1, "_.:/@+, -", MAXPATHLEN - 2) || strstr(a[0],
		    "/..") != NULL))) {
			*errp = "a mount point is a whole path";
			return (NULL);
		}
		if (strcmp(verb, "mount") == 0) {
			/* Only what fstab(5) describes: it says how. */
			if (!in_fstab(a[0])) {
				*errp = wfmt(w, "%s is not in fstab: what is "
				    "mounted from here is what fstab "
				    "describes", a[0]);
				return (NULL);
			}
			ARG(opts.mount_bin);
			/* The fstab this host is told to go by, if another. */
			if (strcmp(opts.fstab_path, PATH_FSTAB) != 0) {
				ARG("-F");
				ARG(opts.fstab_path);
			}
			ARG(a[0]);
		} else if (strcmp(verb, "unmount") == 0) {
			if (strcmp(a[0], "/") == 0) {
				*errp = "the root is not unmounted";
				return (NULL);
			}
			if (!is_mounted(w, a[0])) {
				*errp = wfmt(w, "nothing is mounted on %s",
				    a[0]);
				return (NULL);
			}
			if (sp->force && system_path(a[0])) {
				*errp = wfmt(w, "%s is where the system lives: "
				    "it is not unmounted by force from here",
				    a[0]);
				return (NULL);
			}
			ARG(opts.umount_bin);
			if (sp->force)
				ARG("-f");
			ARG(a[0]);
		} else if ((strcmp(verb, "swapon") == 0 || strcmp(verb,
		    "swapoff") == 0) && na == 1) {
			const char	*bin;

			/* A device to swap on, or no longer. */
			if (strncmp(a[0], "/dev/", 5) != 0 || !word_ok(a[0] +
			    5, "_./-", 64) || strstr(a[0], "..") != NULL) {
				*errp = "swap is on a device: /dev/ada0p3";
				return (NULL);
			}
			if ((bin = tool(w, verb)) == NULL) {
				*errp = wfmt(w, "the host has no %s", verb);
				return (NULL);
			}
			ARG(bin);
			ARG(a[0]);
		} else
			goto verb;
		break;
	case ARC_JOB_KIND_GPART:
		/*
		 * A file system made on a partition, or grown to its
		 * size: newfs(8) and growfs(8) of UFS.  What is on the
		 * partition is looked at before it is run.
		 */
		if (((strcmp(verb, "newfs") == 0 || strcmp(verb,
		    "newfs-msdos") == 0) && (na == 1 || na == 2)) ||
		    (strcmp(verb, "growfs") == 0 && na == 1)) {
			const char	*bin;

			if (!word_ok(a[0], "_.-", 64) || a[0][0] == '.')
				goto geom;
			if (na == 2 && a[1][0] != '\0' && !word_ok(a[1], "_.-",
			    32))
				goto label;
			if ((bin = tool(w, strcmp(verb, "newfs-msdos") == 0 ?
			    "newfs_msdos" : verb)) == NULL) {
				*errp = wfmt(w, "the host has no %s", verb);
				return (NULL);
			}
			ARG(bin);
			if (strcmp(verb, "newfs-msdos") == 0) {
				/* FAT, for what other systems read too, of
				 * the type its size allows (FAT32 needs 65525
				 * clusters); a label of 11 at most, in
				 * capitals. */
				if (na == 2 && strlen(a[1]) > 11) {
					*errp = "a FAT label is 11 characters at "
					    "most";
					return (NULL);
				}
				if (na == 2 && a[1][0] != '\0') {
					char	*u;

					u = wstrdup(w, a[1]);
					for (char *c = u; *c != '\0'; c++)
						*c = (char)toupper((unsigned char)
						    *c);
					ARG("-L");
					ARG(u);
				}
			} else if (verb[0] == 'n') {
				ARG("-U");
				if (na == 2 && a[1][0] != '\0') {
					ARG("-L");
					ARG(a[1]);
				}
			} else
				ARG("-y");
			ARG(wfmt(w, "/dev/%s", a[0]));
			break;
		}
		ARG(opts.gpart_bin);
		if (na < 1 || !word_ok(a[0], "", 32))
			goto geom;
		if (strcmp(verb, "create") == 0 && na == 2) {
			if (strcmp(a[1], "gpt") != 0 && strcmp(a[1], "mbr") !=
			    0 && strcmp(a[1], "bsd") != 0) {
				*errp = "a partition table is gpt, mbr or bsd";
				return (NULL);
			}
			ARG("create");
			ARG("-s");
			ARG(a[1]);
			ARG(a[0]);
		} else if (strcmp(verb, "destroy") == 0 && na == 1) {
			/* Without -F: only a table with nothing in it. */
			ARG("destroy");
			ARG(a[0]);
		} else if (strcmp(verb, "add") == 0 && na >= 2 && na <= 4) {
			/* disk, type, then a size and a label, or "". */
			if (!word_ok(a[1], "-", 36))
				goto type;
			if (na > 2 && a[2][0] != '\0' && !size_ok(a[2]))
				goto size;
			if (na > 3 && a[3][0] != '\0' && !word_ok(a[3], "_.-",
			    36))
				goto label;
			ARG("add");
			ARG("-t");
			ARG(a[1]);
			ARG("-a");
			ARG("1m");
			if (na > 2 && a[2][0] != '\0') {
				ARG("-s");
				ARG(a[2]);
			}
			if (na > 3 && a[3][0] != '\0') {
				ARG("-l");
				ARG(a[3]);
			}
			ARG(a[0]);
		} else if ((strcmp(verb, "delete") == 0 && na == 2) ||
		    (strcmp(verb, "resize") == 0 && (na == 2 || na == 3)) ||
		    (strcmp(verb, "modify") == 0 && na == 3)) {
			/* disk, the partition's index, and what is new. */
			if (a[1][strspn(a[1], "0123456789")] != '\0' ||
			    a[1][0] == '\0' || strlen(a[1]) > 3) {
				*errp = "a partition is named by its index";
				return (NULL);
			}
			ARG(verb);
			ARG("-i");
			ARG(a[1]);
			if (verb[0] == 'r') {
				ARG("-a");
				ARG("1m");
				if (na == 3) {
					if (!size_ok(a[2]))
						goto size;
					ARG("-s");
					ARG(a[2]);
				}
			} else if (verb[0] == 'm') {
				if (!word_ok(a[2], "_.-", 36))
					goto label;
				ARG("-l");
				ARG(a[2]);
			}
			ARG(a[0]);
		} else
			goto verb;
		break;
	case ARC_JOB_KIND_CAM:
		ARG(opts.camcontrol_bin);
		if (strcmp(verb, "rescan") == 0 && na == 0) {
			ARG("rescan");
			ARG("all");
		} else
			goto verb;
		break;
	default:
		goto verb;
	}
	v[n] = NULL;
	return (v);
verb:
	*errp = wfmt(w, "%s is not something to do here, or not with these "
	    "words", verb[0] != '\0' ? verb : "nothing");
	return (NULL);
name:
	*errp = "a dataset is pool/name, a snapshot dataset@name: letters, "
	    "digits and _ . : -, and no pool by itself where it would be "
	    "destroyed";
	return (NULL);
prop:
	*errp = "a property is name=value, of those zfs(8) has or a user's "
	    "own (module:name)";
	return (NULL);
size:
	*errp = "a size is a number, with k, m, g or t after it or without";
	return (NULL);
geom:
	*errp = "a disk is named as GEOM names it: ada0, nda1, da2";
	return (NULL);
type:
	*errp = "a partition's type is as gpart(8) names it: freebsd-zfs, "
	    "freebsd-ufs, freebsd-swap, efi";
	return (NULL);
label:
	*errp = "a label is letters, digits and _ . -";
	return (NULL);
pool:
	*errp = "a pool is made of devices, with mirror, raidz1, raidz2, "
	    "raidz3, log, cache, spare or special before those that are put "
	    "together so; and for a new one mountpoint=/path, altroot=/path "
	    "and ashift=number";
	return (NULL);
}

const char *
storage_check(const struct arc_job_spec *sp)
{
	static _Thread_local char	why[400];
	struct work			 w;
	const char			*e;

	if (sp->jail != NULL && sp->jail[0] != '\0')
		return ("storage is the host's");
	if (sp->safe)
		return ("what is done to storage cannot be taken back by the "
		    "host: not in safe mode");
	work_init(&w);
	e = NULL;
	if (storage_argv(&w, sp, &e) == NULL && e != NULL) {
		/* The words outlive the memory they were made in. */
		snprintf(why, sizeof(why), "%s", e);
		e = why;
	}
	work_free(&w);
	return (e);
}

/* What the job runs, in words: its title. */
char *
storage_title(const struct arc_job_spec *sp)
{
	struct work	 w;
	const char	*e, *base;
	char		**v, *t, *s;
	size_t		 i;

	work_init(&w);
	t = NULL;
	if ((v = storage_argv(&w, sp, &e)) != NULL) {
		base = strrchr(v[0], '/') != NULL ? strrchr(v[0], '/') + 1 :
		    v[0];
		/* A stand-in's name says what it stands for. */
		if (strncmp(base, "fake-", 5) == 0)
			base += 5;
		s = wstrdup(&w, base);
		for (i = 1; v[i] != NULL; i++)
			s = wfmt(&w, "%s %s", s, v[i]);
		t = strdup(s);
	}
	work_free(&w);
	if (t == NULL && (t = strdup("storage")) == NULL)
		err(1, "strdup");
	return (t);
}

/*
 * Why no file system is made on the device: something is mounted from
 * it, a pool or the swap has it, or it has a file system, which only
 * force gives up.  NULL when it may be.
 */
static const char *
newfs_wrong(struct work *w, const char *dev, bool force)
{
	struct statfs	*mnt;
	struct execres	 res;
	const char	*bin, *p;
	char		*argv[4], *path;
	size_t		 len;
	int		 n, i;

	path = wfmt(w, "/dev/%s", dev);
	n = mnts(w, &mnt);
	for (i = 0; i < n; i++)
		if (strcmp(mnt[i].f_mntfromname, path) == 0)
			return (wfmt(w, "%s is mounted on %s", path,
			    mnt[i].f_mntonname));
	argv[0] = (char *)(uintptr_t)opts.swapinfo_bin;
	argv[1] = (char *)(uintptr_t)"-k";
	argv[2] = NULL;
	if (run_exec(w, argv, &res) == 0 && res.out != NULL && strstr(res.out,
	    wfmt(w, "%s ", path)) != NULL)
		return (wfmt(w, "the host swaps on %s", path));
	argv[0] = (char *)(uintptr_t)opts.zpool_bin;
	argv[1] = (char *)(uintptr_t)"status";
	argv[2] = NULL;
	len = strlen(dev);
	if (run_exec(w, argv, &res) == 0 && res.out != NULL)
		for (p = res.out; (p = strstr(p, dev)) != NULL; p += len)
			if ((p == res.out || isspace((unsigned char)p[-1]) ||
			    p[-1] == '/') && (p[len] == '\0' || isspace(
			    (unsigned char)p[len])))
				return (wfmt(w, "%s is a device of a pool",
				    dev));
	if (force)
		return (NULL);
	if ((bin = tool(w, "fstyp")) == NULL)
		return ("the host has no fstyp to tell what is on it: with "
		    "force only");
	argv[0] = (char *)(uintptr_t)bin;
	argv[1] = path;
	argv[2] = NULL;
	if (run_exec(w, argv, &res) == 0 && res.out != NULL && res.out[0] !=
	    '\0')
		return (wfmt(w, "%s has a file system on it (%.*s): it is "
		    "given up with force only", path, (int)strcspn(res.out,
		    "\n"), res.out));
	return (NULL);
}

/* zfs with the words; 0, or -1 and zfs's words in *errp. */
static int
zfs_run(struct work *w, const char **errp, ...)
{
	struct execres	 res;
	va_list		 ap;
	char		*v[8];
	int		 n;

	n = 0;
	v[n++] = (char *)(uintptr_t)opts.zfs_bin;
	va_start(ap, errp);
	while (n < 7 && (v[n] = va_arg(ap, char *)) != NULL)
		n++;
	va_end(ap);
	v[n] = NULL;
	if (run_exec(w, v, &res) != 0) {
		*errp = wtext(w, exec_error(w, &res, "zfs"));
		return (-1);
	}
	return (0);
}

/*
 * A dataset's newest snapshot made again, now, under the same name:
 * the new one is taken first under a name of its own, the old one
 * destroyed, and the new one given the name.  There is a snapshot all
 * along; one zfs will not destroy (held, cloned) stays as it was.
 */
static int
resnapshot(struct work *w, const char *snap, bool recursive,
    const char **errp)
{
	static const char *const list[] = { "list", "-H", "-o", "name",
	    "-s", "createtxg", "-t", "snapshot", "-d", "1" };
	struct execres	 res;
	const char	*r, *newest, *p;
	char		*ds, *tmp, *argv[nitems(list) + 3];
	size_t		 i;

	ds = wstrndup(w, snap, strcspn(snap, "@"));
	r = recursive ? "-r" : NULL;
	argv[0] = (char *)(uintptr_t)opts.zfs_bin;
	for (i = 0; i < nitems(list); i++)
		argv[i + 1] = (char *)(uintptr_t)list[i];
	argv[i + 1] = ds;
	argv[i + 2] = NULL;
	if (run_exec(w, argv, &res) != 0) {
		*errp = wtext(w, exec_error(w, &res, "zfs"));
		return (-1);
	}
	/* The last line: the newest, by when it was made. */
	newest = NULL;
	for (p = res.out != NULL ? res.out : ""; *p != '\0';
	    p += strcspn(p, "\n"), p += *p == '\n')
		if (p[0] != '\n')
			newest = p;
	if (newest == NULL || strncmp(newest, snap, strlen(snap)) != 0 ||
	    (newest[strlen(snap)] != '\n' && newest[strlen(snap)] != '\0')) {
		*errp = newest == NULL ? wfmt(w, "%s has no snapshot", ds) :
		    wfmt(w, "%s is not the newest snapshot of %s: %.*s is",
		    snap, ds, (int)strcspn(newest, "\n"), newest);
		return (-1);
	}
	tmp = wfmt(w, "%s.resnap", snap);
	if (zfs_run(w, errp, "snapshot", r != NULL ? r : tmp, r != NULL ?
	    tmp : NULL, NULL) != 0)
		return (-1);
	if (zfs_run(w, errp, "destroy", r != NULL ? r : snap, r != NULL ?
	    snap : NULL, NULL) != 0) {
		/* The old one stays: the new one goes. */
		(void)zfs_run(w, &p, "destroy", r != NULL ? r : tmp, r !=
		    NULL ? tmp : NULL, NULL);
		*errp = wfmt(w, "%s is kept as it was: %s", snap, *errp);
		return (-1);
	}
	if (zfs_run(w, errp, "rename", r != NULL ? r : tmp, r != NULL ? tmp :
	    snap, r != NULL ? snap : NULL, NULL) != 0) {
		*errp = wfmt(w, "the new snapshot is %s, not renamed: %s", tmp,
		    *errp);
		return (-1);
	}
	return (0);
}

int
do_storage_job(struct work *w, const struct arc_job_spec *sp,
    const char **errp)
{
	struct execres	 res;
	char		**v;

	if ((v = storage_argv(w, sp, errp)) == NULL)
		return (-1);
	if (sp->kind == ARC_JOB_KIND_ZFS && strcmp(sp->verb, "resnapshot") ==
	    0)
		return (resnapshot(w, sp->names.v[0], sp->recursive, errp));
	if (sp->kind == ARC_JOB_KIND_GPART && sp->verb != NULL && (strcmp(
	    sp->verb, "newfs") == 0 || strcmp(sp->verb, "newfs-msdos") == 0) &&
	    (*errp = newfs_wrong(w, sp->names.v[0], sp->force)) != NULL)
		return (-1);
	if (run_exec(w, v, &res) != 0) {
		*errp = wtext(w, exec_error(w, &res, strrchr(v[0], '/') !=
		    NULL ? strrchr(v[0], '/') + 1 : v[0]));
		return (-1);
	}
	return (0);
}

static const char *
sha_hex(struct work *w, const char *data, size_t len)
{
	unsigned char	md[SHA256_DIGEST_LENGTH];
	char		*hex;
	size_t		 i;

	SHA256((const unsigned char *)data, len, md);
	hex = wcalloc(w, 2 * sizeof(md) + 1, 1);
	for (i = 0; i < sizeof(md); i++)
		snprintf(hex + 2 * i, 3, "%02x", md[i]);
	return (hex);
}

static char *
slurp(struct work *w, const char *path, size_t *lenp)
{
	struct stat	 sb;
	char		*buf;
	ssize_t		 n;
	int		 fd;

	if ((fd = open(path, O_RDONLY | O_CLOEXEC)) == -1)
		return (NULL);
	if (fstat(fd, &sb) == -1 || !S_ISREG(sb.st_mode) || sb.st_size >
	    FSTAB_MAX) {
		close(fd);
		errno = EFBIG;
		return (NULL);
	}
	buf = wcalloc(w, (size_t)sb.st_size + 1, 1);
	n = read(fd, buf, (size_t)sb.st_size);
	close(fd);
	if (n != sb.st_size)
		return (NULL);
	*lenp = (size_t)n;
	return (buf);
}

/*
 * Is the text an fstab(5)?  Every line that is not blank or a comment
 * has a device, a mount point, a type and options, and after them at
 * most two numbers.  NULL, or what is wrong and where.
 */
static const char *
fstab_wrong(struct work *w, const char *text)
{
	char	*copy, *line, *p, *f[7];
	int	 n, lineno;

	lineno = 0;
	copy = wstrdup(w, text);
	while ((line = strsep(&copy, "\n")) != NULL) {
		lineno++;
		p = line + strspn(line, " \t");
		if (*p == '\0' || *p == '#')
			continue;
		for (n = 0; n < 7 && (f[n] = strsep(&p, " \t")) != NULL; )
			if (f[n][0] != '\0')
				n++;
		if (n < 4 || n > 6)
			return (wfmt(w, "line %d: an entry is a device, a "
			    "mount point, a type and options, then at most "
			    "two numbers", lineno));
		if (f[1][0] != '/' && strcmp(f[1], "none") != 0)
			return (wfmt(w, "line %d: %s is no mount point: a "
			    "whole path, or none", lineno, f[1]));
		if (!word_ok(f[2], "_.", 32))
			return (wfmt(w, "line %d: %s is no type of file "
			    "system", lineno, f[2]));
		if ((n > 4 && f[4][strspn(f[4], "0123456789")] != '\0') ||
		    (n > 5 && f[5][strspn(f[5], "0123456789")] != '\0'))
			return (wfmt(w, "line %d: the dump frequency and the "
			    "pass are numbers", lineno));
	}
	return (NULL);
}

/*
 * fstab(5): read with its checksum, or put back whole.  A new text has
 * to be an fstab, and to be made from the one that is there: the
 * SHA-256 of that says so.  The one before is kept beside it.
 */
int
do_fstab(struct work *w, const struct arc_fstab_req *rq,
    struct arc_fstab_rsp *rsp)
{
	const char	*path, *sha, *bad;
	char		*old, *tmp, *bak;
	size_t		 oldlen, len;
	int		 fd, step;

	rsp->has_ok = true;
	rsp->ok = false;
	path = opts.fstab_path;
	oldlen = 0;
	step = step_begin(w, ARC_STEP_KIND_FILE, "read", "%s", path);
	old = slurp(w, path, &oldlen);
	step_end(w, step, old != NULL || errno == ENOENT, old != NULL ? NULL :
	    "%s", strerror(errno));
	if (old == NULL && errno != ENOENT) {
		rsp->error = wfmt(w, "%s: %s", path, strerror(errno));
		return (0);
	}
	if (old == NULL)
		old = wstrdup(w, "");
	sha = sha_hex(w, old, oldlen);
	rsp->conf_text = wtext(w, old);
	rsp->sha256 = sha;
	if (rq->conf_text == NULL) {
		rsp->ok = true;
		return (0);
	}
	if (rq->sha256 == NULL || strcmp(rq->sha256, sha) != 0) {
		rsp->error = "the file is not the one this was made from: "
		    "somebody changed it meanwhile.  Read it again";
		return (0);
	}
	len = strlen(rq->conf_text);
	if (len > FSTAB_MAX || (len > 0 && rq->conf_text[len - 1] != '\n')) {
		rsp->error = len > FSTAB_MAX ? "too large for an fstab" :
		    "the last line has to end as the others do";
		return (0);
	}
	if ((bad = fstab_wrong(w, rq->conf_text)) != NULL) {
		rsp->error = bad;
		return (0);
	}
	if (rq->dry_run) {
		rsp->ok = true;
		return (0);
	}
	tmp = wfmt(w, "%s.arcana-new", path);
	bak = wfmt(w, "%s.arcana-old", path);
	step = step_begin(w, ARC_STEP_KIND_FILE, "write", "%s", path);
	if ((fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC |
	    O_NOFOLLOW, 0644)) == -1 || write(fd, rq->conf_text, len) !=
	    (ssize_t)len || fsync(fd) == -1) {
		rsp->error = wfmt(w, "%s: %s", tmp, strerror(errno));
		step_end(w, step, false, "%s", rsp->error);
		if (fd != -1)
			close(fd);
		(void)unlink(tmp);
		return (0);
	}
	close(fd);
	/* The one before stays beside it, under another name. */
	(void)unlink(bak);
	if ((oldlen > 0 && link(path, bak) == -1 && errno != ENOENT) ||
	    rename(tmp, path) == -1) {
		rsp->error = wfmt(w, "%s: %s", path, strerror(errno));
		step_end(w, step, false, "%s", rsp->error);
		(void)unlink(tmp);
		return (0);
	}
	step_end(w, step, true, "the one before it is kept as %s", bak);
	rsp->conf_text = wtext(w, wstrdup(w, rq->conf_text));
	rsp->sha256 = sha_hex(w, rq->conf_text, len);
	rsp->ok = true;
	return (0);
}
