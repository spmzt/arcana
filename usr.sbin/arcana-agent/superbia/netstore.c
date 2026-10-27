/*-
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * The host's network storage services, the base system's: the NFS
 * server, NFSv4 alone (nfsd(8) with nfsv4_server_only, mountd(8) for
 * the exports, no NFSv3 and no rpcbind; exports(5) with its V4: root,
 * a directory on ZFS; the datasets that share themselves by sharenfs,
 * zfsprops(7), which zfs writes to /etc/zfs/exports for mountd; NFSv4.2
 * by vfs.nfsd.server_max_minorversion, pNFS by nfsd's -p and -m, as
 * pnfsserver(4) has it), the iSCSI target (ctld(8), ctl.conf(5),
 * ctladm(8)) and HAST (hastd(8), hast.conf(5), hastctl(8)).  Read
 * whole (the netstore operation), changed by jobs of the nfs, iscsi and
 * hast kinds.
 */

#include <sys/param.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/sysctl.h>

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <ucl.h>

#include "agent.h"

#define	TEXT_MAX	(256 * 1024)

static void
put_s(ucl_object_t *o, const char *k, const char *v)
{

	if (v != NULL)
		ucl_object_insert_key(o, ucl_object_fromstring(v), k, 0, true);
}

static void
put_b(ucl_object_t *o, const char *k, bool v)
{

	ucl_object_insert_key(o, ucl_object_frombool(v), k, 0, true);
}

static char *
slurp(struct work *w, const char *path)
{
	FILE	*fp;
	char	*buf;
	size_t	 n;

	if ((fp = fopen(path, "re")) == NULL)
		return (NULL);
	buf = wcalloc(w, TEXT_MAX + 1, 1);
	n = fread(buf, 1, TEXT_MAX, fp);
	fclose(fp);
	buf[n] = '\0';
	return (buf);
}

/* A file of the system's, written whole: a new one moved over it, with
 * the mode given (ctl.conf may hold CHAP secrets). */
static int
put_file(struct work *w, const char *path, const char *text, mode_t mode,
    const char **errp)
{
	const char	*tmp;
	int		 fd;
	size_t		 len;

	tmp = wfmt(w, "%s.arcana-new", path);
	len = strlen(text);
	if ((fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC |
	    O_NOFOLLOW, mode)) == -1 || fchmod(fd, mode) != 0 || write(fd, text,
	    len) != (ssize_t)len || fsync(fd) != 0) {
		*errp = wfmt(w, "%s: %s", path, strerror(errno));
		if (fd != -1)
			(void)close(fd);
		(void)unlink(tmp);
		return (-1);
	}
	/* Closed once: a failed close or rename closes no other thread's. */
	if (close(fd) != 0 || rename(tmp, path) != 0) {
		*errp = wfmt(w, "%s: %s", path, strerror(errno));
		(void)unlink(tmp);
		return (-1);
	}
	return (0);
}

/* A text a file of the system's is given: printable lines, no NUL. */
static bool
text_ok(const char *t)
{
	const unsigned char	*p;

	if (t == NULL || strlen(t) > TEXT_MAX)
		return (false);
	for (p = (const unsigned char *)t; *p != '\0'; p++)
		if (*p < 0x20 && *p != '\n' && *p != '\t' && *p != '\r')
			return (false);
	return (true);
}

static const char *
tool_out(struct work *w, const char *name, const char *const *args, size_t n)
{
	struct execres	 res;
	const char	*bin;
	char		*argv[8];
	size_t		 i;

	if ((bin = tool(w, name)) == NULL)
		return (NULL);
	argv[0] = (char *)(uintptr_t)bin;
	for (i = 0; i < n && i < 6; i++)
		argv[i + 1] = (char *)(uintptr_t)args[i];
	argv[i + 1] = NULL;
	if (run_exec(w, argv, &res) != 0)
		return (NULL);
	return (wtext(w, res.out));
}

static void
service_json(struct work *w, ucl_object_t *o, const char *name)
{
	bool	enabled, running;

	enabled = running = false;
	service_state(w, name, &running, &enabled);
	put_b(o, wfmt(w, "%s_enabled", name), enabled);
	put_b(o, wfmt(w, "%s_running", name), running);
}

/* nfs_server_flags' words: -n threads, -p the data servers, -m the
 * mirrors. */
static void
nfs_flags_json(struct work *w, ucl_object_t *o, const char *flags)
{
	char	*copy, *it, *word;

	put_s(o, "flags", flags);
	if (flags == NULL)
		return;
	copy = wstrdup(w, flags);
	for (it = copy; (word = strsep(&it, " \t")) != NULL;) {
		if (it == NULL)
			break;
		if (strcmp(word, "-n") == 0)
			put_s(o, "threads", strsep(&it, " \t"));
		else if (strcmp(word, "-p") == 0)
			put_s(o, "pnfs", strsep(&it, " \t"));
		else if (strcmp(word, "-m") == 0)
			put_s(o, "mirror", strsep(&it, " \t"));
	}
}

/*
 * The path of the first V4: line of exports(5), NFSv4's root; NULL
 * for none.  *any says whether the text exports anything at all (a
 * line that is not blank and not a comment).
 */
static const char *
v4_root(struct work *w, const char *text, bool *any)
{
	char	*copy, *it, *line, *p;

	*any = false;
	if (text == NULL)
		return (NULL);
	copy = wstrdup(w, text);
	for (it = copy; (line = strsep(&it, "\n")) != NULL;) {
		line += strspn(line, " \t");
		if (line[0] == '\0' || line[0] == '#')
			continue;
		*any = true;
		if (strncmp(line, "V4:", 3) != 0)
			continue;
		p = line + 3;
		p += strspn(p, " \t");
		p[strcspn(p, " \t\r")] = '\0';
		return (p[0] != '\0' ? p : NULL);
	}
	return (NULL);
}

/* Is the directory on ZFS?  NULL, or why it is not. */
static const char *
not_on_zfs(struct work *w, const char *path)
{
	struct statfs	sf;

	if (statfs(path, &sf) == -1)
		return (wfmt(w, "%s: %s", path, strerror(errno)));
	if (strcmp(sf.f_fstypename, "zfs") != 0)
		return (wfmt(w, "%s is not on ZFS (%s)", path, sf.f_fstypename));
	return (NULL);
}

/* A ZFS filesystem's name: pool/path, no leading slash, no dots up. */
static bool
dataset_ok(const char *s)
{
	size_t	i, n;

	n = strlen(s);
	if (n == 0 || n > 256 || s[0] == '/' || s[0] == '-' ||
	    strstr(s, "..") != NULL)
		return (false);
	for (i = 0; i < n; i++)
		if (!isalnum((unsigned char)s[i]) && strchr("_.:/-", s[i]) ==
		    NULL)
			return (false);
	return (true);
}

static ucl_object_t *
nfs_json(struct work *w)
{
	ucl_object_t	*o, *arr, *s;
	const char	*v, *root, *why;
	char		*copy, *it, *line, *name, *mnt, *share;
	int		 minor;
	size_t		 len;
	bool		 any;

	o = ucl_object_typed_new(UCL_OBJECT);
	service_json(w, o, "nfsd");
	service_json(w, o, "mountd");
	put_s(o, "nfs_server_enable", rc_get(w, "nfs_server_enable"));
	put_s(o, "nfsv4_server_enable", rc_get(w, "nfsv4_server_enable"));
	put_s(o, "nfsv4_server_only", rc_get(w, "nfsv4_server_only"));
	put_s(o, "nfsuserd_enable", rc_get(w, "nfsuserd_enable"));
	nfs_flags_json(w, o, rc_get(w, "nfs_server_flags"));
	len = sizeof(minor);
	if (sysctlbyname("vfs.nfsd.server_max_minorversion", &minor, &len,
	    NULL, 0) == 0)
		ucl_object_insert_key(o, ucl_object_fromint(minor),
		    "max_minorversion", 0, false);
	put_s(o, "exports_path", opts.exports_file);
	if ((v = slurp(w, opts.exports_file)) != NULL) {
		put_s(o, "exports", wtext(w, v));
		/* NFSv4's root, and whether it is on ZFS. */
		if ((root = v4_root(w, v, &any)) != NULL) {
			put_s(o, "v4root", root);
			why = not_on_zfs(w, root);
			ucl_object_insert_key(o, ucl_object_frombool(why == NULL),
			    "v4root_zfs", 0, false);
			if (why != NULL)
				put_s(o, "v4root_error", why);
		}
	}
	/* What zfs wrote for mountd, from the datasets' sharenfs. */
	if ((v = slurp(w, "/etc/zfs/exports")) != NULL)
		put_s(o, "zfs_exports", wtext(w, v));
	/* The datasets that share themselves (sharenfs, zfsprops(7)). */
	{
		struct execres	 res;
		char		*argv[8];

		argv[0] = (char *)(uintptr_t)opts.zfs_bin;
		argv[1] = (char *)(uintptr_t)"list";
		argv[2] = (char *)(uintptr_t)"-H";
		argv[3] = (char *)(uintptr_t)"-o";
		argv[4] = (char *)(uintptr_t)"name,mountpoint,sharenfs";
		argv[5] = (char *)(uintptr_t)"-t";
		argv[6] = (char *)(uintptr_t)"filesystem";
		argv[7] = NULL;
		arr = ucl_object_typed_new(UCL_ARRAY);
		if (run_exec(w, argv, &res) == 0 && res.out != NULL) {
			copy = wstrndup(w, res.out, res.outlen);
			for (it = copy; (line = strsep(&it, "\n")) != NULL;) {
				name = strsep(&line, "\t");
				mnt = strsep(&line, "\t");
				share = line;
				if (name == NULL || mnt == NULL || share == NULL ||
				    strcmp(share, "off") == 0 || strcmp(share, "-") ==
				    0)
					continue;
				s = ucl_object_typed_new(UCL_OBJECT);
				put_s(s, "dataset", name);
				put_s(s, "mountpoint", mnt);
				put_s(s, "sharenfs", share);
				ucl_array_append(arr, s);
			}
		}
		ucl_object_insert_key(o, arr, "shares", 0, false);
	}
	/* What mountd exports now, as showmount(8) asks it. */
	{
		static const char *const e[] = { "-e", "localhost" };

		if ((v = tool_out(w, "showmount", e, 2)) != NULL)
			put_s(o, "exported", v);
	}
	return (o);
}

static ucl_object_t *
iscsi_json(struct work *w)
{
	static const char *const devlist[] = { "devlist" };
	static const char *const islist[] = { "islist" };
	static const char *const portlist[] = { "portlist", "-f", "iscsi" };
	ucl_object_t	*o;
	const char	*v;

	o = ucl_object_typed_new(UCL_OBJECT);
	service_json(w, o, "ctld");
	service_json(w, o, "iscsid");
	put_s(o, "conf_path", opts.ctl_conf);
	if ((v = slurp(w, opts.ctl_conf)) != NULL)
		put_s(o, "conf", wtext(w, v));
	if ((v = tool_out(w, "ctladm", devlist, 1)) != NULL)
		put_s(o, "luns", v);
	if ((v = tool_out(w, "ctladm", islist, 1)) != NULL)
		put_s(o, "sessions", v);
	if ((v = tool_out(w, "ctladm", portlist, 3)) != NULL)
		put_s(o, "ports", v);
	return (o);
}

static ucl_object_t *
hast_json(struct work *w)
{
	static const char *const status[] = { "status" };
	static const char *const list[] = { "list" };
	ucl_object_t	*o;
	const char	*v;

	o = ucl_object_typed_new(UCL_OBJECT);
	service_json(w, o, "hastd");
	put_s(o, "conf_path", opts.hast_conf);
	if ((v = slurp(w, opts.hast_conf)) != NULL)
		put_s(o, "conf", wtext(w, v));
	if ((v = tool_out(w, "hastctl", status, 1)) != NULL)
		put_s(o, "status", v);
	if ((v = tool_out(w, "hastctl", list, 1)) != NULL)
		put_s(o, "list", v);
	return (o);
}

void
do_netstore(struct work *w, const char *const *names, size_t n,
    struct arc_netstore_rsp *rsp)
{
	ucl_object_t	*top;
	char		*json;
	size_t		 i;
	bool		 all;

	rsp->has_ok = true;
	rsp->ok = false;
	all = n == 0;
	for (i = 0; i < n; i++)
		if (names[i] == NULL || (strcmp(names[i], "nfs") != 0 &&
		    strcmp(names[i], "iscsi") != 0 && strcmp(names[i], "hast") !=
		    0)) {
			rsp->error = "netstore reads nfs, iscsi and hast, or all "
			    "of them";
			return;
		}
	top = ucl_object_typed_new(UCL_OBJECT);
	for (i = 0; i < n || (all && i == 0); i++) {
		if (all || strcmp(names[i], "nfs") == 0)
			ucl_object_insert_key(top, nfs_json(w), "nfs", 0, false);
		if (all || strcmp(names[i], "iscsi") == 0)
			ucl_object_insert_key(top, iscsi_json(w), "iscsi", 0,
			    false);
		if (all || strcmp(names[i], "hast") == 0)
			ucl_object_insert_key(top, hast_json(w), "hast", 0,
			    false);
	}
	json = (char *)ucl_object_emit(top, UCL_EMIT_JSON_COMPACT);
	ucl_object_unref(top);
	if (json == NULL) {
		rsp->error = "out of memory";
		return;
	}
	rsp->json = wstrdup(w, json);
	free(json);
	rsp->ok = true;
}

/* ---- Jobs ------------------------------------------------------------ */

static const char *
word(const struct arc_job_spec *sp, const char *key)
{
	size_t	i, k;

	k = strlen(key);
	for (i = 0; i < sp->names.n; i++)
		if (sp->names.v[i] != NULL && strncmp(sp->names.v[i], key, k) ==
		    0 && sp->names.v[i][k] == '=')
			return (sp->names.v[i] + k + 1);
	return (NULL);
}

static bool
yes_no(const char *v)
{

	return (v != NULL && (strcmp(v, "yes") == 0 || strcmp(v, "no") == 0));
}

/* host:/path,host:/path: pNFS's data servers, as nfsd's -p takes them. */
static bool
ds_ok(const char *s)
{
	size_t	n;

	n = strlen(s);
	return (n > 0 && n < 512 && strspn(s, "abcdefghijklmnopqrstuvwxyz"
	    "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-_:/,#[]") == n &&
	    strchr(s, ':') != NULL);
}

static bool
words_known(const struct arc_job_spec *sp, const char *const *keys)
{
	const char *const *k;
	size_t		 i, len;

	for (i = 0; i < sp->names.n; i++) {
		if (sp->names.v[i] == NULL)
			return (false);
		for (k = keys; *k != NULL; k++) {
			len = strlen(*k);
			if (strncmp(sp->names.v[i], *k, len) == 0 &&
			    sp->names.v[i][len] == '=')
				break;
		}
		if (*k == NULL)
			return (false);
	}
	return (true);
}

const char *
netstore_check(const struct arc_job_spec *sp)
{
	static const char *const server[] = { "enable", "minor", "threads",
	    "pnfs", "mirror", NULL };
	static const char *const share[] = { "dataset", "sharenfs", NULL };
	static const char *const enable[] = { "enable", NULL };
	static const char *const role[] = { "resource", "role", NULL };
	static const char *const create[] = { "resource", NULL };
	const char	*v;

	if (sp->jail != NULL && sp->jail[0] != '\0')
		return ("the host's storage services are the host's");
	if (sp->safe)
		return ("a storage service is not undone: not in safe mode");
	if (sp->verb == NULL)
		return ("a storage job has a verb");
	switch (sp->kind) {
	case ARC_JOB_KIND_NFS:
		if (strcmp(sp->verb, "exports") == 0)
			return (text_ok(sp->text) ? NULL : "exports is the text "
			    "of exports(5)");
		if (strcmp(sp->verb, "share") == 0) {
			if (!words_known(sp, share) || (v = word(sp, "dataset")) ==
			    NULL || !dataset_ok(v))
				return ("share takes dataset= (a ZFS filesystem's "
				    "name) and sharenfs=");
			if ((v = word(sp, "sharenfs")) == NULL || v[0] == '\0' ||
			    strlen(v) > 256 || strcspn(v, "\n\r") != strlen(v))
				return ("sharenfs is on, off or exports(5) options, "
				    "one line");
			return (NULL);
		}
		if (strcmp(sp->verb, "server") != 0)
			return ("an nfs job's verb is exports, share or server");
		if (!words_known(sp, server))
			return ("server takes enable=, minor=, threads=, pnfs= and "
			    "mirror=");
		if ((v = word(sp, "enable")) != NULL && !yes_no(v))
			return ("enable is yes or no");
		if ((v = word(sp, "minor")) != NULL && strcmp(v, "0") != 0 &&
		    strcmp(v, "1") != 0 && strcmp(v, "2") != 0)
			return ("minor is NFSv4's 0, 1 or 2");
		if ((v = word(sp, "threads")) != NULL && (strlen(v) > 3 ||
		    strspn(v, "0123456789") != strlen(v) || atoi(v) < 1 ||
		    atoi(v) > 256))
			return ("threads is 1 to 256");
		if ((v = word(sp, "pnfs")) != NULL && v[0] != '\0' && !ds_ok(v))
			return ("pnfs is the data servers, host:/path joined by "
			    "commas");
		if ((v = word(sp, "mirror")) != NULL && v[0] != '\0' &&
		    (strspn(v, "0123456789") != strlen(v) || atoi(v) < 2 ||
		    atoi(v) > 8))
			return ("mirror is 2 to 8 (pNFS's mirrors of a file)");
		return (NULL);
	case ARC_JOB_KIND_ISCSI:
		if (strcmp(sp->verb, "conf") == 0)
			return (text_ok(sp->text) ? NULL : "conf is the text of "
			    "ctl.conf(5)");
		if (strcmp(sp->verb, "enable") == 0)
			return (words_known(sp, enable) && yes_no(word(sp,
			    "enable")) ? NULL : "enable takes enable=yes or no");
		return ("an iscsi job's verb is conf or enable");
	case ARC_JOB_KIND_HAST:
		if (strcmp(sp->verb, "conf") == 0)
			return (text_ok(sp->text) ? NULL : "conf is the text of "
			    "hast.conf(5)");
		if (strcmp(sp->verb, "enable") == 0)
			return (words_known(sp, enable) && yes_no(word(sp,
			    "enable")) ? NULL : "enable takes enable=yes or no");
		if (strcmp(sp->verb, "role") == 0 || strcmp(sp->verb,
		    "create") == 0) {
			if (!words_known(sp, strcmp(sp->verb, "role") == 0 ?
			    role : create) || (v = word(sp, "resource")) ==
			    NULL || v[0] == '\0' || strlen(v) > 64 || strspn(v,
			    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
			    "0123456789_-.") != strlen(v) || v[0] == '-' ||
			    v[0] == '.' || strcmp(v, "all") == 0)
				return ("a hast resource is named: resource= "
				    "(one, not all)");
			if (strcmp(sp->verb, "role") == 0 && ((v = word(sp,
			    "role")) == NULL || (strcmp(v, "init") != 0 &&
			    strcmp(v, "primary") != 0 && strcmp(v,
			    "secondary") != 0)))
				return ("role is init, primary or secondary");
			return (NULL);
		}
		return ("a hast job's verb is conf, enable, role or create");
	default:
		return ("not a storage job");
	}
}

char *
netstore_title(const struct arc_job_spec *sp)
{
	const char	*k;
	char		*t;

	k = sp->kind == ARC_JOB_KIND_NFS ? "nfs" : sp->kind ==
	    ARC_JOB_KIND_ISCSI ? "iscsi" : "hast";
	if (asprintf(&t, "%s %s%s%s", k, sp->verb, word(sp, "resource") !=
	    NULL ? " " : "", word(sp, "resource") != NULL ? word(sp,
	    "resource") : "") == -1)
		return (NULL);
	return (t);
}

/* A service enabled or disabled in rc.conf, and started or stopped. */
static int
service_onoff(struct work *w, const char *name, bool on, const char **errp)
{
	struct arc_service_action_rsp	 r;

	memset(&r, 0, sizeof(r));
	if (do_service_action(w, name, on ? ARC_SERVICE_ACTION_ENABLE :
	    ARC_SERVICE_ACTION_DISABLE, &r) != 0 || !r.ok) {
		*errp = r.error != NULL ? r.error : wfmt(w, "%s not %s", name,
		    on ? "enabled" : "disabled");
		return (-1);
	}
	memset(&r, 0, sizeof(r));
	if (do_service_action(w, name, on ? ARC_SERVICE_ACTION_RESTART :
	    ARC_SERVICE_ACTION_STOP, &r) != 0 || !r.ok) {
		*errp = r.error != NULL ? r.error : wfmt(w, "%s not %s", name,
		    on ? "started" : "stopped");
		return (-1);
	}
	return (0);
}

/* Told to read its configuration again, where it runs; -1 and why
 * when it refuses (the file is written: what it said is the error). */
static int
service_reload(struct work *w, const char *name, const char **errp)
{
	struct arc_service_action_rsp	 r;
	bool				 enabled, running;

	enabled = running = false;
	service_state(w, name, &running, &enabled);
	if (!running)
		return (0);
	memset(&r, 0, sizeof(r));
	if (do_service_action(w, name, ARC_SERVICE_ACTION_RELOAD, &r) != 0 ||
	    !r.ok) {
		*errp = wfmt(w, "written, but %s did not take it: %s", name,
		    r.error != NULL ? r.error : "reload failed");
		return (-1);
	}
	return (0);
}

static int
nfs_server(struct work *w, const struct arc_job_spec *sp, const char **errp)
{
	const char	*v, *flags, *threads, *pnfs, *mirror;
	bool		 on;

	/* NFSv4.2 (or .1, or .0), now and at the next boot. */
	if ((v = word(sp, "minor")) != NULL && do_sysctl_set(w,
	    "vfs.nfsd.server_max_minorversion", v, true, errp) != 0)
		return (-1);
	/* nfsd's flags: its threads, and pNFS's data servers and mirrors
	 * (pnfsserver(4)); the rest as they were. */
	threads = word(sp, "threads");
	pnfs = word(sp, "pnfs");
	mirror = word(sp, "mirror");
	if (threads != NULL || pnfs != NULL || mirror != NULL) {
		/* The flags as they are, -n, -p and -m replaced by what is
		 * given, the others kept. */
		const char	*was = rc_get(w, "nfs_server_flags"), *has_p;
		char		*copy, *it, *tok, out[1024];
		size_t		 off;

		/* Each word put while there is room; past it, refused. */
#define	PUT(...)	do {						\
	if (off < sizeof(out))						\
		off += (size_t)snprintf(out + off, sizeof(out) - off,	\
		    __VA_ARGS__);					\
} while (0)
		copy = wstrdup(w, was != NULL ? was : "-u -t -n 4");
		out[0] = '\0';
		off = 0;
		has_p = pnfs;
		for (it = copy; (tok = strsep(&it, " \t")) != NULL;) {
			if (tok[0] == '\0')
				continue;
			if ((strcmp(tok, "-n") == 0 && threads != NULL) ||
			    (strcmp(tok, "-p") == 0 && pnfs != NULL) ||
			    (strcmp(tok, "-m") == 0 && (mirror != NULL || (pnfs !=
			    NULL && pnfs[0] == '\0')))) {
				(void)strsep(&it, " \t");
				continue;
			}
			if (strcmp(tok, "-p") == 0 && has_p == NULL)
				has_p = "kept";
			PUT("%s%s", off > 0 ? " " : "", tok);
		}
		if (threads != NULL)
			PUT(" -n %s", threads);
		if (pnfs != NULL && pnfs[0] != '\0')
			PUT(" -p %s", pnfs);
		if (mirror != NULL && mirror[0] != '\0') {
			if (has_p == NULL || has_p[0] == '\0') {
				*errp = "mirror needs pNFS's data servers (pnfs=)";
				return (-1);
			}
			PUT(" -m %s", mirror);
		}
#undef	PUT
		if (off >= sizeof(out)) {
			*errp = "nfsd's flags are too long";
			return (-1);
		}
		flags = out;
		if (rc_set(w, "nfs_server_flags", "=", flags, errp) != 0)
			return (-1);
	}
	if ((v = word(sp, "enable")) != NULL) {
		on = strcmp(v, "yes") == 0;
		/* NFSv4 alone: no NFSv3, so no rpcbind; mountd for the
		 * exports (rc.d/nfsd and rc.d/mountd know the setting). */
		if (on && (rc_set(w, "nfsv4_server_enable", "=", "YES", errp) !=
		    0 || rc_set(w, "nfsv4_server_only", "=", "YES", errp) != 0 ||
		    rc_set(w, "mountd_enable", "=", "YES", errp) != 0))
			return (-1);
		if (service_onoff(w, "nfsd", on, errp) != 0)
			return (-1);
		return (0);
	}
	/* Running: started again, as it reads its flags at its start. */
	{
		bool	enabled = false, running = false;

		service_state(w, "nfsd", &running, &enabled);
		if (running) {
			struct arc_service_action_rsp	r;

			memset(&r, 0, sizeof(r));
			(void)do_service_action(w, "nfsd",
			    ARC_SERVICE_ACTION_RESTART, &r);
		}
	}
	return (0);
}

int
do_netstore_job(struct work *w, const struct arc_job_spec *sp,
    const char **errp)
{
	static const char *const create[] = { "create", NULL, NULL };
	const char	*v, *bin;
	struct execres	 res;
	char		*argv[6];
	int		 step;

	if ((*errp = netstore_check(sp)) != NULL)
		return (-1);
	switch (sp->kind) {
	case ARC_JOB_KIND_NFS:
		if (strcmp(sp->verb, "share") == 0) {
			/* zfs writes /etc/zfs/exports and tells mountd itself. */
			argv[0] = (char *)(uintptr_t)opts.zfs_bin;
			argv[1] = (char *)(uintptr_t)"set";
			argv[2] = wfmt(w, "sharenfs=%s", word(sp, "sharenfs"));
			argv[3] = (char *)(uintptr_t)word(sp, "dataset");
			argv[4] = NULL;
			if (run_exec(w, argv, &res) != 0) {
				*errp = wfmt(w, "zfs set sharenfs: %s", exec_error(w,
				    &res, "zfs set"));
				return (-1);
			}
			return (0);
		}
		if (strcmp(sp->verb, "exports") == 0) {
			const char	*root, *why;
			bool		 any;

			/* NFSv4 alone: nothing is served without the V4:
			 * root, and the root is a directory on ZFS. */
			root = v4_root(w, sp->text, &any);
			if (root == NULL && any) {
				*errp = "NFSv4 alone: exports needs a V4: line, its "
				    "root a directory on ZFS";
				return (-1);
			}
			if (root != NULL && (why = not_on_zfs(w, root)) != NULL) {
				*errp = wfmt(w, "V4: root %s", why);
				return (-1);
			}
			if (put_file(w, opts.exports_file, sp->text, 0644, errp) !=
			    0)
				return (-1);
			/* mountd reads exports(5) again on SIGHUP. */
			return (service_reload(w, "mountd", errp));
		}
		return (nfs_server(w, sp, errp));
	case ARC_JOB_KIND_ISCSI:
		if (strcmp(sp->verb, "conf") == 0) {
			if (put_file(w, opts.ctl_conf, sp->text, 0600, errp) != 0)
				return (-1);
			return (service_reload(w, "ctld", errp));
		}
		return (service_onoff(w, "ctld", strcmp(word(sp, "enable"),
		    "yes") == 0, errp));
	case ARC_JOB_KIND_HAST:
		if (strcmp(sp->verb, "conf") == 0) {
			if (put_file(w, opts.hast_conf, sp->text, 0644, errp) !=
			    0)
				return (-1);
			return (service_reload(w, "hastd", errp));
		}
		if (strcmp(sp->verb, "enable") == 0)
			return (service_onoff(w, "hastd", strcmp(word(sp,
			    "enable"), "yes") == 0, errp));
		if ((bin = tool(w, "hastctl")) == NULL)
			bin = "/sbin/hastctl";
		v = word(sp, "resource");
		argv[0] = (char *)(uintptr_t)bin;
		if (strcmp(sp->verb, "role") == 0) {
			argv[1] = (char *)(uintptr_t)"role";
			argv[2] = (char *)(uintptr_t)word(sp, "role");
			argv[3] = (char *)(uintptr_t)v;
			argv[4] = NULL;
		} else {
			argv[1] = (char *)(uintptr_t)create[0];
			argv[2] = (char *)(uintptr_t)v;
			argv[3] = NULL;
		}
		step = step_begin(w, ARC_STEP_KIND_EXEC, "hastctl", "%s %s",
		    sp->verb, v);
		if (run_exec(w, argv, &res) != 0) {
			*errp = wtext(w, exec_error(w, &res, "hastctl"));
			step_end(w, step, false, "%s", *errp);
			return (-1);
		}
		step_end(w, step, true, NULL);
		return (0);
	default:
		*errp = "not a storage job";
		return (-1);
	}
}
