/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Superbia: the host as a bundle, and a bundle made the host
 * (config-export, config-apply).
 *
 * A bundle is what makes the host what it is beyond its hardware and
 * its data: the configuration files Arcana manages, each by the path it
 * has on every FreeBSD host, with its mode, owner, group and text; the
 * packages installed by hand; and what the hardware is, for another
 * host to be checked against before it takes the files.  The agent's
 * own identity (its TLS key and certificates, its SSH keys) is never in
 * it: a host made the same is another host still, enrolled as itself.
 * Secrets (WireGuard's and strongSwan's) are only when asked for.
 *
 * Applied, only paths that a bundle may carry are written, each
 * checked against the same table that made it: a bundle is not a way
 * to write anywhere.  What was there is kept first, under
 * /var/backups/arcana/config-<time>, and each file is written beside
 * itself and renamed into place.  Nothing is restarted: rc.conf,
 * loader.conf and the rest take hold at the next boot, which the
 * report says.  Packages the bundle has and the host lacks are told,
 * never installed (Arcana installs nothing by itself).
 *
 * --root puts every system path under a directory: a test's tree.
 */

#include <sys/param.h>
#include <sys/disk.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/sockio.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <sys/utsname.h>

#include <net/if.h>
#include <net/if_dl.h>
#include <net/if_types.h>

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <ifaddrs.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <ucl.h>
#include <unistd.h>

#include "jailconf.h"
#include "agent.h"

#define	BUNDLE_FILE_MAX	(1024 * 1024)	/* of one file's text */
#define	BUNDLE_FILES	512
#define	BUNDLE_BACKUPS	"/var/backups/arcana"

/* Where a path a bundle names is on this host. */
struct place {
	bool		 dir;		/* the files in it, one level */
	const char	*path;		/* in the bundle: FreeBSD's own */
	const char	*local;		/* here: the option's, else NULL */
	bool		 secret;
};

static const char *
arcana_dir(struct work *w)
{
	const char	*slash = strrchr(opts.history_conf, '/');

	return (slash != NULL ? wfmt(w, "%.*s", (int)(slash -
	    opts.history_conf), opts.history_conf) : ".");
}

/* The places, this host's options in them. */
static size_t
places(struct work *w, struct place *p, size_t max)
{
	size_t	n = 0;

#define	P(d, path, local, secret)	do {				\
	if (n < max)							\
		p[n++] = (struct place){ d, path, local, secret };	\
} while (0)
	P(false, "/etc/rc.conf", NULL, false);
	P(false, "/etc/rc.conf.local", NULL, false);
	P(true, "/etc/rc.conf.d", NULL, false);
	P(false, "/boot/loader.conf", NULL, false);
	P(false, "/boot/loader.conf.local", NULL, false);
	P(true, "/boot/loader.conf.d", NULL, false);
	P(false, "/etc/sysctl.conf", opts.sysctl_conf, false);
	P(false, "/etc/sysctl.conf.local", NULL, false);
	P(false, "/etc/jail.conf", opts.jail_conf, false);
	P(true, "/etc/jail.conf.d", opts.jail_conf_d, false);
	P(false, "/etc/fstab", opts.fstab_path, false);
	P(false, "/etc/hosts", NULL, false);
	P(false, "/etc/resolv.conf", NULL, false);
	P(false, "/etc/ntp.conf", opts.ntp_conf, false);
	P(false, "/etc/rtadvd.conf", opts.rtadvd_conf, false);
	P(false, "/etc/ssh/sshd_config", NULL, false);
	P(false, "/etc/devfs.rules", NULL, false);
	P(false, "/etc/syslog.conf", NULL, false);
	P(true, "/etc/syslog.d", NULL, false);
	P(true, "/etc/newsyslog.conf.d", NULL, false);
	P(false, "/etc/periodic.conf", NULL, false);
	P(false, "/usr/local/etc/bird.conf", opts.bird_conf, false);
	P(false, "/usr/local/etc/swanctl/swanctl.conf", wfmt(w,
	    "%s/swanctl.conf", opts.swanctl_dir), true);
	P(true, "/usr/local/etc/swanctl/conf.d", wfmt(w, "%s/conf.d",
	    opts.swanctl_dir), true);
	P(true, "/usr/local/etc/swanctl/private", wfmt(w, "%s/private",
	    opts.swanctl_dir), true);
	P(true, "/usr/local/etc/swanctl/x509", wfmt(w, "%s/x509",
	    opts.swanctl_dir), false);
	P(true, "/usr/local/etc/swanctl/x509ca", wfmt(w, "%s/x509ca",
	    opts.swanctl_dir), false);
	P(true, "/usr/local/etc/wireguard", opts.wg_dir, true);
	P(false, "/usr/local/etc/dnsmasq.conf", NULL, false);
	P(true, "/usr/local/etc/arcana", arcana_dir(w), false);
#undef P
	return (n);
}

/* A place's path here: the option's, else FreeBSD's under --root. */
static const char *
local_of(struct work *w, const struct place *p)
{

	if (p->local != NULL && strcmp(p->local, p->path) != 0)
		return (p->local);
	return (opts.root != NULL ? wfmt(w, "%s%s", opts.root, p->path) :
	    p->path);
}

/* A file's name in a directory a bundle has: nothing hidden or else. */
static bool
name_ok(const char *s)
{
	size_t	i;

	if (s[0] == '\0' || s[0] == '.' || strlen(s) > 128)
		return (false);
	for (i = 0; s[i] != '\0'; i++)
		if (!((s[i] >= 'a' && s[i] <= 'z') || (s[i] >= 'A' && s[i] <=
		    'Z') || (s[i] >= '0' && s[i] <= '9') || strchr("._-+@",
		    s[i]) != NULL))
			return (false);
	return (true);
}

/* The agent's own: its TLS files, its SSH keys, what is made beside. */
static bool
identity(const char *local, const char *name)
{
	size_t	n = strlen(name);

	return (tls_file_is(local) || strncmp(name, "id_", 3) == 0 ||
	    strncmp(name, "known_hosts", 11) == 0 || (n > 5 &&
	    strcmp(name + n - 5, ".next") == 0) || (n > 7 && strcmp(name +
	    n - 7, ".before") == 0));
}

/*
 * Where path of a bundle is written here, and whether it is a secret;
 * NULL: no bundle may carry it.
 */
static const char *
resolve(struct work *w, const char *path, bool *secret)
{
	struct place	 p[48];
	const char	*slash, *local;
	size_t		 n, i, dl;

	n = places(w, p, nitems(p));
	for (i = 0; i < n; i++) {
		if (!p[i].dir && strcmp(path, p[i].path) == 0) {
			*secret = p[i].secret;
			return (local_of(w, &p[i]));
		}
		dl = strlen(p[i].path);
		if (p[i].dir && strncmp(path, p[i].path, dl) == 0 &&
		    path[dl] == '/' && (slash = strrchr(path, '/')) == path +
		    dl && name_ok(slash + 1)) {
			local = wfmt(w, "%s/%s", local_of(w, &p[i]), slash + 1);
			if (identity(local, slash + 1))
				return (NULL);
			/* Of the agent's own directory, what it writes there:
			 * its ipfw rules, its sampling, its build's settings,
			 * the SD-WAN's files. */
			if (strcmp(p[i].path, "/usr/local/etc/arcana") == 0 &&
			    strcmp(slash + 1, "history.conf") != 0 &&
			    strcmp(slash + 1, "ipfw.rules") != 0 &&
			    strcmp(slash + 1, "config.mk") != 0 &&
			    strncmp(slash + 1, "sdwan-", 6) != 0)
				return (NULL);
			/* What runs leaves there is not configuration. */
			if (strstr(slash + 1, ".pid") != NULL || strstr(slash +
			    1, ".lease") != NULL || strstr(slash + 1, ".log") !=
			    NULL)
				return (NULL);
			*secret = p[i].secret || (strlen(slash + 1) > 4 &&
			    (strcmp(slash + strlen(slash) - 4, ".key") == 0 ||
			    strcmp(slash + strlen(slash) - 4, ".pem") == 0));
			return (local);
		}
	}
	return (NULL);
}

/* A regular file's text, at most BUNDLE_FILE_MAX, none with a NUL. */
static char *
slurp(struct work *w, const char *path, struct stat *sb)
{
	char	*buf;
	ssize_t	 r;
	int	 fd;

	if ((fd = open(path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK |
	    O_CLOEXEC)) == -1)
		return (NULL);
	if (fstat(fd, sb) == -1 || !S_ISREG(sb->st_mode) || sb->st_size >
	    BUNDLE_FILE_MAX) {
		close(fd);
		return (NULL);
	}
	buf = wmalloc(w, (size_t)sb->st_size + 1);
	r = read(fd, buf, (size_t)sb->st_size);
	close(fd);
	if (r != sb->st_size || memchr(buf, '\0', (size_t)r) != NULL)
		return (NULL);
	buf[r] = '\0';
	return (buf);
}

static void
put_str(ucl_object_t *o, const char *k, const char *v)
{

	if (v != NULL)
		ucl_object_insert_key(o, ucl_object_fromstring(v), k, 0, true);
}

static void
put_int(ucl_object_t *o, const char *k, int64_t v)
{

	ucl_object_insert_key(o, ucl_object_fromint(v), k, 0, true);
}

/* One file of the bundle, when it is there. */
static void
file_add(struct work *w, ucl_object_t *arr, const char *path,
    const char *local, bool secret, bool secrets)
{
	struct stat	 sb;
	struct passwd	*pw;
	struct group	*gr;
	ucl_object_t	*o;
	char		*text;

	if (ucl_array_size(arr) >= BUNDLE_FILES ||
	    (text = slurp(w, local, &sb)) == NULL)
		return;
	o = ucl_object_typed_new(UCL_OBJECT);
	put_str(o, "path", path);
	put_str(o, "mode", wfmt(w, "%04o", (unsigned)(sb.st_mode & 07777)));
	pw = getpwuid(sb.st_uid);
	gr = getgrgid(sb.st_gid);
	put_str(o, "owner", pw != NULL ? pw->pw_name : wfmt(w, "%u",
	    (unsigned)sb.st_uid));
	put_str(o, "group", gr != NULL ? gr->gr_name : wfmt(w, "%u",
	    (unsigned)sb.st_gid));
	/* A private key wherever it is: a secret too. */
	secret = secret || strstr(text, "PRIVATE KEY-----") != NULL ||
	    strstr(text, "PrivateKey") != NULL;
	if (secret && !secrets)
		ucl_object_insert_key(o, ucl_object_frombool(true), "secret", 0,
		    true);
	else {
		put_str(o, "text", text);
		if (secret)
			ucl_object_insert_key(o, ucl_object_frombool(true),
			    "secret", 0, true);
	}
	ucl_array_append(arr, o);
}

static int
name_cmp(const void *a, const void *b)
{

	return (strcmp(*(char *const *)a, *(char *const *)b));
}

static ucl_object_t *
files_of(struct work *w, bool secrets)
{
	struct place	 p[48];
	struct dirent	*de;
	ucl_object_t	*arr;
	const char	*local;
	char		*names[BUNDLE_FILES];
	size_t		 n, i, k, nn;
	DIR		*d;

	arr = ucl_object_typed_new(UCL_ARRAY);
	n = places(w, p, nitems(p));
	for (i = 0; i < n; i++) {
		local = local_of(w, &p[i]);
		if (!p[i].dir) {
			file_add(w, arr, p[i].path, local, p[i].secret, secrets);
			continue;
		}
		if ((d = opendir(local)) == NULL)
			continue;
		nn = 0;
		while ((de = readdir(d)) != NULL && nn < nitems(names))
			if (name_ok(de->d_name))
				names[nn++] = wstrdup(w, de->d_name);
		closedir(d);
		qsort(names, nn, sizeof(names[0]), name_cmp);
		for (k = 0; k < nn; k++) {
			bool	secret;
			const char *path = wfmt(w, "%s/%s", p[i].path,
			    names[k]);

			if ((local = resolve(w, path, &secret)) != NULL)
				file_add(w, arr, path, local, secret, secrets);
		}
	}
	return (arr);
}

/* ---- What the hardware is ------------------------------------------ */

static const char *
sysctl_str(struct work *w, const char *name)
{
	char	buf[256];
	size_t	len = sizeof(buf) - 1;

	if (sysctlbyname(name, buf, &len, NULL, 0) == -1)
		return (NULL);
	buf[len] = '\0';
	return (wstrdup(w, buf));
}

/* Is name of a cloner's (bridge0, vlan10, wg0): configuration, not
 * hardware. */
static bool
cloned(const char *name, const char *cl, int ncl)
{
	size_t	n = strcspn(name, "0123456789");
	int	i;

	for (i = 0; i < ncl; i++)
		if (strlen(cl + i * IFNAMSIZ) == n && strncmp(name, cl + i *
		    IFNAMSIZ, n) == 0)
			return (true);
	return (false);
}

/* The cloners' names, IFNAMSIZ each: SIOCIFGCLONERS. */
static char *
cloners(int *n)
{
	struct if_clonereq	 ifcr;
	char			*buf;
	int			 s;

	*n = 0;
	if ((s = socket(AF_LOCAL, SOCK_DGRAM | SOCK_CLOEXEC, 0)) == -1)
		return (NULL);
	memset(&ifcr, 0, sizeof(ifcr));
	if (ioctl(s, SIOCIFGCLONERS, &ifcr) == -1 || ifcr.ifcr_total == 0 ||
	    (buf = calloc((size_t)ifcr.ifcr_total, IFNAMSIZ)) == NULL) {
		close(s);
		return (NULL);
	}
	ifcr.ifcr_count = ifcr.ifcr_total;
	ifcr.ifcr_buffer = buf;
	if (ioctl(s, SIOCIFGCLONERS, &ifcr) == -1) {
		free(buf);
		close(s);
		return (NULL);
	}
	close(s);
	*n = ifcr.ifcr_count < ifcr.ifcr_total ? ifcr.ifcr_count :
	    ifcr.ifcr_total;
	return (buf);
}

/* The physical interfaces: name, driver and MAC. */
static ucl_object_t *
interfaces(struct work *w)
{
	struct ifaddrs		*ifa, *i;
	struct sockaddr_dl	*sdl;
	ucl_object_t		*arr, *o;
	unsigned char		*m;
	char			*cl;
	int			 ncl;

	arr = ucl_object_typed_new(UCL_ARRAY);
	if (getifaddrs(&ifa) == -1)
		return (arr);
	cl = cloners(&ncl);
	for (i = ifa; i != NULL; i = i->ifa_next) {
		if (i->ifa_addr == NULL || i->ifa_addr->sa_family != AF_LINK)
			continue;
		sdl = (struct sockaddr_dl *)(void *)i->ifa_addr;
		if (sdl->sdl_type == IFT_LOOP || cloned(i->ifa_name, cl, ncl) ||
		    sdl->sdl_alen != 6)
			continue;
		m = (unsigned char *)LLADDR(sdl);
		o = ucl_object_typed_new(UCL_OBJECT);
		put_str(o, "name", i->ifa_name);
		put_str(o, "driver", wfmt(w, "%.*s", (int)strcspn(i->ifa_name,
		    "0123456789"), i->ifa_name));
		put_str(o, "mac", wfmt(w, "%02x:%02x:%02x:%02x:%02x:%02x", m[0],
		    m[1], m[2], m[3], m[4], m[5]));
		ucl_array_append(arr, o);
	}
	free(cl);
	freeifaddrs(ifa);
	return (arr);
}

/* kern.disks, each with its size where it can be read. */
static ucl_object_t *
disks(struct work *w)
{
	ucl_object_t	*arr, *o;
	const char	*all;
	char		*copy, *p, *name;
	off_t		 size;
	int		 fd;

	arr = ucl_object_typed_new(UCL_ARRAY);
	if ((all = sysctl_str(w, "kern.disks")) == NULL)
		return (arr);
	copy = wstrdup(w, all);
	for (p = copy; (name = strsep(&p, " ")) != NULL; ) {
		if (name[0] == '\0')
			continue;
		o = ucl_object_typed_new(UCL_OBJECT);
		put_str(o, "name", name);
		if ((fd = open(wfmt(w, "/dev/%s", name), O_RDONLY |
		    O_CLOEXEC)) != -1) {
			if (ioctl(fd, DIOCGMEDIASIZE, &size) == 0)
				put_int(o, "size", (int64_t)size);
			close(fd);
		}
		ucl_array_prepend(arr, o);
	}
	return (arr);
}

static ucl_object_t *
facts(struct work *w)
{
	ucl_object_t	*o;
	uint64_t	 mem;
	size_t		 len;
	int		 ncpu;

	o = ucl_object_typed_new(UCL_OBJECT);
	put_str(o, "arch", sysctl_str(w, "hw.machine_arch"));
	put_str(o, "release", sysctl_str(w, "kern.osrelease"));
	put_str(o, "cpu", sysctl_str(w, "hw.model"));
	len = sizeof(ncpu);
	if (sysctlbyname("hw.ncpu", &ncpu, &len, NULL, 0) == 0)
		put_int(o, "ncpu", ncpu);
	len = sizeof(mem);
	if (sysctlbyname("hw.physmem", &mem, &len, NULL, 0) == 0)
		put_int(o, "memory", (int64_t)mem);
	ucl_object_insert_key(o, interfaces(w), "interfaces", 0, true);
	ucl_object_insert_key(o, disks(w), "disks", 0, true);
	return (o);
}

/* pkg(8)'s packages installed by hand: name, origin, version. */
static ucl_object_t *
packages(struct work *w)
{
	struct execres	 res;
	ucl_object_t	*arr, *o;
	char		*out, *line, *p, *f[3];
	char *const	 argv[] = { (char *)(uintptr_t)opts.pkg_bin,
	    (char *)(uintptr_t)"query", (char *)(uintptr_t)"-e",
	    (char *)(uintptr_t)"%a = 0", (char *)(uintptr_t)"%n\t%o\t%v",
	    NULL };
	int		 k;

	arr = ucl_object_typed_new(UCL_ARRAY);
	if (run_exec(w, argv, &res) != 0 || res.status != 0 || res.out ==
	    NULL)
		return (arr);
	out = wmalloc(w, res.outlen + 1);
	memcpy(out, res.out, res.outlen);
	out[res.outlen] = '\0';
	for (p = out; (line = strsep(&p, "\n")) != NULL; ) {
		for (k = 0; k < 3 && (f[k] = strsep(&line, "\t")) != NULL; k++)
			;
		if (k < 3 || f[0][0] == '\0')
			continue;
		o = ucl_object_typed_new(UCL_OBJECT);
		put_str(o, "name", f[0]);
		put_str(o, "origin", f[1]);
		put_str(o, "version", f[2]);
		ucl_array_append(arr, o);
	}
	return (arr);
}

static const char *
emit(struct work *w, ucl_object_t *top)
{
	unsigned char	*json;

	json = ucl_object_emit(top, UCL_EMIT_JSON_COMPACT);
	ucl_object_unref(top);
	if (json == NULL || strlen((char *)json) > ARC_MAX_JSON) {
		free(json);
		return (NULL);
	}
	return (wtext(w, wadopt(w, json)));
}

int
do_config_export(struct work *w, bool secrets, struct json_rsp *rsp)
{
	ucl_object_t	*top;
	char		 iso[32];
	time_t		 now = time(NULL);
	int		 step;

	rsp->has_ok = true;
	strftime(iso, sizeof(iso), "%Y-%m-%dT%H:%M:%SZ", gmtime(&now));
	top = ucl_object_typed_new(UCL_OBJECT);
	put_str(top, "arcana", "host");
	put_int(top, "format", 1);
	put_str(top, "host", sysctl_str(w, "kern.hostname"));
	put_str(top, "agent", ARCANA_AGENT_VERSION);
	put_str(top, "taken", iso);
	step = step_begin(w, ARC_STEP_KIND_LIB, "sysctl(3)", "the hardware: "
	    "hw.*, kern.disks, getifaddrs(3) less the cloners");
	ucl_object_insert_key(top, facts(w), "facts", 0, true);
	step_end(w, step, true, NULL);
	step = step_begin(w, ARC_STEP_KIND_EXEC, "pkg", "query: those "
	    "installed by hand");
	ucl_object_insert_key(top, packages(w), "packages", 0, true);
	step_end(w, step, true, NULL);
	step = step_begin(w, ARC_STEP_KIND_FILE, "read", "the configuration "
	    "files Arcana manages%s", secrets ? ", secrets too" : "");
	ucl_object_insert_key(top, files_of(w, secrets), "files", 0, true);
	step_end(w, step, true, NULL);
	if ((rsp->json = emit(w, top)) == NULL) {
		rsp->error = "the bundle is larger than a reply carries";
		return (0);
	}
	rsp->ok = true;
	return (0);
}

/* ---- Applied ------------------------------------------------------- */

static bool
has_name(const ucl_object_t *arr, const char *name)
{
	const ucl_object_t	*e;
	ucl_object_iter_t	 it = NULL;

	while ((e = ucl_object_iterate(arr, &it, true)) != NULL)
		if (ucl_object_tostring(ucl_object_lookup(e, "name")) != NULL &&
		    strcmp(ucl_object_tostring(ucl_object_lookup(e, "name")),
		    name) == 0)
			return (true);
	return (false);
}

/* The directories above path made, as mkdir -p. */
static int
mkparents(const char *path)
{
	char	buf[MAXPATHLEN], *p;

	if (strlcpy(buf, path, sizeof(buf)) >= sizeof(buf))
		return (ENAMETOOLONG);
	for (p = buf + 1; (p = strchr(p, '/')) != NULL; p++) {
		*p = '\0';
		if (mkdir(buf, 0755) == -1 && errno != EEXIST)
			return (errno);
		*p = '/';
	}
	return (0);
}

/* text at path, by a file beside it renamed into place. */
static int
write_file(const char *path, const char *text, mode_t mode, uid_t uid,
    gid_t gid, bool own)
{
	char	tmp[MAXPATHLEN];
	size_t	len = strlen(text);
	int	fd, e;

	if ((e = mkparents(path)) != 0)
		return (e);
	snprintf(tmp, sizeof(tmp), "%s.arcana-new", path);
	if ((fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW |
	    O_CLOEXEC, mode)) == -1)
		return (errno);
	if (write(fd, text, len) != (ssize_t)len || fchmod(fd, mode) == -1 ||
	    (own && fchown(fd, uid, gid) == -1) || fsync(fd) == -1) {
		e = errno != 0 ? errno : EIO;
		close(fd);
		unlink(tmp);
		return (e);
	}
	close(fd);
	if (rename(tmp, path) == -1) {
		e = errno;
		unlink(tmp);
		return (e);
	}
	return (0);
}

/* rc.conf's hostname set to name: the line replaced, or added. */
static char *
rehost(struct work *w, const char *text, const char *name)
{
	const char	*p, *e;
	char		*out;
	size_t		 cap;

	cap = strlen(text) + strlen(name) + 32;
	out = wmalloc(w, cap);
	out[0] = '\0';
	for (p = text; *p != '\0'; p = e) {
		e = strchr(p, '\n');
		e = e != NULL ? e + 1 : p + strlen(p);
		if (strncmp(p + strspn(p, " \t"), "hostname=", 9) == 0)
			continue;
		strncat(out, p, (size_t)(e - p));
	}
	if (out[0] != '\0' && out[strlen(out) - 1] != '\n')
		strlcat(out, "\n", cap);
	strlcat(out, "hostname=\"", cap);
	strlcat(out, name, cap);
	strlcat(out, "\"\n", cap);
	return (out);
}

int
do_config_apply(struct work *w, const char *bundle, bool dry_run,
    bool anyway, const char *new_hostname, struct json_rsp *rsp)
{
	struct ucl_parser	*p;
	ucl_object_t		*b, *top, *mism, *files, *pk, *one, *here;
	const ucl_object_t	*f, *e, *x;
	ucl_object_iter_t	 it;
	const char		*path, *local, *text, *arch, *backup;
	char			*cur, iso[32];
	struct stat		 sb;
	struct passwd		*pw;
	struct group		*gr;
	time_t			 now = time(NULL);
	bool			 secret, own;
	int			 step, nchanged, error;

	rsp->has_ok = true;
	if (new_hostname != NULL && new_hostname[0] != '\0' &&
	    (strspn(new_hostname, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOP"
	    "QRSTUVWXYZ0123456789-.") != strlen(new_hostname) || strlen(
	    new_hostname) > 255)) {
		rsp->error = "the new host name is a name: letters, digits, "
		    "- and .";
		return (0);
	}
	p = ucl_parser_new(UCL_PARSER_NO_IMPLICIT_ARRAYS);
	b = ucl_parser_add_string(p, bundle, 0) ? ucl_parser_get_object(p) :
	    NULL;
	ucl_parser_free(p);
	if (b == NULL || ucl_object_tostring(ucl_object_lookup(b, "arcana")) ==
	    NULL || strcmp(ucl_object_tostring(ucl_object_lookup(b, "arcana")),
	    "host") != 0 || ucl_object_toint(ucl_object_lookup(b, "format")) !=
	    1) {
		if (b != NULL)
			ucl_object_unref(b);
		rsp->error = "not a host's bundle (config-export's, format 1)";
		return (0);
	}
	top = ucl_object_typed_new(UCL_OBJECT);

	/* The hardware the bundle was made on, against this host's. */
	step = step_begin(w, ARC_STEP_KIND_LIB, "sysctl(3)", "the hardware "
	    "against the bundle's");
	here = facts(w);
	mism = ucl_object_typed_new(UCL_ARRAY);
	arch = ucl_object_tostring(ucl_object_lookup(ucl_object_lookup(b,
	    "facts"), "arch"));
	if (arch != NULL && ucl_object_tostring(ucl_object_lookup(here,
	    "arch")) != NULL && strcmp(arch, ucl_object_tostring(
	    ucl_object_lookup(here, "arch"))) != 0)
		ucl_array_append(mism, ucl_object_fromstring(wfmt(w, "the "
		    "bundle is of %s, this host %s", arch, ucl_object_tostring(
		    ucl_object_lookup(here, "arch")))));
	it = NULL;
	while ((e = ucl_object_iterate(ucl_object_lookup(ucl_object_lookup(b,
	    "facts"), "interfaces"), &it, true)) != NULL)
		if ((x = ucl_object_lookup(e, "name")) != NULL &&
		    !has_name(ucl_object_lookup(here, "interfaces"),
		    ucl_object_tostring_forced(x)))
			ucl_array_append(mism, ucl_object_fromstring(wfmt(w,
			    "no interface %s here", ucl_object_tostring_forced(
			    x))));
	it = NULL;
	while ((e = ucl_object_iterate(ucl_object_lookup(ucl_object_lookup(b,
	    "facts"), "disks"), &it, true)) != NULL)
		if ((x = ucl_object_lookup(e, "name")) != NULL &&
		    !has_name(ucl_object_lookup(here, "disks"),
		    ucl_object_tostring_forced(x)))
			ucl_array_append(mism, ucl_object_fromstring(wfmt(w,
			    "no disk %s here", ucl_object_tostring_forced(x))));
	step_end(w, step, ucl_array_size(mism) == 0, "%u not the same",
	    ucl_array_size(mism));
	ucl_object_insert_key(top, mism, "mismatches", 0, true);

	/* The packages it has and this host does not: told, not installed. */
	step = step_begin(w, ARC_STEP_KIND_EXEC, "pkg", "query: those "
	    "here, against the bundle's");
	pk = ucl_object_typed_new(UCL_ARRAY);
	{
		ucl_object_t	*have = packages(w);

		it = NULL;
		while ((e = ucl_object_iterate(ucl_object_lookup(b,
		    "packages"), &it, true)) != NULL)
			if ((x = ucl_object_lookup(e, "name")) != NULL &&
			    !has_name(have, ucl_object_tostring_forced(x)))
				ucl_array_append(pk, ucl_object_copy(e));
		ucl_object_unref(have);
	}
	step_end(w, step, true, "%u to install", ucl_array_size(pk));
	ucl_object_insert_key(top, pk, "packages", 0, true);
	ucl_object_unref(here);

	/* Each file: where it goes here, and what it changes. */
	step = step_begin(w, ARC_STEP_KIND_FILE, "read", "each file of the "
	    "bundle against this host's");
	files = ucl_object_typed_new(UCL_ARRAY);
	nchanged = 0;
	it = NULL;
	while ((f = ucl_object_iterate(ucl_object_lookup(b, "files"), &it,
	    true)) != NULL) {
		path = ucl_object_tostring(ucl_object_lookup(f, "path"));
		text = ucl_object_tostring(ucl_object_lookup(f, "text"));
		if (path == NULL || (local = resolve(w, path, &secret)) ==
		    NULL) {
			step_end(w, step, false, "%s: no bundle carries it",
			    path != NULL ? path : "a file without a path");
			rsp->error = wfmt(w, "%s: not a file a bundle may "
			    "carry; nothing was done", path != NULL ? path :
			    "a file without a path");
			goto out;
		}
		if (new_hostname != NULL && new_hostname[0] != '\0' &&
		    text != NULL && strcmp(path, "/etc/rc.conf") == 0)
			text = rehost(w, text, new_hostname);
		one = ucl_object_typed_new(UCL_OBJECT);
		put_str(one, "path", path);
		cur = slurp(w, local, &sb);
		if (text == NULL)
			put_str(one, "state", "withheld");
		else if (cur != NULL && strcmp(cur, text) == 0)
			put_str(one, "state", "same");
		else {
			put_str(one, "state", cur != NULL ? "changed" : "new");
			if (cur != NULL && !secret)
				put_str(one, "diff", wtext(w, wadopt(w,
				    jc_diff(path, cur, strlen(cur), text,
				    strlen(text)))));
			nchanged++;
		}
		ucl_array_append(files, one);
	}
	step_end(w, step, true, "%d to change", nchanged);
	ucl_object_insert_key(top, files, "files", 0, true);
	if (ucl_array_size(mism) > 0 && !anyway) {
		rsp->error = wfmt(w, "this host's hardware is not the bundle's "
		    "(%u differences): nothing was done", ucl_array_size(mism));
		goto report;
	}
	if (dry_run || nchanged == 0)
		goto report;

	/* What is there kept, then each written in its place. */
	strftime(iso, sizeof(iso), "%Y%m%d-%H%M%S", localtime(&now));
	backup = wfmt(w, "%s%s/config-%s", opts.root != NULL ? opts.root : "",
	    BUNDLE_BACKUPS, iso);
	step = step_begin(w, ARC_STEP_KIND_FILE, "write", "the files before, "
	    "to %s", backup);
	it = NULL;
	while ((f = ucl_object_iterate(ucl_object_lookup(b, "files"), &it,
	    true)) != NULL) {
		path = ucl_object_tostring(ucl_object_lookup(f, "path"));
		local = resolve(w, path, &secret);
		if (ucl_object_lookup(f, "text") == NULL ||
		    (cur = slurp(w, local, &sb)) == NULL)
			continue;
		if ((error = write_file(wfmt(w, "%s%s", backup, path), cur,
		    sb.st_mode & 07777, sb.st_uid, sb.st_gid, geteuid() ==
		    0)) != 0) {
			step_end(w, step, false, "%s: %s", path,
			    strerror(error));
			rsp->error = wfmt(w, "%s could not be kept: %s; nothing "
			    "was changed", path, strerror(error));
			goto report;
		}
	}
	step_end(w, step, true, NULL);
	put_str(top, "backup", backup);
	it = NULL;
	while ((f = ucl_object_iterate(ucl_object_lookup(b, "files"), &it,
	    true)) != NULL) {
		mode_t	mode;

		path = ucl_object_tostring(ucl_object_lookup(f, "path"));
		local = resolve(w, path, &secret);
		if ((text = ucl_object_tostring(ucl_object_lookup(f, "text"))) ==
		    NULL)
			continue;
		if (new_hostname != NULL && new_hostname[0] != '\0' &&
		    strcmp(path, "/etc/rc.conf") == 0)
			text = rehost(w, text, new_hostname);
		if ((cur = slurp(w, local, &sb)) != NULL && strcmp(cur, text) ==
		    0)
			continue;
		mode = (mode_t)strtoul(ucl_object_tostring_forced(
		    ucl_object_lookup(f, "mode")), NULL, 8) & 07777;
		if (mode == 0)
			mode = secret ? 0600 : 0644;
		pw = ucl_object_lookup(f, "owner") != NULL ? getpwnam(
		    ucl_object_tostring_forced(ucl_object_lookup(f, "owner"))) :
		    NULL;
		gr = ucl_object_lookup(f, "group") != NULL ? getgrnam(
		    ucl_object_tostring_forced(ucl_object_lookup(f, "group"))) :
		    NULL;
		own = geteuid() == 0;
		step = step_begin(w, ARC_STEP_KIND_FILE, "write", "%s (%04o)",
		    local, (unsigned)mode);
		if ((error = write_file(local, text, mode, pw != NULL ?
		    pw->pw_uid : 0, gr != NULL ? gr->gr_gid : 0, own)) != 0) {
			step_end(w, step, false, "%s", strerror(error));
			rsp->error = wfmt(w, "%s: %s; what was written before it "
			    "stays, the files before are in %s", path,
			    strerror(error), backup);
			goto report;
		}
		step_end(w, step, true, NULL);
	}
	ucl_object_insert_key(top, ucl_object_frombool(true), "applied", 0,
	    true);
	ucl_object_insert_key(top, ucl_object_frombool(true), "reboot", 0,
	    true);
	rsp->ok = true;
	goto report;

report:
	if (dry_run && rsp->error == NULL)
		rsp->ok = true;
	if (!dry_run && nchanged == 0 && rsp->error == NULL)
		rsp->ok = true;
	if ((rsp->json = emit(w, top)) == NULL && rsp->error == NULL) {
		rsp->ok = false;
		rsp->error = "the report is larger than a reply carries";
	}
	ucl_object_unref(b);
	return (0);
out:
	ucl_object_unref(top);
	ucl_object_unref(b);
	return (0);
}
