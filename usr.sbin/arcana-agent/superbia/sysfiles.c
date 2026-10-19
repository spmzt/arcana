/*-
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * The system's own configuration files, a fixed table of them: each
 * read whole and written whole by a sysfile job, whose verb names the
 * entry (no other path can be written this way), then the daemon that
 * reads it told (reload or restart).  devfs.rules(5), devd.conf(5) (a
 * file of Arcana's own beside the system's), syslog.conf(5),
 * newsyslog.conf(5), periodic.conf(5), audit_control(5), audit_user(5),
 * krb5.conf(5), ipsec.conf for setkey(8), rctl.conf(5) and a
 * loader.conf.d file for the boot's tunables.  Read with what shows
 * each at work (the system operation), with the host's NTP peers,
 * Linux compatibility, securelevel, MAC modules, GEOM's tree, GELI's
 * providers, periodic's variables and service jails.
 */

#include <sys/param.h>
#include <sys/stat.h>
#include <sys/sysctl.h>

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <ucl.h>

#include "agent.h"

#define	TEXT_MAX	(256 * 1024)

static const struct sysfile {
	const char	*name;
	const char	*path;
	mode_t		 mode;
	const char	*service;	/* told after a write, or NULL */
	uint8_t		 action;	/* reload or restart */
	const char	*shows;		/* a tool and its words, or NULL */
} files[] = {
	{ "devfs.rules", "/etc/devfs.rules", 0644, "devfs",
	    ARC_SERVICE_ACTION_RESTART, "devfs rule showsets" },
	{ "devd", "/usr/local/etc/devd/arcana.conf", 0644, "devd",
	    ARC_SERVICE_ACTION_RESTART, NULL },
	{ "syslog.conf", "/etc/syslog.conf", 0644, "syslogd",
	    ARC_SERVICE_ACTION_RELOAD, NULL },
	{ "newsyslog.conf", "/etc/newsyslog.conf", 0644, NULL, 0, NULL },
	{ "periodic.conf", "/etc/periodic.conf", 0644, NULL, 0, NULL },
	{ "audit_control", "/etc/security/audit_control", 0600, "auditd",
	    ARC_SERVICE_ACTION_RESTART, NULL },
	{ "audit_user", "/etc/security/audit_user", 0600, "auditd",
	    ARC_SERVICE_ACTION_RESTART, NULL },
	{ "krb5.conf", "/etc/krb5.conf", 0644, NULL, 0, NULL },
	{ "ipsec.conf", "/etc/ipsec.conf", 0600, "ipsec",
	    ARC_SERVICE_ACTION_RESTART, "setkey -DP" },
	{ "rctl.conf", "/etc/rctl.conf", 0644, "rctl",
	    ARC_SERVICE_ACTION_RESTART, "rctl" },
	{ "loader.conf.d", "/boot/loader.conf.d/arcana.conf", 0644, NULL, 0,
	    NULL },
};

static const char *
rooted(struct work *w, const char *path)
{

	return (opts.root != NULL ? wfmt(w, "%s%s", opts.root, path) : path);
}

static void
put_s(ucl_object_t *o, const char *k, const char *v)
{

	if (v != NULL)
		ucl_object_insert_key(o, ucl_object_fromstring(v), k, 0, true);
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

/* A tool's words, its output; NULL when it is not there or fails. */
static const char *
shows(struct work *w, const char *cmd)
{
	struct execres	 res;
	const char	*bin;
	char		*copy, *it, *argv[8];
	int		 n;

	copy = wstrdup(w, cmd);
	it = copy;
	if ((bin = tool(w, strsep(&it, " "))) == NULL)
		return (NULL);
	n = 0;
	argv[n++] = (char *)(uintptr_t)bin;
	while (it != NULL && n < 7)
		argv[n++] = strsep(&it, " ");
	argv[n] = NULL;
	if (run_exec(w, argv, &res) != 0 && res.outlen == 0)
		return (NULL);
	return (wtext(w, res.out));
}

static const struct sysfile *
file_of(const char *name)
{
	size_t	i;

	for (i = 0; i < nitems(files); i++)
		if (name != NULL && strcmp(files[i].name, name) == 0)
			return (&files[i]);
	return (NULL);
}

static ucl_object_t *
file_json(struct work *w, const struct sysfile *f)
{
	ucl_object_t	*o;
	const char	*v;
	bool		 enabled, running;

	o = ucl_object_typed_new(UCL_OBJECT);
	put_s(o, "path", f->path);
	if ((v = slurp(w, rooted(w, f->path))) != NULL)
		put_s(o, "text", wtext(w, v));
	if (f->service != NULL) {
		enabled = running = false;
		service_state(w, f->service, &enabled, &running);
		put_s(o, "service", f->service);
		ucl_object_insert_key(o, ucl_object_frombool(enabled),
		    "enabled", 0, false);
		ucl_object_insert_key(o, ucl_object_frombool(running),
		    "running", 0, false);
	}
	if (f->shows != NULL && (v = shows(w, f->shows)) != NULL)
		put_s(o, "shows", v);
	return (o);
}

static int64_t
sysctl_int(const char *name, int64_t def)
{
	int	v;
	size_t	len;

	len = sizeof(v);
	return (sysctlbyname(name, &v, &len, NULL, 0) == 0 ? v : def);
}

/* The value the last line "name=value" of text gives name, unquoted. */
static const char *
last_value(struct work *w, const char *text, const char *name)
{
	const char	*p, *v, *found;
	size_t		 n;

	n = strlen(name);
	found = NULL;
	for (p = text; p != NULL && *p != '\0'; p = strchr(p, '\n') != NULL ?
	    strchr(p, '\n') + 1 : NULL) {
		if (strncmp(p, name, n) != 0 || p[n] != '=')
			continue;
		v = p + n + 1;
		if (*v == '"')
			v++;
		found = wfmt(w, "%.*s", (int)strcspn(v, "\"\n \t#"), v);
	}
	return (found);
}

/* periodic's variables: those of /etc/defaults/periodic.conf, each
 * with the value periodic.conf gives it, where it does. */
static ucl_object_t *
periodic_json(struct work *w)
{
	ucl_object_t	*arr, *o;
	char		*def, *cur, *it, *line, *eq, *val;
	const char	*mine;

	arr = ucl_object_typed_new(UCL_ARRAY);
	if ((def = slurp(w, rooted(w, "/etc/defaults/periodic.conf"))) ==
	    NULL)
		return (arr);
	cur = slurp(w, rooted(w, "/etc/periodic.conf"));
	for (it = def; (line = strsep(&it, "\n")) != NULL;) {
		if (!islower((unsigned char)line[0]) || (eq = strchr(line,
		    '=')) == NULL)
			continue;
		*eq = '\0';
		if (strlen(line) > 64 || strspn(line,
		    "abcdefghijklmnopqrstuvwxyz0123456789_") != strlen(line) ||
		    strstr(line, "_enable") == NULL)
			continue;
		val = eq + 1;
		val[strcspn(val, "#")] = '\0';
		while (*val == '"')
			val++;
		val[strcspn(val, "\" \t")] = '\0';
		o = ucl_object_typed_new(UCL_OBJECT);
		put_s(o, "name", line);
		put_s(o, "default", val);
		/* What periodic.conf says of it, the last line that does. */
		mine = cur != NULL ? last_value(w, cur, line) : NULL;
		if (mine != NULL)
			put_s(o, "value", mine);
		ucl_array_append(arr, o);
	}
	return (arr);
}

/* rc.conf's service jails: NAME_svcj and NAME_svcj_options. */
static ucl_object_t *
svcj_json(struct work *w)
{
	struct execres	 res;
	ucl_object_t	*o;
	char		*argv[3], *copy, *it, *line, *sep;

	o = ucl_object_typed_new(UCL_OBJECT);
	argv[0] = (char *)(uintptr_t)opts.sysrc_bin;
	argv[1] = (char *)(uintptr_t)"-a";
	argv[2] = NULL;
	if (run_exec(w, argv, &res) != 0 || res.out == NULL)
		return (o);
	copy = wstrdup(w, res.out);
	for (it = copy; (line = strsep(&it, "\n")) != NULL;) {
		if ((sep = strstr(line, ": ")) == NULL)
			continue;
		*sep = '\0';
		if (strstr(line, "_svcj") == NULL)
			continue;
		put_s(o, line, sep + 2);
	}
	return (o);
}

/* Which kernel modules are loaded, of those named. */
static ucl_object_t *
modules_json(const char *const *mods, size_t n)
{
	ucl_object_t	*o;
	size_t		 i;

	o = ucl_object_typed_new(UCL_OBJECT);
	for (i = 0; i < n; i++)
		ucl_object_insert_key(o, ucl_object_frombool(kmod_loaded(
		    mods[i])), mods[i], 0, false);
	return (o);
}

/*
 * Sysctls of hardening, those this kernel has, with their values now:
 * the helper of the Sysctl tab says what each should be and why.
 */
static const char *const hardening[] = {
	"security.bsd.see_other_uids", "security.bsd.see_other_gids",
	"security.bsd.see_jail_proc", "security.bsd.unprivileged_read_msgbuf",
	"security.bsd.unprivileged_proc_debug",
	"security.bsd.hardlink_check_uid", "security.bsd.hardlink_check_gid",
	"security.bsd.unprivileged_get_quota",
	"kern.elf64.aslr.enable", "kern.elf64.aslr.pie_enable",
	"kern.elf64.aslr.stack", "kern.elf64.allow_wx",
	"kern.elf32.aslr.enable", "kern.sugid_coredump",
	"net.inet.tcp.blackhole", "net.inet.udp.blackhole",
	"net.inet.icmp.drop_redirect", "net.inet6.icmp6.rediraccept",
	"net.inet.ip.redirect", "net.inet6.ip6.redirect",
	"net.inet.ip.random_id", "net.inet.tcp.drop_synfin",
	"net.inet.ip.sourceroute", "net.inet.ip.accept_sourceroute",
	"net.inet.icmp.bmcastecho", "kern.securelevel",
};

static ucl_object_t *
hardening_json(void)
{
	ucl_object_t	*o;
	size_t		 i, len;
	int		 v;

	o = ucl_object_typed_new(UCL_OBJECT);
	for (i = 0; i < nitems(hardening); i++) {
		len = sizeof(v);
		if (sysctlbyname(hardening[i], &v, &len, NULL, 0) == 0 &&
		    len == sizeof(v))
			ucl_object_insert_key(o, ucl_object_fromint(v),
			    hardening[i], 0, false);
	}
	return (o);
}

void
do_system(struct work *w, const char *const *names, size_t n,
    struct arc_system_rsp *rsp)
{
	static const char *const mac[] = { "mac_bsdextended", "mac_portacl",
	    "mac_seeotheruids", "mac_partition", "mac_ifoff", "mac_ntpd",
	    "mac_do", "mac_mls", "mac_biba", "mac_lomac" };
	static const char *const linux[] = { "linux", "linux64",
	    "linprocfs", "linsysfs", "fdescfs" };
	ucl_object_t	*top, *o, *fo;
	const char	*v;
	char		*json;
	size_t		 i;
	bool		 enabled, running;

	rsp->has_ok = true;
	rsp->ok = false;
	for (i = 0; i < n; i++)
		if (names[i] == NULL || (file_of(names[i]) == NULL &&
		    strcmp(names[i], "host") != 0)) {
			rsp->error = "system reads its files by name, and host";
			return;
		}
	top = ucl_object_typed_new(UCL_OBJECT);
	fo = ucl_object_typed_new(UCL_OBJECT);
	for (i = 0; i < nitems(files); i++) {
		size_t	k;

		for (k = 0; k < n; k++)
			if (strcmp(names[k], files[i].name) == 0)
				break;
		if (n == 0 || k < n)
			ucl_object_insert_key(fo, file_json(w, &files[i]),
			    files[i].name, 0, false);
	}
	ucl_object_insert_key(top, fo, "files", 0, false);
	for (i = 0; i < n && strcmp(names[i], "host") != 0; i++)
		;
	if (n == 0 || i < n) {
		/* NTP: its servers as ntp.conf has them, its peers. */
		o = ucl_object_typed_new(UCL_OBJECT);
		enabled = running = false;
		service_state(w, "ntpd", &enabled, &running);
		ucl_object_insert_key(o, ucl_object_frombool(enabled), "enabled",
		    0, false);
		ucl_object_insert_key(o, ucl_object_frombool(running), "running",
		    0, false);
		if ((v = slurp(w, opts.ntp_conf)) != NULL)
			put_s(o, "conf", wtext(w, v));
		if ((v = shows(w, "ntpq -pn")) != NULL)
			put_s(o, "peers", v);
		ucl_object_insert_key(top, o, "ntp", 0, false);
		/* Linux compatibility: the service, its modules. */
		o = ucl_object_typed_new(UCL_OBJECT);
		enabled = running = false;
		service_state(w, "linux", &enabled, &running);
		ucl_object_insert_key(o, ucl_object_frombool(enabled), "enabled",
		    0, false);
		ucl_object_insert_key(o, modules_json(linux, nitems(linux)),
		    "modules", 0, false);
		put_s(o, "osrelease", NULL);
		ucl_object_insert_key(top, o, "linux", 0, false);
		/* securelevel, now and at boot. */
		o = ucl_object_typed_new(UCL_OBJECT);
		ucl_object_insert_key(o, ucl_object_fromint(sysctl_int(
		    "kern.securelevel", -1)), "now", 0, false);
		put_s(o, "kern_securelevel_enable", rc_get(w,
		    "kern_securelevel_enable"));
		put_s(o, "kern_securelevel", rc_get(w, "kern_securelevel"));
		ucl_object_insert_key(top, o, "securelevel", 0, false);
		/* MAC: its modules loaded. */
		ucl_object_insert_key(top, modules_json(mac, nitems(mac)),
		    "mac", 0, false);
		/* auditd. */
		o = ucl_object_typed_new(UCL_OBJECT);
		enabled = running = false;
		service_state(w, "auditd", &enabled, &running);
		ucl_object_insert_key(o, ucl_object_frombool(enabled), "enabled",
		    0, false);
		ucl_object_insert_key(o, ucl_object_frombool(running), "running",
		    0, false);
		ucl_object_insert_key(top, o, "auditd", 0, false);
		/* GEOM's tree, GELI's providers, as they say them. */
		if ((v = shows(w, "geom -t")) != NULL)
			put_s(top, "geom", v);
		if ((v = shows(w, "geli list")) != NULL)
			put_s(top, "geli", v);
		ucl_object_insert_key(top, geom_classes_json(w), "geom_classes",
		    0, false);
		/* periodic's variables, and the service jails of rc.conf. */
		ucl_object_insert_key(top, periodic_json(w), "periodic", 0,
		    false);
		ucl_object_insert_key(top, svcj_json(w), "svcj", 0, false);
		/* rctl(8) needs racct, a tunable of the boot. */
		ucl_object_insert_key(top, ucl_object_fromint(sysctl_int(
		    "kern.racct.enable", 0)), "racct", 0, false);
		ucl_object_insert_key(top, hardening_json(), "hardening", 0,
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

/* ---- The sysfile job: a file of the table written ------------------ */

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

const char *
sysfile_check(const struct arc_job_spec *sp)
{
	size_t	i;

	if (sp->jail != NULL && sp->jail[0] != '\0')
		return ("the system's files are the host's");
	/* rc.conf's variables no service owns: securelevel's at boot. */
	if (sp->verb != NULL && strcmp(sp->verb, "rc") == 0) {
		if (sp->names.n == 0)
			return ("rc sets kern_securelevel_enable= and "
			    "kern_securelevel=");
		for (i = 0; i < sp->names.n; i++) {
			const char	*v = sp->names.v[i];

			if (v == NULL || !((strncmp(v, "kern_securelevel_enable=",
			    24) == 0 && (strcmp(v + 24, "YES") == 0 ||
			    strcmp(v + 24, "NO") == 0)) || (strncmp(v,
			    "kern_securelevel=", 17) == 0 && (strcmp(v + 17,
			    "-1") == 0 || (v[17] >= '0' && v[17] <= '3' &&
			    v[18] == '\0')))))
				return ("rc sets kern_securelevel_enable=YES or "
				    "NO and kern_securelevel=-1 to 3");
		}
		return (NULL);
	}
	if (sp->verb != NULL && strcmp(sp->verb, "periodic") == 0) {
		/* periodic.conf's variables: name=YES|NO, each a periodic
		 * one. */
		if (sp->names.n == 0)
			return ("periodic sets its variables: name=YES or NO");
		for (i = 0; i < sp->names.n; i++) {
			const char	*v = sp->names.v[i], *eq;

			if (v == NULL || (eq = strchr(v, '=')) == NULL || eq - v >
			    64 || (size_t)(eq - v) != strspn(v,
			    "abcdefghijklmnopqrstuvwxyz0123456789_") ||
			    strstr(v, "_enable=") == NULL || (strcmp(eq + 1,
			    "YES") != 0 && strcmp(eq + 1, "NO") != 0))
				return ("periodic sets its variables: "
				    "name_enable=YES or NO");
		}
		return (NULL);
	}
	if (file_of(sp->verb) == NULL)
		return ("a sysfile job's verb names its file: devfs.rules, devd, "
		    "syslog.conf, newsyslog.conf, periodic.conf, audit_control, "
		    "audit_user, krb5.conf, ipsec.conf, rctl.conf, loader.conf.d; "
		    "or periodic");
	if (!text_ok(sp->text))
		return ("a file's text is lines of printable characters, 256 KB "
		    "at most");
	return (NULL);
}

char *
sysfile_title(const struct arc_job_spec *sp)
{
	char	*t;

	if (asprintf(&t, "%s written", strcmp(sp->verb, "periodic") == 0 ?
	    "periodic.conf's variables" : strcmp(sp->verb, "rc") == 0 ?
	    "securelevel at boot" : sp->verb) == -1)
		return (NULL);
	return (t);
}

int
do_sysfile_job(struct work *w, const struct arc_job_spec *sp,
    const char **errp)
{
	struct arc_service_action_rsp	 r;
	const struct sysfile		*f;
	struct execres			 res;
	const char			*path, *tmp;
	char				*argv[6], *dir;
	size_t				 i, len;
	int				 fd;
	bool				 enabled, running;

	if ((*errp = sysfile_check(sp)) != NULL)
		return (-1);
	if (strcmp(sp->verb, "rc") == 0) {
		for (i = 0; i < sp->names.n; i++) {
			char	*name = wstrdup(w, sp->names.v[i]), *eq;

			eq = strchr(name, '=');
			*eq = '\0';
			if (rc_set(w, name, "=", eq + 1, errp) != 0)
				return (-1);
		}
		return (0);
	}
	if (strcmp(sp->verb, "periodic") == 0) {
		/* sysrc -f periodic.conf: each variable, the rest kept. */
		for (i = 0; i < sp->names.n; i++) {
			argv[0] = (char *)(uintptr_t)opts.sysrc_bin;
			argv[1] = (char *)(uintptr_t)"-f";
			argv[2] = (char *)(uintptr_t)rooted(w,
			    "/etc/periodic.conf");
			argv[3] = (char *)(uintptr_t)sp->names.v[i];
			argv[4] = NULL;
			if (run_exec(w, argv, &res) != 0) {
				*errp = wtext(w, exec_error(w, &res, "sysrc"));
				return (-1);
			}
		}
		return (0);
	}
	f = file_of(sp->verb);
	path = rooted(w, f->path);
	/* Its directory, and those above it, where they are not. */
	dir = wstrdup(w, path);
	if (strrchr(dir, '/') != NULL) {
		char	*p;

		*strrchr(dir, '/') = '\0';
		for (p = dir + 1; (p = strchr(p, '/')) != NULL; p++) {
			*p = '\0';
			(void)mkdir(dir, 0755);
			*p = '/';
		}
		(void)mkdir(dir, 0755);
	}
	tmp = wfmt(w, "%s.arcana-new", path);
	len = strlen(sp->text);
	if ((fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC,
	    f->mode)) == -1 || write(fd, sp->text, len) != (ssize_t)len ||
	    fsync(fd) != 0 || close(fd) != 0 || rename(tmp, path) != 0) {
		*errp = wfmt(w, "%s: %s", path, strerror(errno));
		if (fd != -1)
			(void)close(fd);
		(void)unlink(tmp);
		return (-1);
	}
	/* Its daemon told, where it runs. */
	if (f->service != NULL) {
		enabled = running = false;
		service_state(w, f->service, &enabled, &running);
		if (running || enabled) {
			memset(&r, 0, sizeof(r));
			if (do_service_action(w, f->service, f->action, &r) != 0 ||
			    !r.ok) {
				*errp = r.error != NULL ? r.error : wfmt(w,
				    "%s did not take it", f->service);
				return (-1);
			}
		}
	}
	return (0);
}
