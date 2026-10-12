/*-
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * The proxies of the SD-WAN services at this edge (MEF 88's url-filter
 * criterion of a security policy): Squid, a plugin the host has
 * installed (nothing is installed by Arcana), one instance per service
 * run in the service's routing table (setfib), its configuration
 * written by the console with places for what the agent knows: the
 * pid file, the CA, the certificate cache, the certificate maker and
 * the file of denied domains.  In mode sni the TLS names are looked
 * at (peek) and a connection to a denied one ended, the rest let
 * through unopened (splice); in mode inspect TLS is opened (bump) with
 * a CA of the instance's own, made once by openssl(1) and kept, its
 * certificate told in the sdwan read for the clients to trust.  Like
 * the DNS filters of sddns.c: those named are started or told to
 * reconfigure, those not named any more are stopped, and the list is
 * kept for the next start.
 */

#include <sys/param.h>
#include <sys/stat.h>

#include <ctype.h>
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include <ucl.h>

#include "agent.h"

#define	PROXY_FILE	"sdwan-proxy.json"
#define	INSTANCES_MAX	64
#define	CONF_MAX	(256 * 1024)
#define	DENY_MAX	(8 * 1024 * 1024)
#define	PATH_CERTGEN	"/usr/local/libexec/squid/security_file_certgen"

struct instance {
	char	name[40];
	char	mode[12];
	int	fib;
};

static pthread_mutex_t	lock = PTHREAD_MUTEX_INITIALIZER;
static struct instance	instances[INSTANCES_MAX];
static int		ninstances;

static bool
name_ok(const char *s)
{
	size_t	i;

	if (s == NULL || s[0] == '\0' || strlen(s) > 32)
		return (false);
	for (i = 0; s[i] != '\0'; i++)
		if (!isalnum((unsigned char)s[i]) && s[i] != '_' && s[i] != '-')
			return (false);
	return (true);
}

/* Where an instance's files are: beside the agent's kept files. */
static const char *
inst_path(struct work *w, const char *name, const char *ext)
{
	char	buf[MAXPATHLEN];

	sdwan_conf_path(wfmt(w, "sdwan-proxy-%s.%s", name, ext), buf,
	    sizeof(buf));
	return (wstrdup(w, buf));
}

/* A file's text, in the work's memory; NULL when it is not there. */
static char *
file_text(struct work *w, const char *path)
{
	FILE	*fp;
	char	*text;
	long	 n;

	if ((fp = fopen(path, "r")) == NULL)
		return (NULL);
	if (fseek(fp, 0, SEEK_END) != 0 || (n = ftell(fp)) < 0 || n > 1024 *
	    1024 || fseek(fp, 0, SEEK_SET) != 0) {
		fclose(fp);
		return (NULL);
	}
	text = wcalloc(w, 1, (size_t)n + 1);
	if (fread(text, 1, (size_t)n, fp) != (size_t)n) {
		fclose(fp);
		return (NULL);
	}
	fclose(fp);
	return (text);
}

/* The programs: squid, and the certificate maker beside it. */
static const char *
squid_bin(struct work *w)
{
	const char	*p;

	if ((p = tool(w, "squid")) != NULL)
		return (p);
	return (opts.squid_bin);
}

static const char *
certgen_bin(struct work *w)
{
	const char	*p;

	if (opts.tools_dir != NULL) {
		p = wfmt(w, "%s/security_file_certgen", opts.tools_dir);
		if (access(p, X_OK) == 0)
			return (p);
	}
	return (PATH_CERTGEN);
}

/* The pid in an instance's pid file, when that process is there. */
static pid_t
inst_pid(struct work *w, const char *name)
{
	FILE	*fp;
	long	 pid = 0;

	if ((fp = fopen(inst_path(w, name, "pid"), "r")) == NULL)
		return (0);
	if (fscanf(fp, "%ld", &pid) != 1)
		pid = 0;
	fclose(fp);
	if (pid <= 1 || kill((pid_t)pid, 0) != 0)
		return (0);
	return ((pid_t)pid);
}

/* An instance stopped: its process signalled and waited for, briefly. */
static void
inst_stop(struct work *w, const char *name)
{
	pid_t	pid;
	int	i;

	if ((pid = inst_pid(w, name)) == 0)
		return;
	(void)kill(pid, SIGTERM);
	for (i = 0; i < 150 && kill(pid, 0) == 0; i++)
		usleep(20000);
	if (kill(pid, 0) == 0)
		(void)kill(pid, SIGKILL);
}

/*
 * The instance's CA, made once by openssl(1) and kept beside its files:
 * the certificate and the key in one file for Squid, the certificate
 * alone for the clients.  False and why when it could not be.
 */
static bool
inst_ca(struct work *w, const char *name, const char **errp)
{
	struct execres	 res;
	const char	*pem, *crt, *key;
	char		*argv[14], *text, *k, *c;
	size_t		 n;
	FILE		*fp;

	pem = inst_path(w, name, "pem");
	crt = inst_path(w, name, "crt");
	if (access(pem, R_OK) == 0 && access(crt, R_OK) == 0)
		return (true);
	key = inst_path(w, name, "key");
	argv[0] = (char *)(uintptr_t)"/usr/bin/openssl";
	argv[1] = (char *)(uintptr_t)"req";
	argv[2] = (char *)(uintptr_t)"-x509";
	argv[3] = (char *)(uintptr_t)"-newkey";
	argv[4] = (char *)(uintptr_t)"ec";
	argv[5] = (char *)(uintptr_t)"-pkeyopt";
	argv[6] = (char *)(uintptr_t)"ec_paramgen_curve:P-256";
	argv[7] = (char *)(uintptr_t)"-nodes";
	argv[8] = (char *)(uintptr_t)"-days";
	argv[9] = (char *)(uintptr_t)"3650";
	argv[10] = (char *)(uintptr_t)"-subj";
	argv[11] = wfmt(w, "/CN=Arcana SD-WAN %s proxy CA", name);
	argv[12] = (char *)(uintptr_t)"-keyout";
	argv[13] = NULL;
	/* The key and the certificate to files of their own, then one. */
	{
		char	*full[18];
		int	 i;

		for (i = 0; argv[i] != NULL; i++)
			full[i] = argv[i];
		full[i++] = (char *)(uintptr_t)key;
		full[i++] = (char *)(uintptr_t)"-out";
		full[i++] = (char *)(uintptr_t)crt;
		full[i] = NULL;
		exec_set_secret(true);
		n = (size_t)run_exec(w, full, &res);
		exec_set_secret(false);
		if (n != 0) {
			*errp = wtext(w, exec_error(w, &res, "openssl"));
			return (false);
		}
	}
	if ((k = file_text(w, key)) == NULL || (c = file_text(w, crt)) == NULL) {
		*errp = wfmt(w, "%s: the CA was not written", name);
		return (false);
	}
	text = wfmt(w, "%s%s", c, k);
	(void)unlink(key);
	if ((fp = fopen(pem, "w")) == NULL) {
		*errp = wfmt(w, "%s: %s", pem, strerror(errno));
		return (false);
	}
	(void)fchmod(fileno(fp), 0600);
	fputs(text, fp);
	fclose(fp);
	explicit_bzero(text, strlen(text));
	explicit_bzero(k, strlen(k));
	return (true);
}

/* A file given to the squid user, when the host has one; else as is. */
static void
inst_chown(struct work *w, const char *path, bool recurse)
{
	struct execres	 res;
	char		*argv[5];
	int		 n;

	n = 0;
	argv[n++] = (char *)(uintptr_t)"/usr/sbin/chown";
	if (recurse)
		argv[n++] = (char *)(uintptr_t)"-R";
	argv[n++] = (char *)(uintptr_t)"squid:squid";
	argv[n++] = (char *)(uintptr_t)path;
	argv[n] = NULL;
	(void)run_exec(w, argv, &res);
}

/* The certificate cache, beside the instance's files: made once, the
 * squid user's; Squid's certificate maker needs it in both modes. */
static bool
inst_ssldb(struct work *w, const char *name, const char **errp)
{
	struct execres	 res;
	char		*argv[7];
	const char	*dir;

	dir = inst_path(w, name, "ssl_db");
	if (access(dir, F_OK) == 0)
		return (true);
	argv[0] = (char *)(uintptr_t)certgen_bin(w);
	argv[1] = (char *)(uintptr_t)"-c";
	argv[2] = (char *)(uintptr_t)"-s";
	argv[3] = (char *)(uintptr_t)dir;
	argv[4] = (char *)(uintptr_t)"-M";
	argv[5] = (char *)(uintptr_t)"4MB";
	argv[6] = NULL;
	if (run_exec(w, argv, &res) != 0) {
		*errp = wtext(w, exec_error(w, &res, "security_file_certgen"));
		return (false);
	}
	inst_chown(w, dir, true);
	return (true);
}

/* An instance's file: the console's text with the agent's places filled. */
static char *
inst_conf(struct work *w, const char *name, const char *conf)
{
	const char	*from[] = { "@PID@", "@CA@", "@SSLDB@", "@CERTGEN@",
			    "@DENY@" };
	const char	*to[5];
	char		*out, *p, *q;
	size_t		 i, n, len;

	to[0] = inst_path(w, name, "pid");
	to[1] = inst_path(w, name, "pem");
	to[2] = inst_path(w, name, "ssl_db");
	to[3] = certgen_bin(w);
	to[4] = inst_path(w, name, "deny");
	len = strlen(conf) + 5 * MAXPATHLEN * 4 + 1;
	out = wcalloc(w, 1, len);
	for (p = (char *)(uintptr_t)conf, q = out; *p != '\0';) {
		for (i = 0; i < 5; i++) {
			n = strlen(from[i]);
			if (strncmp(p, from[i], n) == 0 && (size_t)(q - out) +
			    strlen(to[i]) < len - 1) {
				q = stpcpy(q, to[i]);
				p += n;
				break;
			}
		}
		if (i == 5 && (size_t)(q - out) < len - 1)
			*q++ = *p++;
	}
	*q = '\0';
	return (out);
}

/* An instance started in its table, or told its file again. */
static int
inst_start(struct work *w, const struct instance *in, bool running,
    const char **errp)
{
	struct execres	 res;
	char		*argv[8];
	int		 n;

	n = 0;
	if (running) {
		argv[n++] = (char *)(uintptr_t)squid_bin(w);
		argv[n++] = (char *)(uintptr_t)"-k";
		argv[n++] = (char *)(uintptr_t)"reconfigure";
	} else {
		argv[n++] = (char *)(uintptr_t)opts.setfib_bin;
		argv[n++] = (char *)(uintptr_t)"-F";
		argv[n++] = wfmt(w, "%d", in->fib);
		argv[n++] = (char *)(uintptr_t)squid_bin(w);
	}
	argv[n++] = (char *)(uintptr_t)"-f";
	argv[n++] = (char *)(uintptr_t)inst_path(w, in->name, "conf");
	argv[n] = NULL;
	if (run_exec(w, argv, &res) != 0) {
		*errp = wtext(w, exec_error(w, &res, "squid"));
		return (-1);
	}
	return (0);
}

/* An instance stopped and its files gone, the CA kept. */
static void
inst_down(struct work *w, const char *name)
{

	inst_stop(w, name);
	(void)unlink(inst_path(w, name, "conf"));
	(void)unlink(inst_path(w, name, "deny"));
	(void)unlink(inst_path(w, name, "pid"));
}

static ucl_object_t *
parse(const char *json)
{
	struct ucl_parser	*p;
	ucl_object_t		*o;

	p = ucl_parser_new(UCL_PARSER_NO_IMPLICIT_ARRAYS |
	    UCL_PARSER_DISABLE_MACRO | UCL_PARSER_NO_TIME);
	o = ucl_parser_add_string(p, json, 0) ? ucl_parser_get_object(p) :
	    NULL;
	ucl_parser_free(p);
	return (o);
}

/*
 * The instances applied: {"instances": [{"name", "fib", "mode", "conf",
 * "deny"}, ...]}.  Squid must be there (a plugin); each instance's CA
 * is made once; its file, the places filled, is checked by squid -k
 * parse before it is made the instance's; a running one is told to
 * reconfigure, one not yet is started in its table; those not named
 * any more are stopped.  Kept for the next start.
 */
int
do_sdwan_proxy(struct work *w, const char *json, const char **errp)
{
	ucl_object_t		*top;
	const ucl_object_t	*in, *v;
	ucl_object_iter_t	 it;
	struct instance		 ni[INSTANCES_MAX];
	struct execres		 res;
	char			*argv[6], *text;
	const char		*conf, *deny, *mode, *e;
	int			 n, i, k, step;
	bool			 was, ok;

	if ((top = parse(json)) == NULL || ucl_object_type(top) != UCL_OBJECT) {
		if (top != NULL)
			ucl_object_unref(top);
		*errp = "the instances are an object: instances, each a name, "
		    "a fib, a mode, its conf and its deny";
		return (-1);
	}
	n = 0;
	it = NULL;
	while ((in = ucl_object_iterate(ucl_object_lookup(top, "instances"),
	    &it, true)) != NULL) {
		v = ucl_object_lookup(in, "name");
		conf = ucl_object_tostring(ucl_object_lookup(in, "conf"));
		deny = ucl_object_tostring(ucl_object_lookup(in, "deny"));
		mode = ucl_object_tostring(ucl_object_lookup(in, "mode"));
		if (n == INSTANCES_MAX || v == NULL || ucl_object_type(v) !=
		    UCL_STRING || !name_ok(ucl_object_tostring(v)) ||
		    ucl_object_lookup(in, "fib") == NULL || ucl_object_toint(
		    ucl_object_lookup(in, "fib")) < 0 || ucl_object_toint(
		    ucl_object_lookup(in, "fib")) > 65535 || conf == NULL ||
		    strlen(conf) > CONF_MAX || (deny != NULL && strlen(deny) >
		    DENY_MAX) || mode == NULL || (strcmp(mode, "sni") != 0 &&
		    strcmp(mode, "inspect") != 0)) {
			ucl_object_unref(top);
			*errp = wfmt(w, "an instance is a name of letters, digits, "
			    "_ and -, 32 at most, a fib, a mode (sni or inspect), "
			    "its conf and its deny, %d of them at most",
			    INSTANCES_MAX);
			return (-1);
		}
		for (i = 0; i < n; i++)
			if (strcmp(ni[i].name, ucl_object_tostring(v)) == 0) {
				ucl_object_unref(top);
				*errp = wfmt(w, "instance %s is named twice",
				    ni[i].name);
				return (-1);
			}
		snprintf(ni[n].name, sizeof(ni[n].name), "%s",
		    ucl_object_tostring(v));
		snprintf(ni[n].mode, sizeof(ni[n].mode), "%s", mode);
		ni[n].fib = (int)ucl_object_toint(ucl_object_lookup(in, "fib"));
		n++;
	}
	if (n > 0 && access(squid_bin(w), X_OK) != 0) {
		ucl_object_unref(top);
		*errp = wfmt(w, "the host has no squid (%s): it is a plugin, "
		    "installed by hand (pkg install squid)", squid_bin(w));
		return (-1);
	}
	pthread_mutex_lock(&lock);
	for (i = 0; i < ninstances; i++) {
		for (k = 0; k < n; k++)
			if (strcmp(ni[k].name, instances[i].name) == 0)
				break;
		if (k == n) {
			step = step_begin(w, ARC_STEP_KIND_DAEMON, "arcana-agent",
			    "squid %s stopped", instances[i].name);
			inst_down(w, instances[i].name);
			step_end(w, step, true, NULL);
		}
	}
	ok = true;
	it = NULL;
	for (k = 0; k < n; k++) {
		in = ucl_object_iterate(ucl_object_lookup(top, "instances"), &it,
		    true);
		conf = ucl_object_tostring(ucl_object_lookup(in, "conf"));
		deny = ucl_object_tostring(ucl_object_lookup(in, "deny"));
		was = inst_pid(w, ni[k].name) != 0;
		step = step_begin(w, ARC_STEP_KIND_DAEMON, "arcana-agent",
		    "squid %s in fib %d, %s: %s", ni[k].name, ni[k].fib, ni[k].mode,
		    was ? "reconfigured" : "started");
		e = NULL;
		/* The certificate cache in both modes: Squid's certificate
		 * maker serves the TLS port's own pages too. */
		if (!inst_ca(w, ni[k].name, &e) || !inst_ssldb(w, ni[k].name, &e)) {
			step_end(w, step, false, "%s", e);
			*errp = wfmt(w, "%s: %s", ni[k].name, e);
			ok = false;
			break;
		}
		inst_chown(w, inst_path(w, ni[k].name, "pem"), false);
		if (sdwan_conf_write(wfmt(w, "sdwan-proxy-%s.deny", ni[k].name),
		    deny != NULL ? deny : "", &e) != 0 || sdwan_conf_write(wfmt(w,
		    "sdwan-proxy-%s.conf", ni[k].name), text = inst_conf(w,
		    ni[k].name, conf), &e) != 0) {
			step_end(w, step, false, "%s", e);
			*errp = wfmt(w, "%s: %s", ni[k].name, e);
			ok = false;
			break;
		}
		/* Checked first: what squid refuses is not run. */
		argv[0] = (char *)(uintptr_t)squid_bin(w);
		argv[1] = (char *)(uintptr_t)"-k";
		argv[2] = (char *)(uintptr_t)"parse";
		argv[3] = (char *)(uintptr_t)"-f";
		argv[4] = (char *)(uintptr_t)inst_path(w, ni[k].name, "conf");
		argv[5] = NULL;
		if (run_exec(w, argv, &res) != 0) {
			step_end(w, step, false, "squid does not take it");
			*errp = wfmt(w, "%s: squid does not take it: %s", ni[k].name,
			    res.errlen > 0 ? res.err : res.out != NULL ? res.out :
			    "no reason given");
			ok = false;
			break;
		}
		if (inst_start(w, &ni[k], was, &e) != 0) {
			step_end(w, step, false, "%s", e);
			*errp = e;
			ok = false;
			break;
		}
		step_end(w, step, true, NULL);
	}
	if (ok) {
		memcpy(instances, ni, sizeof(*ni) * (size_t)n);
		ninstances = n;
	}
	pthread_mutex_unlock(&lock);
	ucl_object_unref(top);
	if (!ok)
		return (-1);
	e = NULL;
	if (sdwan_conf_write(PROXY_FILE, json, &e) != 0) {
		*errp = wfmt(w, "%s: %s", PROXY_FILE, e);
		return (-1);
	}
	return (0);
}

/* At the start: the instances kept, started again. */
void
sdwan_proxy_start(void)
{
	struct work	 w;
	char		*json;
	const char	*e;

	work_init(&w);
	if ((json = sdwan_kept_read(PROXY_FILE)) != NULL) {
		e = NULL;
		if (do_sdwan_proxy(&w, json, &e) != 0)
			logmsg(LOG_WARNING, "sdwan proxy: %s", e);
		free(json);
	}
	work_free(&w);
}

/* The instances as they are, into the sdwan reply: each its name, fib,
 * mode, whether its process is there, and its CA's certificate. */
void
sdwan_proxy_json(struct work *w, ucl_object_t *top)
{
	ucl_object_t	*arr, *o;
	char		*ca;
	int		 i;

	pthread_mutex_lock(&lock);
	arr = ucl_object_typed_new(UCL_ARRAY);
	for (i = 0; i < ninstances; i++) {
		o = ucl_object_typed_new(UCL_OBJECT);
		ucl_object_insert_key(o, ucl_object_fromstring(instances[i].name),
		    "name", 0, false);
		ucl_object_insert_key(o, ucl_object_fromint(instances[i].fib),
		    "fib", 0, false);
		ucl_object_insert_key(o, ucl_object_fromstring(instances[i].mode),
		    "mode", 0, false);
		ucl_object_insert_key(o, ucl_object_frombool(inst_pid(w,
		    instances[i].name) != 0), "running", 0, false);
		if ((ca = file_text(w, inst_path(w, instances[i].name, "crt"))) !=
		    NULL)
			ucl_object_insert_key(o, ucl_object_fromstring(ca), "ca", 0,
			    false);
		ucl_array_append(arr, o);
	}
	pthread_mutex_unlock(&lock);
	ucl_object_insert_key(top, arr, "proxy", 0, false);
}
