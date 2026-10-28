/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * The resolvers of the SD-WAN services at this edge (MEF 138's DNF and
 * PDNS, the function policies of a zone, and where a DPF redirects):
 * the base system's unbound(8), local-unbound, one instance
 * per service run in the service's routing table (setfib), its
 * configuration rendered here from the console's form (sdconf.c: the
 * UNIs' provider addresses it listens on, the zones' domains and
 * answers), its pid file beside the agent's kept files.  Like the DHCP instances of sddhcp.c:
 * those named are started or started again, those not named any more
 * are stopped, and the list is kept for the next start.
 */

#include <sys/param.h>
#include <sys/stat.h>

#include <ctype.h>
#include <dirent.h>
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

#define	DNS_FILE	"sdwan-dns.json"
#define	INSTANCES_MAX	64

struct instance {
	char	name[40];
	int	fib;
	bool	tls;		/* serves DNS over TLS */
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

/* A string of the instance's, as a comment takes it: "" for none. */
static const char *
sstr(const ucl_object_t *o, const char *k)
{
	const ucl_object_t	*v;

	v = ucl_object_lookup(o, k);
	return (v != NULL && ucl_object_type(v) == UCL_STRING ?
	    ucl_object_tostring(v) : "");
}

/* Where an instance's files are: beside the agent's kept files. */
static const char *
inst_path(struct work *w, const char *name, const char *ext)
{
	char	buf[MAXPATHLEN];

	sdwan_conf_path(wfmt(w, "sdwan-dns-%s.%s", name, ext), buf,
	    sizeof(buf));
	return (wstrdup(w, buf));
}

/* The pid in an instance's pid file, when that process is there. */
static pid_t
inst_pid(struct work *w, const char *name)
{

	return (pidfile_of(inst_path(w, name, "pid"), opts.unbound_bin));
}

/* An instance stopped: its process signalled and waited for, briefly. */
static void
inst_stop(struct work *w, const char *name)
{
	pid_t	pid;

	if ((pid = inst_pid(w, name)) == 0)
		return;
	pid_stop(pid, opts.unbound_bin, 1000);
}

/* An instance started in its table, by setfib, on its file. */
static int
inst_start(struct work *w, const struct instance *in, const char **errp)
{
	struct execres	 res;
	char		*argv[8];
	int		 n;

	n = 0;
	argv[n++] = (char *)(uintptr_t)opts.setfib_bin;
	argv[n++] = (char *)(uintptr_t)"-F";
	argv[n++] = wfmt(w, "%d", in->fib);
	argv[n++] = (char *)(uintptr_t)opts.unbound_bin;
	argv[n++] = (char *)(uintptr_t)"-c";
	argv[n++] = (char *)(uintptr_t)inst_path(w, in->name, "conf");
	argv[n] = NULL;
	if (run_exec(w, argv, &res) != 0) {
		*errp = wtext(w, exec_error(w, &res, "local-unbound"));
		return (-1);
	}
	return (0);
}

/* An instance's response policy zones gone, all of them. */
static void
rpz_clear(struct work *w, const char *name)
{
	DIR		*d;
	struct dirent	*de;
	const char	*path, *dir, *pre;
	size_t		 n;

	path = inst_path(w, name, "x");
	dir = strrchr(path, '/') != NULL ? wfmt(w, "%.*s", (int)(strrchr(path,
	    '/') - path), path) : ".";
	pre = wfmt(w, "sdwan-dns-%s.rpz-", name);
	n = strlen(pre);
	if ((d = opendir(dir)) == NULL)
		return;
	while ((de = readdir(d)) != NULL)
		if (strncmp(de->d_name, pre, n) == 0)
			(void)unlinkat(dirfd(d), de->d_name, 0);
	closedir(d);
}

/*
 * The key and certificate an instance serves DNS over TLS with: made by
 * openssl(1), the certificate its own (self-signed, the UNIs' addresses
 * its names), kept beside its files and made again when the addresses
 * are others; the sdwan read tells the certificate for the clients to
 * trust.  False and why when it could not be.
 */
static bool
inst_tls(struct work *w, const char *name, const ucl_object_t *spec,
    const char **errp)
{
	struct execres		 res;
	const ucl_object_t	*u;
	ucl_object_iter_t	 it;
	const char		*key, *pem, *names, *san;
	char			*argv[18], had[1024];
	FILE			*fp;
	size_t			 n;
	int			 i;

	key = inst_path(w, name, "tls.key");
	pem = inst_path(w, name, "tls.pem");
	names = inst_path(w, name, "tls.names");
	san = "subjectAltName=";
	it = NULL;
	while ((u = ucl_object_iterate(ucl_object_lookup(spec, "unis"), &it,
	    true)) != NULL)
		if (sstr(u, "address") != NULL)
			san = wfmt(w, "%s%sIP:%s", san, san[15] != '\0' ? "," : "",
			    sstr(u, "address"));
	if (san[15] == '\0') {
		*errp = "DNS over TLS: no address to serve it on";
		return (false);
	}
	had[0] = '\0';
	if ((fp = fopen(names, "r")) != NULL) {
		n = fread(had, 1, sizeof(had) - 1, fp);
		had[n] = '\0';
		fclose(fp);
	}
	if (strcmp(had, san) == 0 && access(key, R_OK) == 0 && access(pem,
	    R_OK) == 0)
		return (true);
	i = 0;
	argv[i++] = (char *)(uintptr_t)"/usr/bin/openssl";
	argv[i++] = (char *)(uintptr_t)"req";
	argv[i++] = (char *)(uintptr_t)"-x509";
	argv[i++] = (char *)(uintptr_t)"-newkey";
	argv[i++] = (char *)(uintptr_t)"ec";
	argv[i++] = (char *)(uintptr_t)"-pkeyopt";
	argv[i++] = (char *)(uintptr_t)"ec_paramgen_curve:P-256";
	argv[i++] = (char *)(uintptr_t)"-nodes";
	argv[i++] = (char *)(uintptr_t)"-days";
	argv[i++] = (char *)(uintptr_t)"3650";
	argv[i++] = (char *)(uintptr_t)"-subj";
	argv[i++] = wfmt(w, "/CN=Arcana SD-WAN %s resolver", name);
	argv[i++] = (char *)(uintptr_t)"-addext";
	argv[i++] = (char *)(uintptr_t)san;
	argv[i++] = (char *)(uintptr_t)"-keyout";
	argv[i++] = (char *)(uintptr_t)key;
	argv[i++] = (char *)(uintptr_t)"-out";
	argv[i++] = (char *)(uintptr_t)pem;
	argv[i] = NULL;
	(void)unlink(key);
	exec_set_secret(true);
	i = run_exec(w, argv, &res);
	exec_set_secret(false);
	if (i != 0) {
		*errp = wtext(w, exec_error(w, &res, "openssl"));
		return (false);
	}
	(void)chmod(key, 0600);
	if ((fp = fopen(names, "w")) == NULL) {
		*errp = wfmt(w, "%s: %s", names, strerror(errno));
		return (false);
	}
	fputs(san, fp);
	fclose(fp);
	return (true);
}

/* The certificate an instance serves DNS over TLS with, in the work's
 * memory; NULL when it serves none. */
static char *
tls_cert(struct work *w, const char *name)
{
	FILE	*fp;
	char	*text;
	size_t	 n;

	if ((fp = fopen(inst_path(w, name, "tls.pem"), "r")) == NULL)
		return (NULL);
	text = wcalloc(w, 1, 16384);
	n = fread(text, 1, 16383, fp);
	fclose(fp);
	text[n] = '\0';
	return (strstr(text, "BEGIN CERTIFICATE") != NULL ? text : NULL);
}

/* An instance stopped and its files gone, its key for DNS over TLS
 * kept. */
static void
inst_down(struct work *w, const char *name)
{

	inst_stop(w, name);
	(void)unlink(inst_path(w, name, "conf"));
	(void)unlink(inst_path(w, name, "pid"));
	rpz_clear(w, name);
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
 * The instances applied: {"instances": [{"name", "fib", "host",
 * "spec"}, ...]}, spec the service's form, rendered by
 * dns_conf_render() (host names the host in its comment), every one
 * before any is changed.
 * Each file, with the pid file and the run as root added (no chroot,
 * the kept files being where they are), is checked by
 * local-unbound-checkconf before it is made the instance's; a running
 * instance is stopped and started again on it; those not named any
 * more are stopped.  Kept for the next start.
 */
int
do_sdwan_dns(struct work *w, const char *json, const char **errp)
{
	ucl_object_t		*top;
	const ucl_object_t	*in, *v;
	ucl_object_iter_t	 it;
	struct instance		 ni[INSTANCES_MAX];
	struct execres		 res;
	struct dnspaths		 dp;
	ucl_object_t		*rpzs[INSTANCES_MAX];
	const ucl_object_t	*z;
	ucl_object_iter_t	 zit;
	char			*argv[3], *text, *confs[INSTANCES_MAX];
	const char		*conf, *e;
	int			 n, i, k, step;
	bool			 was, ok;

	if ((top = parse(json)) == NULL || ucl_object_type(top) != UCL_OBJECT) {
		if (top != NULL)
			ucl_object_unref(top);
		*errp = "the instances are an object: instances, each a name, "
		    "a fib, a host and its spec";
		return (-1);
	}
	n = 0;
	it = NULL;
	while ((in = ucl_object_iterate(ucl_object_lookup(top, "instances"),
	    &it, true)) != NULL) {
		v = ucl_object_lookup(in, "name");
		if (n == INSTANCES_MAX || v == NULL || ucl_object_type(v) !=
		    UCL_STRING || !name_ok(ucl_object_tostring(v)) ||
		    ucl_object_lookup(in, "fib") == NULL || ucl_object_toint(
		    ucl_object_lookup(in, "fib")) < 0 || ucl_object_toint(
		    ucl_object_lookup(in, "fib")) > 65535 || ucl_object_type(
		    ucl_object_lookup(in, "spec")) != UCL_OBJECT) {
			ucl_object_unref(top);
			*errp = wfmt(w, "an instance is a name of letters, digits, "
			    "_ and -, 32 at most, a fib, a host and its spec, %d "
			    "of them at most", INSTANCES_MAX);
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
		ni[n].fib = (int)ucl_object_toint(ucl_object_lookup(in, "fib"));
		ni[n].tls = ucl_object_toboolean(ucl_object_lookup(
		    ucl_object_lookup(in, "spec"), "dot"));
		/* Its file names its own: the key and certificate of DNS
		 * over TLS, the response policy zones' files. */
		dp.tlskey = inst_path(w, ni[n].name, "tls.key");
		dp.tlspem = inst_path(w, ni[n].name, "tls.pem");
		dp.rpz_pre = inst_path(w, ni[n].name, "rpz-");
		rpzs[n] = ucl_object_typed_new(UCL_OBJECT);
		e = NULL;
		if ((confs[n] = dns_conf_render(w, ucl_object_lookup(in,
		    "spec"), sstr(in, "host"), &dp, rpzs[n], &e)) == NULL) {
			for (i = 0; i <= n; i++)
				ucl_object_unref(rpzs[i]);
			ucl_object_unref(top);
			*errp = wfmt(w, "%s: %s", ni[n].name, e);
			return (-1);
		}
		n++;
	}
	pthread_mutex_lock(&lock);
	for (i = 0; i < ninstances; i++) {
		for (k = 0; k < n; k++)
			if (strcmp(ni[k].name, instances[i].name) == 0)
				break;
		if (k == n) {
			step = step_begin(w, ARC_STEP_KIND_DAEMON, "arcana-agent",
			    "unbound %s stopped", instances[i].name);
			inst_down(w, instances[i].name);
			step_end(w, step, true, NULL);
		}
	}
	ok = true;
	it = NULL;
	for (k = 0; k < n; k++) {
		in = ucl_object_iterate(ucl_object_lookup(top, "instances"), &it,
		    true);
		conf = confs[k];
		was = inst_pid(w, ni[k].name) != 0;
		step = step_begin(w, ARC_STEP_KIND_DAEMON, "arcana-agent",
		    "unbound %s in fib %d: %s", ni[k].name, ni[k].fib, was ?
		    "started again" : "started");
		/* Its response policy zones, files of their own; its key
		 * for DNS over TLS where it serves it. */
		e = NULL;
		rpz_clear(w, ni[k].name);
		zit = NULL;
		while ((z = ucl_object_iterate(rpzs[k], &zit, true)) != NULL)
			if (sdwan_conf_write(wfmt(w, "sdwan-dns-%s.rpz-%s",
			    ni[k].name, ucl_object_key(z)), ucl_object_tostring(z),
			    &e) != 0)
				break;
		if (e == NULL && ni[k].tls)
			(void)inst_tls(w, ni[k].name, ucl_object_lookup(in, "spec"),
			    &e);
		if (e != NULL) {
			step_end(w, step, false, "%s", e);
			*errp = wfmt(w, "%s: %s", ni[k].name, e);
			ok = false;
			break;
		}
		/* The agent's own clause after the console's: the pid file,
		 * no chroot and the user it runs as. */
		text = wfmt(w, "%s%sserver:\n\tpidfile: \"%s\"\n\tchroot: \"\"\n\t"
		    "username: \"\"\n", conf, conf[0] != '\0' && conf[strlen(conf)
		    - 1] != '\n' ? "\n" : "", inst_path(w, ni[k].name, "pid"));
		if (sdwan_conf_write(wfmt(w, "sdwan-dns-%s.conf", ni[k].name),
		    text, &e) != 0) {
			step_end(w, step, false, "%s", e);
			*errp = wfmt(w, "%s: %s", ni[k].name, e);
			ok = false;
			break;
		}
		/* Checked first: what unbound refuses is not run. */
		argv[0] = wfmt(w, "%s-checkconf", opts.unbound_bin);
		argv[1] = (char *)(uintptr_t)inst_path(w, ni[k].name, "conf");
		argv[2] = NULL;
		if (run_exec(w, argv, &res) != 0) {
			step_end(w, step, false, "unbound does not take it");
			*errp = wfmt(w, "%s: unbound does not take it: %s",
			    ni[k].name, res.errlen > 0 ? res.err : res.out !=
			    NULL ? res.out : "no reason given");
			ok = false;
			break;
		}
		if (was)
			inst_stop(w, ni[k].name);
		if (inst_start(w, &ni[k], &e) != 0) {
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
	for (k = 0; k < n; k++)
		ucl_object_unref(rpzs[k]);
	ucl_object_unref(top);
	if (!ok)
		return (-1);
	e = NULL;
	if (sdwan_conf_write(DNS_FILE, json, &e) != 0) {
		*errp = wfmt(w, "%s: %s", DNS_FILE, e);
		return (-1);
	}
	return (0);
}

/* At the start: the instances kept, started again. */
void
sdwan_dns_start(void)
{
	struct work	 w;
	char		*json;
	const char	*e;

	work_init(&w);
	if ((json = sdwan_kept_read(DNS_FILE)) != NULL) {
		e = NULL;
		if (do_sdwan_dns(&w, json, &e) != 0)
			logmsg(LOG_WARNING, "sdwan dns: %s", e);
		free(json);
	}
	work_free(&w);
}

/* The instances as they are, into the sdwan reply: each its name, fib,
 * whether its process is there, and the certificate of its DNS over TLS
 * where it serves it. */
void
sdwan_dns_json(struct work *w, ucl_object_t *top)
{
	ucl_object_t	*arr, *o;
	char		*cert;
	int		 i;

	pthread_mutex_lock(&lock);
	arr = ucl_object_typed_new(UCL_ARRAY);
	for (i = 0; i < ninstances; i++) {
		o = ucl_object_typed_new(UCL_OBJECT);
		ucl_object_insert_key(o, ucl_object_fromstring(instances[i].name),
		    "name", 0, false);
		ucl_object_insert_key(o, ucl_object_fromint(instances[i].fib),
		    "fib", 0, false);
		ucl_object_insert_key(o, ucl_object_frombool(inst_pid(w,
		    instances[i].name) != 0), "running", 0, false);
		if (instances[i].tls && (cert = tls_cert(w, instances[i].name)) !=
		    NULL)
			ucl_object_insert_key(o, ucl_object_fromstring(cert),
			    "tls_cert", 0, false);
		ucl_array_append(arr, o);
	}
	pthread_mutex_unlock(&lock);
	ucl_object_insert_key(top, arr, "dns", 0, false);
}
