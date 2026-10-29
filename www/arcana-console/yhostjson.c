/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * The host and its agent (PLAN-SDN-YANG 3.1.9), for the console and
 * arcanactl: arcana-host's host and its read-certificates action,
 * arcana-jail-files' read-files and arcana-agent's agent, made the JSON
 * the stats, certs, jail-files and the agent's operations gave (the
 * agent's stats.c, certs.c, jailmake.c, build.c, bundle.c,
 * transport.c, tlsfiles.c), so that the pages keep reading what they
 * read.
 */

#include <sys/param.h>

#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <cblink.h>
#include <cbl_schema.h>
#include <ucl.h>

#include "ymodel.h"
#include "yhostjson.h"
#include "yqueue.h"
#include "zprog.h"

typedef struct arcana_host_host_read_certificates_output_trusted ycert;

static ucl_object_t	*strs_of(const char *const *, size_t);

static void
put(ucl_object_t *o, const char *key, ucl_object_t *v)
{

	ucl_object_insert_key(o, v, key, 0, true);
}

static void
put_str(ucl_object_t *o, const char *key, const char *v)
{

	if (v != NULL)
		put(o, key, ucl_object_fromstring(v));
}

/* A yang:date-and-time the agent wrote (UTC), as seconds; 0: not one. */
static int64_t
epoch_of(const char *s)
{
	struct tm	 tm;

	memset(&tm, 0, sizeof(tm));
	if (s == NULL || strptime(s, "%Y-%m-%dT%H:%M:%S", &tm) == NULL)
		return (0);
	return ((int64_t)timegm(&tm));
}

int
yh_hello(cbl_conn *conn, ucl_object_t **data, char *err, size_t errlen)
{
	const struct arcana_host_host	*h;
	const struct cbl_yident		*id;
	struct arcana_host		 d;
	const struct cbl_ynode		*n;
	ucl_object_t			*o, *arr;
	cbl_yarena			*a;
	int				 error;

	*data = NULL;
	err[0] = '\0';
	if ((n = yq_top("arcana-host", "host")) == NULL) {
		snprintf(err, errlen, "arcana-host has no host");
		return (ENOENT);
	}
	if ((a = cbl_yarena_new()) == NULL)
		return (ENOMEM);
	memset(&d, 0, sizeof(d));
	if ((error = yq_get(conn, n, -1, &d, a, err, errlen)) != 0) {
		cbl_yarena_free(a);
		return (error);
	}
	if ((h = d.host) == NULL) {
		cbl_yarena_free(a);
		snprintf(err, errlen, "the agent tells no host");
		return (ENOENT);
	}
	o = ucl_object_typed_new(UCL_OBJECT);
	put_str(o, "hostname", h->hostname);
	put_str(o, "sysname", h->sysname);
	put_str(o, "release", h->release);
	put_str(o, "machine", h->machine);
	put(o, "ncpu", ucl_object_fromint(h->ncpu));
	put(o, "physmem", ucl_object_fromint((int64_t)h->physmem));
	put(o, "boottime", ucl_object_fromint(epoch_of(h->boot_time)));
	put(o, "time", ucl_object_fromint(epoch_of(h->time)));
	put(o, "securelevel", ucl_object_fromint(h->securelevel));
	put(o, "privileged", ucl_object_frombool(h->privileged));
	arr = ucl_object_typed_new(UCL_ARRAY);
	for (size_t i = 0; i < h->plugin.n; i++)
		if ((id = cbl_yschema_ident(&ymodel_schema, h->plugin.v[i])) !=
		    NULL)
			ucl_array_append(arr, ucl_object_fromstring(id->name));
	if (h->agent != NULL) {
		put_str(o, "version", h->agent->version);
		put_str(o, "build", h->agent->build);
		if (h->agent->has_safe_wait)
			put(o, "safe_wait", ucl_object_fromint(
			    h->agent->safe_wait));
		if (h->agent->feature.n > 0)
			put(o, "features", strs_of(h->agent->feature.v,
			    h->agent->feature.n));
	}
	put(o, "plugins", arr);
	*data = o;
	cbl_yarena_free(a);
	return (0);
}

bool
yh_takes_gzip(const ucl_object_t *host)
{
	const ucl_object_t	*f, *e;
	ucl_object_iter_t	 it = NULL;

	f = host != NULL ? ucl_object_lookup(host, "features") : NULL;
	while (f != NULL && (e = ucl_object_iterate(f, &it, true)) != NULL)
		if (ucl_object_tostring(e) != NULL &&
		    strcmp(ucl_object_tostring(e), ZPROG_FEATURE) == 0)
			return (true);
	return (false);
}

int
yh_stats(cbl_conn *conn, ucl_object_t **data, char *err, size_t errlen)
{
	struct arcana_host			 d;
	const struct cbl_ynode			*n;
	cbl_yarena				*a;
	int					 error;

	*data = NULL;
	err[0] = '\0';
	if ((n = yq_top("arcana-host", "host")) == NULL) {
		snprintf(err, errlen, "arcana-host has no host");
		return (ENOENT);
	}
	if ((a = cbl_yarena_new()) == NULL)
		return (ENOMEM);
	memset(&d, 0, sizeof(d));
	if ((error = yq_get(conn, n, -1, &d, a, err, errlen)) != 0) {
		cbl_yarena_free(a);
		return (error);
	}
	*data = yh_stats_of(&d);
	cbl_yarena_free(a);
	return (0);
}

/* The same of arcana-host's data as it is held (watch.c). */
ucl_object_t *
yh_stats_of(const struct arcana_host *d)
{
	const struct arcana_host_host_stats	*s;
	ucl_object_t				*o, *pl, *po;

	o = ucl_object_typed_new(UCL_OBJECT);
	if (d->host != NULL && (s = d->host->stats) != NULL) {
		/* The module's CPU in tenths, its loads in hundredths. */
		put(o, "cpu_pct", ucl_object_fromdouble((double)s->cpu / 10));
		put(o, "load1", ucl_object_fromdouble((double)s->load1 / 100));
		put(o, "load5", ucl_object_fromdouble((double)s->load5 / 100));
		put(o, "load15", ucl_object_fromdouble((double)s->load15 /
		    100));
		put(o, "mem_total", ucl_object_fromint((int64_t)
		    s->memory_total));
		put(o, "mem_used", ucl_object_fromint((int64_t)s->memory_used));
		put(o, "mem_inactive", ucl_object_fromint((int64_t)
		    s->memory_inactive));
		put(o, "mem_free", ucl_object_fromint((int64_t)s->memory_free));
		put(o, "swap_total", ucl_object_fromint((int64_t)
		    s->swap_total));
		put(o, "swap_used", ucl_object_fromint((int64_t)s->swap_used));
		pl = ucl_object_typed_new(UCL_ARRAY);
		for (size_t i = 0; i < s->pool.n; i++) {
			po = ucl_object_typed_new(UCL_OBJECT);
			put_str(po, "name", s->pool.v[i].name);
			put(po, "size", ucl_object_fromint((int64_t)
			    s->pool.v[i].size));
			put(po, "alloc", ucl_object_fromint((int64_t)
			    s->pool.v[i].allocated));
			put(po, "free", ucl_object_fromint((int64_t)
			    s->pool.v[i].free));
			put_str(po, "health", s->pool.v[i].health);
			ucl_array_append(pl, po);
		}
		put(o, "pools", pl);
	}
	return (o);
}

static ucl_object_t *
cert_of(const ycert *c)
{
	ucl_object_t	*o;

	o = ucl_object_typed_new(UCL_OBJECT);
	put_str(o, "file", c->file);
	put_str(o, "subject", c->subject);
	put_str(o, "cn", c->common_name);
	put_str(o, "org", c->organization);
	put_str(o, "country", c->country);
	put_str(o, "issuer", c->issuer);
	put(o, "not_before", ucl_object_fromint(epoch_of(c->not_before)));
	put(o, "not_after", ucl_object_fromint(epoch_of(c->not_after)));
	put_str(o, "sha256", c->sha256);
	put_str(o, "key", c->key);
	put(o, "ca", ucl_object_frombool(c->has_ca && c->ca));
	put(o, "self_signed", ucl_object_frombool(c->has_self_signed &&
	    c->self_signed));
	put_str(o, "local", c->local);
	return (o);
}

int
yh_certs(cbl_conn *conn, const char *jail, ucl_object_t **data, char *err,
    size_t errlen)
{
	struct arcana_host_host_read_certificates_input		 in;
	struct arcana_host_host_read_certificates_output	 out;
	const struct cbl_ynode					*n, *act;
	ucl_object_t						*top, *arr;
	cbl_yarena						*a;
	int							 error;

	*data = NULL;
	err[0] = '\0';
	if ((n = yq_top("arcana-host", "host")) == NULL ||
	    (act = yq_child(n, "read-certificates")) == NULL) {
		snprintf(err, errlen, "arcana-host has no read-certificates");
		return (ENOENT);
	}
	memset(&in, 0, sizeof(in));
	in.jail = jail != NULL && jail[0] != '\0' ? jail : NULL;
	if ((a = cbl_yarena_new()) == NULL)
		return (ENOMEM);
	memset(&out, 0, sizeof(out));
	if ((error = yq_call(conn, n, NULL, act, &in, &out, a, err,
	    errlen)) == 0) {
		/* In the order certs.c put them; the store's own two are
		 * the same everywhere. */
		top = ucl_object_typed_new(UCL_OBJECT);
		put_str(top, "localbase", out.localbase);
		put_str(top, "trusted_dir", "/etc/ssl/certs");
		put_str(top, "untrusted_dir", "/etc/ssl/untrusted");
		put_str(top, "added_dir", out.added_dir);
		put_str(top, "distrusted_dir", out.distrusted_dir);
		put(top, "certctl", ucl_object_frombool(out.has_certctl &&
		    out.certctl));
		put(top, "now", ucl_object_fromint(epoch_of(out.now)));
		arr = ucl_object_typed_new(UCL_ARRAY);
		for (size_t i = 0; i < out.trusted.n; i++)
			ucl_array_append(arr, cert_of(&out.trusted.v[i]));
		put(top, "trusted", arr);
		arr = ucl_object_typed_new(UCL_ARRAY);
		for (size_t i = 0; i < out.untrusted.n; i++)
			ucl_array_append(arr, cert_of((const ycert *)
			    &out.untrusted.v[i]));
		put(top, "untrusted", arr);
		*data = top;
	}
	cbl_yarena_free(a);
	return (error);
}

static ucl_object_t *
named_of(const char *name, const char *text)
{
	ucl_object_t	*o;

	o = ucl_object_typed_new(UCL_OBJECT);
	put_str(o, "name", name);
	put_str(o, "text", text != NULL ? text : "");
	return (o);
}

int
yh_jail_files(cbl_conn *conn, ucl_object_t **data, char *err, size_t errlen)
{
	struct arcana_jails_jails_arcjf_read_files_output	 out;
	const struct cbl_ynode					*n, *act;
	ucl_object_t						*top, *o, *arr;
	cbl_yarena						*a;
	int							 error;

	*data = NULL;
	err[0] = '\0';
	act = NULL;
	if ((n = yq_top("arcana-jails", "jails")) != NULL)
		for (uint32_t i = 0; i < n->nchild && act == NULL; i++)
			if (strcmp(n->child[i]->name, "read-files") == 0)
				act = n->child[i];
	if (act == NULL) {
		snprintf(err, errlen, "arcana-jail-files has no read-files");
		return (ENOENT);
	}
	if ((a = cbl_yarena_new()) == NULL)
		return (ENOMEM);
	memset(&out, 0, sizeof(out));
	if ((error = yq_call(conn, n, NULL, act, NULL, &out, a, err,
	    errlen)) == 0) {
		/* In the order jailmake.c put them. */
		top = ucl_object_typed_new(UCL_OBJECT);
		o = ucl_object_typed_new(UCL_OBJECT);
		if (out.defaults != NULL) {
			put_str(o, "path", out.defaults->path);
			put(o, "text", out.defaults->text != NULL ?
			    ucl_object_fromstring(out.defaults->text) :
			    ucl_object_typed_new(UCL_NULL));
		}
		put(top, "defaults", o);
		put_str(top, "dir", out.directory);
		arr = ucl_object_typed_new(UCL_ARRAY);
		for (size_t i = 0; i < out.template.n; i++)
			ucl_array_append(arr, named_of(out.template.v[i].name,
			    out.template.v[i].text));
		put(top, "templates", arr);
		arr = ucl_object_typed_new(UCL_ARRAY);
		for (size_t i = 0; i < out.jail.n; i++)
			ucl_array_append(arr, named_of(out.jail.v[i].name,
			    out.jail.v[i].text));
		put(top, "jails", arr);
		*data = top;
	}
	cbl_yarena_free(a);
	return (error);
}

/* What a fetch the server refused tells, for a person to act on. */
static ucl_object_t *
fetched_of(const char *keys, const char *const *fpv, size_t fpn,
    const char *deploy)
{
	ucl_object_t	*o;

	o = ucl_object_typed_new(UCL_OBJECT);
	put_str(o, "host_keys", keys);
	if (fpn > 0)
		put(o, "fingerprints", strs_of(fpv, fpn));
	put_str(o, "deploy_key", deploy);
	return (o);
}

int
yh_source_log(cbl_conn *conn, const char *source, const char *ref,
    const char *host_keys, const char *ssh_key, uint32_t count,
    ucl_object_t **data, char *err, size_t errlen)
{
	struct arcana_agent_agent_source_log_input	 in;
	struct arcana_agent_agent_source_log_output	 out;
	const struct cbl_ynode				*n, *act;
	ucl_object_t					*top, *arr, *o;
	cbl_yarena					*a;
	int						 error;

	*data = NULL;
	err[0] = '\0';
	if ((n = yq_top("arcana-agent", "agent")) == NULL ||
	    (act = yq_child(n, "source-log")) == NULL) {
		snprintf(err, errlen, "arcana-agent has no source-log");
		return (ENOENT);
	}
	memset(&in, 0, sizeof(in));
	in.source = source;
	in.ref = ref != NULL && ref[0] != '\0' ? ref : NULL;
	in.host_keys = host_keys;
	in.ssh_key = ssh_key;
	in.has_count = count > 0;
	in.count = count;
	if ((a = cbl_yarena_new()) == NULL)
		return (ENOMEM);
	memset(&out, 0, sizeof(out));
	if ((error = yq_call(conn, n, NULL, act, &in, &out, a, err,
	    errlen)) == 0 && out.refused != NULL) {
		snprintf(err, errlen, "%s", out.refused);
		*data = fetched_of(out.host_keys, out.fingerprint.v,
		    out.fingerprint.n, out.deploy_key);
		error = EPERM;
	} else if (error == 0) {
		/* In the order build.c put them. */
		top = ucl_object_typed_new(UCL_OBJECT);
		put_str(top, "commit", out.commit);
		arr = ucl_object_typed_new(UCL_ARRAY);
		for (size_t i = 0; i < out.commit_log.n; i++) {
			const struct arcana_agent_agent_source_log_output_commit_log
			    *c = &out.commit_log.v[i];

			o = ucl_object_typed_new(UCL_OBJECT);
			put_str(o, "commit", c->hash);
			put(o, "time", ucl_object_fromint(epoch_of(c->time)));
			put_str(o, "subject", c->subject != NULL ? c->subject :
			    "");
			put_str(o, "body", c->body != NULL ? c->body : "");
			ucl_array_append(arr, o);
		}
		put(top, "log", arr);
		arr = ucl_object_typed_new(UCL_ARRAY);
		for (size_t i = 0; i < out.tag.n; i++) {
			o = ucl_object_typed_new(UCL_OBJECT);
			put_str(o, "name", out.tag.v[i].name);
			put(o, "time", ucl_object_fromint(epoch_of(
			    out.tag.v[i].time)));
			put_str(o, "message", out.tag.v[i].message != NULL ?
			    out.tag.v[i].message : "");
			ucl_array_append(arr, o);
		}
		put(top, "tags", arr);
		*data = top;
	}
	cbl_yarena_free(a);
	return (error);
}

typedef struct arcana_agent_agent_config_apply_input_bundle ybundle;

/* A string of o's, a's copy; NULL: none. */
static const char *
jdup(cbl_yarena *a, const ucl_object_t *o, const char *key)
{
	const char	*v;
	char		*p;

	if ((v = ucl_object_tostring(ucl_object_lookup(o, key))) == NULL ||
	    (p = cbl_yarena_alloc(a, strlen(v) + 1)) == NULL)
		return (NULL);
	memcpy(p, v, strlen(v) + 1);
	return (p);
}

static size_t
jcount(const ucl_object_t *o)
{

	return (o != NULL && ucl_object_type(o) == UCL_ARRAY ?
	    ucl_array_size(o) : 0);
}

/* The bundle config-export wrote, as the apply's input; NULL: not one. */
static ybundle *
bundle_in(const char *json, cbl_yarena *a)
{
	struct arcana_agent_agent_config_apply_input_bundle_facts *f;
	struct arcana_agent_agent_config_apply_input_bundle_facts_interface *fi;
	struct arcana_agent_agent_config_apply_input_bundle_facts_disk *fd;
	struct arcana_agent_agent_config_apply_input_bundle_package *p;
	struct arcana_agent_agent_config_apply_input_bundle_file *fl;
	struct ucl_parser	*ps;
	const ucl_object_t	*fo, *e, *x;
	ucl_object_iter_t	 it;
	ucl_object_t		*top;
	ybundle			*b;
	size_t			 k;

	ps = ucl_parser_new(UCL_PARSER_NO_IMPLICIT_ARRAYS |
	    UCL_PARSER_DISABLE_MACRO | UCL_PARSER_NO_TIME);
	top = ucl_parser_add_string(ps, json, 0) ? ucl_parser_get_object(ps) :
	    NULL;
	ucl_parser_free(ps);
	/* A host's, of format 1, as bundle.c takes one. */
	if (top == NULL || ucl_object_type(top) != UCL_OBJECT ||
	    ucl_object_tostring(ucl_object_lookup(top, "arcana")) == NULL ||
	    strcmp(ucl_object_tostring(ucl_object_lookup(top, "arcana")),
	    "host") != 0 || ucl_object_toint(ucl_object_lookup(top,
	    "format")) != 1 || (b = cbl_yarena_alloc(a, sizeof(*b))) ==
	    NULL) {
		ucl_object_unref(top);
		return (NULL);
	}
	memset(b, 0, sizeof(*b));
	b->host = jdup(a, top, "host");
	b->agent = jdup(a, top, "agent");
	b->taken = jdup(a, top, "taken");
	if ((fo = ucl_object_lookup(top, "facts")) != NULL &&
	    (f = cbl_yarena_alloc(a, sizeof(*f))) != NULL) {
		memset(f, 0, sizeof(*f));
		f->arch = jdup(a, fo, "arch");
		f->release = jdup(a, fo, "release");
		f->cpu = jdup(a, fo, "cpu");
		if ((x = ucl_object_lookup(fo, "ncpu")) != NULL) {
			f->has_ncpu = true;
			f->ncpu = (uint32_t)ucl_object_toint(x);
		}
		if ((x = ucl_object_lookup(fo, "memory")) != NULL) {
			f->has_memory = true;
			f->memory = (uint64_t)ucl_object_toint(x);
		}
		fi = cbl_yarena_alloc(a, (jcount(ucl_object_lookup(fo,
		    "interfaces")) + 1) * sizeof(*fi));
		fd = cbl_yarena_alloc(a, (jcount(ucl_object_lookup(fo,
		    "disks")) + 1) * sizeof(*fd));
		if (fi != NULL && fd != NULL) {
			it = NULL;
			k = 0;
			while ((e = ucl_object_iterate(ucl_object_lookup(fo,
			    "interfaces"), &it, true)) != NULL) {
				if ((fi[k].name = jdup(a, e, "name")) == NULL)
					continue;
				fi[k].driver = jdup(a, e, "driver");
				fi[k].mac = jdup(a, e, "mac");
				k++;
			}
			f->interface.n = k;
			f->interface.v = fi;
			it = NULL;
			k = 0;
			while ((e = ucl_object_iterate(ucl_object_lookup(fo,
			    "disks"), &it, true)) != NULL) {
				memset(&fd[k], 0, sizeof(fd[k]));
				if ((fd[k].name = jdup(a, e, "name")) == NULL)
					continue;
				if ((x = ucl_object_lookup(e, "size")) != NULL) {
					fd[k].has_size = true;
					fd[k].size = (uint64_t)ucl_object_toint(x);
				}
				k++;
			}
			f->disk.n = k;
			f->disk.v = fd;
		}
		b->facts = f;
	}
	p = cbl_yarena_alloc(a, (jcount(ucl_object_lookup(top, "packages")) +
	    1) * sizeof(*p));
	fl = cbl_yarena_alloc(a, (jcount(ucl_object_lookup(top, "files")) +
	    1) * sizeof(*fl));
	if (p == NULL || fl == NULL) {
		ucl_object_unref(top);
		return (NULL);
	}
	it = NULL;
	k = 0;
	while ((e = ucl_object_iterate(ucl_object_lookup(top, "packages"),
	    &it, true)) != NULL) {
		if ((p[k].name = jdup(a, e, "name")) == NULL)
			continue;
		p[k].origin = jdup(a, e, "origin");
		p[k].version = jdup(a, e, "version");
		k++;
	}
	b->package.n = k;
	b->package.v = p;
	it = NULL;
	k = 0;
	while ((e = ucl_object_iterate(ucl_object_lookup(top, "files"), &it,
	    true)) != NULL) {
		memset(&fl[k], 0, sizeof(fl[k]));
		if ((fl[k].path = jdup(a, e, "path")) == NULL)
			continue;
		fl[k].mode = jdup(a, e, "mode");
		fl[k].owner = jdup(a, e, "owner");
		fl[k].group = jdup(a, e, "group");
		fl[k].text = jdup(a, e, "text");
		if ((x = ucl_object_lookup(e, "secret")) != NULL) {
			fl[k].has_secret = true;
			fl[k].secret = ucl_object_toboolean(x);
		}
		k++;
	}
	b->file.n = k;
	b->file.v = fl;
	ucl_object_unref(top);
	return (b);
}

/* The bundle as bundle.c writes it: export's output has its layout. */
static ucl_object_t *
bundle_json(const ybundle *b)
{
	ucl_object_t	*top, *o, *arr, *e;
	size_t		 i;

	top = ucl_object_typed_new(UCL_OBJECT);
	put_str(top, "arcana", "host");
	put(top, "format", ucl_object_fromint(1));
	put_str(top, "host", b->host);
	put_str(top, "agent", b->agent);
	put_str(top, "taken", b->taken);
	if (b->facts != NULL) {
		o = ucl_object_typed_new(UCL_OBJECT);
		put_str(o, "arch", b->facts->arch);
		put_str(o, "release", b->facts->release);
		put_str(o, "cpu", b->facts->cpu);
		if (b->facts->has_ncpu)
			put(o, "ncpu", ucl_object_fromint(b->facts->ncpu));
		if (b->facts->has_memory)
			put(o, "memory", ucl_object_fromint((int64_t)
			    b->facts->memory));
		arr = ucl_object_typed_new(UCL_ARRAY);
		for (i = 0; i < b->facts->interface.n; i++) {
			e = ucl_object_typed_new(UCL_OBJECT);
			put_str(e, "name", b->facts->interface.v[i].name);
			put_str(e, "driver", b->facts->interface.v[i].driver);
			put_str(e, "mac", b->facts->interface.v[i].mac);
			ucl_array_append(arr, e);
		}
		put(o, "interfaces", arr);
		arr = ucl_object_typed_new(UCL_ARRAY);
		for (i = 0; i < b->facts->disk.n; i++) {
			e = ucl_object_typed_new(UCL_OBJECT);
			put_str(e, "name", b->facts->disk.v[i].name);
			if (b->facts->disk.v[i].has_size)
				put(e, "size", ucl_object_fromint((int64_t)
				    b->facts->disk.v[i].size));
			ucl_array_append(arr, e);
		}
		put(o, "disks", arr);
		put(top, "facts", o);
	}
	arr = ucl_object_typed_new(UCL_ARRAY);
	for (i = 0; i < b->package.n; i++) {
		e = ucl_object_typed_new(UCL_OBJECT);
		put_str(e, "name", b->package.v[i].name);
		put_str(e, "origin", b->package.v[i].origin);
		put_str(e, "version", b->package.v[i].version);
		ucl_array_append(arr, e);
	}
	put(top, "packages", arr);
	arr = ucl_object_typed_new(UCL_ARRAY);
	for (i = 0; i < b->file.n; i++) {
		e = ucl_object_typed_new(UCL_OBJECT);
		put_str(e, "path", b->file.v[i].path);
		put_str(e, "mode", b->file.v[i].mode);
		put_str(e, "owner", b->file.v[i].owner);
		put_str(e, "group", b->file.v[i].group);
		/* A secret withheld: said so, without its text. */
		if (b->file.v[i].has_secret && b->file.v[i].secret &&
		    b->file.v[i].text == NULL)
			put(e, "secret", ucl_object_frombool(true));
		else {
			put_str(e, "text", b->file.v[i].text);
			if (b->file.v[i].has_secret && b->file.v[i].secret)
				put(e, "secret", ucl_object_frombool(true));
		}
		ucl_array_append(arr, e);
	}
	put(top, "files", arr);
	return (top);
}

int
yh_config_export(cbl_conn *conn, bool secrets, ucl_object_t **data,
    char *err, size_t errlen)
{
	struct arcana_agent_agent_config_export_input	 in;
	struct arcana_agent_agent_config_export_output	 out;
	const struct cbl_ynode				*n, *act;
	cbl_yarena					*a;
	int						 error;

	*data = NULL;
	err[0] = '\0';
	if ((n = yq_top("arcana-agent", "agent")) == NULL ||
	    (act = yq_child(n, "config-export")) == NULL) {
		snprintf(err, errlen, "arcana-agent has no config-export");
		return (ENOENT);
	}
	memset(&in, 0, sizeof(in));
	in.has_secrets = true;
	in.secrets = secrets;
	if ((a = cbl_yarena_new()) == NULL)
		return (ENOMEM);
	memset(&out, 0, sizeof(out));
	if ((error = yq_call(conn, n, NULL, act, &in, &out, a, err,
	    errlen)) == 0)
		*data = bundle_json((const ybundle *)(const void *)&out);
	cbl_yarena_free(a);
	return (error);
}

int
yh_config_apply(cbl_conn *conn, const char *bundle, bool dry, bool anyway,
    const char *hostname, ucl_object_t **data, char *err, size_t errlen)
{
	/* The state enumeration's names, by its values. */
	static const char *const states[] = { "same", "changed", "new",
	    "withheld" };
	struct arcana_agent_agent_config_apply_input	 in;
	struct arcana_agent_agent_config_apply_output	 out;
	const struct cbl_ynode				*n, *act;
	ucl_object_t					*top, *arr, *o;
	cbl_yarena					*a;
	int						 error;

	*data = NULL;
	err[0] = '\0';
	if ((n = yq_top("arcana-agent", "agent")) == NULL ||
	    (act = yq_child(n, "config-apply")) == NULL) {
		snprintf(err, errlen, "arcana-agent has no config-apply");
		return (ENOENT);
	}
	if ((a = cbl_yarena_new()) == NULL)
		return (ENOMEM);
	memset(&in, 0, sizeof(in));
	if (bundle == NULL || (in.bundle = bundle_in(bundle, a)) == NULL) {
		cbl_yarena_free(a);
		snprintf(err, errlen, "not a host's bundle (config-export's, "
		    "format 1)");
		return (EINVAL);
	}
	in.has_dry_run = true;
	in.dry_run = dry;
	in.has_anyway = true;
	in.anyway = anyway;
	in.hostname = hostname != NULL && hostname[0] != '\0' ? hostname :
	    NULL;
	memset(&out, 0, sizeof(out));
	if ((error = yq_call(conn, n, NULL, act, &in, &out, a, err,
	    errlen)) == 0) {
		/* In the order bundle.c put them. */
		top = ucl_object_typed_new(UCL_OBJECT);
		arr = ucl_object_typed_new(UCL_ARRAY);
		for (size_t i = 0; i < out.mismatch.n; i++)
			ucl_array_append(arr, ucl_object_fromstring(
			    out.mismatch.v[i]));
		put(top, "mismatches", arr);
		arr = ucl_object_typed_new(UCL_ARRAY);
		for (size_t i = 0; i < out.package.n; i++) {
			o = ucl_object_typed_new(UCL_OBJECT);
			put_str(o, "name", out.package.v[i]);
			ucl_array_append(arr, o);
		}
		put(top, "packages", arr);
		arr = ucl_object_typed_new(UCL_ARRAY);
		for (size_t i = 0; i < out.file.n; i++) {
			o = ucl_object_typed_new(UCL_OBJECT);
			put_str(o, "path", out.file.v[i].path);
			if (out.file.v[i].has_state &&
			    (size_t)out.file.v[i].state < nitems(states))
				put_str(o, "state", states[out.file.v[i].state]);
			put_str(o, "diff", out.file.v[i].diff);
			ucl_array_append(arr, o);
		}
		put(top, "files", arr);
		put_str(top, "backup", out.backup);
		if (out.has_applied && out.applied)
			put(top, "applied", ucl_object_frombool(true));
		if (out.has_reboot && out.reboot)
			put(top, "reboot", ucl_object_frombool(true));
		*data = top;
		/* Refused, the report given still. */
		if (out.refused != NULL) {
			snprintf(err, errlen, "%s", out.refused);
			error = EPERM;
		}
	}
	cbl_yarena_free(a);
	return (error);
}

/* arcana-agent's agent as a read has it, into d (a's). */
static int
agent_read(cbl_conn *conn, struct arcana_agent *d, cbl_yarena *a, char *err,
    size_t errlen)
{
	const struct cbl_ynode	*n;

	if ((n = yq_top("arcana-agent", "agent")) == NULL) {
		snprintf(err, errlen, "arcana-agent has no agent");
		return (ENOENT);
	}
	memset(d, 0, sizeof(*d));
	return (yq_get(conn, n, -1, d, a, err, errlen));
}

/* An action of the agent's container name, child of it (NULL: of it). */
static int
agent_call(cbl_conn *conn, const char *child, const char *name,
    const void *in, void *out, cbl_yarena *a, char *err, size_t errlen)
{
	const struct cbl_ynode	*n, *c, *act;

	if ((n = yq_top("arcana-agent", "agent")) == NULL || (c = child !=
	    NULL ? yq_child(n, child) : n) == NULL || (act = yq_child(c,
	    name)) == NULL) {
		snprintf(err, errlen, "arcana-agent has no %s", name);
		return (ENOENT);
	}
	return (yq_call(conn, c, NULL, act, in, out, a, err, errlen));
}

static ucl_object_t *
strs_of(const char *const *v, size_t n)
{
	ucl_object_t	*arr;

	arr = ucl_object_typed_new(UCL_ARRAY);
	for (size_t i = 0; i < n; i++)
		ucl_array_append(arr, ucl_object_fromstring(v[i]));
	return (arr);
}

int
yh_transport(cbl_conn *conn, bool retry, const char *listen,
    const char *unlisten, bool keep, const char *sctp_also,
    ucl_object_t **data, char *err, size_t errlen)
{
	static const char *const ltransport[] = { "tcp", "sctp", "unix" };
	static const char *const pstate[] = { "active", "inactive",
	    "unconfirmed", "other" };
	struct arcana_agent_agent_transport_listen_input	 lin;
	const struct arcana_agent_agent_transport		*t;
	struct arcana_agent					 d;
	ucl_object_t						*top, *arr, *o;
	ucl_object_t						*pa, *p;
	cbl_yarena						*a;
	int							 error;

	*data = NULL;
	err[0] = '\0';
	if ((a = cbl_yarena_new()) == NULL)
		return (ENOMEM);
	error = 0;
	if (retry)
		error = agent_call(conn, "transport", "retry", NULL, NULL, a,
		    err, errlen);
	if (error == 0 && (listen != NULL || unlisten != NULL || sctp_also !=
	    NULL)) {
		memset(&lin, 0, sizeof(lin));
		lin.listen = listen;
		lin.unlisten = unlisten;
		lin.has_keep = true;
		lin.keep = keep;
		lin.sctp_also = sctp_also;
		error = agent_call(conn, "transport", "listen", &lin, NULL, a,
		    err, errlen);
	}
	if (error == 0)
		error = agent_read(conn, &d, a, err, errlen);
	if (error != 0) {
		cbl_yarena_free(a);
		return (error);
	}
	/* In the order transport.c put them. */
	top = ucl_object_typed_new(UCL_OBJECT);
	arr = ucl_object_typed_new(UCL_ARRAY);
	t = d.agent != NULL ? d.agent->transport : NULL;
	for (size_t i = 0; t != NULL && i < t->listener.n; i++) {
		const struct arcana_agent_agent_transport_listener *l =
		    &t->listener.v[i];

		o = ucl_object_typed_new(UCL_OBJECT);
		put_str(o, "uri", l->uri);
		if (l->has_transport && (size_t)l->transport <
		    nitems(ltransport))
			put_str(o, "transport", ltransport[l->transport]);
		put(o, "up", ucl_object_frombool(l->has_up && l->up));
		put_str(o, "error", l->why);
		/* SCTP's: every address it is bound to. */
		if (l->has_transport && l->transport ==
		    ARCANA_AGENT_AGENT_TRANSPORT_LISTENER_TRANSPORT_SCTP &&
		    l->has_up && l->up)
			put(o, "addresses", strs_of(l->address.v,
			    l->address.n));
		put_str(o, "also_error", l->also_why);
		ucl_array_append(arr, o);
	}
	put(top, "listeners", arr);
	put_str(top, "sctp_also", t != NULL && t->sctp_also != NULL ?
	    t->sctp_also : "");
	put(top, "sctp", ucl_object_frombool(t != NULL && t->has_sctp &&
	    t->sctp));
	put(top, "seen", ucl_object_fromint(t != NULL && t->has_seen ?
	    (int64_t)t->seen : 0));
	arr = ucl_object_typed_new(UCL_ARRAY);
	for (size_t i = 0; t != NULL && i < t->session.n; i++) {
		const struct arcana_agent_agent_transport_session *se =
		    &t->session.v[i];

		o = ucl_object_typed_new(UCL_OBJECT);
		put_str(o, "transport", se->transport);
		put_str(o, "address", se->address);
		put_str(o, "subject", se->name);
		put(o, "since", ucl_object_fromint(epoch_of(se->since)));
		/* An association: its addresses here, its paths there. */
		if (se->transport != NULL && strcmp(se->transport, "sctp") ==
		    0) {
			put(o, "local", strs_of(se->local.v, se->local.n));
			pa = ucl_object_typed_new(UCL_ARRAY);
			for (size_t k = 0; k < se->path.n; k++) {
				const struct
				    arcana_agent_agent_transport_session_path *pp =
				    &se->path.v[k];

				p = ucl_object_typed_new(UCL_OBJECT);
				put_str(p, "address", pp->address);
				if (pp->has_state && (size_t)pp->state <
				    nitems(pstate))
					put_str(p, "state", pstate[pp->state]);
				if (pp->has_srtt)
					put(p, "srtt_ms", ucl_object_fromint(
					    pp->srtt));
				if (pp->has_rto)
					put(p, "rto_ms", ucl_object_fromint(
					    pp->rto));
				put(p, "primary", ucl_object_frombool(
				    pp->has_primary && pp->primary));
				ucl_array_append(pa, p);
			}
			put(o, "paths", pa);
		}
		ucl_array_append(arr, o);
	}
	put(top, "sessions", arr);
	put(top, "time", ucl_object_fromint(t != NULL && t->time != NULL ?
	    epoch_of(t->time) : (int64_t)time(NULL)));
	*data = top;
	cbl_yarena_free(a);
	return (0);
}

/* A certificate of the agent's own as tlsfiles.c writes one. */
static ucl_object_t *
own_cert_of(const char *subject, const char *issuer, const char *nb,
    const char *na, const char *sha256)
{
	ucl_object_t	*o;

	o = ucl_object_typed_new(UCL_OBJECT);
	put_str(o, "subject", subject);
	put_str(o, "issuer", issuer);
	put(o, "not_before", ucl_object_fromint(epoch_of(nb)));
	put(o, "not_after", ucl_object_fromint(epoch_of(na)));
	put_str(o, "sha256", sha256);
	return (o);
}

int
yh_tls(cbl_conn *conn, const char *verb, const char *cert, const char *ca,
    const char *peer, ucl_object_t **data, char *err, size_t errlen)
{
	struct arcana_agent_agent_tls_install_input	 iin;
	struct arcana_agent_agent_tls_csr_output	 cout;
	const struct arcana_agent_agent_tls		*l;
	struct arcana_agent				 d;
	ucl_object_t					*top, *c, *arr;
	cbl_yarena					*a;
	int						 error;

	*data = NULL;
	err[0] = '\0';
	if ((a = cbl_yarena_new()) == NULL)
		return (ENOMEM);
	if (strcmp(verb, "csr") == 0) {
		memset(&cout, 0, sizeof(cout));
		if ((error = agent_call(conn, "tls", "csr", NULL, &cout, a, err,
		    errlen)) == 0) {
			top = ucl_object_typed_new(UCL_OBJECT);
			put_str(top, "csr", cout.csr);
			*data = top;
		}
		cbl_yarena_free(a);
		return (error);
	}
	error = 0;
	if (strcmp(verb, "install") == 0) {
		memset(&iin, 0, sizeof(iin));
		iin.certificate = cert;
		iin.ca = ca;
		iin.peer = peer;
		error = agent_call(conn, "tls", "install", &iin, NULL, a, err,
		    errlen);
	} else if (strcmp(verb, "status") != 0) {
		snprintf(err, errlen, "tls: status, csr or install");
		error = EINVAL;
	}
	if (error == 0)
		error = agent_read(conn, &d, a, err, errlen);
	if (error == 0 && (d.agent == NULL || (l = d.agent->tls) == NULL)) {
		snprintf(err, errlen, "this agent has no TLS files: it listens "
		    "on a local socket only");
		error = ENOENT;
	}
	if (error != 0) {
		cbl_yarena_free(a);
		return (error);
	}
	/* In the order tlsfiles.c put them. */
	top = ucl_object_typed_new(UCL_OBJECT);
	if (l->certificate != NULL) {
		c = own_cert_of(l->certificate->subject,
		    l->certificate->issuer, l->certificate->not_before,
		    l->certificate->not_after, l->certificate->sha256);
		arr = ucl_object_typed_new(UCL_ARRAY);
		for (size_t i = 0; i < l->certificate->intermediate.n; i++) {
			const struct arcana_agent_agent_tls_certificate_intermediate
			    *x = &l->certificate->intermediate.v[i];

			ucl_array_append(arr, own_cert_of(x->subject, x->issuer,
			    x->not_before, x->not_after, x->sha256));
		}
		put(c, "chain", arr);
		put(top, "cert", c);
	}
	arr = ucl_object_typed_new(UCL_ARRAY);
	for (size_t i = 0; i < l->ca.n; i++)
		ucl_array_append(arr, own_cert_of(l->ca.v[i].subject,
		    l->ca.v[i].issuer, l->ca.v[i].not_before,
		    l->ca.v[i].not_after, l->ca.v[i].sha256));
	put(top, "ca", arr);
	put(top, "pending", ucl_object_frombool(l->has_pending &&
	    l->pending));
	*data = top;
	cbl_yarena_free(a);
	return (0);
}

/* An action of arcana-agent's agent container: refused or not, as said. */
static int
agent_do(cbl_conn *conn, const char *name, const void *in, void *out,
    cbl_yarena *a, int ms, char *err, size_t errlen)
{
	const struct cbl_ynode	*n, *act;

	if ((n = yq_top("arcana-agent", "agent")) == NULL ||
	    (act = yq_child(n, name)) == NULL) {
		snprintf(err, errlen, "arcana-agent has no %s", name);
		return (ENOENT);
	}
	return (yq_call_wait(conn, n, NULL, act, in, out, a, ms, err,
	    errlen));
}

int
yh_source_head(cbl_conn *conn, const char *source, const char *ref,
    const char *host_keys, const char *ssh_key, ucl_object_t **data,
    char *err, size_t errlen)
{
	struct arcana_agent_agent_source_head_input	 in;
	struct arcana_agent_agent_source_head_output	 out;
	cbl_yarena					*a;
	int						 error;

	*data = NULL;
	err[0] = '\0';
	memset(&in, 0, sizeof(in));
	in.source = source;
	in.ref = ref != NULL && ref[0] != '\0' ? ref : NULL;
	in.host_keys = host_keys;
	in.ssh_key = ssh_key;
	if ((a = cbl_yarena_new()) == NULL)
		return (ENOMEM);
	memset(&out, 0, sizeof(out));
	if ((error = agent_do(conn, "source-head", &in, &out, a, -1, err,
	    errlen)) == 0 && out.refused != NULL) {
		snprintf(err, errlen, "%s", out.refused);
		*data = fetched_of(out.host_keys, out.fingerprint.v,
		    out.fingerprint.n, out.deploy_key);
		error = EPERM;
	} else if (error == 0) {
		*data = ucl_object_typed_new(UCL_OBJECT);
		put_str(*data, "commit", out.commit);
	}
	cbl_yarena_free(a);
	return (error);
}

int
yh_console_update(cbl_conn *conn, const char *source, const char *ref,
    const char *host_keys, const char *ssh_key, ucl_object_t **data,
    char *err, size_t errlen)
{
	struct arcana_agent_agent_console_update_input	 in;
	struct arcana_agent_agent_console_update_output	 out;
	cbl_yarena					*a;
	int						 error;

	*data = NULL;
	err[0] = '\0';
	memset(&in, 0, sizeof(in));
	in.source = source;
	in.ref = ref != NULL && ref[0] != '\0' ? ref : NULL;
	in.host_keys = host_keys;
	in.ssh_key = ssh_key;
	if ((a = cbl_yarena_new()) == NULL)
		return (ENOMEM);
	memset(&out, 0, sizeof(out));
	if ((error = agent_do(conn, "console-update", &in, &out, a, -1, err,
	    errlen)) == 0 && out.refused != NULL) {
		snprintf(err, errlen, "%s", out.refused);
		*data = fetched_of(out.host_keys, out.fingerprint.v,
		    out.fingerprint.n, out.deploy_key);
		error = EPERM;
	} else if (error == 0) {
		/* Installed, the console and the agent restart (yarcana.c). */
		*data = ucl_object_typed_new(UCL_OBJECT);
		put_str(*data, "commit", out.commit);
		put(*data, "restarting", ucl_object_frombool(true));
	}
	cbl_yarena_free(a);
	return (error);
}

int
yh_agent_build(cbl_conn *conn, const char *source, const char *ref,
    const char *host_keys, const char *ssh_key, bool compress,
    ucl_object_t **data, uint8_t **progp, size_t *lenp, char *err,
    size_t errlen)
{
	struct arcana_agent_agent_build_input	 in;
	struct arcana_agent_agent_build_output	 out;
	const char				*why;
	cbl_yarena				*a;
	uint8_t					*prog;
	int					 error;

	*data = NULL;
	*progp = NULL;
	*lenp = 0;
	err[0] = '\0';
	memset(&in, 0, sizeof(in));
	in.source = source;
	in.ref = ref != NULL && ref[0] != '\0' ? ref : NULL;
	in.host_keys = host_keys;
	in.ssh_key = ssh_key;
	/* Not said to an agent before compressed updates, which has no
	 * compress. */
	in.has_compress = compress;
	in.compress = compress;
	if ((a = cbl_yarena_new()) == NULL)
		return (ENOMEM);
	memset(&out, 0, sizeof(out));
	if ((error = agent_do(conn, "build", &in, &out, a, -1, err,
	    errlen)) == 0 && out.refused != NULL) {
		snprintf(err, errlen, "%s", out.refused);
		*data = fetched_of(out.host_keys, out.fingerprint.v,
		    out.fingerprint.n, out.deploy_key);
		error = EPERM;
	} else if (error == 0 && (out.binary.len == 0 || out.sha256 ==
	    NULL)) {
		snprintf(err, errlen, "the host sent no program");
		error = EINVAL;
	} else if (error == 0) {
		/* Compressed, inflated: the SHA-256 is the program's. */
		if (out.has_program_size) {
			if ((why = zprog_inflate(out.binary.p, out.binary.len,
			    out.program_size, ZPROG_MAX_PROGRAM, &prog)) !=
			    NULL) {
				snprintf(err, errlen, "%s", why);
				cbl_yarena_free(a);
				return (EINVAL);
			}
			*lenp = out.program_size;
		} else {
			if ((prog = malloc(out.binary.len)) == NULL) {
				cbl_yarena_free(a);
				return (ENOMEM);
			}
			memcpy(prog, out.binary.p, out.binary.len);
			*lenp = out.binary.len;
		}
		*progp = prog;
		*data = ucl_object_typed_new(UCL_OBJECT);
		put_str(*data, "version", out.version);
		put_str(*data, "sha256", out.sha256);
		put_str(*data, "commit", out.commit);
	}
	cbl_yarena_free(a);
	return (error);
}

int
yh_agent_update(cbl_conn *conn, const uint8_t *prog, size_t len,
    const char *sha256, const uint8_t *sig, size_t siglen, bool restart,
    bool gzip, int timeout_ms, ucl_object_t **data, char *err,
    size_t errlen)
{
	struct arcana_agent_agent_update_input	 in;
	struct arcana_agent_agent_update_output	 out;
	cbl_yarena				*a;
	uint8_t					*z;
	size_t					 zlen;
	int					 error;

	*data = NULL;
	err[0] = '\0';
	z = NULL;
	memset(&in, 0, sizeof(in));
	/*
	 * Compressed to an agent that takes it so; as it is to one before,
	 * which has no program-size and takes no more than a frame holds.
	 * The signature and the SHA-256 are the program's either way.
	 */
	if (gzip) {
		if ((error = zprog_deflate(prog, len, &z, &zlen)) != 0) {
			snprintf(err, errlen, "the program cannot be "
			    "compressed: %s", strerror(error));
			return (error);
		}
		if (zlen > ZPROG_MAX_BINARY) {
			free(z);
			snprintf(err, errlen, "the program, %zu bytes "
			    "compressed, does not fit in an update (%d at "
			    "most)", zlen, ZPROG_MAX_BINARY);
			return (EFBIG);
		}
		in.binary.p = z;
		in.binary.len = zlen;
		in.has_program_size = true;
		in.program_size = (uint32_t)len;
	} else if (len > ZPROG_MAX_BINARY) {
		snprintf(err, errlen, "this host's arcana-agent takes no "
		    "compressed update, and the program, %zu bytes, is more "
		    "than one carries as it is (%d)", len, ZPROG_MAX_BINARY);
		return (EFBIG);
	} else {
		in.binary.p = prog;
		in.binary.len = len;
	}
	in.sha256 = sha256;
	in.signature.p = sig;
	in.signature.len = sig != NULL ? siglen : 0;
	/* Not said when not asked: an agent before takes it so too. */
	in.has_restart = restart;
	in.restart = restart;
	if ((a = cbl_yarena_new()) == NULL) {
		free(z);
		return (ENOMEM);
	}
	memset(&out, 0, sizeof(out));
	if ((error = agent_do(conn, "update", &in, &out, a, timeout_ms, err,
	    errlen)) == 0) {
		*data = ucl_object_typed_new(UCL_OBJECT);
		put_str(*data, "version", out.version);
		put(*data, "restarting", ucl_object_frombool(
		    out.has_restarting && out.restarting));
	}
	cbl_yarena_free(a);
	free(z);
	return (error);
}

const struct arcana_jobs_step *
yh_steps_of(const cbl_msg *msg, cbl_yarena *a, size_t *np)
{
	struct arcana_jobs_steps	*s;
	const struct cbl_ynode		*n;
	struct cbl_ynotif		 nt;

	*np = 0;
	if ((n = yq_top("arcana-jobs", "steps")) == NULL ||
	    cbl_msg_ynotif(msg, &nt, a) != 0 || nt.sid != n->sid ||
	    (s = cbl_yarena_alloc(a, sizeof(*s))) == NULL)
		return (NULL);
	memset(s, 0, sizeof(*s));
	if (cbl_ydecode(n, nt.content, nt.len, s, a, 0, NULL, 0) != 0)
		return (NULL);
	*np = s->step.n;
	return (s->step.v);
}
