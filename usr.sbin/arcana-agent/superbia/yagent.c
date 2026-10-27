/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Superbia: the agent as YANG, arcana-agent: the
 * transport operation's JSON (invidia/transport.c) and the tls
 * operation's status (tlsfiles.c) read back as the module's state;
 * config-export's bundle (bundle.c) as the export action's output,
 * config-apply's report as the apply action's; source-log's commits
 * and tags (ira/build.c) as that action's output.
 */

#include <sys/param.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <arcana.h>

#include "collect.h"
#include "yjson.h"

static char *
datetime(cbl_yarena *a, int64_t t)
{
	char		buf[32], *p;
	struct tm	tm;
	time_t		tt = (time_t)t;

	if (gmtime_r(&tt, &tm) == NULL || strftime(buf, sizeof(buf),
	    "%Y-%m-%dT%H:%M:%SZ", &tm) == 0)
		return (NULL);
	if ((p = cbl_yarena_alloc(a, strlen(buf) + 1)) != NULL)
		memcpy(p, buf, strlen(buf) + 1);
	return (p);
}

int
yagent_transport_from_json(const char *json, cbl_yarena *a,
    struct arcana_agent_agent_transport *out)
{
	struct arcana_agent_agent_transport_listener	*l;
	struct arcana_agent_agent_transport_session	*s;
	const ucl_object_t				*e;
	ucl_object_iter_t				 it;
	ucl_object_t					*top;
	const char					*v;
	int64_t						 n;
	size_t						 k;

	memset(out, 0, sizeof(*out));
	if ((top = yj_parse(json)) == NULL)
		return (EINVAL);
	if ((l = cbl_yarena_alloc(a, (yj_count(ucl_object_lookup(top,
	    "listeners")) + 1) * sizeof(*l))) == NULL || (s =
	    cbl_yarena_alloc(a, (yj_count(ucl_object_lookup(top, "sessions"))
	    + 1) * sizeof(*s))) == NULL) {
		ucl_object_unref(top);
		return (ENOMEM);
	}
	k = 0;
	YJ_EACH(ucl_object_lookup(top, "listeners"), it, e) {
		memset(&l[k], 0, sizeof(l[k]));
		if ((l[k].uri = yj_str(a, e, "uri")) == NULL)
			continue;
		if ((v = yj_str(a, e, "transport")) != NULL) {
			l[k].has_transport = true;
			l[k].transport = strcmp(v, "sctp") == 0 ?
			    ARCANA_AGENT_AGENT_TRANSPORT_LISTENER_TRANSPORT_SCTP :
			    strcmp(v, "unix") == 0 ?
			    ARCANA_AGENT_AGENT_TRANSPORT_LISTENER_TRANSPORT_UNIX :
			    ARCANA_AGENT_AGENT_TRANSPORT_LISTENER_TRANSPORT_TCP;
		}
		l[k].up = yj_yes(e, "up", &l[k].has_up);
		l[k].why = yj_str(a, e, "error");
		k++;
	}
	out->listener.n = k;
	out->listener.v = l;
	out->sctp = yj_yes(top, "sctp", &out->has_sctp);
	k = 0;
	YJ_EACH(ucl_object_lookup(top, "sessions"), it, e) {
		memset(&s[k], 0, sizeof(s[k]));
		s[k].transport = yj_str(a, e, "transport");
		s[k].address = yj_str(a, e, "address");
		s[k].name = yj_str(a, e, "subject");
		if (yj_num(e, "since", &n))
			s[k].since = datetime(a, n);
		k++;
	}
	out->session.n = k;
	out->session.v = s;
	ucl_object_unref(top);
	return (0);
}

/* A certificate of the agent's own: the two have one layout. */
static void
own_cert(cbl_yarena *a, const ucl_object_t *o,
    struct arcana_agent_agent_tls_ca *c)
{

	memset(c, 0, sizeof(*c));
	c->subject = yj_str(a, o, "subject");
	c->issuer = yj_str(a, o, "issuer");
	c->not_before = yj_str(a, o, "not_before");
	c->not_after = yj_str(a, o, "not_after");
	c->sha256 = yj_str(a, o, "sha256");
}

int
yagent_tls_from_json(const char *json, cbl_yarena *a,
    struct arcana_agent_agent_tls *out)
{
	struct arcana_agent_agent_tls_certificate	*c;
	struct arcana_agent_agent_tls_ca		*ca;
	const ucl_object_t				*e, *o;
	ucl_object_iter_t				 it;
	ucl_object_t					*top;
	size_t						 k = 0;

	memset(out, 0, sizeof(*out));
	if ((top = yj_parse(json)) == NULL)
		return (EINVAL);
	if ((o = ucl_object_lookup(top, "cert")) != NULL) {
		if ((c = cbl_yarena_alloc(a, sizeof(*c))) == NULL) {
			ucl_object_unref(top);
			return (ENOMEM);
		}
		memset(c, 0, sizeof(*c));
		own_cert(a, o, (void *)c);
		if (yj_strs(a, ucl_object_lookup(o, "chain"), &c->chain.n,
		    &c->chain.v) != 0) {
			ucl_object_unref(top);
			return (ENOMEM);
		}
		out->certificate = c;
	}
	if ((ca = cbl_yarena_alloc(a, (yj_count(ucl_object_lookup(top, "ca"))
	    + 1) * sizeof(*ca))) == NULL) {
		ucl_object_unref(top);
		return (ENOMEM);
	}
	YJ_EACH(ucl_object_lookup(top, "ca"), it, e)
		own_cert(a, e, &ca[k++]);
	out->ca.n = k;
	out->ca.v = ca;
	out->pending = yj_yes(top, "pending", &out->has_pending);
	ucl_object_unref(top);
	return (0);
}

/* A bundle, as config-export makes it: the export's output and the
 * apply's input have one layout. */
int
yagent_bundle_from_json(const char *json, cbl_yarena *a,
    struct arcana_agent_agent_config_export_output *out)
{
	struct arcana_agent_agent_config_export_output_facts		*f;
	struct arcana_agent_agent_config_export_output_facts_interface	*fi;
	struct arcana_agent_agent_config_export_output_facts_disk	*fd;
	struct arcana_agent_agent_config_export_output_package		*p;
	struct arcana_agent_agent_config_export_output_file		*fl;
	const ucl_object_t						*e, *o;
	ucl_object_iter_t						 it;
	ucl_object_t							*top;
	size_t								 k;
	int								 error = ENOMEM;

	memset(out, 0, sizeof(*out));
	if ((top = yj_parse(json)) == NULL)
		return (EINVAL);
	out->host = yj_str(a, top, "host");
	out->agent = yj_str(a, top, "agent");
	out->taken = yj_str(a, top, "taken");
	if ((o = ucl_object_lookup(top, "facts")) != NULL) {
		if ((f = cbl_yarena_alloc(a, sizeof(*f))) == NULL || (fi =
		    cbl_yarena_alloc(a, (yj_count(ucl_object_lookup(o,
		    "interfaces")) + 1) * sizeof(*fi))) == NULL || (fd =
		    cbl_yarena_alloc(a, (yj_count(ucl_object_lookup(o, "disks"))
		    + 1) * sizeof(*fd))) == NULL)
			goto out;
		memset(f, 0, sizeof(*f));
		f->arch = yj_str(a, o, "arch");
		f->release = yj_str(a, o, "release");
		f->cpu = yj_str(a, o, "cpu");
		YJ_NUM(o, "ncpu", f, ncpu);
		YJ_NUM(o, "memory", f, memory);
		k = 0;
		YJ_EACH(ucl_object_lookup(o, "interfaces"), it, e) {
			memset(&fi[k], 0, sizeof(fi[k]));
			if ((fi[k].name = yj_str(a, e, "name")) == NULL)
				continue;
			fi[k].driver = yj_str(a, e, "driver");
			fi[k].mac = yj_str(a, e, "mac");
			k++;
		}
		f->interface.n = k;
		f->interface.v = fi;
		k = 0;
		YJ_EACH(ucl_object_lookup(o, "disks"), it, e) {
			memset(&fd[k], 0, sizeof(fd[k]));
			if ((fd[k].name = yj_str(a, e, "name")) == NULL)
				continue;
			YJ_NUM(e, "size", &fd[k], size);
			k++;
		}
		f->disk.n = k;
		f->disk.v = fd;
		out->facts = f;
	}
	if ((p = cbl_yarena_alloc(a, (yj_count(ucl_object_lookup(top,
	    "packages")) + 1) * sizeof(*p))) == NULL || (fl = cbl_yarena_alloc(
	    a, (yj_count(ucl_object_lookup(top, "files")) + 1) *
	    sizeof(*fl))) == NULL)
		goto out;
	k = 0;
	YJ_EACH(ucl_object_lookup(top, "packages"), it, e) {
		memset(&p[k], 0, sizeof(p[k]));
		if ((p[k].name = yj_str(a, e, "name")) == NULL)
			continue;
		p[k].origin = yj_str(a, e, "origin");
		p[k].version = yj_str(a, e, "version");
		k++;
	}
	out->package.n = k;
	out->package.v = p;
	k = 0;
	YJ_EACH(ucl_object_lookup(top, "files"), it, e) {
		memset(&fl[k], 0, sizeof(fl[k]));
		if ((fl[k].path = yj_str(a, e, "path")) == NULL)
			continue;
		fl[k].mode = yj_str(a, e, "mode");
		fl[k].owner = yj_str(a, e, "owner");
		fl[k].group = yj_str(a, e, "group");
		fl[k].text = yj_str(a, e, "text");
		fl[k].secret = yj_yes(e, "secret", &fl[k].has_secret);
		k++;
	}
	out->file.n = k;
	out->file.v = fl;
	error = 0;
out:
	ucl_object_unref(top);
	return (error);
}

static void
put_str(ucl_object_t *o, const char *key, const char *v)
{

	if (v != NULL)
		ucl_object_insert_key(o, ucl_object_fromstring(v), key, 0,
		    false);
}

/* The apply's bundle as config-export wrote it, malloc'd; NULL: out of
 * memory. */
char *
yagent_bundle_json(const struct arcana_agent_agent_config_apply_input_bundle *b)
{
	const struct arcana_agent_agent_config_apply_input_bundle_facts *f;
	ucl_object_t	*top, *o, *arr, *e;
	char		*json;
	size_t		 i;

	top = ucl_object_typed_new(UCL_OBJECT);
	put_str(top, "host", b->host);
	put_str(top, "agent", b->agent);
	put_str(top, "taken", b->taken);
	if ((f = b->facts) != NULL) {
		o = ucl_object_typed_new(UCL_OBJECT);
		put_str(o, "arch", f->arch);
		put_str(o, "release", f->release);
		put_str(o, "cpu", f->cpu);
		if (f->has_ncpu)
			ucl_object_insert_key(o, ucl_object_fromint(f->ncpu),
			    "ncpu", 0, false);
		if (f->has_memory)
			ucl_object_insert_key(o, ucl_object_fromint(
			    (int64_t)f->memory), "memory", 0, false);
		arr = ucl_object_typed_new(UCL_ARRAY);
		for (i = 0; i < f->interface.n; i++) {
			e = ucl_object_typed_new(UCL_OBJECT);
			put_str(e, "name", f->interface.v[i].name);
			put_str(e, "driver", f->interface.v[i].driver);
			put_str(e, "mac", f->interface.v[i].mac);
			ucl_array_append(arr, e);
		}
		ucl_object_insert_key(o, arr, "interfaces", 0, false);
		arr = ucl_object_typed_new(UCL_ARRAY);
		for (i = 0; i < f->disk.n; i++) {
			e = ucl_object_typed_new(UCL_OBJECT);
			put_str(e, "name", f->disk.v[i].name);
			if (f->disk.v[i].has_size)
				ucl_object_insert_key(e, ucl_object_fromint(
				    (int64_t)f->disk.v[i].size), "size", 0,
				    false);
			ucl_array_append(arr, e);
		}
		ucl_object_insert_key(o, arr, "disks", 0, false);
		ucl_object_insert_key(top, o, "facts", 0, false);
	}
	arr = ucl_object_typed_new(UCL_ARRAY);
	for (i = 0; i < b->package.n; i++) {
		e = ucl_object_typed_new(UCL_OBJECT);
		put_str(e, "name", b->package.v[i].name);
		put_str(e, "origin", b->package.v[i].origin);
		put_str(e, "version", b->package.v[i].version);
		ucl_array_append(arr, e);
	}
	ucl_object_insert_key(top, arr, "packages", 0, false);
	arr = ucl_object_typed_new(UCL_ARRAY);
	for (i = 0; i < b->file.n; i++) {
		e = ucl_object_typed_new(UCL_OBJECT);
		put_str(e, "path", b->file.v[i].path);
		put_str(e, "mode", b->file.v[i].mode);
		put_str(e, "owner", b->file.v[i].owner);
		put_str(e, "group", b->file.v[i].group);
		put_str(e, "text", b->file.v[i].text);
		if (b->file.v[i].has_secret)
			ucl_object_insert_key(e, ucl_object_frombool(
			    b->file.v[i].secret), "secret", 0, false);
		ucl_array_append(arr, e);
	}
	ucl_object_insert_key(top, arr, "files", 0, false);
	json = (char *)ucl_object_emit(top, UCL_EMIT_JSON_COMPACT);
	ucl_object_unref(top);
	return (json);
}

int
yagent_apply_from_json(const char *json, cbl_yarena *a,
    struct arcana_agent_agent_config_apply_output *out)
{
	struct arcana_agent_agent_config_apply_output_file	*f;
	const ucl_object_t					*e;
	ucl_object_iter_t					 it;
	ucl_object_t						*top;
	const char						*v;
	size_t							 k = 0;

	memset(out, 0, sizeof(*out));
	if ((top = yj_parse(json)) == NULL)
		return (EINVAL);
	if (yj_strs(a, ucl_object_lookup(top, "mismatches"), &out->mismatch.n,
	    &out->mismatch.v) != 0 || yj_strs(a, ucl_object_lookup(top,
	    "packages"), &out->package.n, &out->package.v) != 0 || (f =
	    cbl_yarena_alloc(a, (yj_count(ucl_object_lookup(top, "files")) +
	    1) * sizeof(*f))) == NULL) {
		ucl_object_unref(top);
		return (ENOMEM);
	}
	YJ_EACH(ucl_object_lookup(top, "files"), it, e) {
		memset(&f[k], 0, sizeof(f[k]));
		if ((f[k].path = yj_str(a, e, "path")) == NULL)
			continue;
		if ((v = yj_str(a, e, "state")) != NULL) {
			f[k].has_state = true;
			f[k].state = strcmp(v, "changed") == 0 ?
			    ARCANA_AGENT_AGENT_CONFIG_APPLY_OUTPUT_FILE_STATE_CHANGED :
			    strcmp(v, "new") == 0 ?
			    ARCANA_AGENT_AGENT_CONFIG_APPLY_OUTPUT_FILE_STATE_NEW :
			    strcmp(v, "withheld") == 0 ?
			    ARCANA_AGENT_AGENT_CONFIG_APPLY_OUTPUT_FILE_STATE_WITHHELD :
			    ARCANA_AGENT_AGENT_CONFIG_APPLY_OUTPUT_FILE_STATE_SAME;
		}
		f[k].diff = yj_str(a, e, "diff");
		k++;
	}
	out->file.n = k;
	out->file.v = f;
	out->backup = yj_str(a, top, "backup");
	out->applied = yj_yes(top, "applied", &out->has_applied);
	out->reboot = yj_yes(top, "reboot", &out->has_reboot);
	ucl_object_unref(top);
	return (0);
}

/* source-log's commits and tags, two JSON lists, with the head. */
int
yagent_log_from_json(const char *commit, const char *log, const char *tags,
    cbl_yarena *a, struct arcana_agent_agent_source_log_output *out)
{
	struct arcana_agent_agent_source_log_output_commit_log	*c;
	struct arcana_agent_agent_source_log_output_tag		*t;
	const ucl_object_t					*e;
	ucl_object_iter_t					 it;
	ucl_object_t						*lo, *to;
	int64_t							 n;
	size_t							 k;

	memset(out, 0, sizeof(*out));
	out->commit = commit;
	lo = log != NULL ? yj_parse(log) : NULL;
	to = tags != NULL ? yj_parse(tags) : NULL;
	if ((c = cbl_yarena_alloc(a, (yj_count(lo) + 1) * sizeof(*c))) == NULL
	    || (t = cbl_yarena_alloc(a, (yj_count(to) + 1) * sizeof(*t))) ==
	    NULL) {
		ucl_object_unref(lo);
		ucl_object_unref(to);
		return (ENOMEM);
	}
	k = 0;
	YJ_EACH(lo, it, e) {
		memset(&c[k], 0, sizeof(c[k]));
		if ((c[k].hash = yj_str(a, e, "commit")) == NULL)
			continue;
		if (yj_num(e, "time", &n))
			c[k].time = datetime(a, n);
		c[k].subject = yj_str(a, e, "subject");
		c[k].body = yj_str(a, e, "body");
		k++;
	}
	out->commit_log.n = k;
	out->commit_log.v = c;
	k = 0;
	YJ_EACH(to, it, e) {
		memset(&t[k], 0, sizeof(t[k]));
		if ((t[k].name = yj_str(a, e, "name")) == NULL)
			continue;
		t[k].message = yj_str(a, e, "message");
		k++;
	}
	out->tag.n = k;
	out->tag.v = t;
	ucl_object_unref(lo);
	ucl_object_unref(to);
	return (0);
}
