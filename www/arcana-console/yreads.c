/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * The host's daemons and files (PLAN-SDN-YANG 3.8), for the console and
 * arcanactl: arcana-sshd's read, arcana-builder's builder and its
 * port-options, arcana-notify's notify, made the JSON the operations
 * gave (the agent's ssh.c, poudriere.c, telegram.c), each key in the
 * place the agent put it; and arcana-crashes', arcana-system's,
 * arcana-netstore's, arcana-suricata's, arcana-smtpd's and
 * arcana-speeder's actions, whose nodes are named as the JSON's keys,
 * by yflat.c; so that the pages keep reading what they read.
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
#include "yflat.h"
#include "yflatnames.h"
#include "yqueue.h"
#include "yreads.h"

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

static void
put_bool(ucl_object_t *o, const char *key, bool v)
{

	put(o, key, ucl_object_frombool(v));
}

#define	PUT_NUM(o, key, y, m) do {					\
	if ((y)->has_##m)						\
		put((o), (key), ucl_object_fromint((int64_t)(y)->m));	\
} while (0)

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

static ucl_object_t *
strs_of(const char *const *v, size_t n)
{
	ucl_object_t	*arr;

	arr = ucl_object_typed_new(UCL_ARRAY);
	for (size_t i = 0; i < n; i++)
		ucl_array_append(arr, ucl_object_fromstring(v[i]));
	return (arr);
}

/* Action name of module mod's top-level node top; NULL: none. */
static const struct cbl_ynode *
action_of(const char *mod, const char *top, const char *name,
    const struct cbl_ynode **np, char *err, size_t errlen)
{
	const struct cbl_ynode	*n, *act;

	act = NULL;
	if ((n = yq_top(mod, top)) != NULL)
		act = yq_child(n, name);
	if (act == NULL)
		snprintf(err, errlen, "%s has no %s", mod, name);
	*np = n;
	return (act);
}

/* ---- sshd ------------------------------------------------------------ */

/* A key as ssh.c's key_obj() put it. */
static ucl_object_t *
key_json(const char *type, const char *fp, const char *options,
    const char *comment, bool has_bits, uint16_t bits)
{
	ucl_object_t	*o;

	o = ucl_object_typed_new(UCL_OBJECT);
	put_str(o, "type", type);
	put_str(o, "fingerprint", fp);
	put_str(o, "options", options);
	if (comment != NULL && comment[0] != '\0')
		put_str(o, "comment", comment);
	if (has_bits)
		put(o, "bits", ucl_object_fromint(bits));
	return (o);
}

static ucl_object_t *
sshd_json(const struct arcana_sshd_sshd_read_output *d)
{
	ucl_object_t	*top, *arr, *k, *c, *u, *ks, *set;

	top = ucl_object_typed_new(UCL_OBJECT);
	put_str(top, "config", d->config);
	put_str(top, "settings_from_file", d->settings_from_file);
	put_bool(top, "before_kept", d->has_before_kept && d->before_kept);
	put_str(top, "banner_text", d->banner);
	arr = ucl_object_typed_new(UCL_ARRAY);
	for (size_t i = 0; i < d->host_key.n; i++) {
		const struct arcana_sshd_host_key		*h;
		const struct arcana_sshd_host_key_certificate	*ce;

		h = &d->host_key.v[i];
		k = key_json(h->type, h->fingerprint, NULL, h->comment,
		    h->has_bits, h->bits);
		put_str(k, "path", h->path);
		if ((ce = h->certificate) != NULL) {
			c = ucl_object_typed_new(UCL_OBJECT);
			PUT_NUM(c, "serial", ce, serial);
			put_str(c, "kind", ce->kind);
			put_str(c, "id", ce->id);
			put(c, "principals", strs_of(ce->principal.v,
			    ce->principal.n));
			/* Forever is none in the model, -1 here. */
			if (ce->valid_after != NULL) {
				put(c, "valid_after", ucl_object_fromint(
				    epoch_of(ce->valid_after)));
				put(c, "valid_before", ucl_object_fromint(
				    ce->valid_before != NULL ?
				    epoch_of(ce->valid_before) : -1));
			}
			put_str(c, "ca", ce->ca);
			put(k, "certificate", c);
		}
		if (h->has_certificate_used)
			put_bool(k, "certificate_used", h->certificate_used);
		ucl_array_append(arr, k);
	}
	put(top, "host_keys", arr);
	arr = ucl_object_typed_new(UCL_ARRAY);
	for (size_t i = 0; i < d->user.n; i++) {
		const struct arcana_sshd_user	*us = &d->user.v[i];

		u = ucl_object_typed_new(UCL_OBJECT);
		put_str(u, "name", us->name);
		put(u, "uid", ucl_object_fromint(us->uid));
		put_str(u, "home", us->home);
		put_str(u, "shell", us->shell);
		put_str(u, "keys_file", us->keys_file != NULL ? us->keys_file :
		    "");
		ks = ucl_object_typed_new(UCL_ARRAY);
		for (size_t j = 0; j < us->key.n; j++)
			ucl_array_append(ks, key_json(us->key.v[j].type,
			    us->key.v[j].fingerprint, us->key.v[j].options,
			    us->key.v[j].comment, us->key.v[j].has_bits,
			    us->key.v[j].bits));
		put(u, "keys", ks);
		ucl_array_append(arr, u);
	}
	put(top, "users", arr);
	if (d->user_ca_key.n > 0 || d->user_cas_text != NULL) {
		arr = ucl_object_typed_new(UCL_ARRAY);
		for (size_t j = 0; j < d->user_ca_key.n; j++)
			ucl_array_append(arr, key_json(d->user_ca_key.v[j].type,
			    d->user_ca_key.v[j].fingerprint,
			    d->user_ca_key.v[j].options,
			    d->user_ca_key.v[j].comment,
			    d->user_ca_key.v[j].has_bits,
			    d->user_ca_key.v[j].bits));
		put(top, "user_cas", arr);
		put_str(top, "user_cas_text", d->user_cas_text);
	}
	set = ucl_object_typed_new(UCL_OBJECT);
	for (size_t i = 0; i < d->setting.n; i++)
		put(set, d->setting.v[i].name, strs_of(d->setting.v[i].value.v,
		    d->setting.v[i].value.n));
	put(top, "settings", set);
	return (top);
}

int
yr_sshd(cbl_conn *conn, const char *jail, ucl_object_t **data, char *err,
    size_t errlen)
{
	struct arcana_sshd_sshd_read_input	 in;
	struct arcana_sshd_sshd_read_output	 out;
	const struct cbl_ynode			*n, *act;
	cbl_yarena				*a;
	int					 error;

	*data = NULL;
	err[0] = '\0';
	if ((act = action_of("arcana-sshd", "sshd", "read", &n, err,
	    errlen)) == NULL)
		return (ENOENT);
	memset(&in, 0, sizeof(in));
	in.jail = jail != NULL && jail[0] != '\0' ? jail : NULL;
	if ((a = cbl_yarena_new()) == NULL)
		return (ENOMEM);
	memset(&out, 0, sizeof(out));
	if ((error = yq_call(conn, n, NULL, act, &in, &out, a, err,
	    errlen)) == 0)
		*data = sshd_json(&out);
	cbl_yarena_free(a);
	return (error);
}

/* ---- poudriere ------------------------------------------------------- */

/* A jail's or a ports tree's files, as dir_values() put them. */
static void
put_dir_value(ucl_object_t *o, const char *key, const char *v)
{

	put_str(o, key, v);
}

static ucl_object_t *
build_json(const struct arcana_builder_builder_build *b)
{
	ucl_object_t	*o, *arr, *e;

#define	PUT_COUNT(k, m) do {						\
	if (b->has_##m)							\
		put(o, (k), ucl_object_fromint((int64_t)b->m));		\
	else								\
		put_str(o, (k), "");					\
} while (0)
	o = ucl_object_typed_new(UCL_OBJECT);
	put_str(o, "set", b->set != NULL ? b->set : "");
	put_str(o, "ports", b->ports != NULL ? b->ports : "");
	put_str(o, "jail", b->jail);
	put_str(o, "build", b->build != NULL ? b->build : "");
	put_str(o, "status", b->status != NULL ? b->status : "");
	PUT_COUNT("queued", queued);
	PUT_COUNT("inspected", inspected);
	PUT_COUNT("ignored", ignored);
	PUT_COUNT("built", built);
	PUT_COUNT("failed", failed);
	PUT_COUNT("skipped", skipped);
	PUT_COUNT("fetched", fetched);
	PUT_COUNT("remaining", remaining);
#undef PUT_COUNT
	put_str(o, "time", b->time != NULL ? b->time : "");
	put_str(o, "logs", b->logs != NULL ? b->logs : "");
	/* Read from the log directory, when it is one. */
	if (b->logs == NULL || b->logs[0] != '/')
		return (o);
	arr = ucl_object_typed_new(UCL_ARRAY);
	for (size_t i = 0; i < b->failed_port.n; i++) {
		const struct arcana_builder_builder_build_failed_port *f =
		    &b->failed_port.v[i];

		e = ucl_object_typed_new(UCL_OBJECT);
		put_str(e, "origin", f->origin);
		put_str(e, "package", f->package);
		put_str(e, "phase", f->phase);
		PUT_NUM(e, "elapsed", f, elapsed);
		put_str(e, "reason", f->reason);
		put_str(e, "log_file", f->log_file);
		put_str(e, "log", f->log);
		ucl_array_append(arr, e);
	}
	put(o, "failed_ports", arr);
	arr = ucl_object_typed_new(UCL_ARRAY);
	for (size_t i = 0; i < b->skipped_port.n; i++) {
		e = ucl_object_typed_new(UCL_OBJECT);
		put_str(e, "origin", b->skipped_port.v[i].origin);
		put_str(e, "package", b->skipped_port.v[i].package);
		put_str(e, "because", b->skipped_port.v[i].because);
		ucl_array_append(arr, e);
	}
	put(o, "skipped_ports", arr);
	return (o);
}

static ucl_object_t *
builder_json(const struct arcana_builder_builder *d)
{
	static const char *const states[] = { "running", "done", "failed",
	    "lost" };
	ucl_object_t	*top, *o, *arr, *e, *ps;

	top = ucl_object_typed_new(UCL_OBJECT);
	put_bool(top, "installed", d->has_installed && d->installed);
	put_str(top, "program", d->program);
	put_str(top, "conf_file", d->conf_file);
	put_str(top, "basefs", d->basefs);
	put_str(top, "data", d->data);
	put_bool(top, "configured", d->has_configured && d->configured);
	o = ucl_object_typed_new(UCL_OBJECT);
	for (size_t i = 0; i < d->conf.n; i++)
		put_str(o, d->conf.v[i].name, d->conf.v[i].value);
	put(top, "conf", o);
	arr = ucl_object_typed_new(UCL_ARRAY);
	for (size_t i = 0; i < d->jail.n; i++) {
		const struct arcana_builder_builder_jail *j = &d->jail.v[i];

		e = ucl_object_typed_new(UCL_OBJECT);
		put_str(e, "name", j->name);
		put_dir_value(e, "version", j->version);
		put_dir_value(e, "arch", j->arch);
		put_dir_value(e, "method", j->method);
		put_dir_value(e, "mnt", j->mnt);
		put_dir_value(e, "fs", j->fs);
		if (j->timestamp != NULL)
			put(e, "timestamp", ucl_object_fromint(epoch_of(
			    j->timestamp)));
		ucl_array_append(arr, e);
	}
	put(top, "jails", arr);
	arr = ucl_object_typed_new(UCL_ARRAY);
	for (size_t i = 0; i < d->ports.n; i++) {
		const struct arcana_builder_builder_ports *p = &d->ports.v[i];

		e = ucl_object_typed_new(UCL_OBJECT);
		put_str(e, "name", p->name);
		put_dir_value(e, "method", p->method);
		put_dir_value(e, "mnt", p->mnt);
		if (p->timestamp != NULL)
			put(e, "timestamp", ucl_object_fromint(epoch_of(
			    p->timestamp)));
		ucl_array_append(arr, e);
	}
	put(top, "ports", arr);
	arr = ucl_object_typed_new(UCL_ARRAY);
	for (size_t i = 0; i < d->make_conf.n; i++) {
		e = ucl_object_typed_new(UCL_OBJECT);
		put_str(e, "name", d->make_conf.v[i].name);
		put_str(e, "file", d->make_conf.v[i].file);
		put_str(e, "text", d->make_conf.v[i].text != NULL ?
		    d->make_conf.v[i].text : "");
		ucl_array_append(arr, e);
	}
	put(top, "makeconf", arr);
	arr = ucl_object_typed_new(UCL_ARRAY);
	for (size_t i = 0; i < d->options.n; i++) {
		const struct arcana_builder_builder_options *od =
		    &d->options.v[i];

		ps = ucl_object_typed_new(UCL_ARRAY);
		for (size_t k = 0; k < od->port.n; k++) {
			o = ucl_object_typed_new(UCL_OBJECT);
			put_str(o, "name", od->port.v[k].name);
			put_str(o, "pkgname", od->port.v[k].pkgname);
			put(o, "set", strs_of(od->port.v[k].set.v,
			    od->port.v[k].set.n));
			put(o, "unset", strs_of(od->port.v[k].unset.v,
			    od->port.v[k].unset.n));
			ucl_array_append(ps, o);
		}
		e = ucl_object_typed_new(UCL_OBJECT);
		put_str(e, "name", od->name);
		put_str(e, "dir", od->dir);
		put(e, "ports", ps);
		ucl_array_append(arr, e);
	}
	put(top, "options", arr);
	arr = ucl_object_typed_new(UCL_ARRAY);
	for (size_t i = 0; i < d->repo.n; i++) {
		e = ucl_object_typed_new(UCL_OBJECT);
		put_str(e, "name", d->repo.v[i].name);
		put_str(e, "path", d->repo.v[i].path);
		put(e, "packages", ucl_object_fromint(d->repo.v[i].packages));
		ucl_array_append(arr, e);
	}
	put(top, "repos", arr);
	arr = ucl_object_typed_new(UCL_ARRAY);
	for (size_t i = 0; i < d->build.n; i++)
		ucl_array_append(arr, build_json(&d->build.v[i]));
	put(top, "builds", arr);
	put_str(top, "builds_error", d->builds_error);
	arr = ucl_object_typed_new(UCL_ARRAY);
	for (size_t i = 0; i < d->run.n; i++) {
		const struct arcana_builder_builder_run *r = &d->run.v[i];

		e = ucl_object_typed_new(UCL_OBJECT);
		put(e, "id", ucl_object_fromint(r->id));
		put_str(e, "title", r->title);
		put(e, "started", ucl_object_fromint(epoch_of(r->started)));
		put(e, "argv", strs_of(r->argv.v, r->argv.n));
		if (r->has_state && (size_t)r->state < nitems(states))
			put_str(e, "state", states[r->state]);
		PUT_NUM(e, "pid", r, pid);
		PUT_NUM(e, "exit", r, exit);
		put_str(e, "log_file", r->log_file);
		put_str(e, "log", r->log);
		ucl_array_append(arr, e);
	}
	put(top, "runs", arr);
	return (top);
}

int
yr_builder(cbl_conn *conn, ucl_object_t **data, char *err, size_t errlen)
{
	struct arcana_builder	 d;
	const struct cbl_ynode	*n;
	cbl_yarena		*a;
	int			 error;

	*data = NULL;
	err[0] = '\0';
	if ((n = yq_top("arcana-builder", "builder")) == NULL) {
		snprintf(err, errlen, "arcana-builder has no builder");
		return (ENOENT);
	}
	if ((a = cbl_yarena_new()) == NULL)
		return (ENOMEM);
	memset(&d, 0, sizeof(d));
	if ((error = yq_get(conn, n, CBL_YDS_OPERATIONAL, &d, a, err,
	    errlen)) == 0) {
		if (d.builder == NULL) {
			snprintf(err, errlen, "poudriere was not read");
			error = EIO;
		} else
			*data = builder_json(d.builder);
	}
	cbl_yarena_free(a);
	return (error);
}

int
yr_port_options(cbl_conn *conn, const char *const *words, size_t n,
    ucl_object_t **data, char *err, size_t errlen)
{
	struct arcana_builder_builder_port_options_input	 in;
	struct arcana_builder_builder_port_options_output	 out;
	const struct cbl_ynode					*b, *act;
	ucl_object_t						*top, *arr;
	ucl_object_t						*s, *o;
	cbl_yarena						*a;
	const char						*eq;
	int							 error;

	*data = NULL;
	err[0] = '\0';
	if ((act = action_of("arcana-builder", "builder", "port-options", &b,
	    err, errlen)) == NULL)
		return (ENOENT);
	/* The words as the builder-options operation took them. */
	memset(&in, 0, sizeof(in));
	for (size_t i = 0; i < n; i++) {
		if ((eq = strchr(words[i], '=')) == NULL) {
			snprintf(err, errlen, "a port's options are asked with "
			    "jail, ports, set and origin");
			return (EINVAL);
		}
		if (strncmp(words[i], "jail=", 5) == 0)
			in.jail = eq + 1;
		else if (strncmp(words[i], "ports=", 6) == 0)
			in.ports = eq + 1;
		else if (strncmp(words[i], "set=", 4) == 0)
			in.set = eq[1] != '\0' ? eq + 1 : NULL;
		else if (strncmp(words[i], "origin=", 7) == 0)
			in.origin = eq + 1;
		else {
			snprintf(err, errlen, "%.*s: a port's options are asked "
			    "with jail, ports, set and origin", (int)(eq -
			    words[i]), words[i]);
			return (EINVAL);
		}
	}
	if (in.jail == NULL || in.origin == NULL) {
		snprintf(err, errlen, "a port's options need jail= and origin=");
		return (EINVAL);
	}
	if (in.ports == NULL || in.ports[0] == '\0')
		in.ports = "default";
	if ((a = cbl_yarena_new()) == NULL)
		return (ENOMEM);
	memset(&out, 0, sizeof(out));
	if ((error = yq_call(conn, b, NULL, act, &in, &out, a, err,
	    errlen)) == 0) {
		/* As do_builder_options() put them. */
		top = ucl_object_typed_new(UCL_OBJECT);
		put_str(top, "jail", in.jail);
		put_str(top, "ports", in.ports);
		put_str(top, "set", in.set != NULL ? in.set : "");
		put_str(top, "origin", in.origin);
		put_str(top, "pkgname", out.pkgname);
		put_str(top, "options_dir", out.options_dir);
		put_bool(top, "options_dir_exists", out.has_options_dir_exists &&
		    out.options_dir_exists);
		put_str(top, "options_file", out.options_file);
		put_bool(top, "configured", out.has_configured &&
		    out.configured);
		arr = ucl_object_typed_new(UCL_ARRAY);
		for (size_t i = 0; i < out.section.n; i++) {
			s = ucl_object_typed_new(UCL_OBJECT);
			put_str(s, "title", out.section.v[i].title != NULL ?
			    out.section.v[i].title : "");
			o = ucl_object_typed_new(UCL_ARRAY);
			for (size_t k = 0; k < out.section.v[i].option.n; k++) {
				const struct
				    arcana_builder_builder_port_options_output_section_option
				    *op = &out.section.v[i].option.v[k];
				ucl_object_t	*e;

				e = ucl_object_typed_new(UCL_OBJECT);
				put_str(e, "name", op->name);
				put_bool(e, "on", op->has_on && op->on);
				put_str(e, "description", op->description != NULL ?
				    op->description : "");
				ucl_array_append(o, e);
			}
			put(s, "options", o);
			ucl_array_append(arr, s);
		}
		put(top, "sections", arr);
		*data = top;
	}
	cbl_yarena_free(a);
	return (error);
}

/* ---- notify ---------------------------------------------------------- */

int
yr_notify(cbl_conn *conn, const char *token, const char *chat,
    const char *text, char *err, size_t errlen)
{
	struct arcana_notify_notify_input	 in;
	const struct cbl_ynode			*rpc;
	cbl_yarena				*a;
	int					 error;

	err[0] = '\0';
	if ((rpc = yq_top("arcana-notify", "notify")) == NULL) {
		snprintf(err, errlen, "arcana-notify has no notify");
		return (ENOENT);
	}
	memset(&in, 0, sizeof(in));
	in.token = token;
	in.chat = chat;
	in.text = text;
	if ((a = cbl_yarena_new()) == NULL)
		return (ENOMEM);
	error = yq_call(conn, NULL, NULL, rpc, &in, NULL, a, err, errlen);
	cbl_yarena_free(a);
	return (error);
}

/* ---- The reads made of their JSON's keys (yflat.c) ------------------- */

/* Action act's output in out as the read's JSON, by names. */
static ucl_object_t *
flat_out(const struct cbl_ynode *act, const void *out,
    const char *const *names)
{
	const struct cbl_ynode	*o = NULL;

	for (uint32_t i = 0; i < act->nchild; i++)
		if (act->child[i]->kind == CBL_YN_OUTPUT)
			o = act->child[i];
	return (o != NULL ? yflat_out(o, out, names) : NULL);
}

/* Action name of mod's container top called with in, its output as
 * the JSON, *data. */
static int
flat_call(cbl_conn *conn, const char *mod, const char *top, const char *name,
    const void *in, size_t outsize, const char *const *names,
    ucl_object_t **data, char *err, size_t errlen)
{
	const struct cbl_ynode	*n, *act;
	cbl_yarena		*a;
	void			*out;
	int			 error;

	*data = NULL;
	err[0] = '\0';
	if ((act = action_of(mod, top, name, &n, err, errlen)) == NULL)
		return (ENOENT);
	if ((a = cbl_yarena_new()) == NULL)
		return (ENOMEM);
	if ((out = cbl_yarena_alloc(a, outsize)) == NULL) {
		cbl_yarena_free(a);
		return (ENOMEM);
	}
	memset(out, 0, outsize);
	if ((error = yq_call(conn, n, NULL, act, in, out, a, err,
	    errlen)) == 0 && (*data = flat_out(act, out, names)) == NULL)
		error = ENOMEM;
	cbl_yarena_free(a);
	return (error);
}

/* A JSON text parsed; NULL: it is none. */
static ucl_object_t *
parsed(const char *text)
{
	struct ucl_parser	*p;
	ucl_object_t		*o;

	if (text == NULL)
		return (NULL);
	p = ucl_parser_new(UCL_PARSER_NO_IMPLICIT_ARRAYS |
	    UCL_PARSER_DISABLE_MACRO | UCL_PARSER_NO_TIME);
	o = ucl_parser_add_string(p, text, 0) ? ucl_parser_get_object(p) : NULL;
	ucl_parser_free(p);
	return (o);
}

int
yr_crashes(cbl_conn *conn, const char *const *words, size_t n,
    ucl_object_t **data, char *err, size_t errlen)
{
	struct arcana_crashes_crashes_read_input	in;

	memset(&in, 0, sizeof(in));
	if (n > 0) {
		if (strcmp(words[0], "backtrace") != 0 || n < 2 || n > 3) {
			*data = NULL;
			snprintf(err, errlen, "crashes takes backtrace, a core and "
			    "its program");
			return (EINVAL);
		}
		in.backtrace = words[1];
		in.program = n > 2 ? words[2] : NULL;
	}
	return (flat_call(conn, "arcana-crashes", "crashes", "read", &in,
	    sizeof(struct arcana_crashes_crashes_read_output), yfn_crashes,
	    data, err, errlen));
}

int
yr_system(cbl_conn *conn, const char *const *words, size_t n,
    ucl_object_t **data, char *err, size_t errlen)
{
	struct arcana_system_system_read_input	in;

	memset(&in, 0, sizeof(in));
	in.name.v = words;
	in.name.n = n;
	return (flat_call(conn, "arcana-system", "system", "read", &in,
	    sizeof(struct arcana_system_system_read_output), yfn_system, data,
	    err, errlen));
}

int
yr_netstore(cbl_conn *conn, const char *const *words, size_t n,
    ucl_object_t **data, char *err, size_t errlen)
{
	static const char *const services[] = { "nfs", "iscsi", "hast" };
	struct arcana_netstore_netstore_read_input	 in;
	enum arcana_netstore_netstore_read_input_name	 v[3];
	size_t						 i, k;

	*data = NULL;
	if (n > nitems(v)) {
		snprintf(err, errlen, "netstore reads nfs, iscsi and hast");
		return (EINVAL);
	}
	for (i = 0; i < n; i++) {
		for (k = 0; k < nitems(services) && strcmp(words[i],
		    services[k]) != 0; k++)
			;
		if (k == nitems(services)) {
			snprintf(err, errlen, "netstore reads nfs, iscsi and "
			    "hast, or all of them");
			return (EINVAL);
		}
		v[i] = (enum arcana_netstore_netstore_read_input_name)k;
	}
	memset(&in, 0, sizeof(in));
	in.name.v = v;
	in.name.n = n;
	return (flat_call(conn, "arcana-netstore", "netstore", "read", &in,
	    sizeof(struct arcana_netstore_netstore_read_output), yfn_netstore,
	    data, err, errlen));
}

/* The word key= of words, its value; NULL: none. */
static const char *
word_of(const char *const *words, size_t n, const char *key)
{
	size_t	len;

	len = strlen(key);
	for (size_t i = 0; i < n; i++)
		if (strncmp(words[i], key, len) == 0 && words[i][len] == '=')
			return (words[i] + len + 1);
	return (NULL);
}

/* A number of a word, from lo to hi; false: it is none. */
static bool
word_num(const char *s, unsigned long lo, unsigned long hi,
    unsigned long *v)
{
	char	*end;

	if (s == NULL || *s == '\0')
		return (false);
	*v = strtoul(s, &end, 10);
	return (*end == '\0' && *v >= lo && *v <= hi);
}

int
yr_suricata(cbl_conn *conn, const char *const *words, size_t n,
    ucl_object_t **data, char **raw, char *err, size_t errlen)
{
	static const char *const keys[] = { "q", "sid", "only", "classtype",
	    "offset", "limit", "sources", "instance", "command", "iface",
	    "profiling" };
	static const char *const commands[] = { "uptime", "version",
	    "running-mode", "capture-mode", "memcap-list", "ruleset-stats",
	    "ruleset-failed-rules", "ruleset-profile", "iface-list",
	    "iface-stat", "dump-counters" };
	static const char *const onlies[] = { "enabled", "disabled",
	    "changed" };
	static const char *const dirs[] = { "running", "replay" };
	const char	*s, *inst, *cmd;
	unsigned long	 v;
	size_t		 i, k;
	int		 error;

	*data = NULL;
	if (raw != NULL)
		*raw = NULL;
	err[0] = '\0';
	for (i = 0; i < n; i++) {
		for (k = 0; k < nitems(keys); k++)
			if (strncmp(words[i], keys[k], strlen(keys[k])) == 0 &&
			    words[i][strlen(keys[k])] == '=')
				break;
		if (k == nitems(keys)) {
			snprintf(err, errlen, "the rules are searched by q=, "
			    "sid=, only=, classtype=, offset= and limit=; "
			    "sources=1 says the rule sources");
			return (EINVAL);
		}
	}
	inst = word_of(words, n, "instance");
	cmd = word_of(words, n, "command");
	/* instance= profiling=1: what its profiling wrote. */
	if (word_of(words, n, "profiling") != NULL) {
		struct arcana_suricata_suricata_read_profiling_input pin;

		if (inst == NULL) {
			snprintf(err, errlen, "profiling is read by instance= "
			    "and profiling=1");
			return (EINVAL);
		}
		memset(&pin, 0, sizeof(pin));
		pin.instance = inst;
		if ((error = flat_call(conn, "arcana-suricata", "suricata",
		    "read-profiling", &pin, sizeof(struct
		    arcana_suricata_suricata_read_profiling_output),
		    yfn_suricata, data, err, errlen)) != 0)
			return (error);
		/* rule_perf.log's dump, Suricata's JSON, with its time. */
		for (i = 0; i < nitems(dirs); i++) {
			ucl_object_t	*d, *r, *doc, *at;

			if ((d = (ucl_object_t *)(uintptr_t)ucl_object_lookup(
			    *data, dirs[i])) == NULL || (r = ucl_object_pop_key(d,
			    "rules")) == NULL)
				continue;
			if ((doc = parsed(ucl_object_tostring(ucl_object_lookup(
			    r, "document")))) != NULL) {
				if ((at = ucl_object_pop_key(r, "at")) != NULL)
					ucl_object_insert_key(doc, at, "at", 0,
					    false);
				ucl_object_insert_key(d, doc, "rules", 0, false);
			}
			ucl_object_unref(r);
		}
		return (0);
	}
	/* instance= command=: Suricata's own answer, as it is. */
	if (inst != NULL || cmd != NULL) {
		struct arcana_suricata_suricata_command_input	 cin;
		ucl_object_t					*o;

		memset(&cin, 0, sizeof(cin));
		for (k = 0; cmd != NULL && k < nitems(commands) && strcmp(cmd,
		    commands[k]) != 0; k++)
			;
		if (inst == NULL || cmd == NULL) {
			snprintf(err, errlen, "Suricata is asked by instance= "
			    "and command=");
			return (EINVAL);
		}
		if (k == nitems(commands)) {
			snprintf(err, errlen, "a command is one that reads: "
			    "uptime, version, running-mode, capture-mode, "
			    "memcap-list, ruleset-stats, ruleset-failed-rules, "
			    "ruleset-profile, iface-list, iface-stat or "
			    "dump-counters");
			return (EINVAL);
		}
		cin.instance = inst;
		cin.has_command = true;
		cin.command = (enum arcana_suricata_suricata_command_input_command)
		    k;
		cin.iface = word_of(words, n, "iface");
		if ((cin.iface != NULL) != (strcmp(cmd, "iface-stat") == 0)) {
			snprintf(err, errlen, "iface-stat, and it alone, names "
			    "an iface=");
			return (EINVAL);
		}
		if ((error = flat_call(conn, "arcana-suricata", "suricata",
		    "command", &cin, sizeof(struct
		    arcana_suricata_suricata_command_output), NULL, &o, err,
		    errlen)) != 0)
			return (error);
		s = ucl_object_tostring(ucl_object_lookup(o, "answer"));
		if (raw != NULL && s != NULL)
			*raw = strdup(s);
		*data = parsed(s);
		ucl_object_unref(o);
		if (*data == NULL) {
			snprintf(err, errlen, "Suricata's answer is no JSON");
			return (EIO);
		}
		return (0);
	}
	/* sources=1: the rule sources, not the rules. */
	if (word_of(words, n, "sources") != NULL)
		return (flat_call(conn, "arcana-suricata", "suricata",
		    "read-sources", NULL, sizeof(struct
		    arcana_suricata_suricata_read_sources_output), yfn_suricata,
		    data, err, errlen));
	{
		struct arcana_suricata_suricata_read_rules_input rin;

		memset(&rin, 0, sizeof(rin));
		rin.q = word_of(words, n, "q");
		rin.classtype = word_of(words, n, "classtype");
		if ((s = word_of(words, n, "only")) != NULL) {
			for (k = 0; k < nitems(onlies) && strcmp(s, onlies[k]) !=
			    0; k++)
				;
			if (k == nitems(onlies)) {
				snprintf(err, errlen, "only is enabled, disabled "
				    "or changed");
				return (EINVAL);
			}
			rin.has_only = true;
			rin.only = (enum
			    arcana_suricata_suricata_read_rules_input_only)k;
		}
		if (((s = word_of(words, n, "sid")) != NULL && !word_num(s, 1,
		    UINT32_MAX, &v)) || ((s = word_of(words, n, "offset")) !=
		    NULL && !word_num(s, 0, 1000000, &v)) || ((s = word_of(words,
		    n, "limit")) != NULL && !word_num(s, 1, 500, &v))) {
			snprintf(err, errlen, "sid is a number, offset a number "
			    "and limit 1 to 500");
			return (EINVAL);
		}
		if (word_num(word_of(words, n, "sid"), 1, UINT32_MAX, &v)) {
			rin.has_sid = true;
			rin.sid = (uint32_t)v;
		}
		if (word_num(word_of(words, n, "offset"), 0, 1000000, &v)) {
			rin.has_offset = true;
			rin.offset = (uint32_t)v;
		}
		if (word_num(word_of(words, n, "limit"), 1, 500, &v)) {
			rin.has_limit = true;
			rin.limit = (uint16_t)v;
		}
		return (flat_call(conn, "arcana-suricata", "suricata",
		    "read-rules", &rin, sizeof(struct
		    arcana_suricata_suricata_read_rules_output), yfn_suricata,
		    data, err, errlen));
	}
}

int
yr_smtpd(cbl_conn *conn, const char *jail, ucl_object_t **data, char *err,
    size_t errlen)
{
	struct arcana_smtpd_smtpd_read_input	 in;
	ucl_object_t				*tabs, *nt, *spec;
	const ucl_object_t			*e, *v;
	ucl_object_iter_t			 it;
	int					 error;

	memset(&in, 0, sizeof(in));
	in.jail = jail != NULL && jail[0] != '\0' ? jail : NULL;
	if ((error = flat_call(conn, "arcana-smtpd", "smtpd", "read", &in,
	    sizeof(struct arcana_smtpd_smtpd_read_output), yfn_smtpd, data,
	    err, errlen)) != 0)
		return (error);
	/* The form, the console's JSON; a table its text, or the names of
	 * a secret one, as smtpd.c put them. */
	if ((spec = ucl_object_pop_key(*data, "spec")) != NULL) {
		if ((v = parsed(ucl_object_tostring(spec))) != NULL)
			ucl_object_insert_key(*data, (ucl_object_t *)(uintptr_t)v,
			    "spec", 0, false);
		ucl_object_unref(spec);
	}
	if ((tabs = ucl_object_pop_key(*data, "tables")) != NULL) {
		nt = ucl_object_typed_new(UCL_OBJECT);
		it = NULL;
		while ((e = ucl_object_iterate(tabs, &it, true)) != NULL) {
			if ((v = ucl_object_lookup(e, "text")) == NULL &&
			    (v = ucl_object_lookup(e, "user")) == NULL)
				v = ucl_object_typed_new(UCL_ARRAY);
			else
				v = ucl_object_copy(v);
			ucl_object_insert_key(nt, (ucl_object_t *)(uintptr_t)v,
			    ucl_object_key(e), 0, true);
		}
		ucl_object_unref(tabs);
		ucl_object_insert_key(*data, nt, "tables", 0, false);
	}
	return (0);
}

int
yr_speeder(cbl_conn *conn, const char *jail, ucl_object_t **data, char *err,
    size_t errlen)
{
	struct arcana_speeder_speeder_read_input	in;

	memset(&in, 0, sizeof(in));
	in.jail = jail != NULL && jail[0] != '\0' ? jail : NULL;
	return (flat_call(conn, "arcana-speeder", "speeder", "read", &in,
	    sizeof(struct arcana_speeder_speeder_read_output), yfn_speeder,
	    data, err, errlen));
}
