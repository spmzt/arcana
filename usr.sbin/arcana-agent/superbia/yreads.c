/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Superbia: the host's daemons and files read through their modules
 * (PLAN-SDN-YANG 3.8): arcana-crashes, arcana-system, arcana-netstore,
 * arcana-suricata, arcana-smtpd and arcana-speeder, each an action that
 * runs the read the operation of arcana.yaml ran (crashes.c,
 * sysfiles.c, netstore.c, surules.c, idsfiles.c, smtpd.c, speeder.c)
 * and gives its JSON as the module's output, by yflat.c and the names
 * of yflatnames.h.  Their containers hold no state: an empty GET.
 */

#include <sys/param.h>

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <arcana.h>

#include "agent.h"
#include "collect.h"
#include "yflat.h"
#include "yflatnames.h"
#include "yjson.h"

/* What an action failed of, said for the request: cblink's error. */
static int
said(cbl_req *req, const char *why)
{

	(void)cbl_req_set_yerr(req, why != NULL ? why : "it failed", 0);
	return (EIO);
}

/* A jail, with or without a network of its own (NULL or "": the
 * host): the work in its scope.  0, or the error said. */
static int
jail_in(cbl_req *req, const char *jail, struct work *w)
{
	const char	*e;

	if (jail == NULL || jail[0] == '\0')
		return (0);
	if (!valid_jail(jail))
		return (said(req, "invalid jail name"));
	e = NULL;
	if (scope_enter_jail(w, jail, &e, false) != 0)
		return (said(req, e));
	return (0);
}

/* top, the read's JSON, into out, path's struct in module mod. */
static int
flat_in(const char *mod, const char *path, const ucl_object_t *top,
    void *out, cbl_yarena *a, const char *const *names)
{
	const struct cbl_ynode	*n;

	if ((n = yflat_find(&ymodel_schema, mod, path)) == NULL)
		return (ENOENT);
	return (yflat_in(n, top, out, a, names));
}

/* The read r ended as told; its JSON into out. */
static int
answer(cbl_req *req, struct work *w, int root, const struct json_rsp *r,
    const char *mod, const char *path, void *out, cbl_yarena *a,
    const char *const *names)
{
	ucl_object_t	*top;
	int		 error;

	step_end(w, root, r->ok, NULL);
	if (!r->ok)
		return (said(req, r->error));
	if ((top = yj_parse(r->json)) == NULL)
		return (EIO);
	error = flat_in(mod, path, top, out, a, names);
	ucl_object_unref(top);
	return (error);
}

/* An object of o's key put back as JSON's text, under key to. */
static void
as_text(ucl_object_t *o, const char *key, const char *to)
{
	const ucl_object_t	*v;
	unsigned char		*t;

	if ((v = ucl_object_lookup(o, key)) == NULL || (t = ucl_object_emit(v,
	    UCL_EMIT_JSON_COMPACT)) == NULL)
		return;
	(void)ucl_object_delete_key(o, key);
	ucl_object_insert_key(o, ucl_object_fromstring((char *)t), to, 0, true);
	free(t);
}

int
arcana_crashes_crashes_get(cbl_req *req, struct arcana_crashes *data,
    cbl_yarena *a)
{

	(void)req;
	(void)data;
	(void)a;
	return (0);
}

int
arcana_crashes_crashes_read_action(cbl_req *req, const struct cbl_bytes *target,
    const struct arcana_crashes_crashes_read_input *in,
    struct arcana_crashes_crashes_read_output *out, cbl_yarena *a)
{
	struct json_rsp	 r;
	struct work	*w;
	const char	*names[3];
	size_t		 n;
	int		 root;

	(void)target;
	if ((w = ywork_told(req, a, "the cores dumped", &root)) == NULL)
		return (ENOMEM);
	n = 0;
	if (in->backtrace != NULL) {
		names[n++] = "backtrace";
		names[n++] = in->backtrace;
		if (in->program != NULL)
			names[n++] = in->program;
	}
	memset(&r, 0, sizeof(r));
	do_crashes(w, names, n, &r);
	return (answer(req, w, root, &r, "arcana-crashes",
	    "crashes/read/output", out, a, yfn_crashes));
}

int
arcana_system_system_get(cbl_req *req, struct arcana_system *data,
    cbl_yarena *a)
{

	(void)req;
	(void)data;
	(void)a;
	return (0);
}

int
arcana_system_system_read_action(cbl_req *req, const struct cbl_bytes *target,
    const struct arcana_system_system_read_input *in,
    struct arcana_system_system_read_output *out, cbl_yarena *a)
{
	struct json_rsp	 r;
	struct work	*w;
	int		 root;

	(void)target;
	if (in->name.n > 16)
		return (said(req, "system reads its files by name, and host"));
	if ((w = ywork_told(req, a, "the system's files read", &root)) ==
	    NULL)
		return (ENOMEM);
	memset(&r, 0, sizeof(r));
	do_system(w, in->name.v, in->name.n, &r);
	return (answer(req, w, root, &r, "arcana-system", "system/read/output",
	    out, a, yfn_system));
}

int
arcana_netstore_netstore_get(cbl_req *req, struct arcana_netstore *data,
    cbl_yarena *a)
{

	(void)req;
	(void)data;
	(void)a;
	return (0);
}

int
arcana_netstore_netstore_read_action(cbl_req *req,
    const struct cbl_bytes *target,
    const struct arcana_netstore_netstore_read_input *in,
    struct arcana_netstore_netstore_read_output *out, cbl_yarena *a)
{
	static const char *const services[] = { "nfs", "iscsi", "hast" };
	struct json_rsp	 r;
	struct work	*w;
	const char	*names[3];
	size_t		 n;
	int		 root;

	(void)target;
	if (in->name.n > nitems(names))
		return (said(req, "netstore reads nfs, iscsi and hast"));
	for (n = 0; n < in->name.n; n++) {
		if ((size_t)in->name.v[n] >= nitems(services))
			return (said(req, "netstore reads nfs, iscsi and hast"));
		names[n] = services[in->name.v[n]];
	}
	if ((w = ywork_told(req, a, "the storage services read", &root)) ==
	    NULL)
		return (ENOMEM);
	memset(&r, 0, sizeof(r));
	do_netstore(w, names, n, &r);
	return (answer(req, w, root, &r, "arcana-netstore",
	    "netstore/read/output", out, a, yfn_netstore));
}

int
arcana_suricata_suricata_get(cbl_req *req, struct arcana_suricata *data,
    cbl_yarena *a)
{

	(void)req;
	(void)data;
	(void)a;
	return (0);
}

int
arcana_suricata_suricata_read_rules_action(cbl_req *req,
    const struct cbl_bytes *target,
    const struct arcana_suricata_suricata_read_rules_input *in,
    struct arcana_suricata_suricata_read_rules_output *out, cbl_yarena *a)
{
	static const char *const onlies[] = { "enabled", "disabled",
	    "changed" };
	struct json_rsp	 r;
	struct work	*w;
	const char	*names[6];
	size_t		 n;
	int		 root;

	(void)target;
	if ((w = ywork_told(req, a, "Suricata's rules read", &root)) == NULL)
		return (ENOMEM);
	/* The words the suricata-rules operation took. */
	n = 0;
	if (in->q != NULL)
		names[n++] = wfmt(w, "q=%s", in->q);
	if (in->has_sid)
		names[n++] = wfmt(w, "sid=%u", in->sid);
	if (in->has_only && (size_t)in->only < nitems(onlies))
		names[n++] = wfmt(w, "only=%s", onlies[in->only]);
	if (in->classtype != NULL)
		names[n++] = wfmt(w, "classtype=%s", in->classtype);
	if (in->has_offset)
		names[n++] = wfmt(w, "offset=%u", in->offset);
	if (in->has_limit)
		names[n++] = wfmt(w, "limit=%u", (unsigned)in->limit);
	memset(&r, 0, sizeof(r));
	do_suricata_rules(w, names, n, &r);
	return (answer(req, w, root, &r, "arcana-suricata",
	    "suricata/read-rules/output", out, a, yfn_suricata));
}

int
arcana_suricata_suricata_read_sources_action(cbl_req *req,
    const struct cbl_bytes *target,
    const struct arcana_suricata_suricata_read_sources_input *in,
    struct arcana_suricata_suricata_read_sources_output *out, cbl_yarena *a)
{
	static const char *const names[] = { "sources=1" };
	struct json_rsp	 r;
	struct work	*w;
	int		 root;

	(void)target;
	(void)in;
	if ((w = ywork_told(req, a, "Suricata's rule sources read", &root)) ==
	    NULL)
		return (ENOMEM);
	memset(&r, 0, sizeof(r));
	do_suricata_rules(w, names, nitems(names), &r);
	return (answer(req, w, root, &r, "arcana-suricata",
	    "suricata/read-sources/output", out, a, yfn_suricata));
}

int
arcana_suricata_suricata_command_action(cbl_req *req,
    const struct cbl_bytes *target,
    const struct arcana_suricata_suricata_command_input *in,
    struct arcana_suricata_suricata_command_output *out, cbl_yarena *a)
{
	static const char *const commands[] = { "uptime", "version",
	    "running-mode", "capture-mode", "memcap-list", "ruleset-stats",
	    "ruleset-failed-rules", "ruleset-profile", "iface-list",
	    "iface-stat", "dump-counters" };
	struct json_rsp	 r;
	struct work	*w;
	const char	*names[3];
	size_t		 n;
	int		 root;

	(void)target;
	if (in->instance == NULL || !in->has_command || (size_t)in->command >=
	    nitems(commands))
		return (said(req, "Suricata is asked by instance and command"));
	if ((w = ywork_told(req, a, "Suricata's answer", &root)) == NULL)
		return (ENOMEM);
	n = 0;
	names[n++] = wfmt(w, "instance=%s", in->instance);
	names[n++] = wfmt(w, "command=%s", commands[in->command]);
	if (in->iface != NULL)
		names[n++] = wfmt(w, "iface=%s", in->iface);
	memset(&r, 0, sizeof(r));
	do_suricata_rules(w, names, n, &r);
	step_end(w, root, r.ok, NULL);
	if (!r.ok)
		return (said(req, r.error));
	/* Its own JSON, as it wrote it. */
	out->answer = r.json;
	return (0);
}

int
arcana_suricata_suricata_read_profiling_action(cbl_req *req,
    const struct cbl_bytes *target,
    const struct arcana_suricata_suricata_read_profiling_input *in,
    struct arcana_suricata_suricata_read_profiling_output *out,
    cbl_yarena *a)
{
	static const char *const dirs[] = { "running", "replay" };
	struct json_rsp	 r;
	struct work	*w;
	ucl_object_t	*top, *d, *rules, *at, *o;
	unsigned char	*t;
	int		 root, error;

	(void)target;
	if (in->instance == NULL)
		return (said(req, "profiling is read of an instance"));
	if ((w = ywork_told(req, a, "Suricata's profiling read", &root)) ==
	    NULL)
		return (ENOMEM);
	memset(&r, 0, sizeof(r));
	suricata_profiling(w, in->instance, &r);
	step_end(w, root, r.ok, NULL);
	if (!r.ok)
		return (said(req, r.error));
	if ((top = yj_parse(r.json)) == NULL)
		return (EIO);
	/* rule_perf.log's dump is Suricata's JSON: a text beside its time. */
	for (size_t i = 0; i < nitems(dirs); i++) {
		d = (ucl_object_t *)(uintptr_t)ucl_object_lookup(top, dirs[i]);
		if (d == NULL || (rules = ucl_object_pop_key(d, "rules")) ==
		    NULL)
			continue;
		at = ucl_object_pop_key(rules, "at");
		o = ucl_object_typed_new(UCL_OBJECT);
		if ((t = ucl_object_emit(rules, UCL_EMIT_JSON_COMPACT)) != NULL) {
			ucl_object_insert_key(o, ucl_object_fromstring((char *)t),
			    "document", 0, false);
			free(t);
		}
		if (at != NULL)
			ucl_object_insert_key(o, at, "at", 0, false);
		ucl_object_unref(rules);
		ucl_object_insert_key(d, o, "rules", 0, false);
	}
	error = flat_in("arcana-suricata", "suricata/read-profiling/output",
	    top, out, a, yfn_suricata);
	ucl_object_unref(top);
	return (error);
}

int
arcana_smtpd_smtpd_get(cbl_req *req, struct arcana_smtpd *data,
    cbl_yarena *a)
{

	(void)req;
	(void)data;
	(void)a;
	return (0);
}

int
arcana_smtpd_smtpd_read_action(cbl_req *req, const struct cbl_bytes *target,
    const struct arcana_smtpd_smtpd_read_input *in,
    struct arcana_smtpd_smtpd_read_output *out, cbl_yarena *a)
{
	struct json_rsp		 r;
	struct work		*w;
	ucl_object_t		*top, *tabs, *nt, *e;
	const ucl_object_t	*v;
	ucl_object_iter_t	 it;
	int			 root, error;

	(void)target;
	if ((w = ywork_told(req, a, "OpenSMTPD read", &root)) == NULL)
		return (ENOMEM);
	if ((error = jail_in(req, in->jail, w)) != 0) {
		step_end(w, root, false, NULL);
		return (error);
	}
	memset(&r, 0, sizeof(r));
	do_smtpd(w, &r);
	step_end(w, root, r.ok, NULL);
	if (!r.ok)
		return (said(req, r.error));
	if ((top = yj_parse(r.json)) == NULL)
		return (EIO);
	/* The form is the console's JSON, a text; a table its text, or a
	 * secret one its names. */
	as_text(top, "spec", "spec");
	if ((tabs = ucl_object_pop_key(top, "tables")) != NULL) {
		nt = ucl_object_typed_new(UCL_OBJECT);
		it = NULL;
		while ((v = ucl_object_iterate(tabs, &it, true)) != NULL) {
			e = ucl_object_typed_new(UCL_OBJECT);
			ucl_object_insert_key(e, ucl_object_copy(v),
			    ucl_object_type(v) == UCL_ARRAY ? "user" : "text", 0,
			    false);
			ucl_object_insert_key(nt, e, ucl_object_key(v), 0, true);
		}
		ucl_object_unref(tabs);
		ucl_object_insert_key(top, nt, "tables", 0, false);
	}
	error = flat_in("arcana-smtpd", "smtpd/read/output", top, out, a,
	    yfn_smtpd);
	ucl_object_unref(top);
	return (error);
}

int
arcana_speeder_speeder_get(cbl_req *req, struct arcana_speeder *data,
    cbl_yarena *a)
{

	(void)req;
	(void)data;
	(void)a;
	return (0);
}

int
arcana_speeder_speeder_read_action(cbl_req *req,
    const struct cbl_bytes *target,
    const struct arcana_speeder_speeder_read_input *in,
    struct arcana_speeder_speeder_read_output *out, cbl_yarena *a)
{
	struct json_rsp	 r;
	struct work	*w;
	int		 root, error;

	(void)target;
	if ((w = ywork_told(req, a, "UDPspeeder's relay read", &root)) ==
	    NULL)
		return (ENOMEM);
	if ((error = jail_in(req, in->jail, w)) != 0) {
		step_end(w, root, false, NULL);
		return (error);
	}
	memset(&r, 0, sizeof(r));
	do_speeder(w, &r);
	return (answer(req, w, root, &r, "arcana-speeder",
	    "speeder/read/output", out, a, yfn_speeder));
}
