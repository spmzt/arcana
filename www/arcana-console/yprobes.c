/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * An SD-WAN edge's probes through arcana-probe (PLAN-SDN-YANG 3.1.11),
 * for the console and arcanactl: what the console's apply made for the
 * sdwan-probes operation (sdwan_edge.c), the targets and the links an
 * edge watches, put in the candidate as the module has them, running's
 * probes with that edge's lists in place of its own, by an EDIT of
 * RFC 7951's JSON (yjsonin.c).  The caller commits.
 */

#include <sys/param.h>

#include <ctype.h>
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <cblink.h>
#include <cbl_schema.h>
#include <ucl.h>

#include "ymodel.h"
#include "yqueue.h"
#include "yjsonin.h"
#include "yprobes.h"

/* Integers a target may have, as arcana-probe names them. */
static const char *const ints[] = { "fib", "interval", "size", "count",
    "dscp", "down", "up", "timeout", "eval", "history", "report" };

/* A jail's name as the agent takes one: letters, digits and _ . -. */
static bool
jail_ok(const char *s)
{

	if (s[0] == '\0' || s[0] == '.' || s[0] == '-' || strstr(s, "..") !=
	    NULL || strlen(s) > 63)
		return (false);
	for (; *s != '\0'; s++)
		if (!isalnum((unsigned char)*s) && strchr("_.-", *s) == NULL)
			return (false);
	return (true);
}

/* A decimal64 of d fraction digits as RFC 7951 has it: a string. */
static void
put_dec(ucl_object_t *o, const ucl_object_t *from, const char *key, int d)
{
	const ucl_object_t	*v;
	char			 buf[32];

	if ((v = ucl_object_lookup(from, key)) == NULL)
		return;
	snprintf(buf, sizeof(buf), "%.*f", d, ucl_object_todouble(v));
	ucl_object_insert_key(o, ucl_object_fromstring(buf), key, 0, true);
}

/* A target as the operation had it, as arcana-probe's. */
static ucl_object_t *
target_of(const ucl_object_t *t)
{
	const ucl_object_t	*v, *c;
	ucl_object_t		*o, *tca;

	o = ucl_object_typed_new(UCL_OBJECT);
	if ((v = ucl_object_lookup(t, "id")) != NULL)
		ucl_object_insert_key(o, ucl_object_copy(v), "id", 0, true);
	if ((v = ucl_object_lookup(t, "address")) != NULL)
		ucl_object_insert_key(o, ucl_object_copy(v), "address", 0, true);
	for (size_t i = 0; i < nitems(ints); i++)
		if ((v = ucl_object_lookup(t, ints[i])) != NULL)
			ucl_object_insert_key(o, ucl_object_copy(v), ints[i], 0,
			    true);
	if ((c = ucl_object_lookup(t, "tca")) != NULL) {
		tca = ucl_object_typed_new(UCL_OBJECT);
		put_dec(tca, c, "delay", 3);
		put_dec(tca, c, "ipdv", 3);
		put_dec(tca, c, "loss", 6);
		if ((v = ucl_object_lookup(c, "damping")) != NULL)
			ucl_object_insert_key(tca, ucl_object_copy(v),
			    "damping", 0, true);
		ucl_object_insert_key(o, tca, "tca", 0, true);
	}
	return (o);
}

/* The lists of an edge's object e as the operation's json says them. */
static void
edge_put(ucl_object_t *e, const ucl_object_t *targets,
    const ucl_object_t *links)
{
	const ucl_object_t	*v, *w;
	ucl_object_iter_t	 it;
	ucl_object_t		*arr, *o;

	ucl_object_delete_key(e, "target");
	ucl_object_delete_key(e, "link");
	if (ucl_array_size(targets) > 0) {
		arr = ucl_object_typed_new(UCL_ARRAY);
		it = NULL;
		while ((v = ucl_object_iterate(targets, &it, true)) != NULL)
			ucl_array_append(arr, target_of(v));
		ucl_object_insert_key(e, arr, "target", 0, true);
	}
	if (ucl_array_size(links) > 0) {
		arr = ucl_object_typed_new(UCL_ARRAY);
		it = NULL;
		while ((v = ucl_object_iterate(links, &it, true)) != NULL) {
			o = ucl_object_typed_new(UCL_OBJECT);
			if ((w = ucl_object_lookup(v, "id")) != NULL)
				ucl_object_insert_key(o, ucl_object_copy(w),
				    "id", 0, true);
			if ((w = ucl_object_lookup(v, "interface")) != NULL)
				ucl_object_insert_key(o, ucl_object_copy(w),
				    "interface", 0, true);
			w = ucl_object_lookup(v, "role");
			ucl_object_insert_key(o, ucl_object_fromstring(w != NULL &&
			    ucl_object_type(w) == UCL_STRING && strcmp(
			    ucl_object_tostring(w), "uni") == 0 ? "uni" : "ucs"),
			    "role", 0, true);
			ucl_array_append(arr, o);
		}
		ucl_object_insert_key(e, arr, "link", 0, true);
	}
}

/* arcana-probe's probes as running has them, RFC 7951's JSON. */
static ucl_object_t *
running(cbl_conn *conn, const struct cbl_ynode *n, char *err, size_t errlen,
    int *errorp)
{
	struct cbl_ybuf		 b = { NULL, 0, 0 };
	struct ucl_parser	*p;
	struct arcana_probe	 d;
	ucl_object_t		*top, *v;
	cbl_yarena		*a;
	cbl_msg			*req, *rep = NULL;
	char			*text;
	bool			 first = true;
	int			 error;

	if ((error = cbl_msg_new(cbl_conn_ctx(conn), CBL_YANG_FAMILY,
	    CBL_YCMD_GET, 0, &req)) != 0 || (error = cbl_msg_put_yget(req,
	    &n->sid, 1)) != 0 || (error = cbl_msg_set_datastore(req,
	    CBL_YDS_RUNNING)) != 0) {
		snprintf(err, errlen, "%s", strerror(error));
		*errorp = error;
		return (NULL);
	}
	if ((error = cbl_request(conn, req, &rep, -1)) != 0) {
		snprintf(err, errlen, "%s", rep != NULL && cbl_msg_err_str(rep) !=
		    NULL ? cbl_msg_err_str(rep) : strerror(error));
		cbl_msg_free(rep);
		*errorp = error;
		return (NULL);
	}
	if ((a = cbl_yarena_new()) == NULL)
		error = ENOMEM;
	else {
		memset(&d, 0, sizeof(d));
		if ((error = cbl_msg_ydecode_member(rep, n, &d, a, 0, err,
		    errlen)) == ENOENT)
			error = 0;
		if (error == 0)
			error = cbl_yjson_members(n->module, &d, &b, &first);
	}
	cbl_yarena_free(a);
	cbl_msg_free(rep);
	if (error != 0) {
		cbl_ybuf_free(&b);
		*errorp = error;
		return (NULL);
	}
	/* The members, an object's. */
	if (asprintf(&text, "{%.*s}", (int)b.len, b.p != NULL ? (const char *)
	    b.p : "") == -1) {
		cbl_ybuf_free(&b);
		*errorp = ENOMEM;
		return (NULL);
	}
	cbl_ybuf_free(&b);
	p = ucl_parser_new(UCL_PARSER_NO_IMPLICIT_ARRAYS |
	    UCL_PARSER_DISABLE_MACRO | UCL_PARSER_NO_TIME);
	top = ucl_parser_add_string(p, text, 0) ? ucl_parser_get_object(p) :
	    NULL;
	ucl_parser_free(p);
	free(text);
	/* None yet: an empty one. */
	if (top == NULL || (v = (ucl_object_t *)(uintptr_t)ucl_object_lookup(
	    top, "arcana-probe:probes")) == NULL) {
		if (top != NULL)
			ucl_object_unref(top);
		return (ucl_object_typed_new(UCL_OBJECT));
	}
	v = ucl_object_ref(v);
	ucl_object_unref(top);
	return (v);
}

int
yprobes_edit(cbl_conn *conn, const char *json, char *err, size_t errlen,
    uint64_t *errsid, char *tag, size_t taglen)
{
	const struct cbl_ynode	*n;
	struct ucl_parser	*p;
	ucl_object_t		*in, *probes, *jails, *e, *keep;
	const ucl_object_t	*v, *w, *targets, *links;
	ucl_object_iter_t	 it;
	const char		*jail;
	int			 error = 0;

	err[0] = tag[0] = '\0';
	*errsid = 0;
	if ((n = yq_top("arcana-probe", "probes")) == NULL) {
		snprintf(err, errlen, "arcana-probe is not in the tables");
		return (ENOENT);
	}
	p = ucl_parser_new(UCL_PARSER_NO_IMPLICIT_ARRAYS |
	    UCL_PARSER_DISABLE_MACRO | UCL_PARSER_NO_TIME);
	in = ucl_parser_add_string(p, json, 0) ? ucl_parser_get_object(p) :
	    NULL;
	ucl_parser_free(p);
	jail = NULL;
	targets = in;
	links = NULL;
	if (in != NULL && ucl_object_type(in) == UCL_OBJECT) {
		if ((v = ucl_object_lookup(in, "jail")) != NULL)
			jail = ucl_object_tostring(v);
		targets = ucl_object_lookup(in, "targets");
		links = ucl_object_lookup(in, "links");
	}
	if (in == NULL || targets == NULL || ucl_object_type(targets) !=
	    UCL_ARRAY || (links != NULL && ucl_object_type(links) !=
	    UCL_ARRAY)) {
		if (in != NULL)
			ucl_object_unref(in);
		snprintf(err, errlen, "the targets are a JSON array, or an "
		    "object with them as targets (and links, jail)");
		return (EINVAL);
	}
	if (jail != NULL && !jail_ok(jail)) {
		ucl_object_unref(in);
		snprintf(err, errlen, "invalid jail name");
		return (EINVAL);
	}
	if ((probes = running(conn, n, err, errlen, &error)) == NULL) {
		ucl_object_unref(in);
		return (error);
	}
	if (jail == NULL)
		edge_put(probes, targets, links);
	else {
		/* The jail's entry, made where it is none; gone when empty. */
		keep = ucl_object_typed_new(UCL_ARRAY);
		e = NULL;
		it = NULL;
		while ((v = ucl_object_iterate(ucl_object_lookup(probes,
		    "jail"), &it, true)) != NULL) {
			if (e == NULL && (w = ucl_object_lookup(v, "name")) !=
			    NULL && strcmp(ucl_object_tostring(w), jail) == 0)
				e = ucl_object_copy(v);
			else
				ucl_array_append(keep, ucl_object_copy(v));
		}
		if (e == NULL) {
			e = ucl_object_typed_new(UCL_OBJECT);
			ucl_object_insert_key(e, ucl_object_fromstring(jail),
			    "name", 0, true);
		}
		edge_put(e, targets, links);
		if (ucl_object_lookup(e, "target") != NULL || ucl_object_lookup(e,
		    "link") != NULL || ucl_object_lookup(e, "monitor") != NULL)
			ucl_array_append(keep, e);
		else
			ucl_object_unref(e);
		ucl_object_delete_key(probes, "jail");
		jails = keep;
		if (ucl_array_size(jails) > 0)
			ucl_object_insert_key(probes, jails, "jail", 0, true);
		else
			ucl_object_unref(jails);
	}
	error = yjson_edit(conn, n, probes, CBL_YDS_CANDIDATE, NULL, 0, err,
	    errlen, errsid, tag, taglen);
	ucl_object_unref(probes);
	ucl_object_unref(in);
	return (error);
}
