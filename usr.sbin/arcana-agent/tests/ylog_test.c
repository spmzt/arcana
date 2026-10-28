/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * ylog: the log operation's JSON as arcana-log has it, and syslog.conf
 * as ietf-syslog (ylog.c), for agent_test.sh.
 *
 *	ylog files reply.json	the log directory's files
 *	ylog read reply.json	a read's lines
 *	ylog conf syslog.conf [newsyslog.conf]
 *				syslogd's actions, what is not held
 *	ylog plan root		a commit of root's files as they are
 *
 * Through YANG-CBOR and back, the same bytes.
 */

#include <err.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <arcana.h>

#include "collect.h"

static char *
slurp(const char *path)
{
	char *buf;
	ssize_t r;
	int fd;

	if ((buf = malloc(1 << 20)) == NULL)
		err(1, "malloc");
	if ((fd = open(path, O_RDONLY)) == -1)
		err(1, "%s", path);
	if ((r = read(fd, buf, (1 << 20) - 1)) < 0)
		err(1, "%s", path);
	close(fd);
	buf[r] = '\0';
	return (buf);
}

static const char *
str(const char *s)
{

	return (s != NULL ? s : "-");
}

/* An identity's name by its SID. */
static const char *
ident(bool has, uint64_t sid)
{

	if (!has)
		return ("-");
	for (uint32_t i = 0; i < ymodel_schema.nident; i++)
		if (ymodel_schema.ident[i].sid == sid)
			return (ymodel_schema.ident[i].name);
	return ("?");
}

static const char *const sevs[] = { "emergency", "alert", "critical",
    "error", "warning", "notice", "info", "debug" };

static void
same(int (*enc)(const void *, struct cbl_ybuf *),
    int (*dec)(const void *, size_t, void *, cbl_yarena *, int, char *,
    size_t), const void *v, void *back, cbl_yarena *a)
{
	struct cbl_ybuf b1 = { 0 }, b2 = { 0 };
	char why[256] = "";

	if (enc(v, &b1) != 0 || dec(b1.p, b1.len, back, a, CBL_YD_STRICT,
	    why, sizeof(why)) != 0 || enc(back, &b2) != 0)
		errx(1, "the round trip: %s", why);
	printf("yang-cbor %zu bytes, %s\n", b1.len, b1.len == b2.len &&
	    memcmp(b1.p, b2.p, b1.len) == 0 ? "the same back" :
	    "not the same");
}

typedef struct ietf_syslog_syslog_actions_file_log_file_filter_facility_list
    yfl;

static void
filter(size_t n, const yfl *v)
{

	for (size_t i = 0; i < n; i++) {
		printf(" %s.", v[i].facility.which == 0 ? ident(true,
		    v[i].facility.v.m0) : "all");
		if (v[i].advanced_compare != NULL)
			printf("=");
		printf("%s", v[i].severity.which == 0 ? sevs[v[i].severity.v.m0] :
		    v[i].severity.v.m1 ==
		    IETF_SYSLOG_SYSLOG_ACTIONS_FILE_LOG_FILE_FILTER_FACILITY_LIST_SEVERITY_M1_ALL ?
		    "all" : "none");
	}
	printf("\n");
}

static void
conf(const char *path, const char *ns, cbl_yarena *a)
{
	struct ietf_syslog y;
	struct ietf_syslog_syslog back;
	struct yunread *u;
	size_t nu;
	int error;

	if ((error = ysyslog_read(NULL, path, ns, a, &y, &u, &nu)) != 0)
		errc(1, error, "ysyslog_read");
	const struct ietf_syslog_syslog_actions *ac = y.syslog->actions;
	if (ac->console != NULL) {
		printf("console");
		filter(ac->console->filter->facility_list.n, (const void *)
		    ac->console->filter->facility_list.v);
	}
	for (size_t i = 0; ac->file != NULL && i < ac->file->log_file.n;
	    i++) {
		const struct ietf_syslog_syslog_actions_file_log_file *f =
		    &ac->file->log_file.v[i];
		const struct ietf_syslog_syslog_actions_file_log_file_file_rotation
		    *r = f->file_rotation;

		printf("file %s", f->name);
		if (r != NULL)
			printf(" files=%d size=%d rollover=%d",
			    r->has_number_of_files ? (int)r->number_of_files : -1,
			    r->has_max_file_size ? (int)r->max_file_size : -1,
			    r->has_rollover ? (int)r->rollover : -1);
		filter(f->filter->facility_list.n, f->filter->facility_list.v);
	}
	for (size_t i = 0; ac->remote != NULL && i < ac->remote->destination.n;
	    i++) {
		const struct ietf_syslog_syslog_actions_remote_destination *d =
		    &ac->remote->destination.v[i];
		const struct ietf_syslog_syslog_actions_remote_destination_udp_udp
		    *uu = &d->udp->udp.v[0];

		printf("remote %s udp %s %s port=%d", d->name, uu->address.which
		    == 0 ? "ipv4" : uu->address.which == 1 ? "ipv6" : "name",
		    uu->address.v.m0, uu->has_port ? uu->port : -1);
		filter(d->filter->facility_list.n, (const void *)
		    d->filter->facility_list.v);
	}
	for (size_t i = 0; i < nu; i++)
		printf("unread %s: %s\n", u[i].var, u[i].why);
	same((void *)ietf_syslog_syslog_encode, (void *)ietf_syslog_syslog_decode,
	    y.syslog, &back, a);
}

/* A commit of root's files as they are, through YANG-CBOR first: the
 * plan changes nothing. */
static void
plan(const char *root, cbl_yarena *a)
{
	struct ietf_syslog y, back;
	struct ietf_syslog_syslog bs;
	struct ysyslog_plan pl;
	struct yunread *u;
	char conf[1024], ns[1024], err[1024];
	size_t nu;
	int error;

	snprintf(conf, sizeof(conf), "%s%s", root, SYSLOG_CONF);
	snprintf(ns, sizeof(ns), "%s%s", root, NEWSYSLOG_CONF);
	if ((error = ysyslog_read(root, conf, ns, a, &y, &u, &nu)) != 0)
		errc(1, error, "ysyslog_read");
	same((void *)ietf_syslog_syslog_encode, (void *)
	    ietf_syslog_syslog_decode, y.syslog, &bs, a);
	back.syslog = &bs;
	if ((error = ysyslog_plan(root, &back, a, &pl, err, sizeof(err))) != 0)
		errx(1, "ysyslog_plan: %s", err);
	printf("changed %s take %zu create %zu included %s/%s\n",
	    pl.changed ? "yes" : "no", pl.ntake, pl.ncreate, pl.included ?
	    "yes" : "no", pl.rot_included ? "yes" : "no");
	for (size_t i = 0; i < pl.ntake; i++)
		printf("take %s:%d\n", pl.take[i].path + strlen(root),
		    pl.take[i].line);
}

int
main(int argc, char **argv)
{
	cbl_yarena *a;
	int error;

	if (argc < 3 || argc > 4)
		errx(2, "usage: ylog files|read reply.json | "
		    "ylog conf syslog.conf [newsyslog.conf] | ylog plan root");
	if ((a = cbl_yarena_new()) == NULL)
		err(1, "cbl_yarena_new");
	if (strcmp(argv[1], "files") == 0) {
		struct arcana_log_logs l, back;

		if ((error = ylog_files_from_json(slurp(argv[2]), "/var/log",
		    a, &l)) != 0)
			errc(1, error, "ylog_files_from_json");
		printf("directory %s\n", str(l.directory));
		for (size_t i = 0; i < l.file.n; i++)
			printf("file %s size=%ju modified=%s packed=%s\n",
			    l.file.v[i].name, (uintmax_t)l.file.v[i].size,
			    str(l.file.v[i].modified), l.file.v[i].has_packed ?
			    "yes" : "-");
		same((void *)arcana_log_logs_encode, (void *)
		    arcana_log_logs_decode, &l, &back, a);
	} else if (strcmp(argv[1], "read") == 0) {
		struct arcana_log_logs_read_output r, back;

		if ((error = ylog_read_from_json(slurp(argv[2]), a, &r)) != 0)
			errc(1, error, "ylog_read_from_json");
		printf("name %s size=%jd position=%jd rotated=%s\n",
		    str(r.name), r.has_size ? (intmax_t)r.size : -1,
		    r.has_position ? (intmax_t)r.position : -1, r.has_rotated ?
		    "yes" : "-");
		for (size_t i = 0; i < r.line.n; i++) {
			const struct arcana_log_logs_read_output_line *l =
			    &r.line.v[i];

			printf("line time=%s host=%s facility=%s severity=%s "
			    "tag=%s pid=%s seq=%jd seen=%s text=%s\n",
			    str(l->time), str(l->host), ident(l->has_facility,
			    l->facility), l->has_severity ? sevs[l->severity] :
			    "-", str(l->tag), str(l->pid), l->has_sequence ?
			    (intmax_t)l->sequence : -1, str(l->seen),
			    str(l->text));
		}
		same((void *)arcana_log_logs_read_output_encode, (void *)
		    arcana_log_logs_read_output_decode, &r, &back, a);
	} else if (strcmp(argv[1], "conf") == 0)
		conf(argv[2], argc > 3 ? argv[3] : NULL, a);
	else if (strcmp(argv[1], "plan") == 0)
		plan(argv[2], a);
	else
		errx(2, "%s: files, read, conf or plan", argv[1]);
	return (0);
}
