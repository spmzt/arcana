/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * What runs on an agent's host and what it wrote down (PLAN-SDN-YANG
 * 3.1.7), for the console and arcanactl: arcana-processes' list and a
 * process's read action, arcana-log's read, arcana-history's read and
 * how it samples committed, arcana-events' read (each event made by
 * yevjson.c), made the JSON the operations gave (the agent's procs.c,
 * log.c, history.c, events.c), so that the pages keep reading what they
 * read.
 */

#include <sys/param.h>

#include <errno.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <cblink.h>
#include <cbl_schema.h>
#include <ucl.h>

#include "ymodel.h"
#include "yevjson.h"
#include "ygula.h"
#include "yqueue.h"

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

#define	PUT_NUM(o, key, y, m) do {					\
	if ((y)->has_##m)						\
		put((o), (key), ucl_object_fromint((int64_t)(y)->m));	\
} while (0)

/* A decimal64 of 2 digits, the number the agent had. */
#define	PUT_DEC2(o, key, y, m) do {					\
	if ((y)->has_##m)						\
		put((o), (key), ucl_object_fromdouble((double)(y)->m /	\
		    100));						\
} while (0)

/* A list's array, its items made by fn; the module's struct, v and n. */
#define	PUT_EACH(o, key, l, fn) do {					\
	ucl_object_t *arr_ = ucl_object_typed_new(UCL_ARRAY);		\
									\
	for (size_t i_ = 0; i_ < (l).n; i_++)				\
		ucl_array_append(arr_, fn(&(l).v[i_]));			\
	put((o), (key), arr_);						\
} while (0)

/* A yang:date-and-time the agent wrote (UTC), as seconds; -1: not one. */
static int64_t
epoch_of(const char *s)
{
	struct tm	 tm;
	const char	*e;

	memset(&tm, 0, sizeof(tm));
	if (s == NULL || (e = strptime(s, "%Y-%m-%dT%H:%M:%S", &tm)) == NULL)
		return (-1);
	return ((int64_t)timegm(&tm));
}

/* An identity's name, by its SID; NULL: none. */
static const char *
ident_name(uint64_t sid)
{

	for (uint32_t i = 0; i < ymodel_schema.nident; i++)
		if (ymodel_schema.ident[i].sid == sid)
			return (ymodel_schema.ident[i].name);
	return (NULL);
}

/* The words of a command line joined again, as kvm_getargv(3)'s were. */
static ucl_object_t *
joined(const char *const *v, size_t n)
{
	ucl_object_t	*o;
	char		*s;
	size_t		 len = 1;

	for (size_t i = 0; i < n; i++)
		len += strlen(v[i]) + 1;
	if ((s = calloc(1, len)) == NULL)
		return (NULL);
	for (size_t i = 0; i < n; i++) {
		if (i > 0)
			strlcat(s, " ", len);
		strlcat(s, v[i], len);
	}
	o = ucl_object_fromstring(s);
	free(s);
	return (o);
}

static ucl_object_t *
process_of(const struct arcana_processes_processes_process *p)
{
	const struct arcana_processes_processes_process_state *s = p->state;
	ucl_object_t	*o, *args;

	o = ucl_object_typed_new(UCL_OBJECT);
	put(o, "pid", ucl_object_fromint((int64_t)p->pid));
	if (s == NULL)
		return (o);
	PUT_NUM(o, "ppid", s, ppid);
	put_str(o, "user", s->user);
	PUT_NUM(o, "jid", s, jid);
	put_str(o, "jail", s->jail);
	put_str(o, "state", s->run_state);
	put_str(o, "wait", s->wait);
	PUT_NUM(o, "nice", s, nice);
	PUT_NUM(o, "pri", s, priority);
	PUT_NUM(o, "threads", s, threads);
	PUT_NUM(o, "rss", s, memory_usage);
	PUT_NUM(o, "size", s, size);
	PUT_DEC2(o, "time", s, cpu_time);
	PUT_DEC2(o, "wcpu", s, wcpu);
	PUT_DEC2(o, "cpu", s, cpu);
	PUT_NUM(o, "in", s, blocks_in);
	PUT_NUM(o, "out", s, blocks_out);
	PUT_DEC2(o, "io", s, io);
	/* OpenConfig's timeticks64, nanoseconds: the seconds it was. */
	if (s->has_start_time)
		put(o, "start", ucl_object_fromint((int64_t)(s->start_time /
		    1000000000u)));
	if (s->has_kernel && s->kernel)
		put(o, "kernel", ucl_object_frombool(true));
	put_str(o, "comm", s->name);
	if (s->args.n > 0 && (args = joined(s->args.v, s->args.n)) != NULL)
		put(o, "args", args);
	return (o);
}

static ucl_object_t *
jail_of(const struct arcana_processes_processes_jail *j)
{
	ucl_object_t	*o;

	o = ucl_object_typed_new(UCL_OBJECT);
	put(o, "jid", ucl_object_fromint(j->jid));
	put_str(o, "name", j->name);
	PUT_NUM(o, "procs", j, procs);
	PUT_NUM(o, "threads", j, threads);
	PUT_NUM(o, "rss", j, rss);
	PUT_DEC2(o, "cpu", j, cpu);
	PUT_DEC2(o, "wcpu", j, wcpu);
	return (o);
}

static ucl_object_t *
file_of(const struct arcana_processes_processes_process_read_output_file *f)
{
	ucl_object_t	*o;

	o = ucl_object_typed_new(UCL_OBJECT);
	PUT_NUM(o, "fd", f, fd);
	put_str(o, "use", f->use);
	put_str(o, "type", f->type);
	put_str(o, "path", f->path);
	put_str(o, "proto", f->proto);
	put_str(o, "local", f->local);
	put_str(o, "remote", f->remote);
	put_str(o, "mode", f->mode);
	return (o);
}

static ucl_object_t *
thread_of(
    const struct arcana_processes_processes_process_read_output_thread *t)
{
	ucl_object_t	*o;

	o = ucl_object_typed_new(UCL_OBJECT);
	put(o, "tid", ucl_object_fromint((int64_t)t->tid));
	put_str(o, "name", t->name);
	put_str(o, "state", t->run_state);
	put_str(o, "wait", t->wait);
	PUT_NUM(o, "pri", t, priority);
	PUT_DEC2(o, "wcpu", t, wcpu);
	PUT_DEC2(o, "time", t, cpu_time);
	PUT_NUM(o, "cpu", t, last_cpu);
	return (o);
}

/* One process's read action: its files and threads. */
static int
process_read(cbl_conn *conn, uint32_t pid, ucl_object_t **data, char *err,
    size_t errlen)
{
	struct arcana_processes_processes_process_read_output	 out;
	const struct cbl_ynode					*list, *act;
	ucl_object_t						*top;
	cbl_yarena						*a;
	uint64_t						 key = pid;
	int							 error;

	if ((list = yq_child(yq_top("arcana-processes", "processes"),
	    "process")) == NULL || (act = yq_child(list, "read")) == NULL) {
		snprintf(err, errlen, "arcana-processes has no read");
		return (ENOENT);
	}
	if ((a = cbl_yarena_new()) == NULL)
		return (ENOMEM);
	memset(&out, 0, sizeof(out));
	if ((error = yq_call(conn, list, &key, act, NULL, &out, a, err,
	    errlen)) == 0) {
		top = ucl_object_typed_new(UCL_OBJECT);
		put(top, "pid", ucl_object_fromint(pid));
		put_str(top, "comm", out.name);
		PUT_EACH(top, "files", out.file, file_of);
		PUT_EACH(top, "threads", out.thread, thread_of);
		*data = top;
	}
	cbl_yarena_free(a);
	return (error);
}

/* A file of a log directory. */
static ucl_object_t *
logfile_of(const struct arcana_log_logs_read_output_file *f)
{
	ucl_object_t	*o;
	int64_t		 t;

	o = ucl_object_typed_new(UCL_OBJECT);
	put_str(o, "name", f->name);
	PUT_NUM(o, "size", f, size);
	if ((t = epoch_of(f->modified)) >= 0)
		put(o, "mtime", ucl_object_fromint(t));
	if (f->has_packed && f->packed)
		put(o, "packed", ucl_object_frombool(true));
	return (o);
}

/*
 * A line of a log, its parts as the agent took them apart: the
 * facility and severity as syslogd -vv writes them (security is RFC
 * 5424's audit); a tag before its pid in RFC 5424's form, after it in
 * syslogd's own, as the agent put them.
 */
static ucl_object_t *
logline_of(const struct arcana_log_logs_read_output_line *l)
{
	static const char *const sev[] = { "emerg", "alert", "crit", "err",
	    "warn", "notice", "info", "debug" };
	ucl_object_t	*o;
	const char	*fac;
	char		 lv[64];
	int64_t		 t;
	bool		 rfc5424;

	o = ucl_object_typed_new(UCL_OBJECT);
	put_str(o, "time", l->time);
	if (l->has_facility && l->has_severity && (size_t)l->severity <
	    nitems(sev) && (fac = ident_name(l->facility)) != NULL) {
		snprintf(lv, sizeof(lv), "%s.%s", strcmp(fac, "audit") == 0 ?
		    "security" : fac, sev[l->severity]);
		put_str(o, "level", lv);
	}
	put_str(o, "host", l->host);
	rfc5424 = l->time != NULL && strlen(l->time) > 10 && l->time[4] == '-' &&
	    l->time[10] == 'T';
	if (rfc5424)
		put_str(o, "tag", l->tag);
	put_str(o, "pid", l->pid);
	if (!rfc5424)
		put_str(o, "tag", l->tag);
	put_str(o, "text", l->text);
	PUT_NUM(o, "seq", l, sequence);
	if ((t = epoch_of(l->seen)) >= 0)
		put(o, "seen", ucl_object_fromint(t));
	return (o);
}

int
ygula_log(cbl_conn *conn, const char *name, const char *filter,
    bool has_position, uint64_t position, uint32_t lines, const char *jail,
    ucl_object_t **data, char *err, size_t errlen)
{
	struct arcana_log_logs_read_input	 in;
	struct arcana_log_logs_read_output	 out;
	const struct cbl_ynode			*n, *act;
	ucl_object_t				*top;
	cbl_yarena				*a;
	int					 error;

	*data = NULL;
	err[0] = '\0';
	if ((n = yq_top("arcana-log", "logs")) == NULL ||
	    (act = yq_child(n, "read")) == NULL) {
		snprintf(err, errlen, "arcana-log has no read");
		return (ENOENT);
	}
	memset(&in, 0, sizeof(in));
	in.name = name != NULL && name[0] != '\0' ? name : "messages";
	in.filter = filter != NULL && filter[0] != '\0' ? filter : NULL;
	in.has_position = has_position;
	in.position = position;
	in.has_lines = lines > 0;
	in.lines = (uint16_t)lines;
	in.jail = jail != NULL && jail[0] != '\0' ? jail : NULL;
	if ((a = cbl_yarena_new()) == NULL)
		return (ENOMEM);
	memset(&out, 0, sizeof(out));
	if ((error = yq_call(conn, n, NULL, act, &in, &out, a, err,
	    errlen)) == 0) {
		/* In the order log.c put them. */
		top = ucl_object_typed_new(UCL_OBJECT);
		put_str(top, "name", out.name);
		if (out.file.n > 0)
			PUT_EACH(top, "files", out.file, logfile_of);
		PUT_EACH(top, "lines", out.line, logline_of);
		PUT_NUM(top, "size", &out, size);
		PUT_NUM(top, "position", &out, position);
		if (out.has_rotated && out.rotated)
			put(top, "rotated", ucl_object_frombool(true));
		*data = top;
	}
	cbl_yarena_free(a);
	return (error);
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

static void
num_append(ucl_object_t *arr, bool has, uint64_t v)
{

	ucl_array_append(arr, ucl_object_fromint(has ? (int64_t)v : 0));
}

/*
 * A sample as history.c wrote it: its fields (t, cpu, load, mem, swap,
 * rx, tx, read, write), then each interface's in and out, each disk's
 * read and written, each jail's CPU (whole percents) and memory, each
 * relay's plain and added.
 */
static ucl_object_t *
sample_of(const struct arcana_history_sample *s)
{
	ucl_object_t	*arr;

	arr = ucl_object_typed_new(UCL_ARRAY);
	ucl_array_append(arr, ucl_object_fromint(epoch_of(s->time)));
	ucl_array_append(arr, ucl_object_fromdouble(s->has_cpu ?
	    (double)s->cpu / 10 : 0));
	ucl_array_append(arr, ucl_object_fromdouble(s->has_load ?
	    (double)s->load / 100 : 0));
	num_append(arr, s->has_memory, s->memory);
	num_append(arr, s->has_swap, s->swap);
	num_append(arr, s->has_received, s->received);
	num_append(arr, s->has_sent, s->sent);
	num_append(arr, s->has_read, s->read);
	num_append(arr, s->has_written, s->written);
	for (size_t i = 0; i < s->interface.n; i++) {
		num_append(arr, s->interface.v[i].has_received,
		    s->interface.v[i].received);
		num_append(arr, s->interface.v[i].has_sent,
		    s->interface.v[i].sent);
	}
	for (size_t i = 0; i < s->disk.n; i++) {
		num_append(arr, s->disk.v[i].has_read, s->disk.v[i].read);
		num_append(arr, s->disk.v[i].has_written,
		    s->disk.v[i].written);
	}
	for (size_t i = 0; i < s->jail.n; i++) {
		num_append(arr, s->jail.v[i].has_cpu, (uint64_t)
		    ((s->jail.v[i].cpu + 5) / 10));
		num_append(arr, s->jail.v[i].has_memory,
		    s->jail.v[i].memory);
	}
	for (size_t i = 0; i < s->relay.n; i++) {
		num_append(arr, s->relay.v[i].has_plain, s->relay.v[i].plain);
		num_append(arr, s->relay.v[i].has_added, s->relay.v[i].added);
	}
	return (arr);
}

static const char *const rule_kinds[] = { "net", "disk", "jail-cpu",
    "jail-mem" };

int
ygula_history(cbl_conn *conn, bool has_after, uint64_t after,
    ucl_object_t **data, char *err, size_t errlen)
{
	static const char *const fields[] = { "t", "cpu", "load", "mem",
	    "swap", "rx", "tx", "read", "write" };
	struct arcana_history_history_read_input	 in;
	struct arcana_history_history_read_output	 out;
	const struct cbl_ynode				*n, *act;
	ucl_object_t					*top, *o, *arr;
	cbl_yarena					*a;
	char						 when[32];
	struct tm					 tm;
	time_t						 t;
	int						 error;

	*data = NULL;
	err[0] = '\0';
	if ((n = yq_top("arcana-history", "history")) == NULL ||
	    (act = yq_child(n, "read")) == NULL) {
		snprintf(err, errlen, "arcana-history has no read");
		return (ENOENT);
	}
	memset(&in, 0, sizeof(in));
	t = (time_t)(after > INT32_MAX * 64ull ? INT32_MAX * 64ull : after);
	if (has_after && gmtime_r(&t, &tm) != NULL && strftime(when,
	    sizeof(when), "%Y-%m-%dT%H:%M:%SZ", &tm) != 0)
		in.after = when;
	if ((a = cbl_yarena_new()) == NULL)
		return (ENOMEM);
	memset(&out, 0, sizeof(out));
	if ((error = yq_call(conn, n, NULL, act, &in, &out, a, err,
	    errlen)) != 0) {
		cbl_yarena_free(a);
		return (error);
	}
	/* In the order history.c wrote them. */
	top = ucl_object_typed_new(UCL_OBJECT);
	o = ucl_object_typed_new(UCL_OBJECT);
	put(o, "cpu", ucl_object_fromint(out.limits != NULL &&
	    out.limits->has_cpu ? out.limits->cpu : 0));
	put(o, "mem", ucl_object_fromint(out.limits != NULL &&
	    out.limits->has_memory ? out.limits->memory : 0));
	put(o, "swap", ucl_object_fromint(out.limits != NULL &&
	    out.limits->has_swap ? out.limits->swap : 0));
	put(o, "storage", ucl_object_fromint(out.limits != NULL &&
	    out.limits->has_storage ? out.limits->storage : 0));
	put(top, "limits", o);
	arr = ucl_object_typed_new(UCL_ARRAY);
	for (size_t i = 0; i < out.rule.n; i++) {
		const struct arcana_history_history_read_output_rule *r =
		    &out.rule.v[i];

		o = ucl_object_typed_new(UCL_OBJECT);
		put_str(o, "kind", (size_t)r->kind < nitems(rule_kinds) ?
		    rule_kinds[r->kind] : "net");
		put_str(o, "name", r->name);
		put(o, "limit", ucl_object_fromint(r->has_limit ?
		    (int64_t)r->limit : 0));
		put(o, "over", ucl_object_frombool(r->has_over && r->over));
		ucl_array_append(arr, o);
	}
	put(top, "rules", arr);
	put(top, "racct", ucl_object_frombool(out.has_racct && out.racct));
	put(top, "step", ucl_object_fromint(out.sampling != NULL &&
	    out.sampling->has_step ? out.sampling->step : 5));
	put(top, "keep", ucl_object_fromint(out.sampling != NULL &&
	    out.sampling->has_keep ? out.sampling->keep : 720));
	put(top, "bytes", ucl_object_fromint(out.has_bytes ?
	    (int64_t)out.bytes : 0));
	put(top, "ncpu", ucl_object_fromint(out.has_ncpu ? out.ncpu : 1));
	put(top, "mem_total", ucl_object_fromint(out.has_memory_total ?
	    (int64_t)out.memory_total : 0));
	put(top, "swap_total", ucl_object_fromint(out.has_swap_total ?
	    (int64_t)out.swap_total : 0));
	put(top, "fields", strs_of(fields, nitems(fields)));
	put(top, "nets", strs_of(out.interface.v, out.interface.n));
	put(top, "disks", strs_of(out.disk.v, out.disk.n));
	put(top, "jails", strs_of(out.jail.v, out.jail.n));
	put(top, "relays", strs_of(out.relay.v, out.relay.n));
	PUT_EACH(top, "samples", out.sample, sample_of);
	cbl_yarena_free(a);
	*data = top;
	return (0);
}

/* "net:igb0=125000000,jail-cpu:web=80" as the list of rules, in a. */
static int
rules_of(const char *list, cbl_yarena *a,
    struct arcana_history_history_rule **vp, size_t *np, char *err,
    size_t errlen)
{
	struct arcana_history_history_rule	*v;
	char					*copy, *p, *tok, *colon, *eq,
						*name, *end;
	size_t					 n = 0, k;
	unsigned long long			 lim;

	*vp = NULL;
	*np = 0;
	if ((v = cbl_yarena_alloc(a, 32 * sizeof(*v))) == NULL ||
	    (copy = cbl_yarena_alloc(a, strlen(list) + 1)) == NULL)
		return (ENOMEM);
	memcpy(copy, list, strlen(list) + 1);
	p = copy;
	while ((tok = strsep(&p, ", ")) != NULL) {
		if (tok[0] == '\0')
			continue;
		if (n == 32) {
			snprintf(err, errlen, "32 rules at most");
			return (EINVAL);
		}
		colon = strchr(tok, ':');
		eq = colon != NULL ? strchr(colon, '=') : NULL;
		for (k = 0; colon != NULL && k < nitems(rule_kinds); k++)
			if (strlen(rule_kinds[k]) == (size_t)(colon - tok) &&
			    strncmp(tok, rule_kinds[k], (size_t)(colon - tok)) ==
			    0)
				break;
		lim = 0;
		end = NULL;
		if (eq != NULL && eq[1] != '-') {
			errno = 0;
			lim = strtoull(eq + 1, &end, 10);
		}
		if (colon == NULL || end == NULL || k == nitems(rule_kinds) ||
		    eq == colon + 1 || end == eq + 1 || *end != '\0' ||
		    lim == 0 || errno != 0) {
			snprintf(err, errlen, "a rule is net:, disk:, jail-cpu: "
			    "or jail-mem:, a name, = and its limit");
			return (EINVAL);
		}
		*eq = '\0';
		name = colon + 1;
		memset(&v[n], 0, sizeof(v[n]));
		v[n].kind = (int)k;
		v[n].name = name;
		v[n].has_limit = true;
		v[n++].limit = lim;
	}
	*vp = v;
	*np = n;
	return (0);
}

int
ygula_history_set(cbl_conn *conn, uint32_t step, uint32_t keep,
    const uint32_t *lim, int storage, const char *rules, char *err,
    size_t errlen)
{
	struct arcana_history_history_sampling	 sp;
	struct arcana_history_history_limits	 li;
	struct arcana_history_history		 h;
	struct arcana_history			 d;
	struct arcana_history_history_rule	*rv;
	const struct cbl_ynode			*n;
	cbl_yarena				*a;
	size_t					 nr;
	int					 error;

	err[0] = '\0';
	if ((n = yq_top("arcana-history", "history")) == NULL) {
		snprintf(err, errlen, "arcana-history is not in the tables");
		return (ENOENT);
	}
	if ((a = cbl_yarena_new()) == NULL)
		return (ENOMEM);
	/* What running has, the rest kept as it is. */
	memset(&d, 0, sizeof(d));
	if ((error = yq_get(conn, n, CBL_YDS_RUNNING, &d, a, err,
	    errlen)) != 0) {
		cbl_yarena_free(a);
		return (error);
	}
	memset(&h, 0, sizeof(h));
	memset(&li, 0, sizeof(li));
	if (d.history != NULL) {
		h = *d.history;
		if (d.history->limits != NULL)
			li = *d.history->limits;
	}
	memset(&sp, 0, sizeof(sp));
	sp.has_step = sp.has_keep = true;
	sp.step = (uint16_t)step;
	sp.keep = keep;
	h.sampling = &sp;
	if (lim != NULL) {
		li.has_cpu = li.has_memory = li.has_swap = true;
		li.cpu = (uint8_t)lim[0];
		li.memory = (uint8_t)lim[1];
		li.swap = (uint8_t)lim[2];
	}
	if (storage >= 0) {
		li.has_storage = true;
		li.storage = (uint8_t)storage;
	}
	h.limits = &li;
	if (rules != NULL) {
		if ((error = rules_of(rules, a, &rv, &nr, err, errlen)) != 0) {
			cbl_yarena_free(a);
			return (error);
		}
		h.rule.v = rv;
		h.rule.n = nr;
	}
	d.history = &h;
	error = yq_commit(conn, n, &d, err, errlen);
	cbl_yarena_free(a);
	return (error);
}

int
ygula_events(cbl_conn *conn, bool has_after, uint64_t after,
    ucl_object_t **data, char *err, size_t errlen)
{
	struct arcana_events_events_read_input	 in;
	struct arcana_events_events_read_output	 out;
	const struct cbl_ynode			*n, *act;
	cbl_yarena				*a;
	int					 error;

	*data = NULL;
	err[0] = '\0';
	if ((n = yq_top("arcana-events", "events")) == NULL ||
	    (act = yq_child(n, "read")) == NULL) {
		snprintf(err, errlen, "arcana-events has no read");
		return (ENOENT);
	}
	memset(&in, 0, sizeof(in));
	in.has_after = has_after;
	in.after = after;
	if ((a = cbl_yarena_new()) == NULL)
		return (ENOMEM);
	memset(&out, 0, sizeof(out));
	if ((error = yq_call(conn, n, NULL, act, &in, &out, a, err,
	    errlen)) == 0)
		*data = yev_list_json(out.has_last, out.last, out.has_first,
		    out.first, out.has_kept, out.kept, out.event.v,
		    out.event.n);
	cbl_yarena_free(a);
	return (error);
}

const struct cbl_ynode *
ygula_event_node(void)
{
	static const struct cbl_ynode	*n;
	const struct cbl_ymodule	*m;

	for (uint32_t i = 0; n == NULL && i < ymodel_schema.nmod; i++) {
		m = ymodel_schema.mod[i];
		if (strcmp(m->name, "arcana-events") != 0)
			continue;
		for (uint32_t k = 0; k < m->ntop; k++)
			if (m->top[k]->kind == CBL_YN_NOTIF &&
			    strcmp(m->top[k]->name, "event") == 0)
				n = m->top[k];
	}
	return (n);
}

ucl_object_t *
ygula_event_of(const cbl_msg *msg)
{
	struct arcana_events_event	 ev;
	const struct cbl_ynode		*n;
	struct cbl_ynotif		 nt;
	ucl_object_t			*o = NULL;
	cbl_yarena			*a;

	if ((n = ygula_event_node()) == NULL || (a = cbl_yarena_new()) ==
	    NULL)
		return (NULL);
	memset(&ev, 0, sizeof(ev));
	if (cbl_msg_ynotif(msg, &nt, a) == 0 && nt.sid == n->sid &&
	    cbl_ydecode(n, nt.content, nt.len, &ev, a, 0, NULL, 0) == 0)
		o = yev_ntf_json(&ev);
	cbl_yarena_free(a);
	return (o);
}

int
ygula_processes(cbl_conn *conn, const char *jail, uint32_t pid,
    ucl_object_t **data, char *err, size_t errlen)
{
	const struct arcana_processes_processes	*ps;
	const struct cbl_ynode			*n;
	struct arcana_processes			 d;
	ucl_object_t				*top, *arr;
	cbl_yarena				*a;
	int					 error;

	*data = NULL;
	err[0] = '\0';
	if (pid != 0)
		return (process_read(conn, pid, data, err, errlen));
	if ((n = yq_top("arcana-processes", "processes")) == NULL) {
		snprintf(err, errlen, "arcana-processes is not in the tables");
		return (ENOENT);
	}
	if ((a = cbl_yarena_new()) == NULL)
		return (ENOMEM);
	memset(&d, 0, sizeof(d));
	if ((error = yq_get(conn, n, -1, &d, a, err, errlen)) != 0) {
		cbl_yarena_free(a);
		return (error);
	}
	/* A jail's: one with processes, which a running jail has. */
	ps = d.processes;
	if (jail != NULL) {
		size_t	 i;

		for (i = 0; ps != NULL && i < ps->jail.n; i++)
			if (ps->jail.v[i].name != NULL &&
			    strcmp(ps->jail.v[i].name, jail) == 0)
				break;
		if (ps == NULL || i == ps->jail.n) {
			snprintf(err, errlen, "jail %s is not running", jail);
			cbl_yarena_free(a);
			return (ESRCH);
		}
	}
	top = ucl_object_typed_new(UCL_OBJECT);
	arr = ucl_object_typed_new(UCL_ARRAY);
	if (ps != NULL)
		for (size_t i = 0; i < ps->process.n; i++) {
			const struct arcana_processes_processes_process *p =
			    &ps->process.v[i];

			/* A jail's: those whose jail it is, by its name. */
			if (jail != NULL && (p->state == NULL ||
			    p->state->jail == NULL || strcmp(p->state->jail,
			    jail) != 0))
				continue;
			ucl_array_append(arr, process_of(p));
		}
	put(top, "processes", arr);
	arr = ucl_object_typed_new(UCL_ARRAY);
	if (ps != NULL)
		for (size_t i = 0; i < ps->jail.n; i++)
			if (jail == NULL || (ps->jail.v[i].name != NULL &&
			    strcmp(ps->jail.v[i].name, jail) == 0))
				ucl_array_append(arr, jail_of(&ps->jail.v[i]));
	put(top, "jails", arr);
	if (ps != NULL) {
		PUT_NUM(top, "ncpu", ps, ncpu);
		PUT_DEC2(top, "elapsed", ps, elapsed);
	}
	cbl_yarena_free(a);
	*data = top;
	return (0);
}
