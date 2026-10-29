/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * yprocs: the processes operation's JSON as arcana-processes has it
 * (yprocs.c), for agent_test.sh.
 *
 *	yprocs list [detail]	a line a process, and its files and
 *				threads with detail, the reply for one pid
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

/* A decimal64 of 2 digits as text. */
static const char *
dec2(bool has, int64_t v)
{
	static char b[4][32];
	static int k;

	if (!has)
		return ("-");
	k = (k + 1) % 4;
	snprintf(b[k], sizeof(b[k]), "%s%jd.%02jd", v < 0 ? "-" : "",
	    (intmax_t)(v < 0 ? -v : v) / 100, (intmax_t)(v < 0 ? -v : v) % 100);
	return (b[k]);
}

int
main(int argc, char **argv)
{
	struct arcana_processes_processes p, back;
	struct cbl_ybuf b1 = { 0 }, b2 = { 0 };
	cbl_yarena *a;
	char why[256];
	int error;

	if (argc < 2 || argc > 3)
		errx(2, "usage: yprocs list [detail]");
	if ((a = cbl_yarena_new()) == NULL)
		err(1, "cbl_yarena_new");
	if ((error = yprocs_from_json(slurp(argv[1]), argc > 2 ?
	    slurp(argv[2]) : NULL, a, &p)) != 0)
		errc(1, error, "yprocs_from_json");
	printf("ncpu %u elapsed %s\n", p.ncpu, dec2(p.has_elapsed,
	    p.elapsed));
	for (size_t i = 0; i < p.process.n; i++) {
		const struct arcana_processes_processes_process *e =
		    &p.process.v[i];
		const struct arcana_processes_processes_process_state *s =
		    e->state;

		printf("process %ju name=%s args=", (uintmax_t)e->pid,
		    str(s->name));
		for (size_t j = 0; j < s->args.n; j++)
			printf("%s%s", j > 0 ? "|" : "", s->args.v[j]);
		printf(" start=%ju util=%u memory=%ju ppid=%ju user=%s "
		    "jail=%u/%s state=%s wait=%s nice=%d pri=%d threads=%u "
		    "size=%ju time=%s cpu=%s wcpu=%s in=%ju out=%ju io=%s%s\n",
		    (uintmax_t)s->start_time, s->cpu_utilization,
		    (uintmax_t)s->memory_usage, (uintmax_t)s->ppid,
		    str(s->user), s->jid, str(s->jail), str(s->run_state),
		    str(s->wait), s->nice, s->priority, s->threads,
		    (uintmax_t)s->size, dec2(s->has_cpu_time, s->cpu_time),
		    dec2(s->has_cpu, s->cpu), dec2(s->has_wcpu, s->wcpu),
		    (uintmax_t)s->blocks_in, (uintmax_t)s->blocks_out,
		    dec2(s->has_io, s->io), s->has_kernel && s->kernel ?
		    " kernel" : "");
		for (size_t j = 0; j < e->file.n; j++) {
			const struct arcana_processes_processes_process_file
			    *f = &e->file.v[j];

			if (f->has_fd)
				printf("  file fd=%d", f->fd);
			else
				printf("  file use=%s", str(f->use));
			printf(" type=%s path=%s proto=%s local=%s remote=%s "
			    "mode=%s\n", str(f->type), str(f->path),
			    str(f->proto), str(f->local), str(f->remote),
			    str(f->mode));
		}
		for (size_t j = 0; j < e->thread.n; j++) {
			const struct arcana_processes_processes_process_thread
			    *t = &e->thread.v[j];

			printf("  thread %ju name=%s state=%s wait=%s pri=%d "
			    "wcpu=%s time=%s on=%d\n", (uintmax_t)t->tid,
			    str(t->name), str(t->run_state), str(t->wait),
			    t->priority, dec2(t->has_wcpu, t->wcpu),
			    dec2(t->has_cpu_time, t->cpu_time), t->has_last_cpu ?
			    t->last_cpu : -1);
		}
	}
	for (size_t i = 0; i < p.jail.n; i++)
		printf("jail %u %s procs=%u threads=%u cpu=%s wcpu=%s rss=%ju\n",
		    p.jail.v[i].jid, str(p.jail.v[i].name), p.jail.v[i].procs,
		    p.jail.v[i].threads, dec2(p.jail.v[i].has_cpu,
		    p.jail.v[i].cpu), dec2(p.jail.v[i].has_wcpu,
		    p.jail.v[i].wcpu), (uintmax_t)p.jail.v[i].rss);
	if (arcana_processes_processes_encode(&p, &b1) != 0 ||
	    arcana_processes_processes_decode(b1.p, b1.len, &back, a,
	    CBL_YD_STRICT, why, sizeof(why)) != 0 ||
	    arcana_processes_processes_encode(&back, &b2) != 0)
		errx(1, "the round trip: %s", why);
	printf("yang-cbor %zu bytes, %s\n", b1.len, b1.len == b2.len &&
	    memcmp(b1.p, b2.p, b1.len) == 0 ? "the same back" :
	    "not the same");
	return (0);
}
