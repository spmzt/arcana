/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

#ifndef _ARCANA_YGULA_H_
#define	_ARCANA_YGULA_H_

#include <stdbool.h>
#include <stdint.h>

#include <cblink.h>
#include <ucl.h>

/*
 * What runs on a host and what it wrote down, through arcana-processes
 * (ygula.c), the console's and arcanactl's, as the JSON the operations
 * gave it.  Each takes conn and gives 0 with *data, or an errno and err
 * (the agent's words).
 *
 * ygula_processes(): the processes, {"processes", "jails", "ncpu",
 * "elapsed"}, of jail alone where it is not NULL; with pid, that one
 * process's files and threads, {"pid", "comm", "files", "threads"}.
 */
int	ygula_processes(cbl_conn *conn, const char *jail, uint32_t pid,
	    ucl_object_t **data, char *err, size_t errlen);
/*
 * ygula_log(): arcana-log's read of log name (messages where NULL),
 * @dmesg or @audit, of jail's log directory where it is not NULL: the
 * last lines (200 where 0) with filter in them, or those after
 * position; {"name", "files", "lines", "size", "position", "rotated"}.
 */
int	ygula_log(cbl_conn *conn, const char *name, const char *filter,
	    bool has_position, uint64_t position, uint32_t lines,
	    const char *jail, ucl_object_t **data, char *err, size_t errlen);
/*
 * ygula_history(): arcana-history's read, the samples after after
 * (seconds since the Epoch) where has_after, with how they are taken
 * and the sampler as it is, {"limits", "rules", "racct", "step",
 * "keep", "bytes", "ncpu", "mem_total", "swap_total", "fields", "nets",
 * "disks", "jails", "relays", "samples"}.  ygula_history_set(): sampled
 * every step seconds and keep of them kept, committed with what running
 * has besides: with lim, the cpu, memory and swap limits (3); with
 * storage not -1, the file systems'; with rules ("net:igb0=125000000,
 * jail-cpu:web=80"; "": none) not NULL, the rules.
 */
int	ygula_history(cbl_conn *conn, bool has_after, uint64_t after,
	    ucl_object_t **data, char *err, size_t errlen);
int	ygula_history_set(cbl_conn *conn, uint32_t step, uint32_t keep,
	    const uint32_t *lim, int storage, const char *rules, char *err,
	    size_t errlen);
/*
 * ygula_events(): arcana-events' read, the events after number after
 * where has_after, {"last", "first", "kept", "events"}.  As they
 * happen: ygula_event_of(), a notification of family 1's group notify
 * that is arcana-events' event, as the events reply has one, {"n",
 * "t", "kind", "jail", "data"}, a new object; NULL, another or none.
 * ygula_event_node(), that notification's node.
 */
int	ygula_events(cbl_conn *conn, bool has_after, uint64_t after,
	    ucl_object_t **data, char *err, size_t errlen);
ucl_object_t *ygula_event_of(const cbl_msg *msg);
const struct cbl_ynode *ygula_event_node(void);

#endif	/* !_ARCANA_YGULA_H_ */
