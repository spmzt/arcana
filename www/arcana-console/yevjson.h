/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

#ifndef _ARCANA_YEVJSON_H_
#define	_ARCANA_YEVJSON_H_

#include <stdbool.h>
#include <stdint.h>

#include <ucl.h>

/*
 * arcana-events' events as the events operation's JSON (yevjson.c):
 * yev_json() one of the list, {"n","t","kind","jail","data"};
 * yev_ntf_json() the notification the same; yev_list_json() the
 * events operation's reply, {"last","first","kept","events"}, of the
 * read's output or the state.  Each a new object.
 */
struct arcana_events_event_entry;
struct arcana_events_event;

ucl_object_t	*yev_json(const struct arcana_events_event_entry *e);
ucl_object_t	*yev_ntf_json(const struct arcana_events_event *n);
ucl_object_t	*yev_list_json(bool has_last, uint64_t last, bool has_first,
		    uint64_t first, bool has_kept, uint16_t kept,
		    const struct arcana_events_event_entry *v, size_t n);

#endif	/* !_ARCANA_YEVJSON_H_ */
