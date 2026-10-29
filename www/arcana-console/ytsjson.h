/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

#ifndef _ARCANA_YTSJSON_H_
#define	_ARCANA_YTSJSON_H_

#include <ucl.h>

/*
 * The outputs of arcana-firewall's trace and arcana-troubleshoot's
 * path-check, traceroute and capture as the fw-trace, path-check,
 * traceroute and capture operations' JSON (ytsjson.c); each a new
 * object.
 */
struct arcana_firewall_firewall_trace_output;
struct arcana_troubleshoot_troubleshoot_path_check_output;
struct arcana_troubleshoot_troubleshoot_traceroute_output;
struct arcana_troubleshoot_troubleshoot_capture_output;

ucl_object_t	*yts_trace_json(
		    const struct arcana_firewall_firewall_trace_output *out);
ucl_object_t	*yts_path_json(
		    const struct arcana_troubleshoot_troubleshoot_path_check_output *p);
ucl_object_t	*yts_traceroute_json(
		    const struct arcana_troubleshoot_troubleshoot_traceroute_output *t);
ucl_object_t	*yts_capture_json(
		    const struct arcana_troubleshoot_troubleshoot_capture_output *c);

#endif	/* !_ARCANA_YTSJSON_H_ */
