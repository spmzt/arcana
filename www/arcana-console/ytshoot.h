/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

#ifndef _ARCANA_YTSHOOT_H_
#define	_ARCANA_YTSHOOT_H_

#include <stdbool.h>
#include <stdint.h>

#include <cblink.h>
#include <ucl.h>

/*
 * Packets and paths followed on a host, through arcana-firewall and
 * arcana-troubleshoot (ytshoot.c), the console's and arcanactl's, as the
 * JSON the operations gave it.  Each takes conn and gives 0 with
 * *data, or an errno and err (the agent's words).
 *
 * yts_fw_trace(): the packets of address the firewall decides on, of
 * jail's own firewall where it is not NULL, for seconds (10 where 0) or
 * packets (100 where 0), {"packets", "seconds", "limit"}.
 */
int	yts_fw_trace(cbl_conn *conn, const char *jail, const char *address,
	    uint32_t seconds, uint32_t packets, ucl_object_t **data,
	    char *err, size_t errlen);
/*
 * yts_path_check(): what the host does with a packet from src to dst,
 * of proto (tcp, udp, sctp, icmp, ip; NULL tcp) to port (0 none),
 * coming in on iface (NULL: by the route back), in FIB fib where
 * has_fib, of jail's network where it is not NULL, its reply where
 * reply: arcana-troubleshoot's path-check.  yts_traceroute(): one round
 * of traceroute to address.  yts_capture(): packets taken off source
 * (NULL: the sources there are) with filter, for seconds (10 where 0,
 * 60 at most) or packets (50 where 0, 500 at most), of jail's network
 * where it is not NULL.
 */
int	yts_path_check(cbl_conn *conn, const char *src, const char *dst,
	    const char *proto, uint32_t port, const char *iface, bool has_fib,
	    uint32_t fib, const char *jail, bool reply, ucl_object_t **data,
	    char *err, size_t errlen);
int	yts_traceroute(cbl_conn *conn, const char *address,
	    ucl_object_t **data, char *err, size_t errlen);
int	yts_capture(cbl_conn *conn, const char *jail, const char *source,
	    const char *filter, uint32_t seconds, uint32_t packets,
	    ucl_object_t **data, char *err, size_t errlen);

#endif	/* !_ARCANA_YTSHOOT_H_ */
