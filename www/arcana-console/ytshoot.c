/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Following packets and paths on an agent's host (PLAN-SDN-YANG
 * 3.1.10), for the console and arcanactl: arcana-firewall's trace
 * action, of the host's firewall or a jail's, and arcana-troubleshoot's
 * path-check, traceroute and capture, made the JSON the operations gave
 * (ytsjson.c), so that the pages keep reading what they read.
 */

#include <sys/param.h>
#include <sys/socket.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <errno.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <cblink.h>
#include <cbl_schema.h>
#include <ucl.h>

#include "ymodel.h"
#include "yqueue.h"
#include "ytshoot.h"
#include "ytsjson.h"

/*
 * The action act of the host's top-level container top of module mod,
 * or of jail's (the container under its entry of arcana-jails, the
 * jail's name its one key): *at the container, what yq_call() takes.
 */
static const struct cbl_ynode *
action_of(const char *mod, const char *top, const char *act,
    const char *jail, const struct cbl_ynode **at)
{

	*at = jail == NULL ? yq_top(mod, top) : yq_child(yq_child(yq_top(
	    "arcana-jails", "jails"), "jail"), top);
	return (yq_child(*at, act));
}

/* An IPv4 or IPv6 address, as the agent takes one. */
static bool
is_address(const char *s)
{
	struct in6_addr	a;

	return (s != NULL && (inet_pton(AF_INET, s, &a) == 1 ||
	    inet_pton(AF_INET6, s, &a) == 1));
}

/* An ip-address-no-zone union of the input: v6 the second. */
#define	ADDRESS(u, s) do {						\
	(u).which = strchr((s), ':') != NULL;				\
	(u).v.m0 = (s);							\
} while (0)

int
yts_fw_trace(cbl_conn *conn, const char *jail, const char *address,
    uint32_t seconds, uint32_t packets, ucl_object_t **data, char *err,
    size_t errlen)
{
	struct arcana_firewall_firewall_trace_input	 in;
	struct arcana_firewall_firewall_trace_output	 out;
	const struct cbl_ynode				*at, *act;
	cbl_yarena					*a;
	int						 error;

	*data = NULL;
	err[0] = '\0';
	if (jail != NULL && jail[0] == '\0')
		jail = NULL;
	if (!is_address(address)) {
		snprintf(err, errlen, "the address to follow is an IPv4 or "
		    "IPv6 address");
		return (EINVAL);
	}
	if ((act = action_of("arcana-firewall", "firewall", "trace", jail,
	    &at)) == NULL) {
		snprintf(err, errlen, "arcana-firewall has no trace");
		return (ENOENT);
	}
	memset(&in, 0, sizeof(in));
	in.has_address = true;
	ADDRESS(in.address, address);
	in.has_seconds = seconds != 0;
	in.seconds = (uint8_t)seconds;
	in.has_packets = packets != 0;
	in.packets = (uint16_t)packets;
	if ((a = cbl_yarena_new()) == NULL)
		return (ENOMEM);
	memset(&out, 0, sizeof(out));
	if ((error = yq_call(conn, at, jail != NULL ? (const void *)&jail :
	    NULL, act, &in, &out, a, err, errlen)) == 0)
		*data = yts_trace_json(&out);
	cbl_yarena_free(a);
	return (error);
}

int
yts_path_check(cbl_conn *conn, const char *src, const char *dst,
    const char *proto, uint32_t port, const char *iface, bool has_fib,
    uint32_t fib, const char *jail, bool reply, ucl_object_t **data,
    char *err, size_t errlen)
{
	static const char *const protos[] = { "tcp", "udp", "icmp", "ip",
	    "sctp" };
	struct arcana_troubleshoot_troubleshoot_path_check_input	 in;
	struct arcana_troubleshoot_troubleshoot_path_check_output	 out;
	const struct cbl_ynode						*at, *act;
	cbl_yarena							*a;
	int								 error;

	*data = NULL;
	err[0] = '\0';
	if (!is_address(src) || !is_address(dst)) {
		snprintf(err, errlen, "the source and the destination are IPv4 "
		    "or IPv6 addresses");
		return (EINVAL);
	}
	if ((act = action_of("arcana-troubleshoot", "troubleshoot",
	    "path-check", NULL, &at)) == NULL) {
		snprintf(err, errlen, "arcana-troubleshoot has no path-check");
		return (ENOENT);
	}
	memset(&in, 0, sizeof(in));
	in.has_source = in.has_destination = true;
	ADDRESS(in.source, src);
	ADDRESS(in.destination, dst);
	for (size_t i = 0; proto != NULL && proto[0] != '\0' && i <
	    nitems(protos); i++)
		if (strcmp(proto, protos[i]) == 0) {
			in.has_protocol = true;
			in.protocol = (int)i;
		}
	if (proto != NULL && proto[0] != '\0' && !in.has_protocol) {
		snprintf(err, errlen, "the protocol is tcp, udp, sctp, icmp or "
		    "ip");
		return (EINVAL);
	}
	in.has_port = port != 0;
	in.port = (uint16_t)port;
	in.interface = iface != NULL && iface[0] != '\0' ? iface : NULL;
	in.has_fib = has_fib;
	in.fib = (uint16_t)fib;
	in.jail = jail != NULL && jail[0] != '\0' ? jail : NULL;
	in.has_reply = reply;
	in.reply = reply;
	if ((a = cbl_yarena_new()) == NULL)
		return (ENOMEM);
	memset(&out, 0, sizeof(out));
	if ((error = yq_call(conn, at, NULL, act, &in, &out, a, err,
	    errlen)) == 0)
		*data = yts_path_json(&out);
	cbl_yarena_free(a);
	return (error);
}

int
yts_traceroute(cbl_conn *conn, const char *address, ucl_object_t **data,
    char *err, size_t errlen)
{
	struct arcana_troubleshoot_troubleshoot_traceroute_input	 in;
	struct arcana_troubleshoot_troubleshoot_traceroute_output	 out;
	const struct cbl_ynode						*at, *act;
	cbl_yarena							*a;
	int								 error;

	*data = NULL;
	err[0] = '\0';
	if (!is_address(address)) {
		snprintf(err, errlen, "an address to trace the route to is "
		    "needed");
		return (EINVAL);
	}
	if ((act = action_of("arcana-troubleshoot", "troubleshoot",
	    "traceroute", NULL, &at)) == NULL) {
		snprintf(err, errlen, "arcana-troubleshoot has no traceroute");
		return (ENOENT);
	}
	memset(&in, 0, sizeof(in));
	in.has_address = true;
	ADDRESS(in.address, address);
	if ((a = cbl_yarena_new()) == NULL)
		return (ENOMEM);
	memset(&out, 0, sizeof(out));
	if ((error = yq_call(conn, at, NULL, act, &in, &out, a, err,
	    errlen)) == 0)
		*data = yts_traceroute_json(&out);
	cbl_yarena_free(a);
	return (error);
}

int
yts_capture(cbl_conn *conn, const char *jail, const char *source,
    const char *filter, uint32_t seconds, uint32_t packets,
    ucl_object_t **data, char *err, size_t errlen)
{
	struct arcana_troubleshoot_troubleshoot_capture_input	 in;
	struct arcana_troubleshoot_troubleshoot_capture_output	 out;
	const struct cbl_ynode					*at, *act;
	cbl_yarena						*a;
	int							 error;

	*data = NULL;
	err[0] = '\0';
	if ((act = action_of("arcana-troubleshoot", "troubleshoot", "capture",
	    NULL, &at)) == NULL) {
		snprintf(err, errlen, "arcana-troubleshoot has no capture");
		return (ENOENT);
	}
	memset(&in, 0, sizeof(in));
	in.interface = source != NULL && source[0] != '\0' ? source : NULL;
	in.filter = filter;
	in.has_seconds = seconds != 0;
	in.seconds = (uint8_t)MIN(seconds, 60);
	in.has_packets = packets != 0;
	in.packets = (uint16_t)MIN(packets, 500);
	in.jail = jail != NULL && jail[0] != '\0' ? jail : NULL;
	if ((a = cbl_yarena_new()) == NULL)
		return (ENOMEM);
	memset(&out, 0, sizeof(out));
	if ((error = yq_call(conn, at, NULL, act, &in, &out, a, err,
	    errlen)) == 0)
		*data = yts_capture_json(&out);
	cbl_yarena_free(a);
	return (error);
}
