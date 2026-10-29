/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Invidia: WireGuard as YANG, arcana-wireguard: what wireguard.c reads
 * (do_wireguard(), wg show dump) as the module's interfaces, the
 * host's state or the read action's output.
 */

#include <sys/param.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <arcana.h>

#include "collect.h"
#include "yjson.h"

static char *
datetime(cbl_yarena *a, int64_t t)
{
	char		buf[32], *p;
	struct tm	tm;
	time_t		tt = (time_t)t;

	if (gmtime_r(&tt, &tm) == NULL || strftime(buf, sizeof(buf),
	    "%Y-%m-%dT%H:%M:%SZ", &tm) == 0)
		return (NULL);
	if ((p = cbl_yarena_alloc(a, strlen(buf) + 1)) != NULL)
		memcpy(p, buf, strlen(buf) + 1);
	return (p);
}

int
ywg_from_json(const char *json, cbl_yarena *a, const char **now,
    size_t *nifp, const struct arcana_wireguard_interface **ifp)
{
	struct arcana_wireguard_interface			*v;
	struct arcana_wireguard_interface_peer			*p;
	struct arcana_wireguard_interface_peer_allowed_ip	*ip;
	const ucl_object_t					*e, *pe, *ie;
	ucl_object_iter_t					 it, pit, iit;
	ucl_object_t						*top;
	int64_t							 n;
	size_t							 ni = 0, np, na;

	*now = NULL;
	*nifp = 0;
	*ifp = NULL;
	if ((top = yj_parse(json)) == NULL)
		return (EINVAL);
	if (yj_num(top, "now", &n))
		*now = datetime(a, n);
	if ((v = cbl_yarena_alloc(a, (yj_count(ucl_object_lookup(top,
	    "interfaces")) + 1) * sizeof(*v))) == NULL) {
		ucl_object_unref(top);
		return (ENOMEM);
	}
	YJ_EACH(ucl_object_lookup(top, "interfaces"), it, e) {
		memset(&v[ni], 0, sizeof(v[ni]));
		if ((v[ni].name = yj_str(a, e, "name")) == NULL)
			continue;
		v[ni].private_key = yj_yes(e, "private-key",
		    &v[ni].has_private_key);
		v[ni].public_key = yj_str(a, e, "public-key");
		YJ_NUM(e, "listen-port", &v[ni], listen_port);
		if ((p = cbl_yarena_alloc(a, (yj_count(ucl_object_lookup(e,
		    "peers")) + 1) * sizeof(*p))) == NULL) {
			ucl_object_unref(top);
			return (ENOMEM);
		}
		np = 0;
		YJ_EACH(ucl_object_lookup(e, "peers"), pit, pe) {
			memset(&p[np], 0, sizeof(p[np]));
			if ((p[np].public_key = yj_str(a, pe, "public-key")) ==
			    NULL)
				continue;
			p[np].preshared_key = yj_yes(pe, "preshared-key",
			    &p[np].has_preshared_key);
			p[np].endpoint = yj_str(a, pe, "endpoint");
			if ((ip = cbl_yarena_alloc(a, (yj_count(
			    ucl_object_lookup(pe, "allowed-ips")) + 1) *
			    sizeof(*ip))) == NULL) {
				ucl_object_unref(top);
				return (ENOMEM);
			}
			na = 0;
			YJ_EACH(ucl_object_lookup(pe, "allowed-ips"), iit, ie) {
				const char	*s;
				char		*d;

				if (ucl_object_type(ie) != UCL_STRING)
					continue;
				s = ucl_object_tostring(ie);
				if ((d = cbl_yarena_alloc(a, strlen(s) + 1)) ==
				    NULL) {
					ucl_object_unref(top);
					return (ENOMEM);
				}
				memcpy(d, s, strlen(s) + 1);
				ip[na].which = strchr(s, ':') != NULL ? 1 : 0;
				ip[na].v.m0 = d;
				na++;
			}
			p[np].allowed_ip.n = na;
			p[np].allowed_ip.v = ip;
			/* 0: never. */
			if (yj_num(pe, "latest-handshake", &n) && n > 0)
				p[np].latest_handshake = datetime(a, n);
			YJ_NUM(pe, "rx", &p[np], received);
			YJ_NUM(pe, "tx", &p[np], sent);
			YJ_NUM(pe, "keepalive", &p[np], keepalive);
			np++;
		}
		v[ni].peer.n = np;
		v[ni].peer.v = p;
		ni++;
	}
	*nifp = ni;
	*ifp = v;
	ucl_object_unref(top);
	return (0);
}
