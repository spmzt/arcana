/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

#ifndef _ARCANA_YSDWAN_H_
#define	_ARCANA_YSDWAN_H_

#include <stdbool.h>
#include <stdint.h>

#include <cblink.h>
#include <ucl.h>

/*
 * An SD-WAN edge through arcana-sdwan (ysdwan.c, the console's and
 * arcanactl's).  ysdwan_edit(): part kind (rules, steer, bird, dhcp,
 * dns, proxy, ids) of an edge, json as the sdwan-<kind> operation took
 * it ("jail" its edge where it is a vnet jail; for proxy and ids
 * "group" security the Security section's instances, sec-, else
 * SD-WAN's), put in arcana-sdwan's candidate in place of what running
 * has of it, the rest as running has it.  0, or an errno, err (the
 * agent's words), *errsid (the node at fault) and tag (an
 * error-app-tag); the candidate is then to be committed, or, where
 * *same (running has it so already), the part set again by
 * ysdwan_apply(), json's part of its edge, arcana-sdwan's apply: what
 * of it is not running started, as the operation did when sent the
 * same again.  ysdwan_read(): the sdwan operation's JSON object, made of
 * arcana-sdwan's and arcana-probe's operational state (with has_after,
 * only the samples after that time), into *data.
 */
int	ysdwan_edit(cbl_conn *conn, const char *kind, const char *json,
	    bool *same, char *err, size_t errlen, uint64_t *errsid,
	    char *tag, size_t taglen);
int	ysdwan_apply(cbl_conn *conn, const char *kind, const char *json,
	    char *err, size_t errlen);
int	ysdwan_read(cbl_conn *conn, bool has_after, uint64_t after,
	    ucl_object_t **data, char *err, size_t errlen);

#endif	/* !_ARCANA_YSDWAN_H_ */
