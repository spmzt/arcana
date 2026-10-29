/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

#ifndef _ARCANA_YFLATNAMES_H_
#define	_ARCANA_YFLATNAMES_H_

/*
 * How each read's JSON differs from its module's names (yflat.c's
 * rules), the agent's and the console's alike: the agent reads the JSON
 * so, the console writes it back so.
 */

/* arcana-crashes' read. */
static const char *const yfn_crashes[] = { "core-file=cores",
    "other?=others", "note=notes", NULL };
/* arcana-system's read. */
static const char *const yfn_system[] = { "file{}=files",
    "module{}=modules", "mac-module{}=mac", "geom-class{}=geom_classes",
    "svcj{}", "hardening{}", "default-value=default", "host^", NULL };
/* arcana-netstore's read. */
static const char *const yfn_netstore[] = { "share=shares",
    "resources=list", NULL };
/* arcana-suricata's actions. */
static const char *const yfn_suricata[] = { "page-rule=rules",
    "group=groups", "class=classes", "source=sources",
    "section=sections", "row=rows", NULL };
/* arcana-smtpd's read. */
static const char *const yfn_smtpd[] = { "status{}", "stat{}=stats",
    "count#", "envelope=queue", "created#", "expires#", "retries#",
    "lasttry#", "next#", "conf-table=conf_tables", "entry-key=key",
    "sample[time,queued,ok,tempfail,permfail,sessions]=series",
    "table{}=tables", "filter=filters", "smtpctl^", "config^",
    "entry?=entries", NULL };
/* arcana-speeder's read. */
static const char *const yfn_speeder[] = {
    "fec-group?[size,redundant]=fec_groups",
    "period[time,to-server,to-client,plain-to-server,plain-to-client]="
    "series", "profile?=profiles", NULL };

#endif	/* !_ARCANA_YFLATNAMES_H_ */
