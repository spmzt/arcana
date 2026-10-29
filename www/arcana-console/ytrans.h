/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

#ifndef _ARCANA_YTRANS_H_
#define	_ARCANA_YTRANS_H_

#include <stdbool.h>
#include <stdint.h>

#include <cblink.h>
#include <ucl.h>

/*
 * The Network tab's interfaces, {"interfaces": [...], "time": ms}, from
 * a GET of the standard models over conn (ytrans.c): addresses of IPv4
 * with v4, of IPv6 with v6.  0, or an errno and err says why.
 */
int	ytrans_interfaces(cbl_conn *conn, bool v4, bool v6,
	    ucl_object_t **out, char *err, size_t errlen);
/*
 * The top-level nodes named, by commas (none: all of them), as RFC
 * 7951's JSON, one object, from a GET of the agent's models over conn.
 * 0, or an errno and err says why.
 */
int	ytrans_data(cbl_conn *conn, const char *names, ucl_object_t **out,
	    char *err, size_t errlen);
/* The same of the nodes by SID (none: all), what xpath selects of them
 * when it is not NULL; refused, the node at fault's SID in *errsid (0:
 * none said) when errsid is not NULL. */
int	ytrans_get(cbl_conn *conn, const uint64_t *sids, size_t ns,
	    const char *xpath, ucl_object_t **out, char *err, size_t errlen,
	    uint64_t *errsid);
/* The same of datastore ds (CBL_YDS_*; -1, none said: the agent's
 * default); _origin: with origin, each configuration node of the
 * operational datastore annotated with its origin (RFC 8342 section
 * 5.3.4, RFC 7952's "@" members). */
int	ytrans_get_ds(cbl_conn *conn, const uint64_t *sids, size_t ns,
	    const char *xpath, int ds, ucl_object_t **out, char *err,
	    size_t errlen, uint64_t *errsid);
int	ytrans_get_origin(cbl_conn *conn, const uint64_t *sids, size_t ns,
	    const char *xpath, int ds, bool origin, ucl_object_t **out,
	    char *err, size_t errlen, uint64_t *errsid);
/* The top-level nodes tops (ntop of them, 32 at most) of datastore ds as
 * a tree of the console's schema, *tp the caller's: those not there are
 * not in it. */
struct cbl_dtree;
int	ytrans_get_tree(cbl_conn *conn, const struct cbl_ynode *const *tops,
	    size_t ntop, int ds, struct cbl_dtree **tp, char *err,
	    size_t errlen, uint64_t *errsid);
/* The same of the top-level nodes tops, every one the server has when
 * ntop is 0, with their origins where origin is set (the operational
 * datastore's). */
int	ytrans_get_tree_origin(cbl_conn *conn,
	    const struct cbl_ynode *const *tops, size_t ntop, int ds,
	    bool origin, struct cbl_dtree **tp, char *err, size_t errlen,
	    uint64_t *errsid);
/* drift.c: what the host has otherwise than running says. */
int	drift_read(cbl_conn *conn, ucl_object_t **out, char *err,
	    size_t errlen);

/*
 * The pages' /sysctl and /kernel from arcana-sysctl and arcana-kernel
 * over conn, their shapes kept.  _sysctl_part: the values whose names
 * begin with prefix (a vnet jail's network's with jail), count of them
 * (0: the agent's most) from the one after after, as the page's rows
 * {name, value, type, rw, tun, descr}; *next the after of the next
 * part, malloc'd, NULL at the end; *total how many there are from there.
 * _sysctl: the first part of them with what sysctl.conf keeps,
 * {"values": [...], "kept": [{name, value}]}, *truncated when more
 * remain.  _kernel: {"files", "available", "kept", "memory"}.
 */
int	ytrans_sysctl_part(cbl_conn *conn, const char *prefix,
	    const char *jail, const char *after, uint16_t count,
	    ucl_object_t **rows, char **next, uint64_t *total, char *err,
	    size_t errlen);
int	ytrans_sysctl(cbl_conn *conn, const char *prefix, const char *jail,
	    ucl_object_t **data, uint64_t *total, bool *truncated, char *err,
	    size_t errlen);
int	ytrans_kernel(cbl_conn *conn, ucl_object_t **data, char *err,
	    size_t errlen);

/*
 * The pages' jails and packages, and what is done to them, from
 * arcana-jails and arcana-packages over conn, the shapes hosts.c had
 * (its jail_object()): _jails puts "jails", "scopes" and "conf_errors"
 * in top, the configured alone with config_only; _jail one jail's
 * object, NULL where it is not; _jail_action the jail's action verb
 * (start, stop, restart, kill); _packages the host's or jail's
 * packages, those installed or what the repository has newer (after
 * pkg update with refresh), as "packages", "repos" and "pkgbase" in
 * top; _pkg_upgrade, jail "*" every running one, as "upgraded" and
 * "packages".  0, or an errno and err says why (the agent's words).
 */
int	ytrans_jails(cbl_conn *conn, bool config_only, ucl_object_t *top,
	    char *err, size_t errlen);
ucl_object_t *ytrans_jail(cbl_conn *conn, const char *name);
int	ytrans_jail_action(cbl_conn *conn, const char *name, const char *verb,
	    char *err, size_t errlen);
int	ytrans_packages(cbl_conn *conn, const char *jail, bool installed,
	    bool refresh, uint8_t ip, bool anyos, ucl_object_t *top, char *err,
	    size_t errlen);
int	ytrans_pkg_upgrade(cbl_conn *conn, const char *jail,
	    const char *const *names, size_t nnames, bool dry_run, bool anyos,
	    uint8_t ip, const char *repo, ucl_object_t *top, char *err,
	    size_t errlen);

/*
 * The Services page's services and what is done to them, from
 * arcana-services over conn, the shapes the services, service-action
 * and service-config operations gave (hosts.c's service_object()):
 * _services puts "services" in top; _service the one service, by its
 * read action, as "service", and with config its "variables" as running
 * has them, "description" and "commands"; _service_action its action
 * (start, stop, restart, reload).
 *
 * A change of the configuration, running's with it put in the
 * candidate, committed confirmed and confirmed at once, the warnings
 * acc (nacc of them) accepted; refused, the candidate as running is and
 * tag the error-app-tag to accept, "" none: _service_set, service
 * name's rcvar (enable 1, -1 to disable, 0 as it is) and its variables
 * v set or unset (remove); _jail_boot, jail name started at boot or not
 * (arcana-jails' boot).  0, or an errno and err says why.
 */
struct arc_variable;
int	ytrans_services(cbl_conn *conn, ucl_object_t *top, char *err,
	    size_t errlen);
int	ytrans_service(cbl_conn *conn, const char *name, bool config,
	    ucl_object_t *top, char *err, size_t errlen);
int	ytrans_service_action(cbl_conn *conn, const char *name,
	    const char *verb, char *err, size_t errlen);
int	ytrans_service_set(cbl_conn *conn, const char *name, int enable,
	    const struct arc_variable *v, size_t nv, const char *const *acc,
	    size_t nacc, char *err, size_t errlen, char *tag, size_t taglen);
int	ytrans_jail_boot(cbl_conn *conn, const char *name, bool on,
	    const char *const *acc, size_t nacc, char *err, size_t errlen,
	    char *tag, size_t taglen);

#include "yjsonin.h"

#endif	/* !_ARCANA_YTRANS_H_ */
