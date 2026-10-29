/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

#ifndef _ARCANA_YREADS_H_
#define	_ARCANA_YREADS_H_

#include <stdbool.h>
#include <stdint.h>

#include <cblink.h>
#include <ucl.h>

/*
 * The host's daemons and files read through their modules (yreads.c),
 * the console's and arcanactl's, as the JSON the operations gave it.
 * Each takes conn and gives 0 with *data, or an errno and err (the
 * agent's words).
 *
 * yr_sshd(): sshd, of jail where it is not NULL, arcana-sshd's read, as
 * ssh.c wrote it: {"config", "settings_from_file", "before_kept",
 * "banner_text", "host_keys", "users", "user_cas", "user_cas_text",
 * "settings"}.
 * yr_builder(): poudriere, a GET of arcana-builder, as poudriere.c
 * wrote it: {"installed", "program", "conf_file", "basefs", "data",
 * "configured", "conf", "jails", "ports", "makeconf", "options",
 * "repos", "builds", "builds_error", "runs"}.
 * yr_port_options(): a port's options, its port-options action of the
 * words (jail=, ports=, set=, origin=), n of them: {"jail", "ports",
 * "set", "origin", "pkgname", "options_dir", "options_dir_exists",
 * "options_file", "configured", "sections"}.
 * yr_notify(): text sent to chat by the bot of token, arcana-notify's
 * notify; no *data.
 *
 * The reads whose nodes are their JSON's keys (yflat.c), the JSON of
 * the operations they were: yr_crashes(), the cores, with words
 * "backtrace", a core and its program, one's backtrace too;
 * yr_system(), the system's files by name and host (none: all);
 * yr_netstore(), nfs, iscsi and hast (none: all); yr_suricata(), the
 * suricata-rules operation's words: a page of the rules (q=, sid=,
 * only=, classtype=, offset=, limit=), sources=1, Suricata's answer
 * (instance=, command=, iface=; where raw is not NULL, *raw its text
 * as Suricata wrote it, malloc(3)ed), or its profiling (instance=,
 * profiling=1); yr_smtpd(), yr_speeder(), of jail where it is not NULL.
 */
int	yr_sshd(cbl_conn *conn, const char *jail, ucl_object_t **data,
	    char *err, size_t errlen);
int	yr_builder(cbl_conn *conn, ucl_object_t **data, char *err,
	    size_t errlen);
int	yr_port_options(cbl_conn *conn, const char *const *words, size_t n,
	    ucl_object_t **data, char *err, size_t errlen);
int	yr_notify(cbl_conn *conn, const char *token, const char *chat,
	    const char *text, char *err, size_t errlen);
int	yr_crashes(cbl_conn *conn, const char *const *words, size_t n,
	    ucl_object_t **data, char *err, size_t errlen);
int	yr_system(cbl_conn *conn, const char *const *words, size_t n,
	    ucl_object_t **data, char *err, size_t errlen);
int	yr_netstore(cbl_conn *conn, const char *const *words, size_t n,
	    ucl_object_t **data, char *err, size_t errlen);
int	yr_suricata(cbl_conn *conn, const char *const *words, size_t n,
	    ucl_object_t **data, char **raw, char *err, size_t errlen);
int	yr_smtpd(cbl_conn *conn, const char *jail, ucl_object_t **data,
	    char *err, size_t errlen);
int	yr_speeder(cbl_conn *conn, const char *jail, ucl_object_t **data,
	    char *err, size_t errlen);

#endif	/* !_ARCANA_YREADS_H_ */
