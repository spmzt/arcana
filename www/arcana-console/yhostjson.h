/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

#ifndef _ARCANA_YHOSTJSON_H_
#define	_ARCANA_YHOSTJSON_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <cblink.h>
#include <cbl_schema.h>
#include <ucl.h>

struct arcana_jobs_step;

/*
 * The host and its agent through arcana-host, arcana-jail-files and
 * arcana-agent (yhostjson.c), the console's and arcanactl's, as the
 * JSON the operations gave it.  Each takes conn and gives 0 with *data,
 * or an errno and err (the agent's words).
 *
 * yh_hello(): what the host is and the agent that answers, a read of
 * arcana-host's host, as hello gave it: {"hostname", "sysname",
 * "release", "machine", "ncpu", "physmem", "boottime", "time",
 * "securelevel", "privileged", "version", "build", "plugins",
 * "safe_wait", "features"}, the times seconds of the epoch; an agent
 * that has no features has none.  yh_takes_gzip(): whether that host's
 * agent takes its program compressed (zprog.h's feature).
 *
 * yh_stats(): how busy the host is, a read of arcana-host's host,
 * {"cpu_pct", "load1", "load5", "load15", "mem_total", "mem_used",
 * "mem_inactive", "mem_free", "swap_total", "swap_used", "pools"}, each
 * pool {"name", "size", "alloc", "free", "health"}.
 * yh_certs(): what OpenSSL trusts, of jail where it is not NULL, by
 * read-certificates, as certs.c wrote it: {"localbase", "trusted_dir",
 * "untrusted_dir", "added_dir", "distrusted_dir", "certctl", "now",
 * "trusted", "untrusted"}, each certificate {"file", "subject", "cn",
 * "org", "country", "issuer", "not_before", "not_after", "sha256",
 * "key", "ca", "self_signed", "local"}, the times seconds of the epoch.
 */
int	yh_hello(cbl_conn *conn, ucl_object_t **data, char *err,
	    size_t errlen);
bool	yh_takes_gzip(const ucl_object_t *host);
int	yh_stats(cbl_conn *conn, ucl_object_t **data, char *err,
	    size_t errlen);
/* yh_stats_of(): the same of arcana-host's data, as a push held it. */
struct arcana_host;
ucl_object_t *yh_stats_of(const struct arcana_host *d);
int	yh_certs(cbl_conn *conn, const char *jail, ucl_object_t **data,
	    char *err, size_t errlen);
/*
 * yh_jail_files(): the files the jails are made with, arcana-jail-files'
 * read-files, as jailmake.c wrote them: {"defaults" {"path", "text",
 * null where there is no such file}, "dir", "templates", "jails"}, each
 * {"name", "text"}.
 */
int	yh_jail_files(cbl_conn *conn, ucl_object_t **data, char *err,
	    size_t errlen);
/*
 * yh_source_log(): what is new in a repository's branch, arcana-agent's
 * source-log (as agent-build fetches: host_keys those confirmed,
 * ssh_key the deploy key; count 0: the agent's 100), as build.c wrote
 * it: {"commit", "log", "tags"}, log each {"commit", "time", "subject",
 * "body"}, tags each {"name", "time", "message"}, the times seconds of
 * the epoch.
 */
int	yh_source_log(cbl_conn *conn, const char *source, const char *ref,
	    const char *host_keys, const char *ssh_key, uint32_t count,
	    ucl_object_t **data, char *err, size_t errlen);
/*
 * The fleet's update through arcana-agent's actions, a repository as
 * yh_source_log() fetches it.  Each fetch the server refused (its host
 * keys to confirm, the deploy key to give access) is EPERM, err why,
 * *data {"host_keys", "fingerprints", "deploy_key"}.
 *
 * yh_source_head(): the head of the branch, {"commit"}.
 * yh_console_update(): the tree built and installed, the console and
 * the agent restarting, {"commit", "restarting"}.
 * yh_agent_build(): arcana-agent built, {"version", "sha256",
 * "commit"}, the program into *progp (malloc(3)), *lenp bytes, sent
 * compressed with compress (to an agent that takes it so, yh_hello())
 * and inflated here; its SHA-256 is the caller's to check.
 * yh_agent_update(): the program, len bytes, put in place, sha256 its
 * SHA-256, sig its signature by the CA key; sent compressed with gzip,
 * as it is otherwise, waited for timeout_ms (-1: the connection's
 * longest); {"version", "restarting"}.  EFBIG and err: too big for an
 * update to carry.
 */
int	yh_source_head(cbl_conn *conn, const char *source, const char *ref,
	    const char *host_keys, const char *ssh_key, ucl_object_t **data,
	    char *err, size_t errlen);
int	yh_console_update(cbl_conn *conn, const char *source, const char *ref,
	    const char *host_keys, const char *ssh_key, ucl_object_t **data,
	    char *err, size_t errlen);
int	yh_agent_build(cbl_conn *conn, const char *source, const char *ref,
	    const char *host_keys, const char *ssh_key, bool compress,
	    ucl_object_t **data, uint8_t **progp, size_t *lenp, char *err,
	    size_t errlen);
int	yh_agent_update(cbl_conn *conn, const uint8_t *prog, size_t len,
	    const char *sha256, const uint8_t *sig, size_t siglen,
	    bool restart, bool gzip, int timeout_ms, ucl_object_t **data,
	    char *err, size_t errlen);
/*
 * The steps of a request as the agent tells them (arcana-jobs' steps,
 * on group notify), msg one notification heard: NULL where it is
 * another; otherwise its steps, *np of them, in a.
 */
const struct arcana_jobs_step *yh_steps_of(const cbl_msg *msg, cbl_yarena *a,
	    size_t *np);
/*
 * yh_config_export(): the host as a bundle, arcana-agent's
 * config-export (with secrets, their texts), as bundle.c writes it:
 * {"arcana": "host", "format": 1, "host", "agent", "taken", "facts",
 * "packages", "files"}.  yh_config_apply(): bundle, that JSON, made the
 * host's configuration by config-apply (dry: the report only; anyway:
 * though the hardware differs; hostname, NULL or the name in rc.conf),
 * the report {"mismatches", "packages" each {"name"}, "files" each
 * {"path", "state", "diff"}, "backup", "applied", "reboot"}.  EINVAL
 * and err: bundle is not a bundle; EPERM and err: refused, *data the
 * report still.
 */
int	yh_config_export(cbl_conn *conn, bool secrets, ucl_object_t **data,
	    char *err, size_t errlen);
int	yh_config_apply(cbl_conn *conn, const char *bundle, bool dry,
	    bool anyway, const char *hostname, ucl_object_t **data, char *err,
	    size_t errlen);
/*
 * yh_transport(): how the agent is reached, arcana-agent's transport,
 * as transport.c writes it: {"listeners" each {"uri", "transport",
 * "up", "error", "addresses", "also_error"}, "sctp_also", "sctp",
 * "seen", "sessions" each {"transport", "address", "subject", "since",
 * "local", "paths" each {"address", "state", "srtt_ms", "rto_ms",
 * "primary"}}, "time"}; first, with retry, its retry action, and with
 * listen, unlisten (keep: kept in rc.conf) or sctp_also not NULL, its
 * listen action.
 */
int	yh_transport(cbl_conn *conn, bool retry, const char *listen,
	    const char *unlisten, bool keep, const char *sctp_also,
	    ucl_object_t **data, char *err, size_t errlen);
/*
 * yh_tls(): the agent's own TLS files, arcana-agent's tls, as tlsfiles.c
 * writes them: verb "status", {"cert" {"subject", "issuer",
 * "not_before", "not_after", "sha256", "chain" each the same less
 * its chain}, "ca" each the same, "pending"}; "csr", its csr action,
 * {"csr"}; "install", its install action of cert, ca (one at least) and
 * peer (the asking console's certificate), then the status.
 */
int	yh_tls(cbl_conn *conn, const char *verb, const char *cert,
	    const char *ca, const char *peer, ucl_object_t **data, char *err,
	    size_t errlen);

#endif	/* !_ARCANA_YHOSTJSON_H_ */
