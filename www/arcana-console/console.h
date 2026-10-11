/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * arcana-console.so: the Kore module that serves the arcana console.
 */

#ifndef _CONSOLE_H_
#define _CONSOLE_H_

#include <sys/types.h>

#include <stdbool.h>
#include <stdint.h>

#include <kore/kore.h>
#include <kore/http.h>
#include <kore/tasks.h>
#include <ucl.h>

/* Generated into the object directory; <> so that a stale copy next
 * to the sources is never picked up. */
#include <arcana.h>

#define	ARCW_VERSION		"0.89.0"
#define	ARCW_LOCAL_AGENT	"unix:/var/run/arcana-agent.sock"
#define	ARCW_CONF		"/usr/local/etc/arcana/web.conf"
#define	ARCW_RELEASES		"https://api.github.com/repos/spmzt/arcana/releases/latest"
#define	ARCW_AGENT_BINARY	"/usr/local/sbin/arcana-agent"

#define	SESSION_COOKIE		"arc_session"
#define	SESSION_IDLE		(30 * 60)
#define	SESSION_MAX		(12 * 60 * 60)
#define	SESSIONS		8
#define	SESSIONS_FILE		"sessions.json"
#define	SESSION_SAVE		60	/* s, between writes of the time of use */
#define	CHALLENGE_TTL		120
#define	CBLINK_MAX_FRAME	(8 * 1024 * 1024)
#define	CBLINK_MAX_ATTRS	(1024 * 1024)
#define	CBLINK_TIMEOUT_MS	(15 * 60 * 1000)

/* config.c: web.conf, a UCL file named by $ARCANA_WEB_CONF. */
struct config {
	char		*rp_id;		/* WebAuthn relying party: host name */
	char		*rp_name;
	char		*origin;	/* "https://console.example" */
	char		*datadir;	/* credentials, servers, setup token */
	bool		 cookie_secure;
	char		*tls_ca;	/* CA of the arcana-agent certificates */
	char		*tls_ca_key;	/* its key, to enrol hosts; or NULL */
	char		*tls_cert;	/* this console's client certificate */
	char		*tls_key;
	bool		 tls_own;	/* no tls {}: the console's own CA */
	char		*update_url;	/* release feed, or NULL: no checks */
	char		*agent_binary;	/* the arcana-agent sent to hosts */
	char		*agent_source;	/* git repository to build it from */
	char		*agent_ref;	/* its branch or tag, or NULL */
	char		*agent_ssh_key;	/* a key on the build host, or NULL */
	char		*local_agent;	/* the agent beside the console, or NULL */
};

extern struct config cfg;

int		 config_load(const char *);
int		 config_check_certs(void);

/* push.c: notifications to the devices that asked, by Web Push. */
int		 push_init(void);
int		 api_push(struct http_request *);
int		 api_push_list(struct http_request *);
int		 api_push_subscribe(struct http_request *);
int		 api_push_send(struct http_request *);
void		 api_push_free(struct http_request *);

/* settings.c: the settings changed from the console. */
void		 settings_init(const char *, const char *);
void		 config_refresh(void);
int		 api_settings(struct http_request *);

/* store.c: small JSON documents in the data directory. */
ucl_object_t	*store_load(const char *);
int		 store_save(const char *, const ucl_object_t *);

/* api.c: HTTP plumbing shared by the handlers. */
int		 reply_json(struct http_request *, int, ucl_object_t *);
int		 reply_error(struct http_request *, int, const char *,
		    const char *, ...) __printflike(4, 5);
ucl_object_t	*read_json(struct http_request *);
bool		 guard(struct http_request *, bool);
bool		 token_valid(struct http_request *);
bool		 token_readable(const char *);
int		 api_tokens(struct http_request *);
int		 api_workflows(struct http_request *);
int		 api_runs(struct http_request *);
int		 api_sdwan(struct http_request *);
/* sdwan.c and sdwan_edge.c: SD-WAN, kept, checked, made on the edges. */
ucl_object_t	*sdwan_load(void);
bool		 sdwan_valid(const ucl_object_t *, char *, size_t);
int		 api_sdwan_edges(struct http_request *);
void		 sdwan_init(void);
void		 workflows_init(void);
void		 thread_log(int, const char *, ...) __printflike(2, 3);
int		 api_transfers(struct http_request *);
void		 transfers_init(void);
bool		 capture(struct http_request *, int, char *, size_t);
const char	*ucl_str(const ucl_object_t *, const char *);
bool		 ucl_flag(const ucl_object_t *, const char *);

/* auth.c: WebAuthn and sessions. */
void		 auth_init(void);
bool		 session_valid(struct http_request *);

/* servers.c: the registry of arcana-agent instances. */
struct server {
	char	id[9];
	char	*name;
	char	*uri;
	char	*peer_name;
};

void		 servers_init(void);
int		 servers_add(const char *, const char *, const char *);
const struct server *server_find(const char *);
const struct server *server_at(int);
int		 servers_move(const char *, const char *);

/* pki.c: the console's CA and host enrolment. */
int		 pki_init(void);

/* hosts.c: requests to arcana-agent over cblink, in Kore task threads. */
int		 hosts_init(void);
void		 hosts_forget(const char *);
const char	*hosts_shared(const char *, const char *, cbl_conn **,
		    struct arc_client *);
void		 hosts_shared_done(cbl_conn *, bool);
char		*hosts_submit(const char *, const char *, const char *,
		    const ucl_object_t *, int *, const char **);
char		*hosts_job(const char *, const char *, const char *, uint64_t,
		    int *);
char		*hosts_arcana(const char *, const char *, const char *,
		    const char *, int *);
char		*hosts_read(const char *, const char *, const char *,
		    const char *, int *);
char		*hosts_events(const char *, const char *, const char *,
		    uint64_t, int *);
char		*hosts_net(const char *, const char *, const char *,
		    const char *, int *);
char		*hosts_sysctl(const char *, const char *, const char *,
		    const char *, int *);
char		*hosts_sdwan_set(const char *, const char *, const char *,
		    const char *, const char *, int *);
int		 api_sdwan_state(struct http_request *);
bool		 host_ref(const char *, char *, size_t, char *, size_t, char *,
		    size_t);
void		 host_refs(void);
const char	*hosts_connect(const char *, const char *, cbl_conn **,
		    cbl_tls **, struct arc_client *);
void		 hosts_release(const char *, const char *, cbl_conn *,
		    cbl_tls *, struct arc_client *, bool);

/* Route handlers, named in the Kore configuration. */
int		 api_health(struct http_request *);
int		 api_auth_status(struct http_request *);
int		 api_register_begin(struct http_request *);
int		 api_register_finish(struct http_request *);
int		 api_login_begin(struct http_request *);
int		 api_login_finish(struct http_request *);
int		 api_logout(struct http_request *);
int		 api_credentials(struct http_request *);
int		 api_credential(struct http_request *);
int		 api_servers(struct http_request *);
int		 api_server(struct http_request *);
int		 api_enrol_tokens(struct http_request *);
int		 api_enrol(struct http_request *);
int		 api_update(struct http_request *);
int		 api_hello(struct http_request *);
int		 api_jails(struct http_request *);
int		 api_action(struct http_request *);
int		 api_address(struct http_request *);
int		 api_services(struct http_request *);
int		 api_service_action(struct http_request *);
int		 api_service_config(struct http_request *);
int		 api_agent_update(struct http_request *);
const char	*agent_build(void);
const char	*agent_version(void);
int		 api_agent_build(struct http_request *);
int		 api_network(struct http_request *);
int		 api_stats(struct http_request *);
int		 api_kernel(struct http_request *);
int		 api_transport(struct http_request *);
int		 api_transport_switch(struct http_request *);
int		 api_sysctl(struct http_request *);
int		 api_processes(struct http_request *);
int		 api_log(struct http_request *);
int		 api_history(struct http_request *);
int		 api_events(struct http_request *);
int		 api_fw_trace(struct http_request *);
int		 api_ipfw_rules(struct http_request *);
int		 api_stream(struct http_request *);
void		 stream_connect(struct connection *);
void		 stream_message(struct connection *, u_int8_t, void *, size_t);
void		 stream_disconnect(struct connection *);
const char	*follow_start(struct connection *, uint64_t,
		    const struct server *);
bool		 follow_stop(struct connection *, uint64_t, bool);
int		 api_storage(struct http_request *);
int		 api_fstab(struct http_request *);
int		 api_bird_config(struct http_request *);
int		 api_packages(struct http_request *);
int		 api_pkg_upgrade(struct http_request *);
int		 api_jobs(struct http_request *);
int		 api_job(struct http_request *);
void		 api_call_free(struct http_request *);

int		 arcw_onload(int);

#endif /* !_CONSOLE_H_ */
