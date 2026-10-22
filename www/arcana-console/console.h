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

_Static_assert(CBLINK_VERSION_MAJOR == 0 && CBLINK_VERSION_MINOR == 2,
    "written for cblink 0.2: its wire, its structs");

#define	ARCW_VERSION		"0.278.0"
#define	ARCW_LOCAL_AGENT	"unix:/var/run/arcana-agent.sock"
#define	ARCW_CONF		"/usr/local/etc/arcana/web.conf"
#define	ARCW_RELEASES		"https://api.github.com/repos/spmzt/arcana/releases/latest"
#define	ARCW_AGENT_BINARY	"/usr/local/sbin/arcana-agent"

#define	ANDROID_KEYS		8	/* signing keys of the Android app */
#define	SESSION_COOKIE		"arc_session"
#define	SESSION_IDLE		(30 * 60)
#define	SESSION_MAX		(12 * 60 * 60)
#define	SESSIONS		8
#define	SESSIONS_DIR		"sessions"	/* a document a session */
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
	int		 session_idle;	/* seconds a sign-in may sit idle */
	int		 session_max;	/* seconds a sign-in lasts at most */
	char		*local_agent;	/* the agent beside the console, or NULL */
	char		*sendmail;	/* what mail is sent by */
	int		 mail_tick;	/* s between reads of the events */
	/* web.conf's for the mail; what is in force: settings_peek(). */
	char		*mail_to;	/* addresses, "" for none */
	char		*mail_from;	/* "": arcana@ the host */
	char		*mail_faults;	/* the least severity, or "none" */
	char		*mail_jobs;	/* "failed", "all" or "none" */
	char		*mail_runs;	/* the same, of workflow runs */
	bool		 mail_limits;	/* thresholds crossed */
	char		*android_package;	/* the Android app, or NULL */
	uint8_t		 android_keys[ANDROID_KEYS][32];	/* SHA-256 of its signers */
	int		 nandroid_keys;
};

extern struct config cfg;

int		 config_load(const char *);
int		 config_check_certs(void);

/* mail.c: what happened, mailed. */
void		 mail_init(void);
int		 mail_send(const char *, const char *, char *, size_t);
void		 mail_run(const char *, unsigned int, const char *);
void		 mail_flush(void);
/* Where a server is reached, as a thread may keep it (workflows.c). */
struct hostref {
	char	id[9];
	char	name[128];
	char	uri[256];
	char	peer[256];
};
int		 host_refs_get(struct hostref *, int);
int		 alert_send(const char *, const char *, const char *, char *,
		    size_t);
int		 api_telegram_test(struct http_request *);
void		 api_telegram_test_free(struct http_request *);
int		 api_mail_test(struct http_request *);

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
char		*settings_peek(const char *);
int		 api_settings(struct http_request *);

/* store.c: small JSON documents in the data directory. */
ucl_object_t	*store_load(const char *);
int		 store_save(const char *, const ucl_object_t *);
int		 store_write(const char *, const void *, size_t);
int		 store_remove(const char *);
void		 store_sweep(void);

/* nodes.c: the consoles of a cluster. */
int		 cluster_config(const ucl_object_t *, const char *);
int		 cluster_init(void);
void		 cluster_started(void);
bool		 cluster_on(void);
bool		 cluster_leads(void);
bool		 cluster_origin(const char *);
bool		 cluster_lock(const char *);
void		 cluster_unlock(const char *);
uint64_t	 cluster_gen(void);
int		 cluster_save(const char *, const void *, size_t, bool);
void		 cluster_status(ucl_object_t *);
void		 cluster_changes(void (*)(const char *));
int		 api_cluster(struct http_request *);
void		 auth_reload(const char *);
void		 users_reload(void);
void		 servers_reload(void);
void		 push_reload(void);
int		 pki_node_cert(const char *, const char *, const char *, char *,
		    size_t);

/* api.c: HTTP plumbing shared by the handlers. */
int		 reply_json(struct http_request *, int, ucl_object_t *);
int		 api_not_found(struct http_request *);
int		 reply_error(struct http_request *, int, const char *,
		    const char *, ...) __printflike(4, 5);
ucl_object_t	*read_json(struct http_request *);
bool		 guard(struct http_request *, bool);
enum { TOKEN_NONE, TOKEN_READ, TOKEN_WRITE };
int		 token_kind(struct http_request *);
const char	*token_login(const char *, char *, size_t);
bool		 token_alive(const char *);
bool		 session_by_token(struct http_request *);

/* ldap.c: sign-in by a directory, when Settings name one. */
bool		 ldap_enabled(void);
bool		 ldap_login(const char *, const char *, char *, size_t, char *,
		    size_t, const char **, int *, int);
int		 api_login_token(struct http_request *);
int		 api_login_ldap(struct http_request *);

/* prefixlists.c: the console's prefix lists, used on any host. */
int		 api_prefix_lists(struct http_request *);
int		 api_prefix_list(struct http_request *);
ucl_object_t	*prefix_list_get(const char *);

/* labels.c: the console's own tags on hosts' interfaces. */
int		 api_labels(struct http_request *);
int		 api_label(struct http_request *);
const char	*label_of(const char *, const char *, char *, size_t);
const char	*token_who(struct http_request *);
bool		 token_readable(const char *);
bool		 token_writable(const char *);
int		 api_tokens(struct http_request *);
int		 api_workflows(struct http_request *);
int		 api_runs(struct http_request *);
int		 api_sdwan(struct http_request *);
/* sdwan.c and sdwan_edge.c: SD-WAN, kept, checked, made on the edges. */
ucl_object_t	*sdwan_load(void);
bool		 sdwan_valid(const ucl_object_t *, char *, size_t);
int		 sdwan_store(ucl_object_t *, char *, size_t);
bool		 cred_named(const char *);
int		 api_sdwan_edges(struct http_request *);
int		 api_sdwan_rekey(struct http_request *);
int		 api_sdwan_lists(struct http_request *);
int		 api_sdwan_record(struct http_request *);
int		 api_sdwan_identities(struct http_request *);
bool		 sdwan_list_exists(const char *);
void		 sdwan_init(void);
void		 workflows_init(void);
void		 thread_log(int, const char *, ...) __printflike(2, 3);
int		 api_transfers(struct http_request *);
void		 transfers_init(void);
bool		 capture(struct http_request *, int, char *, size_t);
bool		 capture_path(const char *, int, char *, size_t);
const char	*ucl_str(const ucl_object_t *, const char *);
bool		 ucl_flag(const ucl_object_t *, const char *);

/* auth.c: WebAuthn and sessions. */
void		 auth_init(void);
bool		 session_valid(struct http_request *);
const char	*session_who(struct http_request *);
const char	*session_user(struct http_request *);
bool		 host_allowed(struct http_request *, const char *, bool, bool);
bool		 host_role_ok(struct http_request *, const char *, bool, bool);
int		 cred_count_of(const char *);
void		 creds_forget_user(const char *);
void		 sessions_end_user(const char *);

/* users.c: the console's users and their roles (RBAC). */
#define	ADMIN_USER	"admin"
enum role { ROLE_NONE, ROLE_VIEWER, ROLE_OPERATOR, ROLE_ADMIN };
enum crole { CROLE_NONE, CROLE_MEMBER, CROLE_OPERATOR, CROLE_OWNER };
void		 users_init(void);
bool		 user_name_ok(const char *);
bool		 user_exists(const char *);
enum crole	 user_console(const char *);
enum role	 user_host(const char *, const char *);
const char	*user_tenant(const char *);
const char	*role_name(enum role);
const char	*crole_name(enum crole);
bool		 user_path_ok(enum crole, const char *, bool);
void		 user_handle(const char *, char *, size_t);
bool		 invite_take(const char *, char *, size_t);
int		 api_users(struct http_request *);
int		 api_user(struct http_request *);
int		 api_user_invite(struct http_request *);
int		 api_groups(struct http_request *);
int		 api_group(struct http_request *);
int		 api_roles(struct http_request *);
#define	ROLES_LDAP_MAX	32
int		 roles_ldap_groups(const char **, const char **, int);
void		 users_ldap_sync(const char *, const char **, int);
int		 api_role(struct http_request *);
/* audit.c: the audit trail of Policy Actions (MEF 118.1 §13.1). */
void		 audit_add(const char *, const char *, const char *,
		    const char *, const char *, const char *, const char *, ...)
		    __printflike(7, 8);
int		 api_sdwan_audit(struct http_request *);
int		 api_wg_keypair(struct http_request *);

/* servers.c: the registry of arcana-agent instances. */
struct server {
	char	id[9];
	char	*name;
	char	*uri;
	char	*peer_name;
	char	*tenant;	/* the fleet it is in, or NULL */
	int	 safe_wait;	/* s a safe change waits; 0 the agent's own */
	ucl_object_t *pkg_repos;	/* {"jail, or . the host": {upgrade, install, base}}: pkg -r
				 * chosen there per action, or NULL */
};

void		 servers_init(void);
int		 servers_add(const char *, const char *, const char *);
const struct server *server_find(const char *);
const struct server *server_at(int);
int		 servers_move(const char *, const char *);
int		 servers_safe_wait(const char *);
#define	SAFE_WAIT_MIN	10	/* s, a rollback timer at least */
#define	SAFE_WAIT_MAX	3600

/* pki.c: the console's CA and host enrolment. */
int		 pki_init(void);
char		*pki_sign_host(const char *, const char *, char *, size_t);
const char	*pki_sign_data(const uint8_t *, size_t, uint8_t **, size_t *);
int		 api_ca(struct http_request *);

/* hosts.c: requests to arcana-agent over cblink, in Kore task threads. */
int		 hosts_init(void);
bool		 hosts_job_kind_known(const char *);
int		 workflows_kinds_check(void);
bool		 workflow_kind_uses(const char *, const char *);
void		 workflow_job_safe(ucl_object_t *);
char		*workflow_submit(const char *, const char *, const char *,
		    ucl_object_t *, int *, const char **, const char **);
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
bool		 hosts_read_known(const char *);
ucl_object_t	*sdwan_ready(const ucl_object_t *, ucl_object_t *);
char		*hosts_read_live(const char *, const char *, const char *,
		    const char *, const char *, void (*)(const char *, void *),
		    void *, int *);
char		*hosts_events(const char *, const char *, const char *,
		    uint64_t, int *);
char		*hosts_net(const char *, const char *, const char *,
		    const char *, int *);
char		*hosts_sysctl(const char *, const char *, const char *,
		    const char *, int *);
char		*hosts_sysctl_in(const char *, const char *, const char *,
		    const char *, const char *, int *);
char		*hosts_net_in(const char *, const char *, const char *,
		    const char *, const char *, int *);
char		*hosts_sdwan_set(const char *, const char *, const char *,
		    const char *, const char *, int *);
int		 api_sdwan_state(struct http_request *);
int		 api_security(struct http_request *);
char		*hosts_listen(const char *, const char *, const char *,
		    const char *, const char *, bool, int *);
char		*hosts_notify(const char *, const char *, const char *,
		    const char *, const char *, const char *, int *);
int		 api_server_move(struct http_request *);
void		 api_server_move_free(struct http_request *);
char		*security_build(const char *, const ucl_object_t *, const char *,
		    char *, size_t);
bool		 sdwan_edge_split(const char *, char *, size_t, char *,
		    size_t);
bool		 host_ref(const char *, char *, size_t, char *, size_t, char *,
		    size_t);
void		 host_refs(void);
const char	*hosts_connect(const char *, const char *, cbl_conn **,
		    cbl_tls **, struct arc_client *);
void		 hosts_release(const char *, const char *, cbl_conn *,
		    cbl_tls *, struct arc_client *, bool);

/* Route handlers, named in the Kore configuration. */
int		 api_health(struct http_request *);
int		 api_assetlinks(struct http_request *);
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
int		 api_update_notes(struct http_request *);
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
int		 api_jail_files(struct http_request *);
int		 api_builder(struct http_request *);
int		 api_builder_options(struct http_request *);
int		 api_suricata_rules(struct http_request *);
int		 api_netstore(struct http_request *);
int		 api_system(struct http_request *);
int		 api_smtpd(struct http_request *);
int		 api_certs(struct http_request *);
int		 api_ssh(struct http_request *);
int		 api_capture(struct http_request *);
int		 api_zfs_key(struct http_request *);
int		 api_tls(struct http_request *);
int		 api_transport(struct http_request *);
int		 api_config_export(struct http_request *);
char		*hosts_path_check(const char *, const char *, const char *,
		    const char *, const char *, const char *, const char *,
		    uint32_t, const char *, bool, int *);
/* troubleshoot.c: a packet's path across the hosts, and what stops it. */
int		 api_troubleshoot_path(struct http_request *);
void		 api_troubleshoot_free(struct http_request *);
int		 api_config_apply(struct http_request *);
/* templates.c: configuration templates, a host's setup by name. */
int		 api_templates(struct http_request *);
int		 api_template(struct http_request *);
bool		 template_name_ok(const char *);
ucl_object_t	*template_get(const char *);
char		*template_render(const char *, const ucl_object_t *, char *,
		    size_t);
int		 api_transport_switch(struct http_request *);
int		 api_sysctl(struct http_request *);
int		 api_processes(struct http_request *);
int		 api_log(struct http_request *);
int		 api_history(struct http_request *);
int		 api_events(struct http_request *);
int		 api_fw_trace(struct http_request *);
int		 api_path(struct http_request *);
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
int		 api_jobs_config(struct http_request *);
int		 api_job(struct http_request *);
void		 api_call_free(struct http_request *);

int		 arcw_onload(int);

#endif /* !_CONSOLE_H_ */
