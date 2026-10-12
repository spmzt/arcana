/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * The arcana console, a C program compiled to WebAssembly.
 */

#ifndef _APP_H_
#define _APP_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <ucl.h>

#define	APP_NAME		"Arcana"
#define	MAX_SERVERS		64
#define	MAX_OPS			40
#define	MAX_TOASTS		4
#define	HISTORY			48	/* usage samples kept per server */
#define	HEALTH_MS		15000
#define	REFRESH_MS		10000
#define	STALE_MS		30000
#define	AGE_STEP_MS		10000	/* how often ages are redrawn */
#define	NOTIFY_MS		10000	/* a task this long is announced */
#define	JOB_POLL_MS		1000	/* a running job is read this often */
#define	MAX_BATCH		64	/* changes held in the queue */
#define	UPDATE_MS		(6 * 3600 * 1000)

/* bridge.js */
void		 arc_patch(const char *, const char *);
void		 arc_set_class(const char *, const char *, int);
void		 arc_focus(const char *);
void		 arc_events_init(void);
void		 arc_http(int, const char *, const char *, const char *);
void		 arc_http_abort(int);
void		 arc_reload(void);
void		 arc_push_sync(void);
void		 arc_push_send(const char *, const char *);
void		 arc_push_remove(const char *);
char		*arc_push_here(void);
char		*arc_store_get(const char *);
void		 arc_store_set(const char *, const char *);
char		*arc_theme_get(void);
void		 arc_theme_set(const char *);
void		 arc_webauthn(int, int, const char *);
void		 arc_sw_register(void);
double		 arc_now(void);
int		 arc_narrow(void);
void		 arc_stream_send(const char *);
int		 arc_map_w(void);
int		 arc_map_h(void);
void		 arc_title(const char *);
char		*arc_loc_get(void);
void		 arc_loc_set(const char *, int);
char		*arc_hostname(void);
char		*arc_origin(void);
int		 arc_fx_get(void);
int		 arc_tree_room(void);
int		 arc_open_get(const char *);
void		 arc_open_set(const char *, int);
int		 arc_queue_get(void);
void		 arc_queue_set(int);
void		 arc_fx_set(int);
void		 arc_notify(const char *, const char *);
int		 arc_notify_state(void);
void		 arc_notify_ask(void);
void		 arc_push_off(void);
int		 arc_install_state(void);
void		 arc_install_prompt(void);
void		 arc_install_dismiss(void);

/* Called from bridge.js. */
void		 arc_on_action(char *, char *, char *);
void		 arc_on_http(int, int, char *);
void		 arc_on_webauthn(int, int, char *);
void		 arc_on_net(int);
void		 arc_on_visible(int);

/* html.c: markup with every dynamic piece escaped. */
struct html {
	char	*s;
	size_t	 len;
	size_t	 cap;
};

void		 h_raw(struct html *, const char *);
void		 h_txt(struct html *, const char *);
void		 h_fit(struct html *, const char *, int);
void		 h_fmt(struct html *, const char *, ...)
		    __attribute__((format(printf, 2, 3)));
void		 h_attr(struct html *, const char *, const char *);
const char	*h_word(const char *, const char *);
char		*h_take(struct html *);
void		 h_reset(struct html *);

/* json.c: libucl helpers. */
ucl_object_t	*json_parse(const char *);
const ucl_object_t *jget(const ucl_object_t *, const char *);
const char	*jstr(const ucl_object_t *, const char *);
int64_t		 jint(const ucl_object_t *, const char *, int64_t);
double		 jnum(const ucl_object_t *, const char *, double);
bool		 jbool(const ucl_object_t *, const char *);
char		*json_quote(const char *);

/* api.c: requests to the console's API with a callback each. */
typedef void	 api_cb(int, const ucl_object_t *, const char *, void *);

int		 api(const char *, const char *, const char *, api_cb *,
		    void *);
void		 webauthn(bool, const char *, void (*)(bool, const char *,
		    void *), void *);

/* State. */
enum link {
	LINK_UNKNOWN,
	LINK_UP,
	LINK_DOWN,
};

enum screen {
	SCREEN_BOOT,
	SCREEN_LOGIN,
	SCREEN_ENROL,
	SCREEN_CONSOLE,
	SCREEN_OFFLINE,		/* the shell, without the console */
};

/* What is selected in the tree: the fleet, a host, or a jail of it. */
enum jail_sort { JAIL_SORT_RUNNING, JAIL_SORT_NAME };
enum svc_sort { SVC_SORT_RUNNING, SVC_SORT_ENABLED, SVC_SORT_NAME };

enum node {
	NODE_FLEET,
	NODE_HOST,
	NODE_JAIL,
	NODE_NETWORK,		/* the fleet's network, as a map */
	NODE_API,		/* the console's API, as it is documented */
	NODE_USAGE,		/* how busy every host has been, drawn */
	NODE_WORKFLOWS,		/* chains of steps, run on several hosts */
	NODE_SDWAN,		/* SD-WAN services, as MEF 70.2 says them */
	NODE_SETTINGS,		/* the console's settings, a tab each */
	NODE_DEVICES,		/* the hosts as a table */
};

enum tab {
	TAB_SUMMARY,
	TAB_JAILS,
	TAB_SERVICES,
	TAB_NETWORK,
	TAB_FIREWALL,
	TAB_PACKAGES,
	TAB_STORAGE,
	TAB_KERNEL,
	TAB_SYSCTL,
	TAB_PROCESSES,
	TAB_LOG,
	TAB_JOBS,
};

/* The packages tab: pending upgrades of the host or of one jail. */
struct pkgview {
	char		 sid[9];	/* the server they came from */
	char		 jail[256];	/* "" for the host */
	ucl_object_t	*data;		/* the reply, or NULL */
	double		 fetched;
	bool		 loading;
	bool		 busy;		/* an upgrade runs */
	char		 error[256];
	char		 result[256];	/* what the last upgrade said */
	char		*names;		/* what it was asked of: JSON, or NULL */
	int		 mode;		/* 0 the installed, 1 the upgrades */
	int		 ip;		/* pkg -4 or -6, or 0 either */
};

enum netkind {
	NET_ROUTES,
	NET_NEXTHOPS,
	NET_CONNECTIONS,
	NET_SOCKETS,
	NET_INTERFACES,
	NET_NETGRAPH,
	NET_WIREGUARD,
	NET_BIRD,
	NET_BRIDGES,
	NET_GENEVE,
	NET_NHGROUPS,
	NET_NEIGHBOURS,
	NET_IPSEC,
};
/* A plugin's view: a tab of its own on a host that has it. */
#define	NET_PLUGIN(k)	((k) == NET_WIREGUARD || (k) == NET_BIRD ||	\
			    (k) == NET_IPSEC)

/* The network tab's one table: what is shown, from which server. */
struct netview {
	enum netkind	 kind;
	int		 family;	/* 0 all, 4, 6 */
	char		 sid[9];	/* the server it came from */
	char		 jail[256];	/* and the vnet jail of it, or "" */
	ucl_object_t	*data;		/* the reply, or NULL */
	double		 fetched;
	bool		 loading;
	char		 error[256];	int		 sort;		/* column sorted by, or -1 */
	bool		 sort_desc;
	char		 host_filter[129]; /* routes: searched for on the host */
	bool		 paused;	/* connections, sockets: not read again by themselves */
	int		 fib;		/* the routing table shown; 0 the first */
};

enum pending {
	PEND_NONE,
	PEND_START,
	PEND_STOP,
	PEND_RESTART,
	PEND_KILL,
	PEND_ADDRESS,
};

struct jailui {
	char		 name[256];
	enum pending	 pending;
	char		 error[256];
};

struct server {
	char		 id[9];
	char		 name[65];
	char		 uri[256];
	bool		 local;
	ucl_object_t	*list;		/* last good list reply */
	double		 fetched;	/* when it arrived, ms */
	bool		 loading;
	bool		 failed;	/* the last refresh failed */
	char		 error[256];
	struct jailui	*jui;
	size_t		 njui;
	ucl_object_t	*stats;		/* last usage reply */
	double		 stats_fetched;
	bool		 stats_loading;
	float		 hist[3][HISTORY];	/* cpu, memory, zfs, in % */
	int		 nhist;		/* samples in hist, newest last */
	ucl_object_t	*jobs;		/* the host's own list of jobs */
	bool		 jobs_loading;
	double		 restart_until;	/* ms: its agent is restarting after an update; 0 none */
	double		 restart_asked;	/* ms: when it was last asked how it is */
	bool		 tree_all;	/* every jail in the tree, room or not */
	ucl_object_t	*services;	/* last good services reply */
	double		 services_fetched;
	bool		 services_loading;
	char		 services_error[256];
	int		 safe_wait;	/* s, its rollback timer; 0 the agent's */
};

enum opstate {
	OP_RUNNING,
	OP_OK,
	OP_FAILED,
};

/* One thing done to a host, for the activity log and the trace view. */
struct op {
	int		 id;
	char		 title[160];
	char		 server[65];
	enum opstate	 state;
	double		 started;
	double		 finished;
	ucl_object_t	*trace;
	char		*diff;
	char		 error[512];
	/* A job on a host: read until it is done. */
	char		 sid[9];
	int		 req;		/* the request it waits for, if it can be given up */
	long long	 job;		/* its number there, 0 if not a job */
	long long	 watched;	/* the number, kept after it is done */
	double		 next_poll;
	bool		 polling;
	bool		 waiting;	/* the host does not answer; it runs on */
	int		 what;		/* JOB_*: what to refresh when done */
	char		*again;		/* a job as it was sent, to send again */
	char		 target[256];	/* the jail or service */
};

enum {
	JOB_WATCH = -1,		/* a job looked at, not sent from here */
	JOB_JAIL,
	JOB_ADDRESS,
	JOB_SERVICE,
	JOB_SERVICE_CONFIG,
	JOB_PACKAGES,
	JOB_IFACE,
	JOB_KERNEL,
	JOB_SYSCTL,
	JOB_FIREWALL,
	JOB_STORAGE,
	JOB_PROCESS,
};

/* A change held back to be sent with others as one batch. */
struct queued {
	char		*json;		/* the job, as the API takes it */
	char		 sid[9];	/* the host it is for */
	char		 host[64];	/* and its name, for the list */
	char		 title[160];
	int		 what;
	char		 target[256];
};

enum modal {
	MODAL_NONE,
	MODAL_CONFIRM,
	MODAL_RAW,
	MODAL_ADD_SERVER,
	MODAL_ENROL,
	MODAL_KEYS,
	MODAL_ADDRESS,
	MODAL_AGENT_UPDATE,
	MODAL_SETTINGS,
	MODAL_HOST_KEY,
	MODAL_IF_ADDRESS,
	MODAL_ROUTE,
	MODAL_TUNNEL,
	MODAL_IF_CREATE,
	MODAL_IF_SET,
	MODAL_NG_CONNECT,
	MODAL_NG_MKPEER,
	MODAL_WG_INIT,
	MODAL_WG_PEER,
	MODAL_WG_CLIENT,
	MODAL_WG_CONF,
	MODAL_JAIL_NEW,
	MODAL_JAIL_DEFAULTS,
	MODAL_JAIL_FILES,
	MODAL_JAIL_TEMPLATE,
	MODAL_JAIL_REMOVE,
	MODAL_NEIGH,
	MODAL_BIRD_PROTO,
	MODAL_BIRD_BLOCK,
	MODAL_BIRD_RPKI,
	MODAL_BIRD_FILE,
	MODAL_IPSEC_CONN,
	MODAL_IPSEC_CHILD,
	MODAL_SD_UCS,
	MODAL_SD_EDGE,
	MODAL_SD_LINK,
	MODAL_SD_IDENTITY,
	MODAL_SD_CONFIG,
	MODAL_SD_SWVC,
	MODAL_SD_ZONE,
	MODAL_SD_SECPOL,
	MODAL_SD_LIST,
	MODAL_SD_FLOW,
	MODAL_SD_POLICY,
	MODAL_SD_EP,
	MODAL_SD_MAP,
	MODAL_PKG_INSTALL,
	MODAL_WF_RUN,
	MODAL_IF_VNET,
	MODAL_STORAGE,
	MODAL_LOOKUP,
	MODAL_NHOP,
};

struct confirm {
	char		 title[160];
	char		 body[512];
	char		 button[32];
	bool		 danger;
	char		 typed[256];	/* must be typed to confirm, or "" */
	char		 act[64];	/* action to run on confirm */
	char		 arg[256];
	char		 value[512];
};

struct toast {
	char		 text[256];
	bool		 error;
	double		 until;
};

struct app {
	enum screen	 screen;
	bool		 online;	/* navigator.onLine */
	enum link	 api;		/* /api/health */
	bool		 visible;
	bool		 fx;		/* blur and idle animations */
	int		 notify;	/* 0 not asked, 1 granted, 2 denied, 3 none */
	bool		 notify_off;	/* turned off here, though allowed */
	int		 install;	/* 0 no offer, 1 prompt, 2 iOS, 3 menu */
	bool		 setup_required;
	char		 version[32];	/* the console's, from /api/health */
	double		 health_retry;	/* ms: ask for its health again then; 0 no */
	char		 agent_build[65]; /* of the arcana-agent it sends */
	char		 agent_version[32]; /* and its version */
	char		 agent_source[256]; /* repository a host builds it from */
	ucl_object_t	*notes;		/* /api/update/notes: what is new */
	bool		 notes_busy;
	char		 notes_error[200];
	char		 notes_for[16];	/* console or agent */
	char		 update_latest[64];	/* a newer release, or "" */
	char		 update_url[512];
	char		 auth_error[256];
	char		 origin_error[400];	/* opened at the wrong address */
	char		 console_origin[256];	/* web.conf's origin, as told */
	bool		 auth_busy;

	struct server	 servers[MAX_SERVERS];
	int		 nservers;
	int		 sel;		/* selected server, or -1 */
	char		 jail[256];	/* open in the drawer, or "" */
	char		 net_jail[256];	/* whose network the tab shows: a vnet jail, or "" the host */
	int		 netsect;	/* the Network section's tab: NETSECT_* */
	int		 settab;	/* the Settings section's tab: SET_* */
	char		 ipsec_auth[8];	/* the connection form: how the peer is known */
	char		 filter[64];
	enum node	 node;		/* what the tree has selected */
	enum tab	 tab;		/* of the selected server */
	char		 service[65];	/* open in the drawer, or "" */
	ucl_object_t	*svc_config;	/* the open service's config reply */
	bool		 svc_loading;
	int		 svc_sort;	/* SVC_SORT_*: running first at start */
	bool		 svc_sort_desc;
	bool		 peek;		/* app.jail is shown in a box over the page */
	bool		 rail_open;	/* the tree, on a narrow screen, is unfolded */
	bool		 who_open;	/* the top bar's menu, on a phone */
	char		 theme[16];	/* "" for the default */
	ucl_object_t	*settings;	/* /api/settings, while its dialog is open */
	ucl_object_t	*push;		/* /api/push: the devices that are told */
	ucl_object_t	*tokens;	/* /api/tokens: read-only API tokens */
	char		 token_name[65];	/* the name typed for a new one */
	char		 token_value[80];	/* a new one's value, shown once */
	ucl_object_t	*build_reply;	/* a build that needs the user: host keys */
	char		 build_sid[9];	/* and the host it was asked of */
	bool		 build_console;	/* it was the console's own update */
	ucl_object_t	*schema;	/* the family's, from schema.json */
	bool		 schema_loading;
	bool		 schema_failed;
	bool		 trace_schema;	/* shown beside the operation */
	int		 jail_sort;	/* JAIL_SORT_*: running first at start */
	bool		 jail_sort_desc;
	char		 svc_error[256];
	struct netview	 net;
	struct pkgview	 pkg;
	bool		 servers_loaded;
	char		 local[12];	/* the agent beside the console: added, absent, denied, ... */
	char		 local_agent[160];	/* and its socket */

	bool		 queue_on;	/* changes are held, not sent */
	struct queued	 batch[MAX_BATCH];
	int		 nbatch;
	struct op	 ops[MAX_OPS];	/* newest first */
	int		 nops;
	int		 nextop;
	int		 trace_op;	/* op shown in the trace panel, or -1 */
	int		 trace_step;	/* selected step, or -1 */
	bool		 dock_open;

	enum modal	 modal;
	struct confirm	 confirm;
	int		 raw_op;
	ucl_object_t	*keys;
	char		 modal_error[256];
	bool		 modal_busy;
	char		*preview;	/* address dry-run diff */
	char		 enrol_cmd[600];	/* the command for a joining host */

	struct toast	 toasts[MAX_TOASTS];
	int		 ntoasts;
};

extern struct app app;

/* main.c */
void		 render(void);
void		 loc_pending(void);
void		 toast(bool, const char *, ...)
		    __attribute__((format(printf, 2, 3)));
struct server	*cur_server(void);
struct jailui	*jailui(struct server *, const char *);
const ucl_object_t *find_jail(const struct server *, const char *);
struct op	*op_find(int);
struct op	*op_begin(const char *, const char *);
void		 op_end(struct op *, bool, const char *);
void		 confirm(const char *, const char *, const char *, bool,
		    const char *, const char *, const char *, const char *);

/* actions.c: what the buttons do. */
void		 refresh_servers(void);
void		 ops_save(void);
void		 op_retry(int);
bool		 box_shut(const char *);
void		 box_head(struct html *, const char *, const char *);
void		 ops_load(void);
void		 job_send(struct server *, char *, const char *, int,
		    const char *);
void		 job_send_host(struct server *, char *, const char *, int,
		    const char *);
void		 job_send_many(struct server *, struct queued *, int, int);
void		 queue_run(void);
void		 queue_clear(void);
void		 jobs_poll(void);
void		 refresh_jails(struct server *, bool);
void		 jail_action(const char *, const char *);
void		 refresh_services(struct server *, bool);
void		 service_action(const char *, const char *);
void		 service_config(const char *, const char *);
void		 refresh_network(struct server *, bool);
const char	*net_scope(void);
bool		 net_jail_ok(const ucl_object_t *);
const char	*plugin_where(const struct server *, const char *);
const char	*kind_plugin(int);
bool		 plugin_at(const struct server *, const char *, const char *);
bool		 has_plugin(const struct server *, const char *);
void		 refresh_stats(struct server *);
bool		 agent_outdated(const struct server *);
void		 agent_update(struct server *, bool);
bool		 version_older(const char *, const char *);
void		 fmt_bytes(char *, size_t, int64_t);
void		 notes_load(const char *, const char *, const char *, bool);
void		 agent_build(struct server *, const char *, bool);
void		 agent_restarts(double);
void		 op_cancel(struct op *);
void		 if_address(struct server *, const char *, const char *, bool,
		    bool);
void		 if_state(struct server *, const char *, bool);
void		 route_change(struct server *, const char *, const char *, bool,
		    bool, int, int, int, const char *);
bool		 service_busy(const struct server *, const char *);
bool		 packages_busy(const struct server *);
void		 load_settings(void);
void		 load_push(void);
void		 load_tokens(void);
void		 token_new(void);
void		 token_del(const char *);
void		 save_settings(const ucl_object_t *);
void		 load_schema(void);
const char	*schema_op(const ucl_object_t *);
void		 view_schema(struct html *, const char *);
void		 refresh_jobs(struct server *);
void		 open_job(struct server *, long long, const char *);
void		 refresh_packages(struct server *, bool);
void		 pkg_upgrade(struct server *, const char *, bool, bool);
void		 address_change(const char *, const char *, bool, bool, bool,
		    bool);
void		 check_health(void);
void		 check_update(void);
void		 auth_status(void);
void		 login(bool);
void		 enrol(const char *, const char *);
void		 add_key(const char *);
void		 logout(void);
void		 load_keys(void);
void		 delete_key(const char *);
void		 add_server(const char *, const char *, const char *);
void		 enrol_host(const char *, const char *);
void		 delete_server(const char *);

/* view.c, graph.c */
#define	VIEW_REGIONS		8
extern const char *const view_regions[VIEW_REGIONS];
void		 view(struct html *);
void		 view_shell(struct html *);
void		 view_region(struct html *, int);
bool		 view_with_drawer(void);
void		 view_trace(struct html *, const struct op *);
void		 view_services(struct html *, struct server *);
void		 view_service_drawer(struct html *, struct server *);
void		 view_network(struct html *, struct server *);
void		 view_gauges(struct html *, struct server *);
void		 view_packages(struct html *, struct server *);
void		 view_fleet(struct html *);
void		 view_devices(struct html *);
int		 count_state(const struct server *, const char *);
void		 view_summary(struct html *, struct server *);
void		 view_jobs(struct html *, struct server *);

/* topo.c: the fleet's network as a map, traffic, routes, netgraph. */
void		 view_netmap(struct html *);
void		 view_netgraph(struct html *, struct server *,
		    const ucl_object_t *);
void		 view_lookup(struct html *, const struct server *);
void		 topo_open(void);
void		 topo_tick(double);
void		 topo_poll(struct server *);
void		 topo_spark(struct html *, const struct server *, const char *);
void		 topo_lookup(struct server *, const char *, int);
void		 topo_lookup_clear(void);
bool		 topo_action(const char *, const char *, const char *);
bool		 ng_action(const char *, const char *, const char *);
bool		 topo_form(const char *, const ucl_object_t *);
bool		 topo_modal(struct html *);
void		 topo_if_create_open(const char *, const char *);
void		 fmt_rate(char *, size_t, double);

/* vpn.c: a host's WireGuard interfaces and its BIRD. */
void		 view_wireguard(struct html *, struct server *,
		    const ucl_object_t *);
void		 view_bird(struct html *, struct server *, const ucl_object_t *);
bool		 vpn_action(const char *, const char *, const char *);
bool		 vpn_form(const char *, const ucl_object_t *);
bool		 vpn_modal(struct html *);
/* ipsec.c: a host's strongSwan, IKEv2 only. */
void		 view_ipsec(struct html *, struct server *,
		    const ucl_object_t *);
bool		 ipsec_action(const char *, const char *, const char *);
bool		 ipsec_form(const char *, const ucl_object_t *);
bool		 ipsec_modal(struct html *);
void		 vpn_age(char *, size_t, int64_t);
void		 qr_svg(struct html *, const char *, const char *);
/* jailmk.c: jails made from the page, their defaults and templates. */
void		 jailmk_buttons(struct html *);
bool		 jailmk_modal(struct html *);
bool		 jailmk_form(const char *, const ucl_object_t *);
bool		 jailmk_action(const char *, const char *, const char *);
/* netview.c: a neighbour set by hand. */
bool		 neigh_modal(struct html *);
bool		 neigh_form(const char *, const ucl_object_t *);
bool		 neigh_action(const char *, const char *, const char *);

/* bird.c: BIRD's neighbours and its configuration. */
bool		 bird_action(const char *, const char *, const char *);
bool		 bird_form(const char *, const ucl_object_t *);
bool		 bird_modal(struct html *);
void		 bird_tick(double);
/* tbl.c: every table sorts by its columns and is filtered. */
struct tcol {
	const char	*title;
	const char	*key;		/* NULL: not to be sorted by */
	bool		 num;
};
void		 tbl_head(struct html *, const char *, const struct tcol *, int,
		    int);
const ucl_object_t **tbl_rows(const char *, const ucl_object_t *,
		    const struct tcol *, int, const char *);
bool		 tbl_sorted(const char *);
void		 tbl_set(const char *, int, bool);
int		 tbl_col(const char *, bool *);
bool		 tbl_action(const char *, const char *, const char *);
void		 refresh_kernel(struct server *, bool);
void		 apidoc_open(void);
void		 view_apidoc(struct html *);
bool		 apidoc_action(const char *, const char *, const char *);
void		 net_live_tick(double);
int		 routes_held(void);
void		 network_more(struct server *);
void		 refresh_firewall(struct server *, bool);
bool		 firewall_rail(struct html *);
bool		 firewall_rail_away(void);
void		 firewall_tick(double);
void		 view_firewall(struct html *, struct server *);
bool		 firewall_form(const char *, const ucl_object_t *);
bool		 firewall_action(const char *, const char *, const char *);
void		 view_bridges(struct html *, struct server *,
		    const ucl_object_t *);
void		 view_geneve(struct html *, struct server *,
		    const ucl_object_t *);
bool		 l2_form(const char *, const ucl_object_t *);
bool		 l2_action(const char *, const char *, const char *);
/* procs.c, logs.c, usage.c: what runs, what was written, how busy. */
void		 refresh_procs(struct server *, bool);
void		 procs_tick(double);
void		 view_procs(struct html *, struct server *);
bool		 procs_form(const char *, const ucl_object_t *);
bool		 procs_action(const char *, const char *, const char *);
void		 refresh_logs(struct server *, bool);
void		 logs_tick(double);
void		 logs_stream(const ucl_object_t *);
void		 view_logs(struct html *, struct server *);
bool		 logs_form(const char *, const ucl_object_t *);
bool		 logs_action(const char *, const char *, const char *);
void		 usage_open(void);
void		 usage_tick(double);
int		 usage_if_rates(const char *, const char *, bool, double,
		    double *, double *, int);
int		 usage_step(const char *);
int		 topo_addr_owner(const char *, char *, size_t, char *, size_t);
void		 topo_poll_all(void);
int		 topo_gw_owner(const char *, int, const char *, char *, size_t,
		    char *, size_t);
bool		 ecmp_shown(void);
void		 ecmp_tick(double);
void		 ecmp_group(struct html *, const struct server *,
		    const ucl_object_t *);
void		 view_ecmp(struct html *);
void		 nhop_modal(struct html *);
bool		 nhop_action(const char *, const char *, const char *);
void		 ecmp_head(struct html *);
enum { NETSECT_MAP, NETSECT_GROUPS, NETSECT_TRACE };
void		 view_traceroute(struct html *);
bool		 mtr_action(const char *, const char *, const char *);
void		 mtr_tick(double);
int		 topo_if_mtu(int, const char *);
const char	*topo_host_addr(int, int);
bool		 ecmp_action(const char *, const char *, const char *);
void		 view_usage(struct html *);
bool		 usage_action(const char *, const char *, const char *);
bool		 usage_form(const char *, const ucl_object_t *);
void		 fmt_size(char *, size_t, double);
void		 refresh_sysctl(struct server *, bool);
void		 sysctl_stream(const ucl_object_t *);
void		 network_stream(const ucl_object_t *);
void		 view_sysctl(struct html *, struct server *);
bool		 sysctl_form(const char *, const ucl_object_t *);
bool		 sysctl_action(const char *, const char *, const char *);
void		 view_safe(struct html *, struct server *);
void		 servers_cb(int, const ucl_object_t *, const char *, void *);
struct plugin_pkg {
	const char	*plugin, *title, *program, *package;
};
const struct plugin_pkg *plugin_pkg(const char *);
bool		 plugin_installing(const struct server *, const char *);
void		 plugin_install(struct server *, const char *);
void		 refresh_transport(struct server *, bool, bool);
void		 transport_tick(double);
void		 view_transport(struct html *, struct server *);
void		 refresh_storage(struct server *, bool);
void		 view_storage(struct html *, struct server *);
/* workflow.c: the workflows, their editor and their runs. */
void		 workflows_open(void);
void		 workflows_tick(double);
void		 view_workflows(struct html *);
bool		 workflows_action(const char *, const char *, const char *);
/* view.c: the settings' tabs. */
enum { SET_LOOK, SET_NOTIFY, SET_TOKENS, SET_KEYS, SET_CONSOLE,
    SET_WEBCONF, SET_NEWS };
int		 settab_of(const char *);
const char	*settab_arg(int);
/* sdwan.c: the SD-WAN services the console keeps. */
void		 sdwan_open(void);
void		 sdwan_tick(double);
void		 view_sdwan(struct html *);
bool		 sdwan_action(const char *, const char *, const char *);
bool		 sdwan_form(const char *, const ucl_object_t *);
bool		 sdwan_modal(struct html *);
bool		 workflows_form(const char *, const ucl_object_t *);
bool		 workflows_modal(struct html *);
void		 storage_tick(double);
bool		 storage_modal(struct html *);
void		 storage_modal_buttons(struct html *);
bool		 storage_form(const char *, const ucl_object_t *);
bool		 storage_action(const char *, const char *, const char *);
void		 view_kernel(struct html *, struct server *);
bool		 kernel_form(const char *, const ucl_object_t *);
bool		 kernel_action(const char *, const char *, const char *);
void		 topo_poll_host(struct server *);
void		 bird_modal_buttons(struct html *);
const char	*state_class(const struct server *, const ucl_object_t *,
		    const struct jailui *);
void		 fmt_age(char *, size_t, double);
void		 fmt_dur(char *, size_t, int64_t);

#endif /* !_APP_H_ */
