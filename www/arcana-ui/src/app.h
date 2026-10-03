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
void		 arc_webauthn(int, int, const char *);
void		 arc_sw_register(void);
double		 arc_now(void);
void		 arc_title(const char *);
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

void		 api(const char *, const char *, const char *, api_cb *,
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
};

enum tab {
	TAB_SUMMARY,
	TAB_JAILS,
	TAB_SERVICES,
	TAB_NETWORK,
	TAB_PACKAGES,
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
};

enum netkind {
	NET_ROUTES,
	NET_NEXTHOPS,
	NET_CONNECTIONS,
	NET_SOCKETS,
};

/* The network tab's one table: what is shown, from which server. */
struct netview {
	enum netkind	 kind;
	int		 family;	/* 0 all, 4, 6 */
	char		 sid[9];	/* the server it came from */
	ucl_object_t	*data;		/* the reply, or NULL */
	double		 fetched;
	bool		 loading;
	char		 error[256];	int		 sort;		/* column sorted by, or -1 */
	bool		 sort_desc;
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
	bool		 tree_all;	/* every jail in the tree, room or not */
	ucl_object_t	*services;	/* last good services reply */
	double		 services_fetched;
	bool		 services_loading;
	char		 services_error[256];
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
	long long	 job;		/* its number there, 0 if not a job */
	long long	 watched;	/* the number, kept after it is done */
	double		 next_poll;
	bool		 polling;
	bool		 waiting;	/* the host does not answer; it runs on */
	int		 what;		/* JOB_*: what to refresh when done */
	char		 target[256];	/* the jail or service */
};

enum {
	JOB_WATCH = -1,		/* a job looked at, not sent from here */
	JOB_JAIL,
	JOB_ADDRESS,
	JOB_SERVICE,
	JOB_SERVICE_CONFIG,
	JOB_PACKAGES,
};

/* A change held back to be sent with others as one batch. */
struct queued {
	char		*json;		/* the job, as the API takes it */
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
	int		 install;	/* 0 no offer, 1 prompt, 2 iOS, 3 menu */
	bool		 setup_required;
	char		 version[32];	/* the console's, from /api/health */
	char		 agent_build[65]; /* of the arcana-agent it sends */
	char		 agent_version[32]; /* and its version */
	char		 agent_source[256]; /* repository a host builds it from */
	char		 update_latest[64];	/* a newer release, or "" */
	char		 update_url[512];
	char		 auth_error[256];
	char		 origin_error[400];	/* opened at the wrong address */
	bool		 auth_busy;

	struct server	 servers[MAX_SERVERS];
	int		 nservers;
	int		 sel;		/* selected server, or -1 */
	char		 jail[256];	/* open in the drawer, or "" */
	char		 filter[64];
	enum node	 node;		/* what the tree has selected */
	enum tab	 tab;		/* of the selected server */
	char		 service[65];	/* open in the drawer, or "" */
	char		 service_busy[65];	/* an action in flight */
	ucl_object_t	*svc_config;	/* the open service's config reply */
	bool		 svc_loading;
	int		 svc_sort;	/* SVC_SORT_*: running first at start */
	bool		 svc_sort_desc;
	int		 jail_sort;	/* JAIL_SORT_*: running first at start */
	bool		 jail_sort_desc;
	char		 svc_error[256];
	struct netview	 net;
	struct pkgview	 pkg;
	bool		 servers_loaded;

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
void		 toast(bool, const char *, ...)
		    __attribute__((format(printf, 2, 3)));
struct server	*cur_server(void);
struct jailui	*jailui(struct server *, const char *);
const ucl_object_t *find_jail(const struct server *, const char *);
struct op	*op_find(int);

/* actions.c: what the buttons do. */
void		 refresh_servers(void);
void		 job_send(struct server *, char *, const char *, int,
		    const char *);
void		 queue_run(void);
void		 queue_clear(void);
void		 jobs_poll(void);
void		 refresh_jails(struct server *, bool);
void		 jail_action(const char *, const char *);
void		 refresh_services(struct server *, bool);
void		 service_action(const char *, const char *);
void		 service_config(const char *, const char *);
void		 refresh_network(struct server *, bool);
void		 refresh_stats(struct server *);
bool		 agent_outdated(const struct server *);
void		 agent_update(struct server *, bool);
void		 agent_build(struct server *);
void		 refresh_jobs(struct server *);
void		 open_job(struct server *, long long, const char *);
void		 refresh_packages(struct server *, bool);
void		 pkg_upgrade(struct server *, const char *, bool);
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
void		 view_summary(struct html *, struct server *);
void		 view_jobs(struct html *, struct server *);
const char	*state_class(const struct server *, const ucl_object_t *,
		    const struct jailui *);
void		 fmt_age(char *, size_t, double);
void		 fmt_dur(char *, size_t, int64_t);

#endif /* !_APP_H_ */
