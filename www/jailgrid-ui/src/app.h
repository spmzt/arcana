/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * The jailgrid console, a C program compiled to WebAssembly.
 */

#ifndef _APP_H_
#define _APP_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <ucl.h>

#define	APP_NAME		"Jailgrid"
#define	MAX_SERVERS		64
#define	MAX_OPS			40
#define	MAX_TOASTS		4
#define	HEALTH_MS		15000
#define	REFRESH_MS		10000
#define	STALE_MS		30000
#define	AGE_STEP_MS		10000	/* how often ages are redrawn */
#define	UPDATE_MS		(6 * 3600 * 1000)

/* bridge.js */
void		 jg_patch(const char *, const char *);
void		 jg_focus(const char *);
void		 jg_events_init(void);
void		 jg_http(int, const char *, const char *, const char *);
void		 jg_webauthn(int, int, const char *);
void		 jg_sw_register(void);
double		 jg_now(void);
void		 jg_title(const char *);
char		*jg_hostname(void);
int		 jg_fx_get(void);
void		 jg_fx_set(int);

/* Called from bridge.js. */
void		 jg_on_action(char *, char *, char *);
void		 jg_on_http(int, int, char *);
void		 jg_on_webauthn(int, int, char *);
void		 jg_on_net(int);
void		 jg_on_visible(int);

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

enum tab {
	TAB_JAILS,
	TAB_SERVICES,
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
};

enum modal {
	MODAL_NONE,
	MODAL_CONFIRM,
	MODAL_RAW,
	MODAL_ADD_SERVER,
	MODAL_ENROL,
	MODAL_KEYS,
	MODAL_ADDRESS,
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
	bool		 setup_required;
	char		 version[32];	/* the console's, from /api/health */
	char		 update_latest[64];	/* a newer release, or "" */
	char		 update_url[512];
	char		 auth_error[256];
	bool		 auth_busy;

	struct server	 servers[MAX_SERVERS];
	int		 nservers;
	int		 sel;		/* selected server, or -1 */
	char		 jail[256];	/* open in the drawer, or "" */
	char		 filter[64];
	enum tab	 tab;		/* of the selected server */
	char		 service[65];	/* open in the drawer, or "" */
	char		 service_busy[65];	/* an action in flight */
	ucl_object_t	*svc_config;	/* the open service's config reply */
	bool		 svc_loading;
	char		 svc_error[256];
	bool		 servers_loaded;

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
void		 refresh_jails(struct server *, bool);
void		 jail_action(const char *, const char *);
void		 refresh_services(struct server *, bool);
void		 service_action(const char *, const char *);
void		 service_config(const char *, const char *);
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
void		 view(struct html *);
void		 view_trace(struct html *, const struct op *);
void		 view_services(struct html *, struct server *);
void		 view_service_drawer(struct html *, struct server *);
const char	*state_class(const struct server *, const ucl_object_t *,
		    const struct jailui *);
void		 fmt_age(char *, size_t, double);
void		 fmt_dur(char *, size_t, int64_t);

#endif /* !_APP_H_ */
