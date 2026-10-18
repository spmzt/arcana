/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

#ifndef _HARNESS_H_
#define _HARNESS_H_

#include <sys/types.h>

#include <atf-c.h>
#include <string.h>

/*
 * ATF's own compares with strcmp(3), which a NULL (a field a slow reply
 * did not have) makes crash, losing the rest of the case: said instead.
 */
#undef	ATF_CHECK_STREQ
#define	ATF_CHECK_STREQ(want, got) do {					\
	const char *want_ = (want), *got_ = (got);			\
									\
	ATF_CHECK_MSG(want_ != NULL && got_ != NULL &&			\
	    strcmp(want_, got_) == 0, "%s != %s (%s != %s)", #want, #got,	\
	    want_ != NULL ? want_ : "(null)", got_ != NULL ? got_ :	\
	    "(null)");							\
} while (0)
#include <stdbool.h>
#include <ucl.h>

#define	ORIGIN		"http://localhost:8443"
#define	RP_ID		"localhost"

struct resp {
	int		 status;
	char		*body;
	ucl_object_t	*json;
};

#define	EXPECT(r, code) ATF_REQUIRE_MSG((r)->status == (code),		\
	"HTTP %d, expected %d: %s", (r)->status, (code), (r)->body)

extern char		 cookie[160];	/* "arc_session=..." */
extern bool		 send_xjg;	/* send X-Arcana: 1 */
extern const char	*origin_hdr;
extern char		 harness_origin[64];
extern int		 harness_port;
extern char		 harness_webconf[1024];
extern bool		 harness_other_agent;
extern bool		 harness_newer_agent;
extern bool		 harness_local_agent;
extern bool		 harness_webconf_only_local;
extern char		 harness_telegram_api[128];

const char	*locate(const atf_tc_t *, const char *, const char *,
		    const char *);
void		 put(const char *, const char *);
pid_t		 spawn(char *const [], const char *);
pid_t		 spawn_server(char *const [], const char *);
void		 wait_for(const char *);
void		 show(const char *);
bool		 run_prog(char *const []);
void		 start(const atf_tc_t *, int, const char *);
void		 stop(void);
void		 restart_console(void);
void		 console_stop(void);
void		 console_start(void);
void		 http_abandon(const char *);
int		 tcp_socket(int);
void		 http(const char *, const char *, const char *, struct resp *);
int		 ws_open(const char *);
void		 ws_send(int, const char *);
char		*ws_recv(int);
void		 http_bearer(const char *, const char *, const char *,
		    const char *, struct resp *);
void		 http_on(int, const char *, const char *, const char *,
		    const char *, const char *, struct resp *);
void		 resp_free(struct resp *);
/* A network made up for the troubleshooter: routers r1, r2, r3 as
 * jails 11, 12, 13 by the stand-ins; r2's routes back and ruleset given. */
void		 ts_net(const char *, const char *, const char *);
const char	*jstr(const struct resp *, const char *);
const ucl_object_t *jail_named(const struct resp *, const char *);
const char	*jail_str(const struct resp *, const char *, const char *);

#endif /* !_HARNESS_H_ */
