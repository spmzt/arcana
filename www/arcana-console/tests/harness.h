/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

#ifndef _HARNESS_H_
#define _HARNESS_H_

#include <sys/types.h>

#include <atf-c.h>
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
extern bool		 harness_local_agent;
extern bool		 harness_webconf_only_local;

const char	*locate(const atf_tc_t *, const char *, const char *,
		    const char *);
void		 put(const char *, const char *);
pid_t		 spawn(char *const [], const char *);
pid_t		 spawn_server(char *const [], const char *);
void		 wait_for(const char *);
bool		 run_prog(char *const []);
void		 start(const atf_tc_t *, int, const char *);
void		 stop(void);
void		 restart_console(void);
void		 http_abandon(const char *);
int		 tcp_socket(int);
void		 http(const char *, const char *, const char *, struct resp *);
void		 http_on(int, const char *, const char *, const char *,
		    const char *, const char *, struct resp *);
void		 resp_free(struct resp *);
const char	*jstr(const struct resp *, const char *);
const ucl_object_t *jail_named(const struct resp *, const char *);
const char	*jail_str(const struct resp *, const char *, const char *);

#endif /* !_HARNESS_H_ */
