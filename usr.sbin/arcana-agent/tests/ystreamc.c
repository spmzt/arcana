/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * ystreamc uri ca cert key cmd [name ...]: an arcana-stream stream of
 * command cmd (1 zfs-send, 2 zfs-receive, 3 suricata-pcap-put, 4
 * suricata-pcap-get) opened with names over mutual TLS, as the
 * certificate's peer; "opened", or what refused it, printed, and the
 * stream reset.  For agent_tls_test.sh: who may open the streams.
 */

#include <sys/types.h>

#include <err.h>
#include <errno.h>
#include <poll.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <cblink.h>

#include "ystream.h"

static bool	done;

static void
on_open(cbl_stream *s, cbl_msg *accept, int error, void *arg)
{

	(void)arg;
	done = true;
	if (error != 0)
		printf("refused: %s\n", accept != NULL &&
		    cbl_msg_err_str(accept) != NULL ? cbl_msg_err_str(accept) :
		    strerror(error));
	else {
		printf("opened\n");
		(void)cbl_stream_reset(s, ECANCELED);
	}
}

static void
on_close(cbl_stream *s, int code, const char *text, void *arg)
{

	(void)s;
	(void)arg;
	if (!done && code != 0)
		printf("refused: %s\n", text != NULL ? text : strerror(code));
	done = true;
}

static const struct cbl_stream_cbs cbs = {
	.on_open = on_open,
	.on_close = on_close,
};

int
main(int argc, char **argv)
{
	struct arcana_stream_open	 rq;
	struct pollfd			 pfd;
	cbl_ctx				*ctx;
	cbl_conn			*c;
	cbl_tls				*tls;
	cbl_stream			*s;
	int				 error, ev, ms;

	if (argc < 6)
		errx(2, "usage: ystreamc uri ca cert key cmd [name ...]");
	if ((error = cbl_ctx_new(&ctx)) != 0 || (error = cbl_conn_new(ctx,
	    argv[1], 0, &c)) != 0)
		errc(1, error, "%s", argv[1]);
	if (cbl_tls_new(&tls) != 0 || cbl_tls_set_cert(tls, argv[3],
	    argv[4]) != 0 || cbl_tls_set_ca(tls, argv[2], NULL) != 0)
		errx(1, "tls: %s", tls != NULL ? cbl_tls_errstr(tls) : "none");
	(void)cbl_conn_set_tls(c, tls);
	if ((error = cbl_conn_connect(c)) != 0)
		errx(1, "%s: %s", argv[1], cbl_conn_errstr(c));
	memset(&rq, 0, sizeof(rq));
	rq.name.v = (const char *const *)&argv[6];
	rq.name.n = (size_t)argc - 6;
	if ((error = ys_open(c, (uint16_t)atoi(argv[5]), &rq, YS_WINDOW, 0,
	    &cbs, NULL, &s)) != 0) {
		/* A host may not even resolve the family. */
		printf("refused: %s\n", strerror(error));
		return (0);
	}
	while (!done) {
		ev = 0;
		ms = -1;
		(void)cbl_conn_interest(c, &ev, &ms);
		pfd.fd = cbl_conn_fd(c);
		pfd.events = ((ev & CBL_EV_READ) != 0 ? POLLIN : 0) |
		    ((ev & CBL_EV_WRITE) != 0 ? POLLOUT : 0);
		pfd.revents = 0;
		if (poll(&pfd, 1, ms) == -1)
			break;
		ev = ((pfd.revents & (POLLIN | POLLHUP | POLLERR)) != 0 ?
		    CBL_EV_READ : 0) | ((pfd.revents & POLLOUT) != 0 ?
		    CBL_EV_WRITE : 0);
		if (cbl_conn_process(c, ev) != 0) {
			if (!done)
				printf("refused: the connection ended\n");
			break;
		}
	}
	cbl_conn_free(c);
	cbl_ctx_free(ctx);
	return (0);
}
