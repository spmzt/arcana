/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * arcana-stream (PLAN-SDN-YANG 3.8): the streams that carry bytes
 * between the console and its hosts (a snapshot sent and received, a
 * capture put, a pcap-log file got), on a cblink family of Arcana's
 * own, as cblink's FAMILIES.md has a stream; its bodies are
 * arcana-stream's structures, put and read with what cblink-gen wrote.
 * The agent's, the console's and arcanactl's.
 */

#include <sys/types.h>

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include <cblink.h>
#include <cbl_schema.h>

#include "ymodel.h"
#include "ystream.h"

struct ys_ctx {
	struct ys_cbs	 cbs;
	void		*arg;
};

static void
s_on_data(cbl_stream *s, cbl_msg *data, void *arg)
{
	struct ys_ctx			*c = arg;
	struct arcana_stream_chunk	 d;
	cbl_yarena			*a;

	if ((a = cbl_yarena_new()) == NULL) {
		(void)cbl_stream_reset(s, ENOMEM);
		return;
	}
	if (ys_chunk(data, &d, a) != 0) {
		cbl_yarena_free(a);
		(void)cbl_stream_reset(s, EBADMSG);
		return;
	}
	if (c->cbs.on_data != NULL)
		c->cbs.on_data(s, &d, c->arg);
	cbl_yarena_free(a);
}

static void
s_on_hclose(cbl_stream *s, void *arg)
{
	struct ys_ctx	*c = arg;

	if (c->cbs.on_hclose != NULL)
		c->cbs.on_hclose(s, c->arg);
}

static void
s_on_close(cbl_stream *s, int code, const char *text, void *arg)
{
	struct ys_ctx	*c = arg;

	if (c->cbs.on_close != NULL)
		c->cbs.on_close(s, code, text, c->arg);
	free(c);
}

static void
s_on_writable(cbl_stream *s, size_t credit, void *arg)
{
	struct ys_ctx	*c = arg;

	if (c->cbs.on_writable != NULL)
		c->cbs.on_writable(s, credit, c->arg);
}

static const struct cbl_stream_cbs s_cbs = {
	.on_data = s_on_data,
	.on_hclose = s_on_hclose,
	.on_close = s_on_close,
	.on_writable = s_on_writable,
};

int
ys_accept(cbl_stream *s, const struct arcana_stream_opened *opened,
    const struct ys_cbs *cbs, void *arg)
{
	struct ys_ctx	*c;
	cbl_msg		*msg;
	int		 error;

	if ((error = cbl_stream_msg_new(s, &msg)) != 0)
		return (error);
	if (opened != NULL && (error = arcana_stream_opened_put(msg,
	    opened)) != 0) {
		cbl_msg_free(msg);
		return (error);
	}
	(void)cbl_msg_set_window(msg, YS_WINDOW);
	if ((c = calloc(1, sizeof(*c))) == NULL) {
		cbl_msg_free(msg);
		return (ENOMEM);
	}
	c->cbs = *cbs;
	c->arg = arg;
	if ((error = cbl_stream_accept(s, msg, 0, &s_cbs, c)) != 0)
		free(c);
	return (error);
}

int
ys_send(cbl_stream *s, const void *data, size_t len)
{
	struct arcana_stream_chunk	 c;
	cbl_msg				*msg;
	int				 error;

	memset(&c, 0, sizeof(c));
	c.data.p = data;
	c.data.len = len;
	if ((error = cbl_stream_msg_new(s, &msg)) != 0)
		return (error);
	if ((error = arcana_stream_chunk_put(msg, &c)) != 0) {
		cbl_msg_free(msg);
		return (error);
	}
	/* EAGAIN (no credit) leaves the message ours. */
	if ((error = cbl_stream_send(s, msg)) == EAGAIN)
		cbl_msg_free(msg);
	return (error);
}

int
ys_family(cbl_conn *conn, uint16_t *id)
{
	cbl_family_info	*info;
	int		 error;

	if ((error = cbl_resolve(conn, YS_FAMILY_NAME, &info)) != 0)
		return (error);
	*id = cbl_family_info_id(info);
	cbl_family_info_free(info);
	return (0);
}

int
ys_open(cbl_conn *conn, uint16_t cmd, const struct arcana_stream_open *rq,
    uint32_t window, uint32_t flags, const struct cbl_stream_cbs *cbs,
    void *arg, cbl_stream **sp)
{
	cbl_msg		*msg;
	uint16_t	 fam;
	int		 error;

	if ((error = ys_family(conn, &fam)) != 0)
		return (error);
	if ((error = cbl_msg_new(cbl_conn_ctx(conn), fam, cmd, CBL_F_REQUEST |
	    CBL_F_S_OPEN, &msg)) != 0)
		return (error);
	if ((error = arcana_stream_open_put(msg, rq)) != 0) {
		cbl_msg_free(msg);
		return (error);
	}
	if (window > 0)
		(void)cbl_msg_set_window(msg, window);
	return (cbl_stream_open(conn, msg, flags, cbs, arg, sp));
}

int
ys_opened(const cbl_msg *msg, struct arcana_stream_opened *o, cbl_yarena *a)
{

	memset(o, 0, sizeof(*o));
	return (arcana_stream_opened_parse(msg, o, a, 0, NULL, 0));
}

int
ys_chunk(const cbl_msg *msg, struct arcana_stream_chunk *c, cbl_yarena *a)
{

	memset(c, 0, sizeof(*c));
	return (arcana_stream_chunk_parse(msg, c, a, CBL_YD_STRICT, NULL, 0));
}
