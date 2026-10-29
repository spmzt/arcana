/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

#ifndef _ARCANA_YSTREAM_H_
#define	_ARCANA_YSTREAM_H_

#include <stdbool.h>

#include <cblink.h>
#include <cbl_schema.h>

#include "ymodel.h"

/*
 * arcana-stream, Arcana's own cblink family for bytes on a stream
 * (ystream.c), its bodies arcana-stream's structures: the agent serves
 * it, the console and arcanactl open its streams.
 *
 * ys_accept(): an opened stream accepted, opened (NULL: none) its
 * answer, each data message's chunk handed to cbs.  ys_send(): data,
 * the next bytes, sent on s; EAGAIN, no credit (nothing sent).
 * ys_family(): the family's id on conn, resolved.  ys_open(): a stream
 * of command cmd opened on conn with the open structure rq, cbs the
 * caller's own (cblink's), what it takes before it gives credit window
 * (0: cblink's own).  ys_opened(),
 * ys_chunk(): an accept's and a data message's structures, a's.
 */
#define	YS_FAMILY_NAME		"arcana-stream"
#define	YS_ZFS_SEND		1
#define	YS_ZFS_RECEIVE		2
#define	YS_PCAP_PUT		3
#define	YS_PCAP_GET		4
#define	YS_WINDOW		4194304		/* what is taken before credit */

struct ys_cbs {
	void	(*on_data)(cbl_stream *, const struct arcana_stream_chunk *,
		    void *);
	void	(*on_hclose)(cbl_stream *, void *);
	void	(*on_close)(cbl_stream *, int, const char *, void *);
	void	(*on_writable)(cbl_stream *, size_t, void *);
};

int	ys_accept(cbl_stream *s, const struct arcana_stream_opened *opened,
	    const struct ys_cbs *cbs, void *arg);
int	ys_send(cbl_stream *s, const void *data, size_t len);
int	ys_family(cbl_conn *conn, uint16_t *id);
int	ys_open(cbl_conn *conn, uint16_t cmd,
	    const struct arcana_stream_open *rq, uint32_t window,
	    uint32_t flags, const struct cbl_stream_cbs *cbs, void *arg,
	    cbl_stream **sp);
int	ys_opened(const cbl_msg *msg, struct arcana_stream_opened *o,
	    cbl_yarena *a);
int	ys_chunk(const cbl_msg *msg, struct arcana_stream_chunk *c,
	    cbl_yarena *a);

#endif	/* !_ARCANA_YSTREAM_H_ */
