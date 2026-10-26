/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/* What the y* test programs share: a file read whole, "-" for NULL, a
 * value through YANG-CBOR and back, the same bytes. */

#ifndef _YCOMMON_H_
#define	_YCOMMON_H_

#include <err.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <arcana.h>

#include "collect.h"

static inline char *
slurp(const char *path)
{
	char *buf;
	ssize_t r;
	int fd;

	if ((buf = malloc(1 << 20)) == NULL)
		err(1, "malloc");
	if ((fd = open(path, O_RDONLY)) == -1)
		err(1, "%s", path);
	if ((r = read(fd, buf, (1 << 20) - 1)) < 0)
		err(1, "%s", path);
	close(fd);
	buf[r] = '\0';
	return (buf);
}

static inline const char *
str(const char *s)
{

	return (s != NULL ? s : "-");
}

static inline void
same(int (*enc)(const void *, struct cbl_ybuf *),
    int (*dec)(const void *, size_t, void *, cbl_yarena *, int, char *,
    size_t), const void *v, void *back, cbl_yarena *a)
{
	struct cbl_ybuf b1 = { 0 }, b2 = { 0 };
	char why[256] = "";

	if (enc(v, &b1) != 0 || dec(b1.p, b1.len, back, a, CBL_YD_STRICT,
	    why, sizeof(why)) != 0 || enc(back, &b2) != 0)
		errx(1, "the round trip: %s", why);
	printf("yang-cbor %zu bytes, %s\n", b1.len, b1.len == b2.len &&
	    memcmp(b1.p, b2.p, b1.len) == 0 ? "the same back" :
	    "not the same");
}

#endif /* !_YCOMMON_H_ */
