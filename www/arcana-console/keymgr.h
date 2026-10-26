/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/* The HTTPS key's own process (keymgr.c). */

#ifndef KEYMGR_H
#define KEYMGR_H

#include <openssl/ssl.h>

/* The key manager forked, the key read there; the descriptors named
 * are closed in it.  0, or -1 with the reason logged. */
int	keymgr_start(const char *, const char *, const char *, const int *,
	    int);
/* The certificate, and the key manager's key, on a vhost's SSL_CTX. */
int	keymgr_tls(SSL_CTX *, const char *);

#endif /* !KEYMGR_H */
