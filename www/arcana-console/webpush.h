/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

#ifndef WEBPUSH_H
#define	WEBPUSH_H

#include <sys/types.h>

#include <stdint.h>
#include <time.h>

#include <openssl/evp.h>

char		*wp_b64url(const void *, size_t);
uint8_t		*wp_unb64url(const char *, size_t *);
int		 wp_encrypt(const uint8_t *, const uint8_t *, EVP_PKEY *,
		    const uint8_t *, const uint8_t *, size_t, uint8_t **,
		    size_t *);
char		*wp_vapid(EVP_PKEY *, const char *, const char *, time_t);

#endif /* !WEBPUSH_H */
