/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

#ifndef _ARCANA_YDESC_H_
#define	_ARCANA_YDESC_H_

#include <stddef.h>
#include <stdint.h>

/*
 * What the schema tables leave out of Arcana's modules, written by
 * ydescgen at the build (ydesc.c), sorted by key: a node's schema-node
 * path ("/m:a/b"), an enum's ("/m:a/b=x"), a choice's or a case's
 * ("/m:a/(c)", "/m:a/(c)/(k)"), an identity's ("m:i"), a module's
 * ("m").  dsc: its description, or NULL; tname: a leaf's typedef, or
 * NULL; order: a node's place in the module's text, its siblings' order
 * (0: not a node).
 */
struct ydesc {
	const char	*key;
	const char	*dsc;
	const char	*tname;
	uint32_t	 order;
};

extern const struct ydesc	ydesc[];
extern const size_t		nydesc;

#endif	/* !_ARCANA_YDESC_H_ */
