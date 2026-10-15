/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * ipfw(8)'s ruleset walked for one packet (fwmatch.c): which rule
 * decides it, and which before it could not be judged.
 */

#ifndef _ARCANA_FWMATCH_H_
#define	_ARCANA_FWMATCH_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define	FW_RULES		4096
#define	FW_TABLES		64
#define	FW_TABLE_ENTRIES	4096
#define	FW_UNCERTAIN		16
#define	FW_MATCHED		32
#define	FW_LOCAL		256

struct fwentry {
	int		 af;
	uint8_t		 addr[16];
	int		 len;
	char		 value[64];
};

struct fwtable {
	char		 name[64];
	struct fwentry	*v;
	size_t		 n, cap;
};

struct fwrule {
	long		 num;
	char		 text[1024];
};

struct fwset {
	struct fwrule	*rules;
	size_t		 n, cap;
	struct fwtable	 tables[FW_TABLES];
	size_t		 ntables;
};

/* A packet as the firewall would see it at one place. */
struct fwpkt {
	int		 af;		/* AF_INET or AF_INET6 */
	uint8_t		 src[16], dst[16];
	int		 proto;		/* IPPROTO_* */
	int		 sport, dport;	/* -1: none */
	int		 icmptype;	/* -1: none */
	bool		 out;		/* going out; else coming in */
	const char	*rcvif;		/* came in on, or NULL: made here */
	const char	*xmitif;	/* goes out by, or NULL */
	bool		 syn;		/* TCP: opens a connection */
	bool		 ack;		/* TCP: of one (established) */
	bool		 state;		/* a state of this host's has its flow */
	bool		 rpf;		/* the route back to src is by rcvif */
	bool		 src_reach;	/* there is a route back to src */
	bool		 src_local;	/* src is one of this host's */
	bool		 dst_local;	/* dst is */
	int		 fib;
	/* The host's own addresses, for me and for via an address. */
	size_t		 nlocal;
	int		 local_af[FW_LOCAL];
	uint8_t		 local[FW_LOCAL][16];
	char		 local_if[FW_LOCAL][16];
};

struct fwverdict {
	/* allow, deny, fwd, nat, pipe, queue, divert, ..., unknown, or
	 * none: no rule decided (an empty ruleset). */
	const char	*verdict;
	size_t		 rule;		/* its index in the set */
	bool		 by_state;	/* allowed by a state (check-state) */
	bool		 keep;		/* it made a state */
	int		 setfib;	/* -1 none, -2 by a table */
	char		 fwd[64];
	const char	*note;
	size_t		 uncertain[FW_UNCERTAIN];
	char		 uncertain_why[FW_UNCERTAIN][32];
	size_t		 nuncertain;
	size_t		 matched[FW_MATCHED];	/* count, setfib ... and it */
	size_t		 nmatched;
};

int	fw_parse(struct fwset *, const char *, const char *);
void	fw_free(struct fwset *);
void	fw_eval(const struct fwset *, const struct fwpkt *,
	    struct fwverdict *);

#endif /* !_ARCANA_FWMATCH_H_ */
