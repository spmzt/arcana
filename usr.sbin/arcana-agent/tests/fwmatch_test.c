/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * fwmatch: a packet walked through a ruleset (fwmatch.c), for
 * agent_test.sh.
 *
 *	fwmatch list tables word...
 *
 * list is `ipfw list`'s, tables `ipfw table all list`'s; the words say
 * the packet: in | out, src=, dst=, proto= (tcp, udp, icmp, a number),
 * sport=, dport=, icmp=, rcv=, xmit=, syn, ack, state, rpf, reach,
 * srclocal, fib=, local=address@interface (again for each).  It prints
 * the verdict, the rule that made it, and those it could not judge.
 */

#include <sys/socket.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "fwmatch.h"

static char *
slurp(const char *path)
{
	FILE	*fp;
	char	*buf;
	size_t	 n;

	if ((fp = fopen(path, "r")) == NULL)
		err(1, "%s", path);
	if ((buf = malloc(1 << 20)) == NULL)
		err(1, "malloc");
	n = fread(buf, 1, (1 << 20) - 1, fp);
	buf[n] = '\0';
	fclose(fp);
	return (buf);
}

static void
addr(const char *s, int *af, uint8_t *a)
{

	if (inet_pton(AF_INET, s, a) == 1)
		*af = AF_INET;
	else if (inet_pton(AF_INET6, s, a) == 1)
		*af = AF_INET6;
	else
		errx(2, "%s: not an address", s);
}

int
main(int argc, char **argv)
{
	static struct fwset	 set;
	static struct fwpkt	 k;
	struct fwverdict	 v;
	int			 i, af;
	size_t			 j;
	char			*at;

	if (argc < 4)
		errx(2, "usage: fwmatch list tables word...");
	if (fw_parse(&set, slurp(argv[1]), slurp(argv[2])) != 0)
		errx(1, "fw_parse");
	k.sport = k.dport = k.icmptype = -1;
	for (i = 3; i < argc; i++) {
		const char *w = argv[i];

		if (strcmp(w, "in") == 0)
			k.out = false;
		else if (strcmp(w, "out") == 0)
			k.out = true;
		else if (strncmp(w, "src=", 4) == 0)
			addr(w + 4, &k.af, k.src);
		else if (strncmp(w, "dst=", 4) == 0)
			addr(w + 4, &af, k.dst);
		else if (strcmp(w, "proto=tcp") == 0)
			k.proto = IPPROTO_TCP;
		else if (strcmp(w, "proto=udp") == 0)
			k.proto = IPPROTO_UDP;
		else if (strcmp(w, "proto=icmp") == 0)
			k.proto = IPPROTO_ICMP;
		else if (strcmp(w, "proto=icmp6") == 0)
			k.proto = IPPROTO_ICMPV6;
		else if (strncmp(w, "proto=", 6) == 0)
			k.proto = atoi(w + 6);
		else if (strncmp(w, "sport=", 6) == 0)
			k.sport = atoi(w + 6);
		else if (strncmp(w, "dport=", 6) == 0)
			k.dport = atoi(w + 6);
		else if (strncmp(w, "icmp=", 5) == 0)
			k.icmptype = atoi(w + 5);
		else if (strncmp(w, "rcv=", 4) == 0)
			k.rcvif = w + 4;
		else if (strncmp(w, "xmit=", 5) == 0)
			k.xmitif = w + 5;
		else if (strcmp(w, "syn") == 0)
			k.syn = true;
		else if (strcmp(w, "ack") == 0)
			k.ack = true;
		else if (strcmp(w, "state") == 0)
			k.state = true;
		else if (strcmp(w, "rpf") == 0)
			k.rpf = true;
		else if (strcmp(w, "reach") == 0)
			k.src_reach = true;
		else if (strcmp(w, "srclocal") == 0)
			k.src_local = true;
		else if (strncmp(w, "fib=", 4) == 0)
			k.fib = atoi(w + 4);
		else if (strncmp(w, "local=", 6) == 0 && (at = strchr(w,
		    '@')) != NULL && k.nlocal < FW_LOCAL) {
			char	a[64];

			snprintf(a, sizeof(a), "%.*s", (int)(at - w - 6), w + 6);
			addr(a, &k.local_af[k.nlocal], k.local[k.nlocal]);
			snprintf(k.local_if[k.nlocal], sizeof(k.local_if[0]),
			    "%s", at + 1);
			k.nlocal++;
		} else
			errx(2, "%s: not a word of a packet", w);
	}
	fw_eval(&set, &k, &v);
	printf("%s", v.verdict);
	if (strcmp(v.verdict, "none") != 0)
		printf(" %ld", set.rules[v.rule].num);
	if (v.by_state)
		printf(" by-state");
	if (v.keep)
		printf(" keep-state");
	if (v.setfib != -1)
		printf(" setfib=%d", v.setfib);
	if (v.fwd[0] != '\0')
		printf(" fwd=%s", v.fwd);
	for (j = 0; j < v.nuncertain; j++)
		printf(" uncertain=%ld(%s)", set.rules[v.uncertain[j]].num,
		    v.uncertain_why[j]);
	printf("\n");
	fw_free(&set);
	return (0);
}
