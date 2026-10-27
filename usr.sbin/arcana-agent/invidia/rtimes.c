/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Invidia: when each route last changed, for
 * ietf-routing's last-updated.  The kernel keeps no such time; the route
 * events netlink(4) sends (RTM_NEWROUTE, RTM_DELROUTE, every FIB on one
 * socket, RTA_TABLE saying which) do: each is noted here by its FIB and
 * prefix, and the collector looks it up.  A route not seen to change
 * since the agent started has none.  The table is bounded: past it, a
 * new prefix takes the slot of the one noted longest ago.
 */

#include <sys/types.h>
#include <sys/socket.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "rtimes.h"

#define	RT_SLOTS	16384		/* a power of 2 */
#define	RT_PROBE	8		/* slots looked at for one key */

struct rt_slot {
	char	 key[INET6_ADDRSTRLEN + 24];	/* "fib prefix" */
	time_t	 when;
};

static struct rt_slot	slots[RT_SLOTS];
static pthread_mutex_t	rt_lock = PTHREAD_MUTEX_INITIALIZER;

static uint32_t
hash(const char *s)
{
	uint32_t h = 2166136261u;

	for (; *s != '\0'; s++)
		h = (h ^ (unsigned char)*s) * 16777619u;
	return (h);
}

static void
key_of(char *key, size_t len, uint32_t fib, const char *prefix)
{

	snprintf(key, len, "%u %s", fib, prefix);
}

/*
 * A prefix as yrt.c writes one: the address (a link-local one without
 * its embedded scope) and its length.
 */
void
rt_prefix(char *buf, size_t len, const struct sockaddr *dst, int af,
    uint8_t plen)
{
	char a[INET6_ADDRSTRLEN];

	if (dst == NULL)
		snprintf(a, sizeof(a), "%s", af == AF_INET6 ? "::" : "0.0.0.0");
	else if (dst->sa_family == AF_INET)
		inet_ntop(AF_INET, &((const struct sockaddr_in *)
		    (const void *)dst)->sin_addr, a, sizeof(a));
	else if (dst->sa_family == AF_INET6) {
		struct in6_addr in6 = ((const struct sockaddr_in6 *)
		    (const void *)dst)->sin6_addr;

		if (IN6_IS_ADDR_LINKLOCAL(&in6))
			in6.s6_addr[2] = in6.s6_addr[3] = 0;
		inet_ntop(AF_INET6, &in6, a, sizeof(a));
	} else {
		buf[0] = '\0';
		return;
	}
	snprintf(buf, len, "%s/%u", a, plen);
}

/* A route of FIB fib changed at when: noted; gone, forgotten. */
void
rt_touched(uint32_t fib, const char *prefix, time_t when, bool gone)
{
	char key[sizeof(slots[0].key)];
	uint32_t h;
	size_t oldest = SIZE_MAX;

	if (prefix[0] == '\0')
		return;
	key_of(key, sizeof(key), fib, prefix);
	h = hash(key);
	pthread_mutex_lock(&rt_lock);
	for (int k = 0; k < RT_PROBE; k++) {
		struct rt_slot *s = &slots[(h + (uint32_t)k) & (RT_SLOTS - 1)];

		if (strcmp(s->key, key) == 0) {
			if (gone)
				s->key[0] = '\0';
			else
				s->when = when;
			pthread_mutex_unlock(&rt_lock);
			return;
		}
		if (s->key[0] == '\0' && oldest == SIZE_MAX)
			oldest = (h + (uint32_t)k) & (RT_SLOTS - 1);
	}
	if (!gone) {
		/* None free: the one noted longest ago gives way. */
		if (oldest == SIZE_MAX) {
			oldest = h & (RT_SLOTS - 1);
			for (int k = 1; k < RT_PROBE; k++) {
				size_t i = (h + (uint32_t)k) & (RT_SLOTS - 1);

				if (slots[i].when < slots[oldest].when)
					oldest = i;
			}
		}
		strlcpy(slots[oldest].key, key, sizeof(slots[oldest].key));
		slots[oldest].when = when;
	}
	pthread_mutex_unlock(&rt_lock);
}

/* When a route of FIB fib last changed; false: not seen to. */
bool
rt_last(uint32_t fib, const char *prefix, time_t *when)
{
	char key[sizeof(slots[0].key)];
	uint32_t h;
	bool found = false;

	key_of(key, sizeof(key), fib, prefix);
	h = hash(key);
	pthread_mutex_lock(&rt_lock);
	for (int k = 0; k < RT_PROBE && !found; k++) {
		const struct rt_slot *s =
		    &slots[(h + (uint32_t)k) & (RT_SLOTS - 1)];

		if (strcmp(s->key, key) == 0) {
			*when = s->when;
			found = true;
		}
	}
	pthread_mutex_unlock(&rt_lock);
	return (found);
}
