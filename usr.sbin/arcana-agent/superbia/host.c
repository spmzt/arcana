/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

#include <sys/param.h>
#include <sys/sysctl.h>
#include <sys/time.h>
#include <sys/utsname.h>

#include <string.h>
#include <time.h>
#include <unistd.h>

#include "agent.h"

/* Facts about this host, from uname(3) and sysctl(3). */
void
host_info(struct work *w, struct arc_host *h)
{
	struct utsname	 u;
	struct timeval	 boot;
	uint64_t	 physmem;
	size_t		 len;
	char		 name[MAXHOSTNAMELEN];
	int		 ncpu, securelevel, step;

	memset(h, 0, sizeof(*h));
	step = step_begin(w, ARC_STEP_KIND_LIB, "uname(3)", NULL);
	if (uname(&u) == 0) {
		h->sysname = wtext(w, wstrdup(w, u.sysname));
		h->release = wtext(w, wstrdup(w, u.release));
		h->machine = wtext(w, wstrdup(w, u.machine));
		step_end(w, step, true, "%s %s %s", u.sysname, u.release,
		    u.machine);
	} else
		step_end(w, step, false, NULL);
	if (gethostname(name, sizeof(name)) == 0)
		h->hostname = wtext(w, wstrdup(w, name));
	h->has_osreldate = true;
	h->osreldate = (uint32_t)getosreldate();

	step = step_begin(w, ARC_STEP_KIND_LIB, "sysctlbyname(3)",
	    "hw.ncpu hw.physmem kern.boottime kern.securelevel");
	len = sizeof(ncpu);
	if (sysctlbyname("hw.ncpu", &ncpu, &len, NULL, 0) == 0) {
		h->has_ncpu = true;
		h->ncpu = (uint32_t)ncpu;
	}
	len = sizeof(physmem);
	if (sysctlbyname("hw.physmem", &physmem, &len, NULL, 0) == 0) {
		h->has_physmem = true;
		h->physmem = physmem;
	}
	len = sizeof(boot);
	if (sysctlbyname("kern.boottime", &boot, &len, NULL, 0) == 0) {
		h->has_boottime = true;
		h->boottime = boot.tv_sec;
	}
	len = sizeof(securelevel);
	if (sysctlbyname("kern.securelevel", &securelevel, &len, NULL,
	    0) == 0) {
		h->has_securelevel = true;
		h->securelevel = securelevel;
	}
	step_end(w, step, true, NULL);
	h->has_time = true;
	h->time = time(NULL);
	h->has_privileged = true;
	h->privileged = geteuid() == 0;
	h->version = ARCANA_AGENT_VERSION;
	if (opts.build[0] != '\0')
		h->build = opts.build;
	plugins_there(w, NULL, &h->plugins.v, &h->plugins.n);
}
