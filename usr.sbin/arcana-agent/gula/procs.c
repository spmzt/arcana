/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Gula: what runs on the host, as top(1) sees it.  The processes come
 * from the kernel, kern.proc.proc; what each used between two looks is
 * the difference from the look before, whoever made it, and the first
 * look is made twice, a quarter of a second apart.  One process is sent
 * a signal with kill(2) or given another nice value with setpriority(2).
 */

#include <sys/param.h>
#include <sys/proc.h>
#include <sys/resource.h>
#include <sys/sysctl.h>
#include <sys/user.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <netdb.h>

#include <ctype.h>
#include <errno.h>
#include <jail.h>
#include <libprocstat.h>
#include <pthread.h>
#include <pwd.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <ucl.h>
#include <unistd.h>

#include "agent.h"

#define	PROCS_STALE	15	/* s, after which a look is no measure */
#define	PROCS_ARGS	300	/* of one command line, and no more */
#define	JAILS_SEEN	64
#define	PROCS_PID_MAX	99999	/* the kernel's PID_MAX */

/* What a process had used at the look before. */
struct seen {
	pid_t		pid;
	time_t		start;
	uint64_t	runtime;	/* us */
	uint64_t	io;		/* blocks */
};

struct shown {
	const struct kinfo_proc	*kp;
	double			 cpu;
	double			 io;
};

static pthread_mutex_t	procs_lock = PTHREAD_MUTEX_INITIALIZER;
static struct seen	*last;
static size_t		 nlast;
static struct timespec	 last_at;

static int
seen_cmp(const void *a, const void *b)
{
	const struct seen	*x = a, *y = b;

	return (x->pid < y->pid ? -1 : x->pid > y->pid);
}

/* The busiest first, and of two as busy the one that began first. */
static int
shown_cmp(const void *a, const void *b)
{
	const struct shown	*x = a, *y = b;

	if (x->cpu != y->cpu)
		return (x->cpu > y->cpu ? -1 : 1);
	return (x->kp->ki_pid < y->kp->ki_pid ? -1 : x->kp->ki_pid >
	    y->kp->ki_pid);
}

/* Every process, as the kernel says them; free(3) it. */
static struct kinfo_proc *
procs_read(size_t *np)
{
	struct kinfo_proc	*kp;
	int			 mib[3] = { CTL_KERN, KERN_PROC, KERN_PROC_PROC };
	size_t			 len;
	int			 try;

	for (try = 0; try < 4; try++) {
		len = 0;
		if (sysctl(mib, 3, NULL, &len, NULL, 0) == -1)
			return (NULL);
		len += len / 8 + 16 * sizeof(*kp);
		if ((kp = malloc(len)) == NULL)
			return (NULL);
		if (sysctl(mib, 3, kp, &len, NULL, 0) == 0) {
			if (len >= sizeof(*kp) && kp->ki_structsize !=
			    (int)sizeof(*kp)) {
				free(kp);
				return (NULL);
			}
			*np = len / sizeof(*kp);
			return (kp);
		}
		free(kp);
		if (errno != ENOMEM)
			return (NULL);
	}
	return (NULL);
}

/* Keep what each has used, for the look after this one. */
static void
procs_keep(const struct kinfo_proc *kp, size_t n)
{
	struct seen	*s;
	size_t		 i;

	if ((s = calloc(n > 0 ? n : 1, sizeof(*s))) == NULL)
		return;
	for (i = 0; i < n; i++) {
		s[i].pid = kp[i].ki_pid;
		s[i].start = kp[i].ki_start.tv_sec;
		s[i].runtime = kp[i].ki_runtime;
		s[i].io = (uint64_t)kp[i].ki_rusage.ru_inblock +
		    (uint64_t)kp[i].ki_rusage.ru_oublock;
	}
	qsort(s, n, sizeof(*s), seen_cmp);
	free(last);
	last = s;
	nlast = n;
	clock_gettime(CLOCK_MONOTONIC, &last_at);
}

static const char *
state_name(const struct kinfo_proc *kp)
{

	switch (kp->ki_stat) {
	case SIDL:
		return ("idle");
	case SRUN:
		return ("run");
	case SSLEEP:
		return ("sleep");
	case SSTOP:
		return ("stop");
	case SZOMB:
		return ("zombie");
	case SWAIT:
		return ("wait");
	case SLOCK:
		return ("lock");
	default:
		return ("?");
	}
}

/* The command line of a process, its words a space apart. */
static const char *
args_of(struct work *w, pid_t pid)
{
	char	buf[4096];
	int	mib[4] = { CTL_KERN, KERN_PROC, KERN_PROC_ARGS, pid };
	size_t	len, i;

	len = sizeof(buf) - 1;
	if (sysctl(mib, 4, buf, &len, NULL, 0) == -1 || len == 0)
		return (NULL);
	while (len > 0 && buf[len - 1] == '\0')
		len--;
	if (len > PROCS_ARGS)
		len = PROCS_ARGS;
	for (i = 0; i < len; i++)
		if (buf[i] == '\0' || (unsigned char)buf[i] < 0x20)
			buf[i] = ' ';
	buf[len] = '\0';
	return (wtext(w, buf));
}

static void
num(ucl_object_t *o, const char *key, int64_t v)
{

	ucl_object_insert_key(o, ucl_object_fromint(v), key, 0, false);
}

static void
real(ucl_object_t *o, const char *key, double v)
{

	/* Two decimals are all that is shown of one. */
	ucl_object_insert_key(o, ucl_object_fromdouble((double)(int64_t)(v *
	    100 + 0.5) / 100), key, 0, false);
}

static void
str(ucl_object_t *o, const char *key, const char *v)
{

	if (v != NULL)
		ucl_object_insert_key(o, ucl_object_fromstring(v), key, 0,
		    false);
}

/* {"processes":[...],"ncpu":n,"elapsed":s}; of one jail, with jail. */
int
do_processes(struct work *w, const char *jail, struct json_rsp *rsp)
{
	struct {
		int	 jid;
		char	*name;
		int	 procs;
		long long threads, rss;
		double	 cpu, wcpu;
	}			 jails[JAILS_SEEN];
	struct kinfo_proc	*kp;
	const struct kinfo_proc	*p;
	struct shown		*sh;
	struct seen		 key, *was;
	struct timespec		 now;
	struct passwd		*pw;
	ucl_object_t		*top, *arr, *o;
	unsigned char		*json;
	const char		*name;
	double			 elapsed;
	size_t			 n, i, k, ns, nj;
	int			 step, jid, ncpu;
	bool			 args;

	rsp->has_ok = true;
	rsp->ok = false;
	jid = -1;
	if (jail != NULL && jail[0] != '\0' && (jid = jail_getid(jail)) ==
	    -1) {
		rsp->error = wfmt(w, "jail %s is not running", jail);
		return (0);
	}
	step = step_begin(w, ARC_STEP_KIND_LIB, "sysctl(3)",
	    "kern.proc.proc, against the look before");
	pthread_mutex_lock(&procs_lock);
	kp = procs_read(&n);
	clock_gettime(CLOCK_MONOTONIC, &now);
	if (kp != NULL && (last == NULL || now.tv_sec - last_at.tv_sec >
	    PROCS_STALE)) {
		procs_keep(kp, n);
		free(kp);
		usleep(250000);
		kp = procs_read(&n);
		clock_gettime(CLOCK_MONOTONIC, &now);
	}
	if (kp == NULL) {
		pthread_mutex_unlock(&procs_lock);
		step_end(w, step, false, "kern.proc.proc: %s",
		    strerror(errno));
		rsp->error = "the kernel did not say what runs";
		return (0);
	}
	elapsed = (double)(now.tv_sec - last_at.tv_sec) +
	    (double)(now.tv_nsec - last_at.tv_nsec) / 1e9;
	if (elapsed < 0.05)
		elapsed = 0.05;
	sh = wcalloc(w, n > 0 ? n : 1, sizeof(*sh));
	for (i = ns = 0; i < n; i++) {
		p = &kp[i];
		if (jid != -1 && p->ki_jid != jid)
			continue;
		sh[ns].kp = p;
		key.pid = p->ki_pid;
		was = last != NULL ? bsearch(&key, last, nlast, sizeof(*last),
		    seen_cmp) : NULL;
		if (was != NULL && was->start == p->ki_start.tv_sec &&
		    p->ki_runtime >= was->runtime) {
			sh[ns].cpu = (double)(p->ki_runtime - was->runtime) /
			    1e4 / elapsed;
			k = (uint64_t)p->ki_rusage.ru_inblock +
			    (uint64_t)p->ki_rusage.ru_oublock;
			sh[ns].io = k >= was->io ? (double)(k - was->io) /
			    elapsed : 0;
		}
		ns++;
	}
	qsort(sh, ns, sizeof(*sh), shown_cmp);
	procs_keep(kp, n);
	step_end(w, step, true, "%zu processes, %.1f s since the look before",
	    ns, elapsed);

	nj = 0;
	json = NULL;
	/* With the command lines; without them when that is too much. */
	for (args = true;; args = false) {
		top = ucl_object_typed_new(UCL_OBJECT);
		arr = ucl_object_typed_new(UCL_ARRAY);
		for (i = 0; i < ns; i++) {
			p = sh[i].kp;
			o = ucl_object_typed_new(UCL_OBJECT);
			num(o, "pid", p->ki_pid);
			num(o, "ppid", p->ki_ppid);
			/* getpwuid(3) is not for two threads: the lock. */
			pw = getpwuid(p->ki_uid);
			str(o, "user", pw != NULL ? wtext(w, pw->pw_name) :
			    wfmt(w, "%u", (unsigned int)p->ki_uid));
			num(o, "jid", p->ki_jid);
			if (p->ki_jid != 0) {
				for (k = 0; k < nj && jails[k].jid !=
				    p->ki_jid; k++)
					;
				if (k == nj && nj < JAILS_SEEN) {
					memset(&jails[nj], 0, sizeof(jails[0]));
					jails[nj].jid = p->ki_jid;
					jails[nj++].name =
					    jail_getname(p->ki_jid);
				}
				if (k < nj && jails[k].name != NULL)
					str(o, "jail", wtext(w,
					    jails[k].name));
				/* What the jail uses, all of it added up;
				 * counted once, not when the command lines
				 * are tried without. */
				if (k < nj && args) {
					jails[k].procs++;
					jails[k].threads += p->ki_numthreads;
					jails[k].rss += (long long)p->ki_rssize *
					    getpagesize();
					jails[k].cpu += sh[i].cpu;
					jails[k].wcpu += 100.0 *
					    (double)p->ki_pctcpu / FSCALE;
				}
			}
			str(o, "state", state_name(p));
			if (p->ki_stat == SSLEEP && p->ki_wmesg[0] != '\0')
				str(o, "wait", wtext(w, p->ki_wmesg));
			num(o, "nice", p->ki_nice - NZERO);
			num(o, "pri", p->ki_pri.pri_level - PZERO);
			num(o, "threads", p->ki_numthreads);
			num(o, "rss", (int64_t)p->ki_rssize * getpagesize());
			num(o, "size", (int64_t)p->ki_size);
			real(o, "time", (double)p->ki_runtime / 1e6);
			real(o, "wcpu", 100.0 * (double)p->ki_pctcpu / FSCALE);
			real(o, "cpu", sh[i].cpu);
			num(o, "in", p->ki_rusage.ru_inblock);
			num(o, "out", p->ki_rusage.ru_oublock);
			real(o, "io", sh[i].io);
			num(o, "start", p->ki_start.tv_sec);
			if ((p->ki_flag & (P_SYSTEM | P_KPROC)) != 0)
				ucl_object_insert_key(o,
				    ucl_object_frombool(true), "kernel", 0,
				    false);
			str(o, "comm", wtext(w, p->ki_comm));
			if (args && (name = args_of(w, p->ki_pid)) != NULL)
				str(o, "args", name);
			ucl_array_append(arr, o);
		}
		ucl_object_insert_key(top, arr, "processes", 0, false);
		arr = ucl_object_typed_new(UCL_ARRAY);
		for (k = 0; k < nj; k++) {
			o = ucl_object_typed_new(UCL_OBJECT);
			num(o, "jid", jails[k].jid);
			if (jails[k].name != NULL)
				str(o, "name", wtext(w, jails[k].name));
			num(o, "procs", jails[k].procs);
			num(o, "threads", jails[k].threads);
			num(o, "rss", jails[k].rss);
			real(o, "cpu", jails[k].cpu);
			real(o, "wcpu", jails[k].wcpu);
			ucl_array_append(arr, o);
		}
		ucl_object_insert_key(top, arr, "jails", 0, false);
		ncpu = (int)sysconf(_SC_NPROCESSORS_ONLN);
		num(top, "ncpu", ncpu > 0 ? ncpu : 1);
		real(top, "elapsed", elapsed);
		json = ucl_object_emit(top, UCL_EMIT_JSON_COMPACT);
		ucl_object_unref(top);
		if (json != NULL && strlen((char *)json) <= ARC_MAX_JSON)
			break;
		free(json);
		json = NULL;
		if (!args)
			break;
	}
	pthread_mutex_unlock(&procs_lock);
	for (k = 0; k < nj; k++)
		free(jails[k].name);
	free(kp);
	if (json == NULL) {
		rsp->error = "more runs than a reply carries";
		return (0);
	}
	rsp->json = wtext(w, wadopt(w, json));
	rsp->ok = true;
	return (0);
}

/* A process's number: not init's, and nothing that means a group. */
static bool
pid_of(const char *s, pid_t *pid)
{
	const char	*e;
	long long	 v;

	if (s == NULL)
		return (false);
	v = strtonum(s, 2, PROCS_PID_MAX, &e);
	if (e != NULL)
		return (false);
	*pid = (pid_t)v;
	return (true);
}

/* TERM, SIGTERM, term or 15: the signal's number, or 0. */
static int
sig_of(const char *s)
{
	const char	*e;
	int		 i;

	if (s == NULL || s[0] == '\0')
		return (0);
	if (isdigit((unsigned char)s[0])) {
		i = (int)strtonum(s, 1, NSIG - 1, &e);
		return (e != NULL ? 0 : i);
	}
	if (strncasecmp(s, "SIG", 3) == 0)
		s += 3;
	for (i = 1; i < NSIG; i++)
		if (sys_signame[i] != NULL && strcasecmp(s, sys_signame[i]) ==
		    0)
			return (i);
	return (0);
}

static bool
nice_of(const char *s, int *n)
{
	const char	*e;

	if (s == NULL)
		return (false);
	*n = (int)strtonum(s, PRIO_MIN, PRIO_MAX, &e);
	return (e == NULL);
}

static bool
is_signal(const struct arc_job_spec *sp)
{

	return (sp->verb != NULL && strcmp(sp->verb, "signal") == 0);
}

/* Is the job one that can be done?  NULL, or what is wrong with it. */
const char *
proc_check(const struct arc_job_spec *sp)
{
	const char	*e;
	pid_t		 pid;
	int		 n;

	if (sp->safe)
		return ("what was done to a process is not taken back");
	if (sp->verb == NULL || (!is_signal(sp) && strcmp(sp->verb,
	    "renice") != 0))
		return ("a process is sent a signal or given a nice value: "
		    "signal, renice");
	if (sp->names.n < 2 || sp->names.n > 3)
		return ("name the process by its number, and the signal or "
		    "the nice value");
	if (!pid_of(sp->names.v[0], &pid))
		return ("a process is named by its number, and not init's");
	if (pid == getpid())
		return ("the agent is stopped as a service, not from here");
	if (is_signal(sp) && sig_of(sp->names.v[1]) == 0)
		return ("no such signal");
	if (!is_signal(sp) && !nice_of(sp->names.v[1], &n))
		return ("a nice value is from -20 to 20");
	if (sp->names.n == 3) {
		(void)strtonum(sp->names.v[2], 0, INT64_MAX, &e);
		if (e != NULL)
			return ("when it started is a number of seconds");
	}
	return (NULL);
}

/* The activity log's line: as it would be typed. */
char *
proc_title(const struct arc_job_spec *sp)
{
	char	*t;
	int	 sig;

	if (is_signal(sp)) {
		sig = sig_of(sp->names.v[1]);
		if (asprintf(&t, "kill -%s %s", sig > 0 && sig < NSIG ?
		    sys_signame[sig] : sp->names.v[1], sp->names.v[0]) == -1)
			return (NULL);
		for (sig = 6; t[sig] != ' ' && t[sig] != '\0'; sig++)
			t[sig] = (char)toupper((unsigned char)t[sig]);
	} else if (asprintf(&t, "renice %s %s", sp->names.v[1],
	    sp->names.v[0]) == -1)
		return (NULL);
	return (t);
}

int
do_proc_job(struct work *w, const struct arc_job_spec *sp, const char **errp)
{
	struct kinfo_proc	 kp;
	int			 mib[4] = { CTL_KERN, KERN_PROC, KERN_PROC_PID,
				    0 };
	size_t			 len;
	pid_t			 pid;
	int			 step, sig, n, jid, rc;

	if ((*errp = proc_check(sp)) != NULL)
		return (-1);
	(void)pid_of(sp->names.v[0], &pid);
	mib[3] = pid;
	len = sizeof(kp);
	step = step_begin(w, ARC_STEP_KIND_LIB, "sysctl(3)",
	    "kern.proc.pid.%d", (int)pid);
	if (sysctl(mib, 4, &kp, &len, NULL, 0) == -1 || len < sizeof(kp)) {
		step_end(w, step, false, "not there");
		*errp = wfmt(w, "no process %d", (int)pid);
		return (-1);
	}
	step_end(w, step, true, "%s, of uid %u", kp.ki_comm,
	    (unsigned int)kp.ki_uid);
	if ((kp.ki_flag & (P_SYSTEM | P_KPROC)) != 0) {
		*errp = wfmt(w, "%d (%s) is the kernel's own", (int)pid,
		    kp.ki_comm);
		return (-1);
	}
	if (sp->names.n == 3 && strtonum(sp->names.v[2], 0, INT64_MAX,
	    NULL) != kp.ki_start.tv_sec) {
		*errp = wfmt(w, "the process that was %d is gone: %s has its "
		    "number now", (int)pid, kp.ki_comm);
		return (-1);
	}
	if (sp->jail != NULL && sp->jail[0] != '\0' && ((jid =
	    jail_getid(sp->jail)) == -1 || jid != kp.ki_jid)) {
		*errp = wfmt(w, "%d (%s) is not a process of jail %s",
		    (int)pid, kp.ki_comm, sp->jail);
		return (-1);
	}
	if (is_signal(sp)) {
		sig = sig_of(sp->names.v[1]);
		step = step_begin(w, ARC_STEP_KIND_LIB, "kill(2)",
		    "SIG%s to %d (%s)", sys_signame[sig], (int)pid,
		    kp.ki_comm);
		rc = kill(pid, sig);
	} else {
		(void)nice_of(sp->names.v[1], &n);
		step = step_begin(w, ARC_STEP_KIND_LIB, "setpriority(2)",
		    "%d (%s) from %d to %d", (int)pid, kp.ki_comm,
		    kp.ki_nice - NZERO, n);
		rc = setpriority(PRIO_PROCESS, pid, n);
	}
	if (rc == -1) {
		*errp = wfmt(w, "%d (%s): %s", (int)pid, kp.ki_comm,
		    strerror(errno));
		step_end(w, step, false, "%s", strerror(errno));
		return (-1);
	}
	step_end(w, step, true, NULL);
	return (0);
}

/* A socket's address as text, or the family's name. */
static const char *
sock_text(struct work *w, const struct sockaddr_storage *ss)
{
	char	host[NI_MAXHOST], port[NI_MAXSERV];

	if (ss->ss_family == AF_UNIX)
		return (wtext(w, ((const struct sockaddr_un *)(const void *)
		    ss)->sun_path));
	if ((ss->ss_family == AF_INET || ss->ss_family == AF_INET6) &&
	    getnameinfo((const struct sockaddr *)ss, ss->ss_len, host,
	    sizeof(host), port, sizeof(port), NI_NUMERICHOST | NI_NUMERICSERV)
	    == 0)
		return (wfmt(w, ss->ss_family == AF_INET6 ? "[%s]:%s" : "%s:%s",
		    host, port));
	return ("");
}

/*
 * One process, and more of it than the list has: its files, with what
 * each is (a vnode's path, a socket's addresses), and its threads.
 */
int
do_process(struct work *w, uint32_t pid, struct json_rsp *rsp)
{
	static const char *const types[] = { [PS_FST_TYPE_VNODE] = "file",
	    [PS_FST_TYPE_FIFO] = "fifo", [PS_FST_TYPE_SOCKET] = "socket",
	    [PS_FST_TYPE_PIPE] = "pipe", [PS_FST_TYPE_PTS] = "tty",
	    [PS_FST_TYPE_KQUEUE] = "kqueue", [PS_FST_TYPE_MQUEUE] = "mqueue",
	    [PS_FST_TYPE_SHM] = "shm", [PS_FST_TYPE_SEM] = "sem",
	    [PS_FST_TYPE_PROCDESC] = "process", [PS_FST_TYPE_DEV] = "device" };
	struct procstat		*ps;
	struct kinfo_proc	*kp, *tp;
	struct filestat_list	*files;
	struct filestat		*fst;
	struct sockstat		 sock;
	ucl_object_t		*top, *arr, *o;
	unsigned char		*json;
	char			 errbuf[2048];
	unsigned int		 cnt, i, n;
	int			 step;

	rsp->has_ok = true;
	rsp->ok = false;
	step = step_begin(w, ARC_STEP_KIND_LIB, "procstat(3)", "process %u",
	    pid);
	if ((ps = procstat_open_sysctl()) == NULL) {
		step_end(w, step, false, "procstat_open_sysctl failed");
		rsp->error = "the processes could not be looked at";
		return (0);
	}
	if ((kp = procstat_getprocs(ps, KERN_PROC_PID, (int)pid, &cnt)) == NULL
	    || cnt == 0) {
		procstat_close(ps);
		step_end(w, step, false, "not there");
		rsp->error = wfmt(w, "no process %u", pid);
		return (0);
	}
	top = ucl_object_typed_new(UCL_OBJECT);
	num(top, "pid", pid);
	str(top, "comm", wtext(w, kp->ki_comm));
	arr = ucl_object_typed_new(UCL_ARRAY);
	n = 0;
	if ((files = procstat_getfiles(ps, kp, 0)) != NULL) {
		STAILQ_FOREACH(fst, files, next) {
			if (n++ >= 500)
				break;
			o = ucl_object_typed_new(UCL_OBJECT);
			if (fst->fs_fd >= 0)
				num(o, "fd", fst->fs_fd);
			else
				str(o, "use", (fst->fs_uflags & PS_FST_UFLAG_CDIR)
				    != 0 ? "cwd" : (fst->fs_uflags &
				    PS_FST_UFLAG_RDIR) != 0 ? "root" :
				    (fst->fs_uflags & PS_FST_UFLAG_TEXT) != 0 ?
				    "text" : (fst->fs_uflags &
				    PS_FST_UFLAG_MMAP) != 0 ? "mapped" :
				    "other");
			str(o, "type", fst->fs_type >= 0 && fst->fs_type <
			    (int)nitems(types) && types[fst->fs_type] != NULL ?
			    types[fst->fs_type] : "other");
			if (fst->fs_path != NULL)
				str(o, "path", wtext(w, fst->fs_path));
			if (fst->fs_type == PS_FST_TYPE_SOCKET &&
			    procstat_get_socket_info(ps, fst, &sock, errbuf) ==
			    0) {
				str(o, "proto", wtext(w, sock.dname));
				str(o, "local", sock_text(w, &sock.sa_local));
				str(o, "remote", sock_text(w, &sock.sa_peer));
			}
			if ((fst->fs_fflags & (PS_FST_FFLAG_READ |
			    PS_FST_FFLAG_WRITE)) != 0)
				str(o, "mode", (fst->fs_fflags &
				    PS_FST_FFLAG_WRITE) != 0 ? (fst->fs_fflags &
				    PS_FST_FFLAG_READ) != 0 ? "rw" : "w" : "r");
			ucl_array_append(arr, o);
		}
		procstat_freefiles(ps, files);
	}
	ucl_object_insert_key(top, arr, "files", 0, false);
	procstat_freeprocs(ps, kp);
	arr = ucl_object_typed_new(UCL_ARRAY);
	if ((tp = procstat_getprocs(ps, KERN_PROC_PID | KERN_PROC_INC_THREAD,
	    (int)pid, &cnt)) != NULL) {
		for (i = 0; i < cnt && i < 1000; i++) {
			o = ucl_object_typed_new(UCL_OBJECT);
			num(o, "tid", tp[i].ki_tid);
			str(o, "name", wtext(w, tp[i].ki_tdname));
			str(o, "state", state_name(&tp[i]));
			if (tp[i].ki_stat == SSLEEP && tp[i].ki_wmesg[0] != '\0')
				str(o, "wait", wtext(w, tp[i].ki_wmesg));
			num(o, "pri", tp[i].ki_pri.pri_level - PZERO);
			real(o, "wcpu", 100.0 * (double)tp[i].ki_pctcpu / FSCALE);
			real(o, "time", (double)tp[i].ki_runtime / 1e6);
			num(o, "cpu", tp[i].ki_lastcpu);
			ucl_array_append(arr, o);
		}
		procstat_freeprocs(ps, tp);
	}
	ucl_object_insert_key(top, arr, "threads", 0, false);
	procstat_close(ps);
	step_end(w, step, true, "%u files, %u threads", n, cnt);
	json = ucl_object_emit(top, UCL_EMIT_JSON_COMPACT);
	ucl_object_unref(top);
	if (json == NULL || strlen((char *)json) > ARC_MAX_JSON) {
		free(json);
		rsp->error = "more of it than a reply carries";
		return (0);
	}
	rsp->json = wtext(w, wadopt(w, json));
	rsp->ok = true;
	return (0);
}
