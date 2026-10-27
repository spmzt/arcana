/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * The firewall, ipfw(8).  What it has is read from ipfw itself: every
 * rule with its set and its counters, the tables, the NAT instances.
 *
 * It is changed in two ways.  At once: a rule added to, or deleted
 * from, what the kernel has now.  And kept: the rules are a file of
 * ipfw's own commands, one a line, which is what the host loads when it
 * starts (rc.conf's firewall_type) and what "apply" makes the whole
 * ruleset without a gap: the file's rules go into set 1 while it is
 * disabled, and set 1 is then swapped with set 0, so that the packets
 * see the old rules or the new ones and never half of either.  In safe
 * mode the old rules wait in set 1, disabled, and are swapped back
 * unless the change is confirmed: a ruleset that cuts the console off
 * takes itself back.
 *
 * Aliases: a name for what rules say again and again, written $name in
 * a rule.  An address list is an ipfw table of its name, the rule
 * saying table(name), so that changing the list changes the table and
 * no rule; a port list or a single value (an interface, an address) is
 * written into each rule that names it.  The kept file stays ipfw's own
 * commands, which the host loads at boot as they are: an alias is a
 * comment line, "#arcana alias name kind value", and a rule written
 * with aliases is its own comment line, "#arcana add number words",
 * before the rule as ipfw reads it, written again whenever an alias it
 * names changes.
 */

#include <sys/param.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <sys/socket.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ucl.h>
#include <unistd.h>

#include <openssl/evp.h>

#include "agent.h"

#define	IPFW_FILE_MAX	(1024 * 1024)
#define	IPFW_RULES_MAX	20000
#define	IPFW_TABLE_ROWS	500	/* of one table, and no more are sent */
#define	IPFW_WORDS	120
#define	IPFW_DYN_MAX	3000	/* dynamic rules in a reply, at most */
#define	ALIAS_MAX	256

/* An alias, $name in a rule. */
struct alias {
	char		 name[33];
	char		 kind[8];	/* addr, ports, value */
	char		*value;		/* addr: the entries, a space between */
};

static size_t	aliases_of(struct work *, const char *, struct alias *,
		    size_t);
static char	*text_expand(struct work *, const char *, const char **);

static pthread_mutex_t	file_lock = PTHREAD_MUTEX_INITIALIZER;

static void
put(ucl_object_t *o, const char *key, const char *v)
{

	if (v != NULL)
		ucl_object_insert_key(o, ucl_object_fromstring(v), key, 0,
		    false);
}

static const char *
sha_hex(struct work *w, const char *data, size_t len)
{
	unsigned char	md[EVP_MAX_MD_SIZE];
	unsigned int	mdlen, i;
	char		*hex;

	if (EVP_Digest(data, len, md, &mdlen, EVP_sha256(), NULL) != 1)
		return ("");
	hex = wcalloc(w, mdlen * 2 + 1, 1);
	for (i = 0; i < mdlen; i++)
		snprintf(hex + i * 2, 3, "%02x", md[i]);
	return (hex);
}

/* The kept rules' file, in the jail whose firewall it is when one is. */
static char *
file_read(struct work *w, size_t *lenp)
{
	char	*text;
	FILE	*fp;
	size_t	 n;

	*lenp = 0;
	if (w->jail != NULL)
		return (scope_slurp(w, opts.ipfw_rules, lenp));
	if ((fp = fopen(opts.ipfw_rules, "re")) == NULL)
		return (NULL);
	text = wcalloc(w, IPFW_FILE_MAX + 2, 1);
	n = fread(text, 1, IPFW_FILE_MAX + 1, fp);
	fclose(fp);
	if (n > IPFW_FILE_MAX) {
		errno = EFBIG;
		return (NULL);
	}
	text[n] = '\0';
	*lenp = n;
	return (text);
}

static int
file_write(struct work *w, const char *text, size_t len, const char **errp)
{
	char	*tmp, *bak, *dir, *slash;
	int	 fd;

	if (w->jail != NULL) {
		if (scope_replace(w, opts.ipfw_rules, text, len, 0600,
		    ".arcana-old") != 0) {
			*errp = wfmt(w, "%s: %s", opts.ipfw_rules, strerror(
			    errno));
			return (-1);
		}
		return (0);
	}
	dir = wstrdup(w, opts.ipfw_rules);
	if ((slash = strrchr(dir, '/')) != NULL && slash != dir) {
		*slash = '\0';
		(void)mkdir(dir, 0755);
	}
	tmp = wfmt(w, "%s.arcana-new", opts.ipfw_rules);
	bak = wfmt(w, "%s.arcana-old", opts.ipfw_rules);
	if ((fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC |
	    O_NOFOLLOW, 0600)) == -1 || write(fd, text, len) != (ssize_t)len ||
	    fsync(fd) == -1) {
		*errp = wfmt(w, "%s: %s", tmp, strerror(errno));
		if (fd != -1)
			close(fd);
		(void)unlink(tmp);
		return (-1);
	}
	close(fd);
	(void)unlink(bak);
	if ((link(opts.ipfw_rules, bak) == -1 && errno != ENOENT) || rename(
	    tmp, opts.ipfw_rules) == -1) {
		*errp = wfmt(w, "%s: %s", opts.ipfw_rules, strerror(errno));
		(void)unlink(tmp);
		return (-1);
	}
	return (0);
}

/* A word of a rule: what ipfw's own words are made of, and no more. */
static bool
word_ok(const char *s)
{
	size_t	i;

	if (s == NULL || s[0] == '\0' || strlen(s) > 255)
		return (false);
	/* An alias: $ and its name, a word of its own. */
	if (s[0] == '$') {
		for (i = 1; s[i] != '\0'; i++)
			if (!isalnum((unsigned char)s[i]) && s[i] != '_')
				return (false);
		return (i > 1 && i <= 33 && !isdigit((unsigned char)s[1]));
	}
	for (i = 0; s[i] != '\0'; i++)
		if (!isalnum((unsigned char)s[i]) && strchr("._:/,-{}!()=+*@"
		    "<>[]%~^&|#", s[i]) == NULL)
			return (false);
	return (true);
}

static bool
number_ok(const char *s)
{
	char	*end;
	long	 v;

	if (s == NULL || !isdigit((unsigned char)s[0]))
		return (false);
	v = strtol(s, &end, 10);
	return (*end == '\0' && v >= 1 && v <= 65534);
}

/*
 * Text made by appending, a memstream's: nothing is cut short, however
 * long aliases make it.  ms_close(): the text in w's arena, its length
 * in *lenp; NULL when memory ran out.
 */
struct ms {
	FILE	*fp;
	char	*buf;
	size_t	 len;
};

static bool
ms_open(struct ms *m)
{

	m->buf = NULL;
	m->len = 0;
	return ((m->fp = open_memstream(&m->buf, &m->len)) != NULL);
}

static char *
ms_close(struct work *w, struct ms *m, size_t *lenp)
{
	char	*s = NULL;

	if (fclose(m->fp) == 0 && m->buf != NULL) {
		s = wcalloc(w, m->len + 1, 1);
		memcpy(s, m->buf, m->len);
		if (lenp != NULL)
			*lenp = m->len;
	}
	free(m->buf);
	return (s);
}

/*
 * A line of the kept file as a rule: its number, and where its words
 * begin; false for what is not "add <number> ...".
 */
static bool
kept_rule(const char *line, long *nump, const char **restp)
{
	const char	*p;
	char		*end;

	p = line + strspn(line, " \t");
	if (strncmp(p, "add", 3) != 0 || (p[3] != ' ' && p[3] != '\t'))
		return (false);
	p += 3 + strspn(p + 3, " \t");
	if (!isdigit((unsigned char)*p))
		return (false);
	*nump = strtol(p, &end, 10);
	if (*end != ' ' && *end != '\t')
		return (false);
	/* ipfw's numbers are 1 to 65535: past it, no rule of ours. */
	if (*nump < 1 || *nump > 65535)
		return (false);
	end += strspn(end, " \t");
	/*
	 * "add N set S ...": a set of the rule's own, as a script that
	 * stages its rules in a set writes them.  The kept rules are set
	 * 0's once applied (Apply loads them into set 1 and swaps), so the
	 * rule's words begin after it.
	 */
	if (strncmp(end, "set", 3) == 0 && (end[3] == ' ' || end[3] == '\t')) {
		char	*after;

		p = end + 3 + strspn(end + 3, " \t");
		if (isdigit((unsigned char)*p)) {
			(void)strtol(p, &after, 10);
			if (*after == ' ' || *after == '\t')
				end = after + strspn(after, " \t");
		}
	}
	*restp = end;
	return (true);
}

static bool	alias_name_ok(const char *);
static bool	src_rule(const char *, long *, const char **);
static bool	prefix_ok(const char *);
static size_t	split(struct work *, const char *, const char **, size_t);
static int	ipfw_norm(struct work *, int, const long *, const char *const *,
		    const char **, const char **);

/*
 * Is there a firewall to ask?  ipfw in the kernel; or another program
 * in ipfw's place, which is how the tests run and answers for itself.
 */
static bool
have(void)
{

	return (kmod_loaded("ipfw") || strcmp(opts.ipfw_bin, "/sbin/ipfw") !=
	    0);
}

/* On, in the network looked at: a jail's is its own, read inside it. */
static bool
enabled(struct work *w)
{
	static const char *const name[] = { "net.inet.ip.fw.enable" };
	struct execres	res;
	int		v;
	size_t		len;

	if (w->jail != NULL)
		return (run_exec(w, helper_argv(w, "sysctl-int", 1, name),
		    &res) == 0 && res.out != NULL && atoi(res.out) != 0);
	len = sizeof(v);
	return (sysctlbyname(name[0], &v, &len, NULL, 0) == 0 && v != 0);
}

/* Run ipfw with the words; 0, or -1 and why. */
static int
ipfw(struct work *w, const char **errp, int quiet, ...)
{
	struct execres	 res;
	va_list		 ap;
	char		*argv[IPFW_WORDS + 4];
	const char	*a;
	int		 n;

	n = 0;
	argv[n++] = (char *)(uintptr_t)opts.ipfw_bin;
	if (quiet)
		argv[n++] = (char *)(uintptr_t)"-q";
	va_start(ap, quiet);
	while ((a = va_arg(ap, const char *)) != NULL && n < IPFW_WORDS + 2)
		argv[n++] = (char *)(uintptr_t)a;
	va_end(ap);
	argv[n] = NULL;
	if (run_exec(w, scope_argv(w, argv), &res) != 0) {
		if (errp != NULL) {
			*errp = scope_missing(w, &res, "ipfw", NULL);
			if (*errp == NULL)
				*errp = wtext(w, exec_error(w, &res, "ipfw"));
		}
		return (-1);
	}
	return (0);
}

/* --- dummynet, read ---------------------------------------------------- */

/* "10.000 Mbit/s" as bits a second; 0 for no limit. */
static int64_t
dn_bw(const char *s)
{
	double	v;
	char	unit[16];

	if (sscanf(s, "%lf %15s", &v, unit) != 2)
		return (0);
	if (strncmp(unit, "Gbit", 4) == 0)
		v *= 1e9;
	else if (strncmp(unit, "Mbit", 4) == 0)
		v *= 1e6;
	else if (strncmp(unit, "Kbit", 4) == 0)
		v *= 1e3;
	return ((int64_t)(v + .5));
}

/* A mask of 32 bits as its prefix's length, -1 when it is none. */
static int
dn_prefix(unsigned long m)
{
	int	n;

	for (n = 0; n < 32 && (m & (0x80000000UL >> n)) != 0; n++)
		;
	return ((m << n & 0xffffffffUL) == 0 ? n : -1);
}

/* "mask:  0x00 0xffffff00/0x0000 -> 0x00000000/0x0000" */
static ucl_object_t *
dn_mask(const char *line)
{
	ucl_object_t	*m;
	unsigned long	 proto, src, sp, dst, dp;

	if (sscanf(line, " mask: 0x%lx 0x%lx/0x%lx -> 0x%lx/0x%lx", &proto,
	    &src, &sp, &dst, &dp) != 5)
		return (NULL);
	m = ucl_object_typed_new(UCL_OBJECT);
	ucl_object_insert_key(m, ucl_object_fromint(dn_prefix(src)), "src",
	    0, false);
	ucl_object_insert_key(m, ucl_object_fromint(dn_prefix(dst)), "dst",
	    0, false);
	ucl_object_insert_key(m, ucl_object_fromint((int64_t)sp), "src_port",
	    0, false);
	ucl_object_insert_key(m, ucl_object_fromint((int64_t)dp), "dst_port",
	    0, false);
	ucl_object_insert_key(m, ucl_object_fromint((int64_t)proto), "proto",
	    0, false);
	return (m);
}

/* "00001:  10.000 Mbit/s   20 ms burst 0": a link's figures, into o. */
static bool
dn_link(const char *line, ucl_object_t *o)
{
	const char	*p, *ms;
	char		*end;
	long		 num;

	num = strtol(line, &end, 10);
	if (end == line || *end != ':')
		return (false);
	p = end + 1;
	p += strspn(p, " ");
	ucl_object_insert_key(o, ucl_object_fromint(num), "num", 0, false);
	if (strncmp(p, "unlimited", 9) == 0)
		ucl_object_insert_key(o, ucl_object_fromint(0), "bw", 0, false);
	else
		ucl_object_insert_key(o, ucl_object_fromint(dn_bw(p)), "bw", 0,
		    false);
	if ((ms = strstr(p, " ms")) != NULL) {
		while (ms > p && ms[-1] >= '0' && ms[-1] <= '9')
			ms--;
		ucl_object_insert_key(o, ucl_object_fromint(strtol(ms, NULL,
		    10)), "delay", 0, false);
	}
	if ((ms = strstr(p, "burst ")) != NULL)
		ucl_object_insert_key(o, ucl_object_fromint(strtoll(ms + 6,
		    NULL, 10)), "burst", 0, false);
	return (true);
}

/* "q00001  50 sl.plr 0.01 0 flows (64 buckets) sched 1 weight 10 ...":
 * a flowset's figures, into o. */
static void
dn_flowset(const char *line, ucl_object_t *o)
{
	const char	*p;

	p = line + 1 + strspn(line + 1, "0123456789");
	p += strspn(p, " ");
	if (strstr(p, " KB") != NULL && strstr(p, " KB") < strstr(p, "flows"))
		ucl_object_insert_key(o, ucl_object_fromint(strtol(p, NULL,
		    10) * 1024), "bytes", 0, false);
	else
		ucl_object_insert_key(o, ucl_object_fromint(strtol(p, NULL,
		    10)), "slots", 0, false);
	if ((p = strstr(line, "plr ")) != NULL)
		ucl_object_insert_key(o, ucl_object_fromdouble(strtod(p + 4,
		    NULL)), "plr", 0, false);
	if ((p = strstr(line, " sched ")) != NULL)
		ucl_object_insert_key(o, ucl_object_fromint(strtol(p + 7, NULL,
		    10)), "sched", 0, false);
	if ((p = strstr(line, " weight ")) != NULL)
		ucl_object_insert_key(o, ucl_object_fromint(strtol(p + 8, NULL,
		    10)), "weight", 0, false);
	if ((p = strstr(line, " pri ")) != NULL)
		ucl_object_insert_key(o, ucl_object_fromint(strtol(p + 5, NULL,
		    10)), "pri", 0, false);
}

/*
 * The pipes, schedulers and queues of dummynet, as objects: ipfw pipe,
 * sched and queue show, read.  A pipe's own scheduler and queue (65536
 * and on) are its own, not shown apart.
 */
static ucl_object_t *
dn_read(struct work *w)
{
	static const char *const kinds[] = { "pipe", "sched", "queue" };
	struct execres	 res;
	ucl_object_t	*top, *arr, *cur, *m;
	char		*argv[4], *text, *p, *line, *t;
	size_t		 k;

	top = ucl_object_typed_new(UCL_OBJECT);
	for (k = 0; k < nitems(kinds); k++) {
		arr = ucl_object_typed_new(UCL_ARRAY);
		argv[0] = (char *)(uintptr_t)opts.ipfw_bin;
		argv[1] = (char *)(uintptr_t)kinds[k];
		argv[2] = (char *)(uintptr_t)"show";
		argv[3] = NULL;
		cur = NULL;
		if (run_exec(w, scope_argv(w, argv), &res) == 0 && res.out !=
		    NULL) {
			text = wstrndup(w, res.out, res.outlen);
			p = text;
			while ((line = strsep(&p, "\n")) != NULL) {
				t = line + strspn(line, " \t");
				if (k < 2 && line[0] >= '0' && line[0] <= '9') {
					cur = ucl_object_typed_new(UCL_OBJECT);
					if (!dn_link(line, cur)) {
						ucl_object_unref(cur);
						cur = NULL;
						continue;
					}
					ucl_array_append(arr, cur);
				} else if (k == 2 && line[0] == 'q') {
					cur = ucl_object_typed_new(UCL_OBJECT);
					ucl_object_insert_key(cur,
					    ucl_object_fromint(strtol(line + 1,
					    NULL, 10)), "num", 0, false);
					dn_flowset(line, cur);
					ucl_array_append(arr, cur);
				} else if (cur == NULL)
					continue;
				else if (k == 0 && line[0] == 'q')
					dn_flowset(line, cur);
				else if (k == 1 && strncmp(t, "sched ", 6) == 0) {
					t = strstr(t, " type ");
					if (t != NULL)
						ucl_object_insert_key(cur,
						    ucl_object_fromlstring(t + 6,
						    strcspn(t + 6, " ")), "type",
						    0, false);
				} else if (strncmp(t, "mask:", 5) == 0) {
					if ((m = dn_mask(t)) != NULL)
						ucl_object_insert_key(cur, m,
						    "mask", 0, true);
				} else if (k == 1 && strncmp(t, "Children "
				    "flowsets:", 18) == 0) {
					ucl_object_t	*ch;
					char		*q, *e;

					ch = ucl_object_typed_new(UCL_ARRAY);
					for (q = t + 18; *q != '\0'; q = e) {
						long	v;

						v = strtol(q, &e, 10);
						if (e == q)
							break;
						ucl_array_append(ch,
						    ucl_object_fromint(v));
					}
					ucl_object_insert_key(cur, ch,
					    "queues", 0, true);
				} else if (strncmp(t, "RED ", 4) == 0 ||
				    strncmp(t, "GRED ", 5) == 0)
					ucl_object_insert_key(cur,
					    ucl_object_fromstring(t), "red", 0,
					    true);
				else if (k == 1 && line[0] == ' ' &&
				    isupper((unsigned char)t[0]) && strncmp(t,
				    "Children", 8) != 0)
					/* FQ_CODEL target 5ms ...: its own. */
					ucl_object_insert_key(cur,
					    ucl_object_fromstring(t), "params", 0,
					    true);
			}
		}
		ucl_object_insert_key(top, arr, k == 0 ? "pipes" : k == 1 ?
		    "scheds" : "queues", 0, false);
	}
	return (top);
}

/* {"loaded","enabled","rules":[...],"tables","nat","kept","other",...} */
int
do_ipfw(struct work *w, struct arc_network_rsp *rsp)
{
	struct execres	 res;
	ucl_object_t	*top, *rules, *o, *kept, *other, *arr, *rc;
	unsigned char	*json;
	const ucl_object_t *co;
	ucl_object_iter_t it;
	char		*argv[5], *text, *p, *line, *t, *end;
	const char	*rest, *v;
	size_t		 len;
	long		 num;
	int		 n;
	bool		 disabled, loaded;

	rsp->has_ok = true;
	rsp->ok = false;
	top = ucl_object_typed_new(UCL_OBJECT);
	rules = ucl_object_typed_new(UCL_ARRAY);
	loaded = have();
	ucl_object_insert_key(top, ucl_object_frombool(loaded), "loaded", 0,
	    false);
	ucl_object_insert_key(top, ucl_object_frombool(loaded && (enabled(w) ||
	    !kmod_loaded("ipfw"))), "enabled", 0, false);
	argv[0] = (char *)(uintptr_t)opts.ipfw_bin;
	argv[1] = (char *)(uintptr_t)"-S";
	argv[2] = (char *)(uintptr_t)"show";
	argv[3] = NULL;
	if (loaded && run_exec_max(w, scope_argv(w, argv), &res, 16 * 1024 *
	    1024) == 0) {
		text = wstrndup(w, res.out != NULL ? res.out : "", res.outlen);
		p = text;
		n = 0;
		while ((line = strsep(&p, "\n")) != NULL && n < IPFW_RULES_MAX) {
			/* "# DISABLED " before one whose set is off. */
			disabled = strncmp(line, "# DISABLED ", 11) == 0;
			if (disabled)
				line += 11;
			if (!isdigit((unsigned char)line[0]))
				continue;
			o = ucl_object_typed_new(UCL_OBJECT);
			num = strtol(line, &end, 10);
			ucl_object_insert_key(o, ucl_object_fromint(num), "num",
			    0, false);
			t = end + strspn(end, " ");
			ucl_object_insert_key(o, ucl_object_fromint(strtoll(t,
			    &end, 10)), "pkts", 0, false);
			t = end + strspn(end, " ");
			ucl_object_insert_key(o, ucl_object_fromint(strtoll(t,
			    &end, 10)), "bytes", 0, false);
			t = end + strspn(end, " ");
			if (strncmp(t, "set ", 4) == 0) {
				ucl_object_insert_key(o, ucl_object_fromint(
				    strtol(t + 4, &end, 10)), "set", 0, false);
				t = end + strspn(end, " ");
			} else
				ucl_object_insert_key(o, ucl_object_fromint(0),
				    "set", 0, false);
			put(o, "text", t);
			if (disabled)
				ucl_object_insert_key(o, ucl_object_frombool(
				    true), "disabled", 0, false);
			ucl_array_append(rules, o);
			n++;
		}
	}
	ucl_object_insert_key(top, rules, "rules", 0, false);
	/*
	 * The dynamic rules, as ipfw -D show has them: the connections
	 * the stateful rules let through, each with the rule that made
	 * it, its counters and how long it still lives.
	 */
	arr = ucl_object_typed_new(UCL_ARRAY);
	argv[1] = (char *)(uintptr_t)"-D";
	argv[2] = (char *)(uintptr_t)"show";
	argv[3] = NULL;
	if (loaded && run_exec_max(w, scope_argv(w, argv), &res, 8 * 1024 *
	    1024) == 0) {
		text = wstrndup(w, res.out != NULL ? res.out : "", res.outlen);
		p = text;
		n = 0;
		while ((line = strsep(&p, "\n")) != NULL) {
			if (!isdigit((unsigned char)line[0]))
				continue;
			if (++n > IPFW_DYN_MAX)
				continue;
			o = ucl_object_typed_new(UCL_OBJECT);
			ucl_object_insert_key(o, ucl_object_fromint(strtol(
			    line, &end, 10)), "num", 0, false);
			t = end + strspn(end, " ");
			ucl_object_insert_key(o, ucl_object_fromint(strtoll(t,
			    &end, 10)), "pkts", 0, false);
			t = end + strspn(end, " ");
			ucl_object_insert_key(o, ucl_object_fromint(strtoll(t,
			    &end, 10)), "bytes", 0, false);
			t = end + strspn(end, " ");
			if (*t == '(') {
				ucl_object_insert_key(o, ucl_object_fromint(
				    strtol(t + 1, &end, 10)), "ttl", 0, false);
				t = end + strcspn(end, " ");
				t += strspn(t, " ");
			}
			/* STATE, PARENT or LIMIT, and then the flow. */
			if (isupper((unsigned char)*t)) {
				end = t + strcspn(t, " ");
				put(o, "kind", wstrndup(w, t, (size_t)(end -
				    t)));
				t = end + strspn(end, " ");
			}
			put(o, "flow", t);
			ucl_array_append(arr, o);
		}
		ucl_object_insert_key(top, ucl_object_fromint(n), "dynamic_total",
		    0, false);
	}
	ucl_object_insert_key(top, arr, "dynamic", 0, false);
	/* The tables, by name, and the NAT instances as they were made. */
	arr = ucl_object_typed_new(UCL_ARRAY);
	argv[1] = (char *)(uintptr_t)"table";
	argv[2] = (char *)(uintptr_t)"all";
	argv[3] = (char *)(uintptr_t)"info";
	argv[4] = NULL;
	if (loaded && run_exec(w, scope_argv(w, argv), &res) == 0) {
		text = wstrndup(w, res.out != NULL ? res.out : "", res.outlen);
		p = text;
		o = NULL;
		while ((line = strsep(&p, "\n")) != NULL) {
			if (strncmp(line, "--- table(", 10) == 0) {
				line += 10;
				line[strcspn(line, ")")] = '\0';
				o = ucl_object_typed_new(UCL_OBJECT);
				put(o, "name", line);
				ucl_array_append(arr, o);
			} else if (o != NULL && strstr(line, "kindex") !=
			    NULL && (t = strstr(line, " type: ")) != NULL) {
				t += 7;
				t[strcspn(t, ", ")] = '\0';
				put(o, "type", t);
			}
		}
		/* What each holds: a key a line, and its value. */
		it = NULL;
		while ((co = ucl_object_iterate(arr, &it, true)) != NULL) {
			ucl_object_t	*ents, *e;
			int		 cnt;

			o = (ucl_object_t *)(uintptr_t)co;
			argv[2] = (char *)(uintptr_t)ucl_object_tostring(
			    ucl_object_lookup(o, "name"));
			argv[3] = (char *)(uintptr_t)"list";
			ents = ucl_object_typed_new(UCL_ARRAY);
			cnt = 0;
			if (run_exec(w, scope_argv(w, argv), &res) == 0 &&
			    res.out != NULL) {
				text = wstrndup(w, res.out, res.outlen);
				p = text;
				while ((line = strsep(&p, "\n")) != NULL) {
					if (line[0] == '\0' || line[0] == '-')
						continue;
					if (cnt++ >= IPFW_TABLE_ROWS)
						continue;
					e = ucl_object_typed_new(UCL_OBJECT);
					t = line + strcspn(line, " ");
					if (*t != '\0')
						*t++ = '\0';
					put(e, "key", line);
					put(e, "value", t);
					ucl_array_append(ents, e);
				}
			}
			ucl_object_insert_key(o, ents, "entries", 0, false);
			ucl_object_insert_key(o, ucl_object_fromint(cnt),
			    "count", 0, false);
		}
		argv[2] = (char *)(uintptr_t)"all";
	}
	ucl_object_insert_key(top, arr, "tables", 0, false);
	arr = ucl_object_typed_new(UCL_ARRAY);
	argv[1] = (char *)(uintptr_t)"nat";
	argv[2] = (char *)(uintptr_t)"show";
	argv[3] = (char *)(uintptr_t)"config";
	if (loaded && kmod_loaded("ipfw_nat") && run_exec(w, scope_argv(w,
	    argv), &res) == 0) {
		text = wstrndup(w, res.out != NULL ? res.out : "", res.outlen);
		p = text;
		while ((line = strsep(&p, "\n")) != NULL)
			if (line[0] != '\0')
				ucl_array_append(arr, ucl_object_fromstring(
				    line));
	}
	ucl_object_insert_key(top, arr, "nat", 0, false);
	/* The pipes and queues of dummynet, as ipfw shows them. */
	arr = ucl_object_typed_new(UCL_ARRAY);
	argv[1] = (char *)(uintptr_t)"pipe";
	argv[2] = (char *)(uintptr_t)"show";
	argv[3] = NULL;
	if (loaded && (kmod_loaded("dummynet") || strcmp(opts.ipfw_bin,
	    "/sbin/ipfw") != 0) && run_exec(w, scope_argv(w,
	    argv), &res) == 0) {
		text = wstrndup(w, res.out != NULL ? res.out : "", res.outlen);
		p = text;
		while ((line = strsep(&p, "\n")) != NULL)
			if (line[0] != '\0')
				ucl_array_append(arr, ucl_object_fromstring(
				    line));
	}
	ucl_object_insert_key(top, arr, "pipes", 0, false);
	/* And as objects, for QoS by forms. */
	if (loaded && (kmod_loaded("dummynet") || strcmp(opts.ipfw_bin,
	    "/sbin/ipfw") != 0))
		ucl_object_insert_key(top, dn_read(w), "qos", 0, false);
	/* Whether a rule with log writes a line to the security log. */
	{
		int	vb;
		size_t	vl;

		vl = sizeof(vb);
		if (loaded && sysctlbyname("net.inet.ip.fw.verbose", &vb, &vl,
		    NULL, 0) == 0)
			ucl_object_insert_key(top, ucl_object_frombool(vb !=
			    0), "verbose", 0, false);
	}

	/* What is kept: its rules, and its lines that are not rules. */
	kept = ucl_object_typed_new(UCL_ARRAY);
	other = ucl_object_typed_new(UCL_ARRAY);
	pthread_mutex_lock(&file_lock);
	text = file_read(w, &len);
	pthread_mutex_unlock(&file_lock);
	/* The aliases, an address list with its entries. */
	{
		struct alias	al[ALIAS_MAX];
		size_t		nal, i;

		nal = aliases_of(w, text, al, nitems(al));
		arr = ucl_object_typed_new(UCL_ARRAY);
		for (i = 0; i < nal; i++) {
			o = ucl_object_typed_new(UCL_OBJECT);
			put(o, "name", al[i].name);
			put(o, "kind", al[i].kind);
			put(o, "value", al[i].value);
			ucl_array_append(arr, o);
		}
		ucl_object_insert_key(top, arr, "aliases", 0, false);
	}
	{
		const char	*src = NULL;
		long		 srcnum = -1;

		p = text;
		while (p != NULL && (line = strsep(&p, "\n")) != NULL) {
			line += strspn(line, " \t");
			/* A rule's own words, its aliases in them. */
			if (src_rule(line, &srcnum, &src))
				continue;
			if (line[0] == '\0' || line[0] == '#')
				continue;
			if (kept_rule(line, &num, &rest)) {
				o = ucl_object_typed_new(UCL_OBJECT);
				ucl_object_insert_key(o, ucl_object_fromint(num),
				    "num", 0, false);
				put(o, "text", rest);
				if (src != NULL && srcnum == num)
					put(o, "source", src);
				ucl_array_append(kept, o);
			} else
				ucl_array_append(other, ucl_object_fromstring(
				    line));
			src = NULL;
			srcnum = -1;
		}
	}
	/*
	 * Each kept rule as ipfw writes it back (ipfw -n, the kernel not
	 * asked): "norm", what the kernel's listing of it would say, for
	 * the panel to set beside the kernel's own without a difference of
	 * wording.  Where ipfw stops at one, those after have none.
	 */
	{
		const ucl_object_t	*ko;
		ucl_object_iter_t	 kit;
		const char		**texts, **out, *e;
		long			*nums;
		int			 nk, k;

		nk = (int)ucl_array_size(kept);
		nums = wcalloc(w, (size_t)nk + 1, sizeof(*nums));
		texts = wcalloc(w, (size_t)nk + 1, sizeof(*texts));
		out = wcalloc(w, (size_t)nk + 1, sizeof(*out));
		k = 0;
		kit = NULL;
		while ((ko = ucl_object_iterate(kept, &kit, true)) != NULL &&
		    k < nk) {
			nums[k] = (long)ucl_object_toint(ucl_object_lookup(ko,
			    "num"));
			texts[k] = ucl_object_tostring(ucl_object_lookup(ko,
			    "text"));
			if (texts[k] == NULL)
				texts[k] = "";
			k++;
		}
		if (nk > 0)
			(void)ipfw_norm(w, nk, nums, texts, out, &e);
		k = 0;
		kit = NULL;
		while ((ko = ucl_object_iterate(kept, &kit, true)) != NULL &&
		    k < nk) {
			if (out[k] != NULL)
				put((ucl_object_t *)(uintptr_t)ko, "norm", out[k]);
			k++;
		}
	}
	ucl_object_insert_key(top, kept, "kept", 0, false);
	ucl_object_insert_key(top, other, "other", 0, false);
	ucl_object_insert_key(top, ucl_object_frombool(text != NULL), "file", 0,
	    false);
	put(top, "path", opts.ipfw_rules);
	rc = ucl_object_typed_new(UCL_OBJECT);
	if (w->jail == NULL) {
		if ((v = rc_get(w, "firewall_enable")) != NULL)
			put(rc, "firewall_enable", v);
		if ((v = rc_get(w, "firewall_type")) != NULL)
			put(rc, "firewall_type", v);
		if ((v = rc_get(w, "firewall_script")) != NULL)
			put(rc, "firewall_script", v);
	}
	ucl_object_insert_key(top, rc, "rc", 0, false);
	json = ucl_object_emit(top, UCL_EMIT_JSON_COMPACT);
	ucl_object_unref(top);
	if (json == NULL || strlen((char *)json) > ARC_MAX_JSON) {
		free(json);
		rsp->error = "the firewall's rules are more than a reply "
		    "carries";
		return (0);
	}
	rsp->json = wtext(w, wadopt(w, json));
	rsp->ok = true;
	return (0);
}

/*
 * Has ipfw anything against the text?  It reads it without doing it
 * (ipfw -n), from a file beside the kept one.
 */
static const char *
file_wrong(struct work *w, const char *text, size_t len)
{
	struct execres	 res;
	char		*argv[5], *tmp;
	const char	*e;
	int		 fd;

	if (w->jail != NULL || !have())
		return (NULL);
	tmp = wfmt(w, "%s.arcana-check", opts.ipfw_rules);
	if ((fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC |
	    O_NOFOLLOW, 0600)) == -1)
		return (NULL);
	if (write(fd, text, len) != (ssize_t)len) {
		close(fd);
		(void)unlink(tmp);
		return (NULL);
	}
	close(fd);
	argv[0] = (char *)(uintptr_t)opts.ipfw_bin;
	argv[1] = (char *)(uintptr_t)"-n";
	argv[2] = (char *)(uintptr_t)"-q";
	argv[3] = tmp;
	argv[4] = NULL;
	e = NULL;
	if (run_exec(w, argv, &res) != 0)
		e = wtext(w, exec_error(w, &res, "ipfw"));
	(void)unlink(tmp);
	return (e);
}

/* sysrc -n of a variable, in the jail whose firewall it is; "" none. */
static const char *
rc_value(struct work *w, const char *var)
{
	struct execres	 res;
	char		*argv[5];

	argv[0] = (char *)(uintptr_t)opts.sysrc_bin;
	argv[1] = (char *)(uintptr_t)"-i";
	argv[2] = (char *)(uintptr_t)"-n";
	argv[3] = (char *)(uintptr_t)var;
	argv[4] = NULL;
	if (run_exec(w, scope_argv(w, argv), &res) == 0 && res.out != NULL)
		return (wstrndup(w, res.out, strcspn(res.out, "\n")));
	return ("");
}

/* A shell word of the script taken as it is, its quotes and the
 * backslashes before ( ) taken off: what ipfw is given. */
static size_t
unshell(char *q)
{
	char	*r, *t, quote;

	quote = '\0';
	for (r = t = q; *r != '\0'; r++) {
		if (quote == '\0' && (*r == '"' || *r == '\'')) {
			quote = *r;
			continue;
		}
		if (quote != '\0' && *r == quote) {
			quote = '\0';
			continue;
		}
		if (quote == '\0' && *r == '\\' && r[1] != '\0') {
			*t++ = *++r;
			continue;
		}
		*t++ = *r;
	}
	*t = '\0';
	return ((size_t)(t - q));
}

/*
 * What a line of the firewall's script asks of ipfw, without ipfw and
 * its options: the line begins with ipfw (or its path) or a variable
 * holding it ($fwcmd, ${cmd}); NULL for a line of the shell's own.
 */
static bool
ipfw_word(const char *q)
{
	static const char *const words[] = { "add", "table", "pipe", "queue",
	    "sched", "nat", "nat64lsn", "nat64stl", "nat64clat", "nptv6",
	    "flush", "set", "delete" };
	size_t	i, n;

	n = strcspn(q, " \t");
	for (i = 0; i < nitems(words); i++)
		if (n == strlen(words[i]) && strncmp(q, words[i], n) == 0)
			return (true);
	return (false);
}

static char *
script_ipfw(char *q)
{
	char	*tok, *after;
	size_t	 n, i;
	bool	 func;

	n = strcspn(q, " \t");
	tok = q;
	/* A function of the script's own in ipfw's place (fw add ...): a
	 * name, then ipfw's words. */
	func = n > 0 && (isalpha((unsigned char)tok[0]) || tok[0] == '_');
	for (i = 0; func && i < n; i++)
		if (!isalnum((unsigned char)tok[i]) && tok[i] != '_')
			func = false;
	after = q + n;
	after += strspn(after, " \t");
	if (func && !ipfw_word(after))
		func = false;
	/* The shell's own commands are not a function standing for ipfw. */
	if (func && ((n == 4 && strncmp(tok, "echo", 4) == 0) || (n == 6 &&
	    (strncmp(tok, "printf", 6) == 0 || strncmp(tok, "logger", 6) ==
	    0)) || (n == 4 && strncmp(tok, "test", 4) == 0) || (n == 5 &&
	    strncmp(tok, "local", 5) == 0)))
		func = false;
	/* ipfw, a path to it, or a variable: not an assignment. */
	if (!func && (memchr(tok, '=', n) != NULL || !((n == 4 && strncmp(tok,
	    "ipfw", 4) == 0) || (tok[0] == '/' && n > 5 && strncmp(tok + n - 5,
	    "/ipfw", 5) == 0) || (tok[0] == '$' && n > 1))))
		return (NULL);
	q += n;
	q += strspn(q, " \t");
	/* A variable may be ipfw with its options already: what follows
	 * must be ipfw's words, not a shell's. */
	while (q[0] == '-' && q[1] != '\0' && strchr(" \t", q[2]) != NULL &&
	    strchr("qfnN", q[1]) != NULL)
		q += 2 + strspn(q + 2, " \t");
	if (tok[0] == '$' && strncmp(q, "add", 3) != 0 && strncmp(q, "table",
	    5) != 0 && strncmp(q, "pipe", 4) != 0 && strncmp(q, "queue", 5) !=
	    0 && strncmp(q, "sched", 5) != 0 && strncmp(q, "nat", 3) != 0 &&
	    strncmp(q, "flush", 5) != 0 && strncmp(q, "set", 3) != 0 &&
	    strncmp(q, "delete", 6) != 0)
		return (NULL);
	return (q);
}

/* A script's variables, as its assignments set them. */
struct shvar {
	char		 name[64];
	const char	*value;		/* NULL: set by what is not known here */
};
#define	SHVARS	128

/*
 * NAME=value at the head of a line: true, the name and the value as the
 * shell would take it (one word, or quoted), into *namep and *valp.
 */
static bool
sh_assignment(struct work *w, const char *q, char *name, size_t nlen,
    char **valp)
{
	const char	*v, *e;
	size_t		 n;

	n = 0;
	if (!isalpha((unsigned char)q[0]) && q[0] != '_')
		return (false);
	while (isalnum((unsigned char)q[n]) || q[n] == '_')
		n++;
	if (q[n] != '=' || n >= nlen)
		return (false);
	memcpy(name, q, n);
	name[n] = '\0';
	v = q + n + 1;
	if (*v == '"' || *v == '\'') {
		if ((e = strchr(v + 1, *v)) == NULL)
			return (false);
		*valp = wstrndup(w, v + 1, (size_t)(e - v - 1));
	} else
		*valp = wstrndup(w, v, strcspn(v, " \t;"));
	return (true);
}

/*
 * The line with $NAME and ${NAME} put in from vars; *unknownp true when
 * one is not known (a variable set by what is not read here, a $1).
 */
static char *
sh_subst(struct work *w, const char *q, const struct shvar *vars, int nv,
    bool *unknownp)
{
	char		*out, name[64];
	const char	*p, *val;
	size_t		 cap, len, n;
	int		 i;
	bool		 brace;

	cap = strlen(q) + 1;
	for (i = 0; i < nv; i++)
		if (vars[i].value != NULL)
			cap += strlen(vars[i].value) * 8;
	out = wcalloc(w, cap + 1, 1);
	len = 0;
	for (p = q; *p != '\0' && len < cap;) {
		if (p[0] != '$') {
			out[len++] = *p++;
			continue;
		}
		brace = p[1] == '{';
		n = 0;
		while (n < sizeof(name) - 1 && (isalnum((unsigned char)p[1 +
		    brace + n]) || p[1 + brace + n] == '_'))
			n++;
		if (n == 0 || (brace && p[1 + brace + n] != '}')) {
			if (unknownp != NULL)
				*unknownp = true;
			out[len++] = *p++;
			continue;
		}
		memcpy(name, p + 1 + brace, n);
		name[n] = '\0';
		val = NULL;
		for (i = nv - 1; i >= 0 && val == NULL; i--)
			if (strcmp(vars[i].name, name) == 0)
				val = vars[i].value;
		if (val == NULL) {
			if (unknownp != NULL)
				*unknownp = true;
			n += 1 + brace + (brace ? 1 : 0);
			memcpy(out + len, p, n < cap - len ? n : cap - len);
			len += n;
			p += n;
			continue;
		}
		len += strlcpy(out + len, val, cap - len);
		p += 1 + brace + n + (brace ? 1 : 0);
	}
	out[len < cap ? len : cap] = '\0';
	return (out);
}

/* Does the line open (1) or close (-1) a block of the shell's? */
static int
sh_block(const char *q)
{
	static const char *const open[] = { "if", "case", "for", "while",
	    "until" };
	static const char *const close[] = { "fi", "esac", "done" };
	size_t	i, n;

	n = strcspn(q, " \t;");
	for (i = 0; i < nitems(open); i++)
		if (n == strlen(open[i]) && strncmp(q, open[i], n) == 0)
			return (1);
	for (i = 0; i < nitems(close); i++)
		if (n == strlen(close[i]) && strncmp(q, close[i], n) == 0)
			return (-1);
	return (0);
}

/*
 * The file the host, or the jail, loads now as its firewall, as kept
 * rules: the script rc.conf's firewall_script names when it is one of
 * the host's own, its ipfw commands taken out of it (the shell's own
 * lines left in as comments); else the file firewall_type names, when
 * it names a file and not a kind of rc.firewall's own.  What applying
 * does itself (flush, set, delete, an option alone) is left in as a
 * comment, and the options before a command (-q, -f) taken off it.
 */
static const char *
rc_ruleset(struct work *w, const char **pathp, const char **errp)
{
	static const char	 note[] = "# left out, applying does it: ";
	static const char	 shnote[] = "# left out, the script's own: ";
	char			*text, *out, *p, *line, *q, *c;
	const char		*type, *script, *file, *rest;
	size_t			 len, n, o;
	long			 num;
	int			 step, e;
	bool			 sh;

	script = rc_value(w, "firewall_script");
	type = rc_value(w, "firewall_type");
	sh = script[0] == '/' && strcmp(script, "/etc/rc.firewall") != 0;
	if (sh)
		file = script;
	else if (type[0] == '/')
		file = type;
	else {
		*errp = type[0] != '\0' ? wfmt(w, "firewall_script is %s and "
		    "firewall_type %s, one of rc.firewall's own rulesets: there "
		    "is no file of rules the firewall loads", script[0] != '\0' ?
		    script : "/etc/rc.firewall", type) : wfmt(w, "rc.conf sets no "
		    "firewall_script of its own nor a firewall_type file: there "
		    "is no file of rules the firewall loads");
		return (NULL);
	}
	*pathp = file;
	if (strcmp(file, opts.ipfw_rules) == 0) {
		*errp = wfmt(w, "%s is %s already: the kept rules are what the "
		    "firewall loads", sh ? "firewall_script" : "firewall_type",
		    file);
		return (NULL);
	}
	step = step_begin(w, ARC_STEP_KIND_FILE, "read", "%s", file);
	text = scope_slurp(w, file, &len);
	e = errno;
	step_end(w, step, text != NULL, text != NULL ? NULL : "%s",
	    strerror(e));
	if (text == NULL) {
		*errp = wfmt(w, "%s: %s", file, strerror(e));
		return (NULL);
	}
	if (len > IPFW_FILE_MAX) {
		*errp = wfmt(w, "%s: too large for a ruleset", file);
		return (NULL);
	}
	/* A script's lines continued by a backslash, joined. */
	if (sh)
		for (c = text; (c = strstr(c, "\\\n")) != NULL;) {
			n = 2 + strspn(c + 2, " \t");
			if (c > text && (c[-1] == ' ' || c[-1] == '\t'))
				memmove(c, c + n, strlen(c + n) + 1);
			else {
				c[0] = ' ';
				memmove(c + 1, c + n, strlen(c + n) + 1);
			}
		}
	/*
	 * Written on a stream: a variable put in makes a line longer.  The
	 * script's assignments are kept (NAME=value, the variables known
	 * by then put in), so that "cmd=\"ipfw -q add\"" and "$cmd 00010
	 * allow ..." read as the rule they make; a line naming a variable
	 * that is not known is left out, said so.  A rule the script adds
	 * inside an if, case or loop is taken, and said so above it.
	 */
	{
		static const char	 varnote[] = "# left out, a variable "
		    "not known here: ";
		struct shvar	*vars;
		FILE		*fp;
		char		*buf, name[64], *val, *sub;
		size_t		 blen;
		int		 nvars, depth, i;
		bool		 unknown, said;

		vars = wcalloc(w, SHVARS, sizeof(*vars));
		nvars = depth = 0;
		said = false;
		buf = NULL;
		blen = 0;
		if ((fp = open_memstream(&buf, &blen)) == NULL) {
			*errp = wfmt(w, "open_memstream: %s", strerror(errno));
			return (NULL);
		}
		p = text;
		while ((line = strsep(&p, "\n")) != NULL) {
			if (p == NULL && line[0] == '\0')
				break;
			q = line + strspn(line, " \t");
			if (q[0] == '\0' || q[0] == '#') {
				if (sh && q[0] == '#' && q[1] == '!')
					continue;
				fprintf(fp, "%s\n", line);
				continue;
			}
			if (sh) {
				if (sh_block(q) != 0) {
					depth += sh_block(q);
					if (depth < 0)
						depth = 0;
					said = false;
				}
				if (sh_assignment(w, q, name, sizeof(name), &val)) {
					unknown = false;
					val = sh_subst(w, val, vars, nvars, &unknown);
					if (strstr(val, "$(") != NULL || strchr(val,
					    '`') != NULL || unknown)
						val = NULL;
					for (i = 0; i < nvars; i++)
						if (strcmp(vars[i].name, name) == 0)
							break;
					if (i == nvars && nvars < SHVARS)
						nvars++;
					if (i < SHVARS) {
						strlcpy(vars[i].name, name,
						    sizeof(vars[i].name));
						vars[i].value = val;
					}
					fprintf(fp, "%s%s\n", shnote, q);
					continue;
				}
				unknown = false;
				sub = sh_subst(w, q, vars, nvars, &unknown);
				if ((c = script_ipfw(sub)) == NULL) {
					/* The shell's own: kept, as a comment. */
					fprintf(fp, "%s%s\n", shnote, q);
					continue;
				}
				if (unknown) {
					fprintf(fp, "%s%s\n", varnote, q);
					continue;
				}
				if (depth > 0 && !said) {
					fprintf(fp, "# taken from inside the script's "
					    "if, case or loop above: it may add these "
					    "only at times\n");
					said = true;
				}
				q = c;
				q[unshell(q)] = '\0';
			}
			/* ipfw -q add …: the options are applying's. */
			while ((q[0] == '-' && (q[1] == 'q' || q[1] == 'f') &&
			    (q[2] == ' ' || q[2] == '\t')))
				q += 2 + strspn(q + 2, " \t");
			/*
			 * A set of the script's own, as a script that stages
			 * its rules in a set and swaps them in writes them:
			 * applying stages the kept rules itself.  "set N
			 * table|nat64…|nptv6 …" is that object's command,
			 * kept without the set (applying gives it set 1, then
			 * set 0); "add N set S …" the rule without it.
			 */
			{
				char	*t = q, *after;

				if (strncmp(t, "set", 3) == 0 && (t[3] == ' ' ||
				    t[3] == '\t')) {
					t += 3 + strspn(t + 3, " \t");
					if (isdigit((unsigned char)*t)) {
						(void)strtol(t, &after, 10);
						after += strspn(after, " \t");
						if ((strncmp(after, "table ", 6) == 0 ||
						    strncmp(after, "nat64", 5) == 0 ||
						    strncmp(after, "nptv6 ", 6) == 0) &&
						    strstr(after, " all ") == NULL)
							q = after;
					}
				}
				if (kept_rule(q, &num, &rest) && rest != q &&
				    strstr(q, " set ") != NULL &&
				    strstr(q, " set ") < rest) {
					q = wfmt(w, "add %05ld %s", num, wstrdup(w,
					    rest));
				}
			}
			/* Left out: the line as it is written. */
			if (strncmp(q, "flush", 5) == 0 || strncmp(q, "set ",
			    4) == 0 || strncmp(q, "delete ", 7) == 0 ||
			    q[0] == '-') {
				fprintf(fp, "%s%s\n", note, line + strspn(line,
				    " \t"));
				continue;
			}
			fprintf(fp, "%s\n", q);
		}
		if (fclose(fp) != 0 || buf == NULL) {
			free(buf);
			*errp = "out of memory";
			return (NULL);
		}
		out = wstrdup(w, buf);
		free(buf);
	}
	(void)n;
	(void)o;
	return (out);
}

/* The kept rules read, or put in place: as fstab is. */
int
do_ipfw_rules(struct work *w, const struct arc_ipfw_rules_req *rq,
    struct arc_ipfw_rules_rsp *rsp)
{
	const char	*sha, *bad, *e, *rq_text;
	char		*old, *copy, *p, *line;
	size_t		 oldlen, len;
	int		 step, n;

	rsp->has_ok = true;
	rsp->ok = false;
	rq_text = rq->conf_text;
	pthread_mutex_lock(&file_lock);
	step = step_begin(w, ARC_STEP_KIND_FILE, "read", "%s", opts.ipfw_rules);
	old = file_read(w, &oldlen);
	step_end(w, step, old != NULL || errno == ENOENT, old != NULL ? NULL :
	    "%s", strerror(errno));
	if (old == NULL && errno != ENOENT) {
		rsp->error = wfmt(w, "%s: %s", opts.ipfw_rules, strerror(
		    errno));
		goto out;
	}
	if (old == NULL)
		old = wstrdup(w, "");
	sha = sha_hex(w, old, oldlen);
	rsp->conf_text = wtext(w, old);
	rsp->sha256 = sha;
	if (rq->from_rc) {
		e = NULL;
		if ((p = (char *)(uintptr_t)rc_ruleset(w, &rsp->rc_file,
		    &e)) == NULL) {
			rsp->error = e;
			goto out;
		}
		rsp->conf_text = wtext(w, p);
		rsp->ok = true;
		goto out;
	}
	if (rq->conf_text == NULL) {
		rsp->ok = true;
		goto out;
	}
	if (rq->sha256 == NULL || strcmp(rq->sha256, sha) != 0) {
		rsp->error = "the file is not the one this was made from: "
		    "somebody changed it meanwhile.  Read it again";
		goto out;
	}
	len = strlen(rq->conf_text);
	if (len > IPFW_FILE_MAX || (len > 0 && rq->conf_text[len - 1] !=
	    '\n')) {
		rsp->error = len > IPFW_FILE_MAX ? "too large for a ruleset" :
		    "the last line has to end as the others do";
		goto out;
	}
	/* Rules written with aliases, as ipfw is to read them. */
	{
		const char	*xe = NULL;
		char		*x;

		if ((x = text_expand(w, rq->conf_text, &xe)) == NULL) {
			rsp->error = xe;
			goto out;
		}
		rq_text = x;
		len = strlen(x);
	}
	if (len > IPFW_FILE_MAX) {
		rsp->error = len > IPFW_FILE_MAX ? "too large for a ruleset" :
		    "the last line has to end as the others do";
		goto out;
	}
	/* The sets are the agent's to swap: a line does not name one. */
	copy = wstrdup(w, rq_text);
	p = copy;
	n = 0;
	while ((line = strsep(&p, "\n")) != NULL) {
		n++;
		line += strspn(line, " \t");
		if (strncmp(line, "set ", 4) == 0 || strncmp(line, "flush",
		    5) == 0 || strncmp(line, "delete ", 7) == 0 || line[0] ==
		    '-') {
			rsp->error = wfmt(w, "line %d: the kept rules are "
			    "what there is to be, add and table and nat "
			    "lines: no set, flush, delete or option, which "
			    "applying them does", n);
			goto out;
		}
	}
	if ((bad = file_wrong(w, rq_text, len)) != NULL) {
		rsp->error = bad;
		goto out;
	}
	if (rq->dry_run) {
		rsp->ok = true;
		goto out;
	}
	step = step_begin(w, ARC_STEP_KIND_FILE, "write", "%s",
	    opts.ipfw_rules);
	e = NULL;
	if (file_write(w, rq_text, len, &e) != 0) {
		rsp->error = e;
		step_end(w, step, false, "%s", e);
		goto out;
	}
	step_end(w, step, true, "the one before it is kept as %s.arcana-old",
	    opts.ipfw_rules);
	rsp->conf_text = wtext(w, wstrdup(w, rq_text));
	rsp->sha256 = sha_hex(w, rq_text, len);
	rsp->ok = true;
out:
	pthread_mutex_unlock(&file_lock);
	return (0);
}

/* Is the verb one of what ipfw has beside its rules? */
static bool
object_verb(const char *verb)
{
	static const char *const verbs[] = { "table", "nat", "nat64lsn",
	    "nat64stl", "nat64clat", "nptv6", "pipe", "queue", "sched" };
	size_t	i;

	for (i = 0; i < nitems(verbs); i++)
		if (strcmp(verb, verbs[i]) == 0)
			return (true);
	return (false);
}

/* What is wrong with the job, or NULL. */
const char *
ipfw_check(const struct arc_job_spec *sp)
{
	const char	*verb;
	size_t		 i;

	verb = sp->verb != NULL ? sp->verb : "";
	if (strcmp(verb, "add") == 0) {
		if (sp->names.n < 2 || sp->names.n > IPFW_WORDS ||
		    !number_ok(sp->names.v[0]))
			return ("a rule is its number, 1 to 65534, and then "
			    "its words");
		for (i = 1; i < sp->names.n; i++)
			if (!word_ok(sp->names.v[i]))
				return ("a rule's words are ipfw's: letters, "
				    "digits and . _ : / , - { } ! ( ) = and "
				    "the like, with no quotes and nothing a "
				    "shell would read");
		if (strcmp(sp->names.v[1], "set") == 0)
			return ("a rule is not given a set here: the sets "
			    "are how the kept rules are applied");
		if (!sp->live && !sp->persist)
			return ("say live, persist or both");
	} else if (strcmp(verb, "replace") == 0) {
		if (sp->names.n < 3 || sp->names.n > IPFW_WORDS + 1 ||
		    !number_ok(sp->names.v[0]) || !number_ok(sp->names.v[1]))
			return ("a rule replaced is named by its number, then "
			    "the new one's number, 1 to 65534, and its words");
		for (i = 2; i < sp->names.n; i++)
			if (!word_ok(sp->names.v[i]))
				return ("a rule's words are ipfw's: letters, "
				    "digits and . _ : / , - { } ! ( ) = [ ] and "
				    "the like, with no quotes: ipfw is given them "
				    "without a shell");
		if (strcmp(sp->names.v[2], "set") == 0)
			return ("a rule is not given a set here: the sets "
			    "are how the kept rules are applied");
		if (!sp->live && !sp->persist)
			return ("say live, persist or both");
		if (sp->safe)
			return ("a rule replaced is not put back by itself: "
			    "apply the kept rules in safe mode instead");
		/* The old rule's words, to tell it from another of its
		 * number: one line, ipfw's words or aliases. */
		if (sp->text != NULL && (strlen(sp->text) > 4096 ||
		    strcspn(sp->text, "\n\r#") != strlen(sp->text)))
			return ("the old rule's words are one line, with no #");
	} else if (strcmp(verb, "delete") == 0) {
		if (sp->names.n < 1 || sp->names.n > IPFW_WORDS ||
		    !number_ok(sp->names.v[0]))
			return ("name the rule to delete by its number, and by "
			    "its words when the number has several");
		for (i = 1; i < sp->names.n; i++)
			if (!word_ok(sp->names.v[i]))
				return ("a rule's words are ipfw's: letters, "
				    "digits and . _ : / , - { } ! ( ) = and "
				    "the like, with no quotes");
		if (!sp->live && !sp->persist)
			return ("say live, persist or both");
		if (sp->safe)
			return ("a rule deleted is not put back by itself: "
			    "apply the kept rules in safe mode instead");
	} else if (strcmp(verb, "renumber") == 0) {
		if (sp->names.n < 2 || sp->names.n % 2 != 0 || sp->names.n > 64)
			return ("renumber takes pairs of numbers, from and to, "
			    "up to 32 of them");
		for (i = 0; i < sp->names.n; i++)
			if (!number_ok(sp->names.v[i]))
				return ("a rule's number is 1 to 65534");
		for (i = 0; i + 1 < sp->names.n; i += 2)
			if (strcmp(sp->names.v[i], sp->names.v[i + 1]) == 0)
				return ("a rule renumbered gets another number");
		if (!sp->live && !sp->persist)
			return ("say live, persist or both");
		if (sp->safe)
			return ("rules renumbered are not put back by themselves");
	} else if (strcmp(verb, "alias") == 0) {
		if (sp->names.n < 2 || !alias_name_ok(sp->names.v[0]))
			return ("an alias is its name (letters, digits, _), and "
			    "addr, ports or value with what it is, or delete");
		if (strcmp(sp->names.v[1], "delete") == 0) {
			if (sp->names.n != 2)
				return ("an alias deleted is named alone");
		} else if (strcmp(sp->names.v[1], "addr") == 0) {
			if (sp->names.n < 3)
				return ("an address list has an address or a "
				    "network at least");
			for (i = 2; i < sp->names.n; i++)
				if (!prefix_ok(sp->names.v[i]))
					return ("an address list is of addresses "
					    "and networks (10.0.0.0/8, "
					    "2001:db8::/32)");
		} else if (strcmp(sp->names.v[1], "ports") == 0) {
			if (sp->names.n != 3 || strspn(sp->names.v[2],
			    "0123456789,-") != strlen(sp->names.v[2]))
				return ("a port list is ports and ranges with "
				    "commas between: 80,443,8000-8080");
		} else if (strcmp(sp->names.v[1], "value") == 0) {
			if (sp->names.n != 3 || !word_ok(sp->names.v[2]) ||
			    sp->names.v[2][0] == '$')
				return ("a value is one word of ipfw's: an "
				    "interface, an address, a number");
		} else
			return ("an alias is addr, ports or value");
		if (sp->safe)
			return ("an alias is not taken back by itself");
	} else if (strcmp(verb, "apply") == 0 || strcmp(verb, "enable") == 0 ||
	    strcmp(verb, "disable") == 0) {
		if (sp->names.n != 0)
			return ("apply, enable and disable take nothing");
	} else if (strcmp(verb, "zero") == 0) {
		if (sp->names.n > 1 || (sp->names.n == 1 && !number_ok(
		    sp->names.v[0])))
			return ("zero takes a rule's number, or nothing");
		if (sp->safe)
			return ("counters cleared are not brought back");
	} else if (object_verb(verb)) {
		/*
		 * What a rule names and is not one: a table and what is
		 * in it, a NAT instance, a pipe.  The words are ipfw's.
		 */
		if (sp->names.n < 2 || sp->names.n > IPFW_WORDS)
			return ("name it, and say what to do with it: table "
			    "T46 add 10.0.0.1, nat 1 config if em0, pipe 1 "
			    "config bw 10Mbit/s");
		for (i = 0; i < sp->names.n; i++)
			if (!word_ok(sp->names.v[i]))
				return ("the words are ipfw's: letters, "
				    "digits and . _ : / , - and the like");
		if (strcmp(sp->names.v[0], "all") == 0)
			return ("one at a time: not all of them at once");
		if (sp->safe)
			return ("it is not taken back by itself");
	} else
		return ("an ipfw job is add, delete, renumber, alias, apply, "
		    "enable, disable, zero, or table, nat, nat64lsn, nat64stl, "
		    "nat64clat, nptv6, pipe, queue, sched with their words");
	return (NULL);
}

char *
ipfw_title(const struct arc_job_spec *sp)
{
	char	*t, *all;
	size_t	 i, len;

	len = 16;
	for (i = 0; i < sp->names.n; i++)
		len += strlen(sp->names.v[i]) + 1;
	if ((all = calloc(1, len)) == NULL)
		return (NULL);
	for (i = 0; i < sp->names.n; i++) {
		strlcat(all, " ", len);
		strlcat(all, sp->names.v[i], len);
	}
	if (asprintf(&t, "ipfw %s%s%s", sp->verb != NULL ? sp->verb : "?", all,
	    strcmp(sp->verb != NULL ? sp->verb : "", "add") == 0 || strcmp(
	    sp->verb != NULL ? sp->verb : "", "delete") == 0 || strcmp(
	    sp->verb != NULL ? sp->verb : "", "renumber") == 0 ? sp->live &&
	    sp->persist ? " (now, and kept)" : sp->persist ? " (kept)" :
	    " (now)" : sp->persist ? " (kept)" : "") == -1)
		t = NULL;
	free(all);
	return (t);
}

/* ---- The kernel's rules, one by one --------------------------------- */

/*
 * The kept rules become set 0's: Apply swaps them in there, and a rule
 * added now goes there.  The other sets are not touched here: SD-WAN's
 * own, the rules Apply holds back in set 1, the default rule's 31.
 * ipfw has no name for one rule among several of a number, so a rule
 * is picked by its number and its words; a change at a number is one
 * script of ipfw's, its rules checked first by ipfw -n, and the
 * number's rules are put back as they were listed when the kernel
 * refuses a line of it after all.
 */
#define	SCRIPT_MAX	(4 * 1024 * 1024)	/* a ruleset, for ipfw -n */

struct liverule {
	long		 num;
	const char	*text;
};

/*
 * Set 0's rules of a number, or of every number (0) but the default.
 * How many, or -1 when ipfw could not be asked.
 */
static int
live_rules(struct work *w, long num, struct liverule **outp)
{
	struct liverule	*v, *nv;
	struct execres	 res;
	char		*argv[5], *text, *p, *line, *end;
	long		 set;
	int		 n, cap;

	*outp = NULL;
	argv[0] = (char *)(uintptr_t)opts.ipfw_bin;
	argv[1] = (char *)(uintptr_t)"-S";
	argv[2] = (char *)(uintptr_t)"list";
	argv[3] = num > 0 ? wfmt(w, "%ld", num) : NULL;
	argv[4] = NULL;
	if (run_exec_max(w, scope_argv(w, argv), &res, 16 * 1024 * 1024) !=
	    0) {
		/* A number with no rule is not a failure. */
		if (num > 0 && ((res.err != NULL && strstr(res.err,
		    "does not exist") != NULL) || (res.out != NULL &&
		    strstr(res.out, "does not exist") != NULL)))
			return (0);
		return (-1);
	}
	text = wstrndup(w, res.out != NULL ? res.out : "", res.outlen);
	cap = 16;
	v = wcalloc(w, (size_t)cap, sizeof(*v));
	n = 0;
	p = text;
	while ((line = strsep(&p, "\n")) != NULL) {
		if (!isdigit((unsigned char)line[0]))
			continue;
		if (n == cap) {
			nv = wcalloc(w, (size_t)cap * 2, sizeof(*nv));
			memcpy(nv, v, (size_t)n * sizeof(*v));
			v = nv;
			cap *= 2;
		}
		v[n].num = strtol(line, &end, 10);
		end += strspn(end, " ");
		set = 0;
		if (strncmp(end, "set ", 4) == 0) {
			set = strtol(end + 4, &end, 10);
			end += strspn(end, " ");
		}
		/* A number out of ipfw's range (a jail's ipfw says what its
		 * root has it say) is no rule: renumber() indexes by it. */
		if (set != 0 || v[n].num < 1 || v[n].num >= 65535 ||
		    (num > 0 && v[n].num != num))
			continue;
		v[n].text = end;
		n++;
	}
	*outp = v;
	return (n);
}

/*
 * Rules as ipfw writes them back, read by ipfw -n, which asks nothing
 * of the kernel: out[i] the words of rule nums[i] texts[i].  0 when ipfw
 * took every one; -1 and why when it stopped at one.
 */
static int
ipfw_norm(struct work *w, int n, const long *nums, const char *const *texts,
    const char **out, const char **errp)
{
	struct execres	 res;
	struct ms	 m;
	char		*in, *argv[4], *t, *p, *line;
	size_t		 len, off;
	int		 i, k, rc;

	for (i = 0; i < n; i++)
		out[i] = NULL;
	if (n == 0)
		return (0);
	len = 1;
	for (i = 0; i < n; i++) {
		/* A script's # begins a comment: not a rule's words. */
		if (strchr(texts[i], '#') != NULL || strchr(texts[i], '\n') !=
		    NULL) {
			*errp = wfmt(w, "rule %ld has a # in its words, which "
			    "ipfw reads as a comment in a script", nums[i]);
			return (-1);
		}
		len += strlen(texts[i]) + 24;
	}
	if (len > SCRIPT_MAX) {
		*errp = "too many rules to check at once";
		return (-1);
	}
	if (!ms_open(&m)) {
		*errp = "out of memory";
		return (-1);
	}
	for (i = 0; i < n; i++)
		fprintf(m.fp, "add %ld %s\n", nums[i], texts[i]);
	if ((in = ms_close(w, &m, &off)) == NULL) {
		*errp = "out of memory";
		return (-1);
	}
	argv[0] = (char *)(uintptr_t)opts.ipfw_bin;
	argv[1] = (char *)(uintptr_t)"-n";
	argv[2] = (char *)(uintptr_t)"/dev/stdin";
	argv[3] = NULL;
	exec_set_stdin(in, off);
	rc = run_exec_max(w, scope_argv(w, argv), &res, 2 * SCRIPT_MAX);
	t = wstrndup(w, res.out != NULL ? res.out : "", res.outlen);
	k = 0;
	for (p = t; (line = strsep(&p, "\n")) != NULL && k < n;) {
		if (!isdigit((unsigned char)line[0]))
			continue;
		line += strspn(line, "0123456789");
		out[k++] = line + strspn(line, " ");
	}
	if (rc != 0 || k < n) {
		*errp = res.errlen > 0 ? wtext(w, wstrndup(w, res.err,
		    strcspn(res.err, "\n"))) : rc == 0 ? wfmt(w, "ipfw -n wrote "
		    "back %d of the %d rules", k, n) : wtext(w, exec_error(w,
		    &res, "ipfw -n"));
		return (-1);
	}
	return (0);
}

/* ipfw reading its commands, a line each, from the script (ipfw -q). */
static int
ipfw_script(struct work *w, const char *script, const char **errp)
{
	struct execres	 res;
	char		*argv[4];

	argv[0] = (char *)(uintptr_t)opts.ipfw_bin;
	argv[1] = (char *)(uintptr_t)"-q";
	argv[2] = (char *)(uintptr_t)"/dev/stdin";
	argv[3] = NULL;
	exec_set_stdin(script, strlen(script));
	if (run_exec(w, scope_argv(w, argv), &res) != 0) {
		*errp = scope_missing(w, &res, "ipfw", NULL);
		if (*errp == NULL)
			*errp = res.errlen > 0 ? wtext(w, wstrndup(w, res.err,
			    strcspn(res.err, "\n"))) : wtext(w, exec_error(w,
			    &res, "ipfw"));
		return (-1);
	}
	return (0);
}

/*
 * Which of a number's rules lv is the one of these words: the same
 * text, or the same once ipfw -n has written them; with no words, or
 * none the same, the number's only rule.  -1 and why when it cannot be
 * told which.
 */
static int
live_pick(struct work *w, long num, const struct liverule *lv, int nl,
    const char *words, const char **errp)
{
	const char	*nw, *e;
	int		 i;

	if (nl <= 0) {
		*errp = wfmt(w, "there is no rule %ld now", num);
		return (-1);
	}
	if (words != NULL && words[0] != '\0') {
		for (i = 0; i < nl; i++)
			if (strcmp(lv[i].text, words) == 0)
				return (i);
		/* Words ipfw reads, and none of the rules: not this one. */
		if (ipfw_norm(w, 1, &num, &words, &nw, &e) == 0) {
			for (i = 0; i < nl; i++)
				if (strcmp(lv[i].text, nw) == 0)
					return (i);
			*errp = wfmt(w, "%s rule %ld now has these words: "
			    "nothing was changed", nl == 1 ? "the" : "no",
			    num);
			if (nl == 1)
				*errp = wfmt(w, "rule %ld now is \"%s\", not "
				    "these words: nothing was changed", num,
				    lv[0].text);
			return (-1);
		}
	}
	/* No words, or words ipfw cannot read here (aliases): the only
	 * rule of the number. */
	if (nl == 1)
		return (0);
	*errp = words != NULL && words[0] != '\0' ? wfmt(w, "%d rules %ld "
	    "now, none of them these words: nothing was changed", nl, num) :
	    wfmt(w, "%d rules %ld now: say which, by its words; nothing was "
	    "changed", nl, num);
	return (-1);
}

/* lv's rules as an ipfw script's add lines, at num. */
static size_t
add_lines(char *buf, size_t len, long num, const struct liverule *lv,
    int nl, int skip)
{
	size_t	off;
	int	i;

	off = 0;
	for (i = 0; i < nl; i++)
		if (i != skip)
			off += (size_t)snprintf(buf + off, len > off ? len - off :
			    0, "add %ld %s\n", num, lv[i].text);
	return (off);
}

/*
 * At num, set 0's rules lv become lv but drop (-1: none dropped), and
 * words are added at to (words NULL: none).  Checked whole by ipfw -n
 * first; then one script: the number deleted, the others added again,
 * the new one last.  If the kernel refuses a line after all, the
 * number's rules are put back as they were listed.
 */
static int
live_redo(struct work *w, long num, const struct liverule *lv, int nl,
    int drop, long to, const char *words, const char **errp)
{
	long		*nums;
	const char	**texts, **out, *e, *e2;
	char		*script, *back;
	size_t		 len, off;
	int		 i, n;

	nums = wcalloc(w, (size_t)nl + 2, sizeof(*nums));
	texts = wcalloc(w, (size_t)nl + 2, sizeof(*texts));
	out = wcalloc(w, (size_t)nl + 2, sizeof(*out));
	n = 0;
	len = 64;
	for (i = 0; i < nl; i++) {
		len += strlen(lv[i].text) + 24;
		if (i == drop)
			continue;
		nums[n] = num;
		texts[n++] = lv[i].text;
	}
	if (words != NULL) {
		nums[n] = to;
		texts[n++] = words;
		len += strlen(words) + 24;
	}
	if (ipfw_norm(w, n, nums, texts, out, &e) != 0) {
		*errp = wfmt(w, "ipfw does not take %s, so nothing was "
		    "changed: %s", words != NULL ? "the rule" : "the rules left",
		    e);
		return (-1);
	}
	if (len > SCRIPT_MAX) {
		*errp = wfmt(w, "rule %ld has too many rules to change at once",
		    num);
		return (-1);
	}
	script = wcalloc(w, len, 1);
	off = 0;
	if (nl > 0)
		off += (size_t)snprintf(script, len, "set 0 delete %ld\n", num);
	off += add_lines(script + off, len - off, num, lv, nl, drop);
	if (words != NULL)
		off += (size_t)snprintf(script + off, len - off, "add %ld %s\n",
		    to, words);
	if (ipfw_script(w, script, &e) == 0)
		return (0);
	if (nl == 0) {
		*errp = wfmt(w, "ipfw did not take it: %s", e);
		return (-1);
	}
	/* As they were: the number emptied, its rules added again. */
	back = wcalloc(w, len, 1);
	off = (size_t)snprintf(back, len, "set 0 delete %ld\n", num);
	(void)add_lines(back + off, len - off, num, lv, nl, -1);
	if (ipfw_script(w, back, &e2) != 0)
		*errp = wtext(w, wfmt(w, "ipfw did not take it: %s; and rule "
		    "%ld could not be put back as it was (%s): its rules were: "
		    "%s", e, num, e2, back + strcspn(back, "\n") + 1));
	else
		*errp = wtext(w, wfmt(w, "ipfw did not take it: %s; rule %ld "
		    "was put back as it was", e, num));
	return (-1);
}

/*
 * Set 0's rules of from moved to to, which has none: added there first,
 * then from deleted, so there is no moment without them; if the kernel
 * refuses a line, to is emptied again and from is as it was.
 */
static int
live_move(struct work *w, long from, long to, const struct liverule *lv,
    int nl, const char **errp)
{
	long		*nums;
	const char	**texts, **out, *e, *e2;
	char		*script;
	size_t		 len, off;
	int		 i;

	nums = wcalloc(w, (size_t)nl + 1, sizeof(*nums));
	texts = wcalloc(w, (size_t)nl + 1, sizeof(*texts));
	out = wcalloc(w, (size_t)nl + 1, sizeof(*out));
	len = 64;
	for (i = 0; i < nl; i++) {
		nums[i] = to;
		texts[i] = lv[i].text;
		len += strlen(lv[i].text) + 24;
	}
	if (ipfw_norm(w, nl, nums, texts, out, &e) != 0) {
		*errp = wfmt(w, "ipfw does not take rule %ld at %ld, so nothing "
		    "was changed: %s", from, to, e);
		return (-1);
	}
	if (len > SCRIPT_MAX) {
		*errp = wfmt(w, "rule %ld has too many rules to move at once",
		    from);
		return (-1);
	}
	script = wcalloc(w, len, 1);
	off = add_lines(script, len, to, lv, nl, -1);
	(void)snprintf(script + off, len - off, "set 0 delete %ld\n", from);
	if (ipfw_script(w, script, &e) == 0)
		return (0);
	if (ipfw_script(w, wfmt(w, "set 0 delete %ld\n", to), &e2) != 0)
		*errp = wtext(w, wfmt(w, "ipfw did not take it: %s; and %ld, "
		    "where rule %ld was being copied, could not be emptied "
		    "again (%s): look at both", e, to, from, e2));
	else
		*errp = wtext(w, wfmt(w, "ipfw did not take it: %s; rule %ld "
		    "is as it was", e, from));
	return (-1);
}

/* ---- The kept rules, one by one -------------------------------------- */

/* The kept file's lines, in order; how many.  NULL text: none. */
static int
kept_lines(struct work *w, char *text, char ***linesp)
{
	char	**v, *p, *line;
	int	  n, cap;

	n = 0;
	cap = 1;
	for (p = text; p != NULL && *p != '\0'; p++)
		if (*p == '\n')
			cap++;
	v = wcalloc(w, (size_t)cap + 1, sizeof(*v));
	p = text;
	while (p != NULL && *p != '\0' && (line = strsep(&p, "\n")) != NULL &&
	    n < cap)
		v[n++] = line;
	*linesp = v;
	return (n);
}

/*
 * The kept rule of a number with these words: its line's place among
 * lines, and the place of its own words' line just before it (-1 for
 * none).  *atp -1 when the number has no kept rule.  The same words, as
 * kept or as their own, or the same once ipfw -n has written both, or
 * the number's only rule; -1 and why when several are kept and it
 * cannot be told which.
 */
static int
kept_pick(struct work *w, char **lines, int nlines, long num,
    const char *words, int *atp, int *srcp, const char **errp)
{
	const char	*rest, *nw, *e, *at_rest[64], **out;
	long		 n, nums[64];
	int		 i, at[64], nat;

	*atp = *srcp = -1;
	nat = 0;
	for (i = 0; i < nlines && nat < (int)nitems(at); i++)
		if (kept_rule(lines[i], &n, &rest) && n == num) {
			at_rest[nat] = rest;
			at[nat++] = i;
		}
	if (nat == 0)
		return (0);
#define	SRC_OF(k)	(at[k] > 0 && src_rule(lines[at[k] - 1], &n, &rest) && \
	    n == num ? at[k] - 1 : -1)
	if (words != NULL && words[0] != '\0') {
		for (i = 0; i < nat; i++)
			if (strcmp(at_rest[i], words) == 0 || (SRC_OF(i) >= 0 &&
			    src_rule(lines[SRC_OF(i)], &n, &rest) && strcmp(rest,
			    words) == 0))
				goto found;
		/* As ipfw writes them: words and the kept lines alike. */
		out = wcalloc(w, (size_t)nat + 1, sizeof(*out));
		for (i = 0; i < nat; i++)
			nums[i] = num;
		if (ipfw_norm(w, 1, &num, &words, &nw, &e) == 0 &&
		    ipfw_norm(w, nat, nums, at_rest, out, &e) == 0) {
			for (i = 0; i < nat; i++)
				if (strcmp(out[i], nw) == 0)
					goto found;
			/* Words ipfw reads, and none of the kept rules. */
			*errp = wfmt(w, "no kept rule %ld has these words: "
			    "nothing was changed", num);
			return (-1);
		}
	}
	if (nat == 1) {
		i = 0;
		goto found;
	}
	*errp = words != NULL && words[0] != '\0' ? wfmt(w, "%d kept rules "
	    "%ld, none of them these words: nothing was changed", nat, num) :
	    wfmt(w, "%d kept rules %ld: say which, by its words; nothing was "
	    "changed", nat, num);
	return (-1);
found:
	*atp = at[i];
	*srcp = SRC_OF(i);
#undef	SRC_OF
	return (0);
}

/*
 * One kept rule of a number taken out of the kept file, picked as
 * kept_pick does, with its own words' line; with dry, only whether it
 * can be told.  0 when the number has no kept rule too.
 */
static int
kept_drop_one(struct work *w, long num, const char *words, bool dry,
    const char **errp)
{
	char	*old, *out, **lines;
	size_t	 oldlen, len;
	int	 nl, i, at, src, rc;

	pthread_mutex_lock(&file_lock);
	if ((old = file_read(w, &oldlen)) == NULL) {
		rc = errno == ENOENT ? 0 : -1;
		if (rc != 0)
			*errp = wfmt(w, "%s: %s", opts.ipfw_rules,
			    strerror(errno));
		pthread_mutex_unlock(&file_lock);
		return (rc);
	}
	nl = kept_lines(w, old, &lines);
	if (kept_pick(w, lines, nl, num, words, &at, &src, errp) != 0) {
		pthread_mutex_unlock(&file_lock);
		return (-1);
	}
	if (at < 0 || dry) {
		pthread_mutex_unlock(&file_lock);
		return (0);
	}
	out = wcalloc(w, oldlen + 2, 1);
	len = 0;
	for (i = 0; i < nl; i++)
		if (i != at && i != src)
			len += (size_t)snprintf(out + len, oldlen + 2 - len,
			    "%s\n", lines[i]);
	rc = file_write(w, out, len, errp);
	pthread_mutex_unlock(&file_lock);
	return (rc);
}

/*
 * The kept rules of one number given another, which has none (with
 * their own words' lines); their place in the file moves with the
 * number, so the file stays in the order of the numbers.
 */
static int
kept_renumber(struct work *w, long from, long to, const char **errp)
{
	struct ms	 m;
	char		*old, *out, **lines, *moved;
	const char	*rest;
	size_t		 oldlen, len, mlen;
	long		 n;
	int		 nl, i;
	bool		 put;
	int		 rc;

	pthread_mutex_lock(&file_lock);
	if ((old = file_read(w, &oldlen)) == NULL) {
		rc = errno == ENOENT ? 0 : -1;
		if (rc != 0)
			*errp = wfmt(w, "%s: %s", opts.ipfw_rules,
			    strerror(errno));
		pthread_mutex_unlock(&file_lock);
		return (rc);
	}
	nl = kept_lines(w, old, &lines);
	for (i = 0; i < nl; i++)
		if (kept_rule(lines[i], &n, &rest) && n == to) {
			*errp = wfmt(w, "kept rule %ld is there already: it is "
			    "moved first", to);
			pthread_mutex_unlock(&file_lock);
			return (-1);
		}
	if (!ms_open(&m)) {
		*errp = "out of memory";
		pthread_mutex_unlock(&file_lock);
		return (-1);
	}
	for (i = 0; i < nl; i++) {
		if (src_rule(lines[i], &n, &rest) && n == from)
			fprintf(m.fp, "#arcana add %05ld %s\n", to, rest);
		else if (kept_rule(lines[i], &n, &rest) && n == from)
			fprintf(m.fp, "add %05ld %s\n", to, rest);
	}
	if ((moved = ms_close(w, &m, &mlen)) == NULL || !ms_open(&m)) {
		*errp = "out of memory";
		pthread_mutex_unlock(&file_lock);
		return (-1);
	}
	put = mlen == 0;
	for (i = 0; i < nl; i++) {
		if ((src_rule(lines[i], &n, &rest) || kept_rule(lines[i], &n,
		    &rest)) && n == from)
			continue;
		if (!put && (kept_rule(lines[i], &n, &rest) || src_rule(
		    lines[i], &n, &rest)) && n > to) {
			fputs(moved, m.fp);
			put = true;
		}
		fprintf(m.fp, "%s\n", lines[i]);
	}
	if (!put)
		fputs(moved, m.fp);
	if ((out = ms_close(w, &m, &len)) == NULL) {
		*errp = "out of memory";
		pthread_mutex_unlock(&file_lock);
		return (-1);
	}
	rc = file_write(w, out, len, errp);
	pthread_mutex_unlock(&file_lock);
	return (rc);
}

/*
 * The kept file with a rule put in at its number, or the rules of a
 * number taken out.  0, or -1 and why.
 */
static int
kept_change_src(struct work *w, long num, const char *rule, const char *src,
    const char **errp);

/* The same, the rule's own words with aliases kept before it. */
static int
kept_change_src(struct work *w, long num, const char *rule, const char *src,
    const char **errp)
{
	struct ms	 m;
	char		*old, *out, *p, *line;
	const char	*rest;
	size_t		 oldlen, len;
	long		 n;
	bool		 done;
	int		 rc;

	pthread_mutex_lock(&file_lock);
	old = file_read(w, &oldlen);
	if (old == NULL && errno != ENOENT) {
		*errp = wfmt(w, "%s: %s", opts.ipfw_rules, strerror(errno));
		pthread_mutex_unlock(&file_lock);
		return (-1);
	}
	if (old == NULL)
		old = wstrdup(w, "");
	/*
	 * The first rule kept, with no rule kept yet: the kernel's rules
	 * are kept first, so that applying the kept rules keeps what the
	 * host runs with, and does not take it all away for the one.
	 */
	if (rule != NULL && have()) {
		struct liverule	*lv;
		int		 nl, i;
		bool		 any = false;

		for (p = old; !any && p != NULL && *p != '\0';) {
			line = p;
			p = strchr(p, '\n');
			if (p != NULL)
				*p++ = '\0';
			any = kept_rule(line, &n, &rest);
			if (p != NULL)
				p[-1] = '\n';
		}
		if (!any && (nl = live_rules(w, 0, &lv)) > 0) {
			const char	*nr, *e;
			char		*seed;
			size_t		 soff;
			int		 same = -1;

			/* The rule kept now may be in the kernel already
			 * (added now and kept): not kept twice. */
			for (i = 0; i < nl && same < 0; i++)
				if (lv[i].num == num && strcmp(lv[i].text, rule) ==
				    0)
					same = i;
			if (same < 0 && ipfw_norm(w, 1, &num, &rule, &nr, &e) ==
			    0)
				for (i = 0; i < nl && same < 0; i++)
					if (lv[i].num == num && strcmp(lv[i].text,
					    nr) == 0)
						same = i;
			if (!ms_open(&m)) {
				*errp = "out of memory";
				pthread_mutex_unlock(&file_lock);
				return (-1);
			}
			fprintf(m.fp, "%s%s# The kernel's rules when the first "
			    "rule was kept, by Arcana: the kept rules are the "
			    "whole ruleset once applied.\n", old, oldlen > 0 &&
			    old[oldlen - 1] != '\n' ? "\n" : "");
			for (i = 0; i < nl; i++)
				if (i != same)
					fprintf(m.fp, "add %05ld %s\n",
					    lv[i].num, lv[i].text);
			if ((seed = ms_close(w, &m, &soff)) == NULL) {
				*errp = "out of memory";
				pthread_mutex_unlock(&file_lock);
				return (-1);
			}
			old = seed;
			oldlen = soff;
		}
	}
	if (!ms_open(&m)) {
		*errp = "out of memory";
		pthread_mutex_unlock(&file_lock);
		return (-1);
	}
	done = rule == NULL;
	p = old;
	while (p != NULL && *p != '\0' && (line = strsep(&p, "\n")) != NULL) {
		/* A rule's own words go with it when it is deleted. */
		if (src_rule(line, &n, &rest) && rule == NULL && n == num)
			continue;
		if (kept_rule(line, &n, &rest) || src_rule(line, &n, &rest)) {
			/* Deleted: every line of the number goes. */
			if (rule == NULL && n == num)
				continue;
			/* Added: before the first of a higher number. */
			if (!done && n > num) {
				if (src != NULL)
					fprintf(m.fp, "#arcana add %05ld %s\n",
					    num, src);
				fprintf(m.fp, "add %05ld %s\n", num, rule);
				done = true;
			}
		}
		fprintf(m.fp, "%s\n", line);
	}
	if (!done) {
		if (src != NULL)
			fprintf(m.fp, "#arcana add %05ld %s\n", num, src);
		fprintf(m.fp, "add %05ld %s\n", num, rule);
	}
	if ((out = ms_close(w, &m, &len)) == NULL) {
		*errp = "out of memory";
		pthread_mutex_unlock(&file_lock);
		return (-1);
	}
	rc = file_write(w, out, len, errp);
	pthread_mutex_unlock(&file_lock);
	return (rc);
}

/* ---- Aliases --------------------------------------------------------- */


static bool
alias_name_ok(const char *s)
{
	size_t	i;

	if (s == NULL || s[0] == '\0' || isdigit((unsigned char)s[0]) ||
	    strlen(s) > 32)
		return (false);
	for (i = 0; s[i] != '\0'; i++)
		if (!isalnum((unsigned char)s[i]) && s[i] != '_')
			return (false);
	return (true);
}

/* "#arcana add 01000 words": a rule's own words, aliases and all. */
static bool
src_rule(const char *line, long *nump, const char **restp)
{
	const char	*p = line + strspn(line, " \t");

	if (strncmp(p, "#arcana ", 8) != 0)
		return (false);
	return (kept_rule(p + 8, nump, restp));
}

/* The aliases of the kept text; an address list's entries from its
 * table's lines. */
static size_t
aliases_of(struct work *w, const char *text, struct alias *a, size_t max)
{
	char	*copy, *p, *line, *sp, *k[4];
	size_t	 n = 0, i;
	int	 nk;

	if (text == NULL)
		return (0);
	copy = wstrdup(w, text);
	for (p = copy; (line = strsep(&p, "\n")) != NULL && n < max; ) {
		line += strspn(line, " \t");
		if (strncmp(line, "#arcana alias ", 14) != 0)
			continue;
		sp = line + 14;
		for (nk = 0; nk < 3 && (k[nk] = strsep(&sp, " \t")) != NULL;
		    nk++)
			if (*k[nk] == '\0')
				nk--;
		if (nk < 2 || !alias_name_ok(k[0]))
			continue;
		memset(&a[n], 0, sizeof(a[n]));
		strlcpy(a[n].name, k[0], sizeof(a[n].name));
		strlcpy(a[n].kind, k[1], sizeof(a[n].kind));
		a[n].value = wstrdup(w, nk > 2 ? k[2] : "");
		if (sp != NULL && strcmp(a[n].kind, "addr") != 0)
			a[n].value = wfmt(w, "%s %s", a[n].value, sp);
		n++;
	}
	/* An address list: what its table's lines add. */
	copy = wstrdup(w, text);
	for (p = copy; (line = strsep(&p, "\n")) != NULL; ) {
		char	tn[64], ad[80];

		line += strspn(line, " \t");
		if (sscanf(line, "table %63s add %79s", tn, ad) != 2)
			continue;
		for (i = 0; i < n; i++)
			if (strcmp(a[i].kind, "addr") == 0 && strcmp(a[i].name,
			    tn) == 0)
				a[i].value = a[i].value[0] == '\0' ? wstrdup(w,
				    ad) : wfmt(w, "%s %s", a[i].value, ad);
	}
	return (n);
}

/*
 * A rule's words with its aliases put in: $list as table(list), $ports
 * and $value as what they are.  NULL with why in *errp for one that
 * there is not.
 */
static const char **
expand(struct work *w, const struct alias *a, size_t na,
    const char *const *words, size_t nw, const char **errp)
{
	const char	**out;
	size_t		  i, k;

	out = wcalloc(w, nw + 1, sizeof(*out));
	for (i = 0; i < nw; i++) {
		if (words[i][0] != '$') {
			out[i] = words[i];
			continue;
		}
		for (k = 0; k < na && strcmp(a[k].name, words[i] + 1) != 0; k++)
			;
		if (k == na) {
			*errp = wfmt(w, "%s: there is no such alias", words[i]);
			return (NULL);
		}
		out[i] = strcmp(a[k].kind, "addr") == 0 ? wfmt(w, "table(%s)",
		    a[k].name) : a[k].value;
	}
	return (out);
}

static bool
uses_alias(const char *const *words, size_t n)
{
	size_t	i;

	for (i = 0; i < n; i++)
		if (words[i][0] == '$')
			return (true);
	return (false);
}

static char *
join(struct work *w, const char *const *words, size_t n)
{
	size_t	 i, len = 1;
	char	*s;

	for (i = 0; i < n; i++)
		len += strlen(words[i]) + 1;
	s = wcalloc(w, len, 1);
	for (i = 0; i < n; i++) {
		if (i > 0)
			strlcat(s, " ", len);
		strlcat(s, words[i], len);
	}
	return (s);
}

/* A rule's text split into its words, in the arena. */
static size_t
split(struct work *w, const char *text, const char **v, size_t max)
{
	char	*c = wstrdup(w, text), *x;
	size_t	 n = 0;

	while ((x = strsep(&c, " \t")) != NULL && n < max)
		if (*x != '\0')
			v[n++] = x;
	return (n);
}

/* The aliases kept now. */
static size_t
aliases_now(struct work *w, struct alias *a, size_t max)
{
	char	*text;
	size_t	 len;

	pthread_mutex_lock(&file_lock);
	text = file_read(w, &len);
	pthread_mutex_unlock(&file_lock);
	return (aliases_of(w, text, a, max));
}

/*
 * The kept text with every rule of its own words written again from
 * them, as its aliases say now; a rule written with aliases and no
 * line of its own words given one.  NULL with why in *errp.
 */
static char *
text_expand(struct work *w, const char *text, const char **errp)
{
	struct alias	 a[ALIAS_MAX];
	struct ms	 m;
	const char	*v[IPFW_WORDS], **e, *rest;
	char		*copy, *p, *line, *out;
	size_t		 na, nv;
	long		 num, pend = -1;
	int		 ln = 0;

	na = aliases_of(w, text, a, nitems(a));
	/* An alias expanded makes a line as long as it likes. */
	if (!ms_open(&m)) {
		*errp = "out of memory";
		return (NULL);
	}
	copy = wstrdup(w, text);
	for (p = copy; p != NULL && *p != '\0' &&
	    (line = strsep(&p, "\n")) != NULL; ) {
		ln++;
		if (src_rule(line, &num, &rest)) {
			nv = split(w, rest, v, nitems(v));
			if ((e = expand(w, a, na, v, nv, errp)) == NULL) {
				*errp = wfmt(w, "line %d: %s", ln, *errp);
				(void)ms_close(w, &m, NULL);
				return (NULL);
			}
			fprintf(m.fp, "%s\nadd %05ld %s\n", line, num,
			    join(w, e, nv));
			pend = num;
			continue;
		}
		if (kept_rule(line, &num, &rest)) {
			/* The one its own words were just written again. */
			if (num == pend) {
				pend = -1;
				continue;
			}
			pend = -1;
			nv = split(w, rest, v, nitems(v));
			if (uses_alias(v, nv)) {
				if ((e = expand(w, a, na, v, nv, errp)) == NULL) {
					*errp = wfmt(w, "line %d: %s", ln, *errp);
					(void)ms_close(w, &m, NULL);
					return (NULL);
				}
				fprintf(m.fp, "#arcana add %05ld %s\nadd %05ld "
				    "%s\n", num, rest, num, join(w, e, nv));
				continue;
			}
		} else
			pend = -1;
		fprintf(m.fp, "%s\n", line);
	}
	if ((out = ms_close(w, &m, NULL)) == NULL)
		*errp = "out of memory";
	return (out);
}

/*
 * The kept rules as the whole ruleset: into set 1, disabled, and then
 * in set 0's place.  With hold the rules that were there stay in set
 * 1 until ipfw_settle() says which of the two it is to be.
 */
static int
apply(struct work *w, bool hold, const char **errp)
{
	struct execres	 res;
	struct ms	 m;
	char		*text, *p, *line, *load, *tmp, *argv[4];
	const char	*rest;
	size_t		 len, n;
	long		 num;
	int		 fd, step;

	pthread_mutex_lock(&file_lock);
	text = file_read(w, &len);
	pthread_mutex_unlock(&file_lock);
	if (text == NULL) {
		*errp = wfmt(w, "there are no kept rules to apply: %s: %s",
		    opts.ipfw_rules, strerror(errno));
		return (-1);
	}
	/* What ipfw is to read: the file's lines, each in set 1. */
	if (!ms_open(&m)) {
		*errp = "out of memory";
		return (-1);
	}
	p = text;
	while ((line = strsep(&p, "\n")) != NULL) {
		line += strspn(line, " \t");
		if (line[0] == '\0' || line[0] == '#')
			continue;
		if (kept_rule(line, &num, &rest))
			fprintf(m.fp, "add %05ld set 1 %s\n", num, rest);
		else if (strncmp(line, "table ", 6) == 0 || strncmp(line,
		    "nat64", 5) == 0 || strncmp(line, "nptv6 ", 6) == 0)
			fprintf(m.fp, "set 1 %s\n", line);
		else
			fprintf(m.fp, "%s\n", line);
	}
	if ((load = ms_close(w, &m, &n)) == NULL) {
		*errp = "out of memory";
		return (-1);
	}
	if (n == 0) {
		*errp = "the kept rules are empty: applied, they would leave "
		    "the firewall with its last rule alone";
		return (-1);
	}
	tmp = wfmt(w, "%s.arcana-load", opts.ipfw_rules);
	step = step_begin(w, ARC_STEP_KIND_FILE, "write", "%s", tmp);
	if (w->jail != NULL) {
		if (scope_replace(w, tmp, load, n, 0600, NULL) != 0) {
			*errp = wfmt(w, "%s: %s", tmp, strerror(errno));
			step_end(w, step, false, "%s", *errp);
			return (-1);
		}
	} else if ((fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC |
	    O_NOFOLLOW, 0600)) == -1 || write(fd, load, n) != (ssize_t)n) {
		*errp = wfmt(w, "%s: %s", tmp, strerror(errno));
		step_end(w, step, false, "%s", *errp);
		if (fd != -1)
			close(fd);
		return (-1);
	} else
		close(fd);
	step_end(w, step, true, NULL);
	/* Set 1 is emptied and filled while nothing looks at it. */
	if (ipfw(w, errp, true, "set", "disable", "1", NULL) != 0)
		return (-1);
	(void)ipfw(w, NULL, true, "-f", "set", "1", "flush", NULL);
	(void)ipfw(w, NULL, true, "set", "1", "table", "all", "destroy", NULL);
	if (kmod_loaded("ipfw_nat64")) {
		(void)ipfw(w, NULL, true, "set", "1", "nat64lsn", "all",
		    "destroy", NULL);
		(void)ipfw(w, NULL, true, "set", "1", "nat64stl", "all",
		    "destroy", NULL);
		(void)ipfw(w, NULL, true, "set", "1", "nat64clat", "all",
		    "destroy", NULL);
	}
	argv[0] = (char *)(uintptr_t)opts.ipfw_bin;
	argv[1] = (char *)(uintptr_t)"-q";
	argv[2] = tmp;
	argv[3] = NULL;
	if (run_exec(w, scope_argv(w, argv), &res) != 0) {
		*errp = wtext(w, exec_error(w, &res, "ipfw"));
		/* Not half a ruleset left behind in set 1. */
		(void)ipfw(w, NULL, true, "-f", "set", "1", "flush", NULL);
		(void)unlink(tmp);
		return (-1);
	}
	(void)unlink(tmp);
	if (ipfw(w, errp, true, "set", "swap", "0", "1", NULL) != 0)
		return (-1);
	if (!hold)
		(void)ipfw(w, NULL, true, "-f", "delete", "set", "1", NULL);
	return (0);
}

/*
 * After an apply that held the old rules back in set 1: keep the new
 * ones and drop the old, or swap the old ones in again.
 */
const char *
ipfw_settle(struct work *w, bool keep)
{
	const char	*e;

	e = NULL;
	if (!keep && ipfw(w, &e, true, "set", "swap", "0", "1", NULL) != 0)
		return (e);
	(void)ipfw(w, NULL, true, "-f", "delete", "set", "1", NULL);
	return (NULL);
}

/* A line that is not a rule, at the head of the kept file, once. */
static int
kept_line(struct work *w, const char *line, const char **errp)
{
	char	*old, *out, *p, *l;
	size_t	 len;
	int	 rc;

	pthread_mutex_lock(&file_lock);
	old = file_read(w, &len);
	if (old == NULL)
		old = wstrdup(w, "");
	/*
	 * An object configured again ("pipe 1 config ..."): its line
	 * before, which the kept file would do after the new one, goes.
	 */
	{
		char	k[32], n[32], c[16], *nl, *keep;
		size_t	klen;

		klen = 0;
		if (sscanf(line, "%31s %31s %15s", k, n, c) == 3 &&
		    strcmp(c, "config") == 0)
			klen = strlen(k) + strlen(n) + strlen(c) + 3;
		keep = wcalloc(w, len + 1, 1);
		p = wstrdup(w, old);
		while ((l = strsep(&p, "\n")) != NULL) {
			if (strcmp(l + strspn(l, " \t"), line) == 0) {
				pthread_mutex_unlock(&file_lock);
				return (0);
			}
			nl = l + strspn(l, " \t");
			if (klen > 0 && strncmp(nl, wfmt(w, "%s %s %s ", k, n,
			    c), klen) == 0)
				continue;
			if (p != NULL || l[0] != '\0') {
				strlcat(keep, l, len + 1);
				if (p != NULL)
					strlcat(keep, "\n", len + 1);
			}
		}
		old = keep;
	}
	/* Before the rules: a rule may name what the line makes. */
	out = wfmt(w, "%s\n%s", line, old);
	rc = file_write(w, out, strlen(out), errp);
	pthread_mutex_unlock(&file_lock);
	return (rc);
}

/*
 * Lines of the kept file that what was just undone had made, taken out:
 * an object deleted (destroy, delete) takes all its lines, a table
 * flushed its entries, an entry deleted its own.  words is the
 * command, verb first: "table T destroy", "nat 1 delete", "table T
 * delete 10.0.0.1".  0 also when it had none.
 */
static int
kept_forget(struct work *w, const char *const words[], size_t n,
    const char **errp)
{
	char	*old, *out, *p, *l, *obj, *entry;
	size_t	 len, olen, elen;
	bool	 drop, any;
	int	 rc;

	if (n < 3)
		return (0);
	obj = wfmt(w, "%s %s ", words[0], words[1]);
	olen = strlen(obj);
	entry = NULL;
	elen = 0;
	if (strcmp(words[2], "flush") == 0)
		entry = wfmt(w, "%sadd ", obj);
	else if (strcmp(words[0], "table") == 0 && strcmp(words[2],
	    "delete") == 0 && n > 3)
		entry = wfmt(w, "%sadd %s", obj, words[3]);
	else if (strcmp(words[2], "destroy") != 0 && strcmp(words[2],
	    "delete") != 0)
		return (0);
	if (entry != NULL)
		elen = strlen(entry);
	pthread_mutex_lock(&file_lock);
	if ((old = file_read(w, &len)) == NULL) {
		pthread_mutex_unlock(&file_lock);
		return (0);
	}
	out = wcalloc(w, len + 1, 1);
	p = wstrdup(w, old);
	any = false;
	while ((l = strsep(&p, "\n")) != NULL) {
		const char	*t = l + strspn(l, " \t");

		if (entry == NULL)
			drop = strncmp(t, obj, olen) == 0;
		else
			/* The entry, and only it: a word ends there. */
			drop = strncmp(t, entry, elen) == 0 && (t[elen] ==
			    '\0' || t[elen] == ' ' || entry[elen - 1] == ' ');
		if (drop) {
			any = true;
			continue;
		}
		if (p != NULL || l[0] != '\0') {
			strlcat(out, l, len + 1);
			if (p != NULL)
				strlcat(out, "\n", len + 1);
		}
	}
	rc = any ? file_write(w, out, strlen(out), errp) : 0;
	pthread_mutex_unlock(&file_lock);
	return (rc);
}

/*
 * A rule deleted: of its number, the one of the words given, now and
 * where it is kept; with no words, the number's only rule.  Which, on
 * each side, is told before anything is touched.
 */
static int
delete_one(struct work *w, const struct arc_job_spec *sp, const char **errp)
{
	struct liverule	*lv;
	const char	*words;
	long		 num;
	int		 nl, i;

	num = strtol(sp->names.v[0], NULL, 10);
	words = sp->names.n > 1 ? join(w, (const char *const *)(uintptr_t)
	    (sp->names.v + 1), sp->names.n - 1) : NULL;
	if (sp->persist && kept_drop_one(w, num, words, true, errp) != 0)
		return (-1);
	nl = 0;
	lv = NULL;
	i = -1;
	if (sp->live) {
		if ((nl = live_rules(w, num, &lv)) < 0) {
			*errp = "ipfw could not be asked for the rules";
			return (-1);
		}
		if (nl == 0 && !sp->persist) {
			*errp = wfmt(w, "there is no rule %ld now", num);
			return (-1);
		}
		if (nl > 0 && (i = live_pick(w, num, lv, nl, words, errp)) < 0)
			return (-1);
	}
	if (sp->live && nl > 0 && live_redo(w, num, lv, nl, i, 0, NULL, errp) !=
	    0)
		return (-1);
	if (sp->persist && kept_drop_one(w, num, words, false, errp) != 0)
		return (-1);
	return (0);
}

/*
 * Rules given other numbers, pairs of from and to in the order given
 * (the farthest first, when a run of them makes room for another).
 * Planned whole first: each to must be free, now and kept, by the time
 * it is reached, and each from be there; nothing is touched otherwise.
 */
static int
renumber(struct work *w, const struct arc_job_spec *sp, const char **errp)
{
	struct liverule	*lv;
	uint8_t		*live_at, *kept_at;
	char		*text, **lines;
	const char	*rest;
	size_t		 i, len;
	long		 from, to, n;
	int		 nl, k;

	live_at = wcalloc(w, 65536, 1);
	kept_at = wcalloc(w, 65536, 1);
	if (sp->live) {
		if ((nl = live_rules(w, 0, &lv)) < 0) {
			*errp = "ipfw could not be asked for the rules";
			return (-1);
		}
		for (k = 0; k < nl; k++)
			live_at[lv[k].num] = 1;
	}
	if (sp->persist) {
		pthread_mutex_lock(&file_lock);
		text = file_read(w, &len);
		pthread_mutex_unlock(&file_lock);
		nl = kept_lines(w, text, &lines);
		for (k = 0; k < nl; k++)
			if (kept_rule(lines[k], &n, &rest) && n > 0 && n < 65536)
				kept_at[n] = 1;
	}
	for (i = 0; i + 1 < sp->names.n; i += 2) {
		from = strtol(sp->names.v[i], NULL, 10);
		to = strtol(sp->names.v[i + 1], NULL, 10);
		if (!live_at[from] && !kept_at[from]) {
			*errp = wfmt(w, "there is no rule %ld to move: nothing "
			    "was changed", from);
			return (-1);
		}
		if (live_at[to] || kept_at[to]) {
			*errp = wfmt(w, "%ld has a rule by the time %ld is moved "
			    "there: nothing was changed", to, from);
			return (-1);
		}
		live_at[to] = live_at[from];
		kept_at[to] = kept_at[from];
		live_at[from] = kept_at[from] = 0;
	}
	for (i = 0; i + 1 < sp->names.n; i += 2) {
		from = strtol(sp->names.v[i], NULL, 10);
		to = strtol(sp->names.v[i + 1], NULL, 10);
		if (sp->live) {
			if ((nl = live_rules(w, from, &lv)) < 0) {
				*errp = "ipfw could not be asked for the rules";
				return (-1);
			}
			if (nl > 0 && live_move(w, from, to, lv, nl, errp) != 0) {
				if (i > 0)
					*errp = wfmt(w, "%s (the moves before it "
					    "were done)", *errp);
				return (-1);
			}
		}
		if (sp->persist && kept_renumber(w, from, to, errp) != 0)
			return (-1);
	}
	return (0);
}

/*
 * A rule changed as one: of the old number, the rule of the words it
 * had (text; with none, the number's only rule) goes and the new one
 * comes, the others of that number staying; ipfw -n reads them all
 * before anything is touched, and the number is put back as it was
 * listed if the kernel does not take it after all.  Kept, that one
 * line goes and the new one comes.
 */
static int
replace(struct work *w, const struct arc_job_spec *sp, const char **errp)
{
	struct liverule		*lv;
	const char		**words;
	char			*rule, *src;
	size_t			 i, nw;
	long			 old;
	int			 nl, k;

	words = (const char **)(uintptr_t)(sp->names.v + 1);
	nw = sp->names.n - 1;
	src = NULL;
	/* $aliases put in, the rule's own words kept beside. */
	if (uses_alias(words + 1, nw - 1)) {
		struct alias	a[ALIAS_MAX];
		const char	**ex;
		size_t		na;

		na = aliases_now(w, a, nitems(a));
		if ((ex = expand(w, a, na, words + 1, nw - 1, errp)) == NULL)
			return (-1);
		src = join(w, words + 1, nw - 1);
		words = wcalloc(w, nw + 1, sizeof(*words));
		words[0] = sp->names.v[1];
		for (i = 1; i < nw; i++)
			words[i] = ex[i - 1];
	}
	old = strtol(sp->names.v[0], NULL, 10);
	rule = join(w, words + 1, nw - 1);
	/* Which rule of the old number, on each side, before anything is
	 * touched: the one of the words it had (text), or its only one. */
	if (sp->persist && kept_drop_one(w, old, sp->text, true, errp) != 0)
		return (-1);
	if (sp->live) {
		if ((nl = live_rules(w, old, &lv)) < 0) {
			*errp = "ipfw could not be asked for the rules";
			return (-1);
		}
		k = -1;
		if (nl > 0 && (k = live_pick(w, old, lv, nl, sp->text, errp)) <
		    0)
			return (-1);
		if (live_redo(w, old, lv, nl, k, strtol(sp->names.v[1], NULL,
		    10), rule, errp) != 0)
			return (-1);
	}
	if (sp->persist && (kept_drop_one(w, old, sp->text, false, errp) !=
	    0 || kept_change_src(w, strtol(sp->names.v[1], NULL, 10), rule,
	    src, errp) != 0))
		return (-1);
	return (0);
}

/* A prefix of an address list: an address, its length after a slash. */
static bool
prefix_ok(const char *s)
{
	char		 buf[64], *slash, *e;
	unsigned char	 a[16];
	long		 l;
	int		 af;

	if (strlcpy(buf, s, sizeof(buf)) >= sizeof(buf))
		return (false);
	if ((slash = strchr(buf, '/')) != NULL)
		*slash++ = '\0';
	if (inet_pton(AF_INET, buf, a) == 1)
		af = 32;
	else if (inet_pton(AF_INET6, buf, a) == 1)
		af = 128;
	else
		return (false);
	if (slash == NULL)
		return (true);
	l = strtol(slash, &e, 10);
	return (*e == '\0' && l >= 0 && l <= af);
}

/*
 * alias name kind value...: set, kind addr (the entries), ports ("80,443")
 * or value (one word); alias name delete.  Kept as a line of the kept
 * file; an address list as its table's lines too.  The rules that name
 * it are written again, and in the kernel the table made again and
 * those rules replaced, as a table's change is made now.
 */
static int
alias_job(struct work *w, const struct arc_job_spec *sp, const char **errp)
{
	struct alias	 a[ALIAS_MAX];
	struct ms	 m;
	const char	*name, *kind, *rest, *v[IPFW_WORDS], **e;
	char		*text, *copy, *p, *line, *out, *val;
	size_t		 len, na, nv, i, k;
	long		 num;
	bool		 del, addr, named;
	struct {
		long		 num;
		char		*rule;
		const char	*was;	/* as it was put in before, or NULL */
	}		 redo[512];
	size_t		 nredo = 0;

	name = sp->names.v[0];
	kind = sp->names.v[1];
	del = strcmp(kind, "delete") == 0;
	addr = strcmp(kind, "addr") == 0;
	pthread_mutex_lock(&file_lock);
	text = file_read(w, &len);
	if (text == NULL)
		text = wstrdup(w, "");
	/* A rule that names it: deleted, it would name none. */
	if (del) {
		copy = wstrdup(w, text);
		for (p = copy; (line = strsep(&p, "\n")) != NULL; ) {
			if (!src_rule(line, &num, &rest))
				continue;
			nv = split(w, rest, v, nitems(v));
			for (i = 0; i < nv; i++)
				if (v[i][0] == '$' && strcmp(v[i] + 1, name) ==
				    0) {
					pthread_mutex_unlock(&file_lock);
					*errp = wfmt(w, "rule %ld names $%s: it is "
					    "not deleted while a rule names it",
					    num, name);
					return (-1);
				}
		}
	}
	val = del || addr ? NULL : join(w, (const char *const *)(uintptr_t)
	    (sp->names.v + 2), sp->names.n - 2);
	/* The file again: the alias's lines out, its new ones in at the
	 * head; an address list's table made there too. */
	if (!ms_open(&m)) {
		pthread_mutex_unlock(&file_lock);
		*errp = "out of memory";
		return (-1);
	}
	if (!del) {
		fprintf(m.fp, "#arcana alias %s %s%s%s\n", name, kind,
		    val != NULL ? " " : "", val != NULL ? val : "");
		if (addr) {
			fprintf(m.fp, "table %s create type addr\n", name);
			for (i = 2; i < sp->names.n; i++)
				fprintf(m.fp, "table %s add %s\n", name,
				    sp->names.v[i]);
		}
	}
	copy = wstrdup(w, text);
	for (p = copy; p != NULL && *p != '\0' && (line = strsep(&p, "\n")) !=
	    NULL; ) {
		const char	*t = line + strspn(line, " \t");
		char		 an[40];

		if (sscanf(t, "#arcana alias %39s", an) == 1 && strcmp(an,
		    name) == 0)
			continue;
		/* Its table's lines, when it is (or was) an address list. */
		if (strncmp(t, "table ", 6) == 0 && strncmp(t + 6, name,
		    strlen(name)) == 0 && t[6 + strlen(name)] == ' ') {
			na = aliases_of(w, text, a, nitems(a));
			for (k = 0; k < na; k++)
				if (strcmp(a[k].name, name) == 0 && strcmp(
				    a[k].kind, "addr") == 0)
					break;
			if (k < na || addr)
				continue;
		}
		fprintf(m.fp, "%s\n", line);
	}
	if ((out = ms_close(w, &m, NULL)) == NULL) {
		pthread_mutex_unlock(&file_lock);
		*errp = "out of memory";
		return (-1);
	}
	/* The rules that name it, written again from their own words. */
	if ((out = text_expand(w, out, errp)) == NULL) {
		pthread_mutex_unlock(&file_lock);
		return (-1);
	}
	if (file_write(w, out, strlen(out), errp) != 0) {
		pthread_mutex_unlock(&file_lock);
		return (-1);
	}
	pthread_mutex_unlock(&file_lock);
	/* Now too, as a table's or a NAT's change is: the table made
	 * again, the rules that name it replaced. */
	if (del)
		return (0);
	if (addr) {
		(void)ipfw(w, NULL, true, "table", name, "create", "type",
		    "addr", NULL);
		if (ipfw(w, errp, true, "table", name, "flush", NULL) != 0)
			return (-1);
		for (i = 2; i < sp->names.n; i++)
			if (ipfw(w, errp, true, "table", name, "add",
			    sp->names.v[i], NULL) != 0)
				return (-1);
		return (0);
	}
	na = aliases_of(w, out, a, nitems(a));
	copy = wstrdup(w, out);
	for (p = copy; (line = strsep(&p, "\n")) != NULL && nredo <
	    nitems(redo); ) {
		if (!src_rule(line, &num, &rest))
			continue;
		nv = split(w, rest, v, nitems(v));
		named = false;
		for (i = 0; i < nv; i++)
			named = named || (v[i][0] == '$' && strcmp(v[i] + 1,
			    name) == 0);
		if (!named || (e = expand(w, a, na, v, nv, errp)) == NULL)
			continue;
		redo[nredo].num = num;
		redo[nredo].rule = join(w, e, nv);
		redo[nredo].was = NULL;
		/* Its words as the file had them put in before: the rule
		 * the kernel has now, to be told from another of its
		 * number. */
		{
			char		**ol;
			const char	 *orest, *krest;
			long		  on, kn;
			int		  nol, j;

			nol = kept_lines(w, wstrdup(w, text), &ol);
			for (j = 0; j + 1 < nol; j++)
				if (src_rule(ol[j], &on, &orest) && on == num &&
				    strcmp(orest, rest) == 0 && kept_rule(ol[j + 1],
				    &kn, &krest) && kn == num) {
					redo[nredo].was = krest;
					break;
				}
		}
		nredo++;
	}
	/* Now too: each rule that names it, in the kernel, is put in again
	 * from its words; one that is not loaded now stays so. */
	for (i = 0; i < nredo; i++) {
		struct liverule	*lv;
		int		 nl, pick;

		if ((nl = live_rules(w, redo[i].num, &lv)) <= 0)
			continue;
		if ((pick = live_pick(w, redo[i].num, lv, nl, redo[i].was,
		    errp)) < 0 || live_redo(w, redo[i].num, lv, nl, pick,
		    redo[i].num, redo[i].rule, errp) != 0)
			return (-1);
	}
	return (0);
}

/* Do the job.  *heldp says an apply left the old rules to be settled. */
int
do_ipfw_job(struct work *w, const struct arc_job_spec *sp, bool *heldp,
    const char **errp)
{
	const char	*verb, *argvv[IPFW_WORDS + 4];
	struct execres	 res;
	char		*rule, *argv[IPFW_WORDS + 6];
	size_t		 i, len;
	int		 n;
	bool		 on;

	*heldp = false;
	if ((*errp = ipfw_check(sp)) != NULL)
		return (-1);
	verb = sp->verb;
	(void)argvv;
	if (strcmp(verb, "alias") == 0)
		return (alias_job(w, sp, errp));
	if (strcmp(verb, "add") == 0) {
		const char	**words = (const char **)(uintptr_t)sp->names.v;
		char		 *src = NULL;

		/* $aliases put in, the rule's own words kept beside. */
		if (uses_alias(words + 1, sp->names.n - 1)) {
			struct alias	a[ALIAS_MAX];
			const char	**e;
			size_t		na;

			na = aliases_now(w, a, nitems(a));
			if ((e = expand(w, a, na, words + 1, sp->names.n - 1,
			    errp)) == NULL)
				return (-1);
			src = join(w, words + 1, sp->names.n - 1);
			words = wcalloc(w, sp->names.n + 1, sizeof(*words));
			words[0] = sp->names.v[0];
			for (i = 1; i < sp->names.n; i++)
				words[i] = e[i - 1];
		}
		if (sp->live) {
			n = 0;
			argv[n++] = (char *)(uintptr_t)opts.ipfw_bin;
			argv[n++] = (char *)(uintptr_t)"-q";
			argv[n++] = (char *)(uintptr_t)"add";
			for (i = 0; i < sp->names.n; i++)
				argv[n++] = (char *)(uintptr_t)words[i];
			argv[n] = NULL;
			if (run_exec(w, scope_argv(w, argv), &res) != 0) {
				*errp = scope_missing(w, &res, "ipfw", NULL);
				if (*errp == NULL)
					*errp = wtext(w, exec_error(w, &res,
					    "ipfw"));
				return (-1);
			}
		}
		if (sp->persist) {
			rule = join(w, words + 1, sp->names.n - 1);
			if (kept_change_src(w, strtol(sp->names.v[0], NULL, 10),
			    rule, src, errp) != 0)
				return (-1);
		}
		return (0);
	}
	if (strcmp(verb, "replace") == 0)
		return (replace(w, sp, errp));
	if (strcmp(verb, "delete") == 0)
		return (delete_one(w, sp, errp));
	if (strcmp(verb, "renumber") == 0)
		return (renumber(w, sp, errp));
	if (strcmp(verb, "apply") == 0) {
		if (apply(w, sp->safe, errp) != 0)
			return (-1);
		*heldp = sp->safe;
		return (0);
	}
	if (object_verb(verb)) {
		n = 0;
		argv[n++] = (char *)(uintptr_t)opts.ipfw_bin;
		argv[n++] = (char *)(uintptr_t)"-q";
		argv[n++] = (char *)(uintptr_t)verb;
		len = strlen(verb) + 2;
		for (i = 0; i < sp->names.n; i++) {
			argv[n++] = (char *)(uintptr_t)sp->names.v[i];
			len += strlen(sp->names.v[i]) + 1;
		}
		argv[n] = NULL;
		if (run_exec(w, scope_argv(w, argv), &res) != 0) {
			*errp = scope_missing(w, &res, "ipfw", NULL);
			if (*errp == NULL)
				*errp = wtext(w, exec_error(w, &res, "ipfw"));
			return (-1);
		}
		/* dummynet says "x is invalid parameter" (on standard
		 * output, with -q too), leaves it out and exits 0: what it
		 * says is its failure. */
		if ((strcmp(verb, "pipe") == 0 || strcmp(verb, "sched") == 0 ||
		    strcmp(verb, "queue") == 0) && (res.outlen > 0 ||
		    res.errlen > 0)) {
			const char	*said;

			said = res.outlen > 0 ? res.out : res.err;
			*errp = wtext(w, wfmt(w, "ipfw %s: %s", verb, wstrndup(w,
			    said, strcspn(said, "\n"))));
			return (-1);
		}
		/* Undone: so are the kept lines it had made. */
		if (sp->persist && sp->names.n >= 2 &&
		    (strcmp(sp->names.v[1], "destroy") == 0 ||
		    strcmp(sp->names.v[1], "delete") == 0 ||
		    strcmp(sp->names.v[1], "flush") == 0)) {
			argvv[0] = verb;
			for (i = 0; i < sp->names.n && i < IPFW_WORDS + 2; i++)
				argvv[i + 1] = sp->names.v[i];
			return (kept_forget(w, argvv, i + 1, errp));
		}
		/* Kept: the same words, a line of the kept file. */
		if (sp->persist) {
			rule = wcalloc(w, len, 1);
			strlcpy(rule, verb, len);
			for (i = 0; i < sp->names.n; i++) {
				strlcat(rule, " ", len);
				strlcat(rule, sp->names.v[i], len);
			}
			return (kept_line(w, rule, errp));
		}
		return (0);
	}
	if (strcmp(verb, "zero") == 0)
		return (sp->names.n == 1 ? ipfw(w, errp, true, "zero",
		    sp->names.v[0], NULL) : ipfw(w, errp, true, "zero", NULL));
	/* On or off, now; and what the next boot does, kept. */
	on = strcmp(verb, "enable") == 0;
	if (ipfw(w, errp, true, on ? "enable" : "disable", "firewall", NULL) !=
	    0)
		return (-1);
	if (sp->persist && w->jail == NULL) {
		if (rc_set(w, "firewall_enable", "=", on ? "YES" : "NO",
		    errp) != 0)
			return (-1);
		if (on && rc_set(w, "firewall_type", "=", opts.ipfw_rules,
		    errp) != 0)
			return (-1);
	}
	return (0);
}

/* Take back a rule that was added now: for safe mode. */
const char *
ipfw_unadd(struct work *w, const struct arc_job_spec *sp)
{
	struct liverule	 *lv;
	const char	**words, *e, *src, *rule;
	long		  num;
	size_t		  i;
	int		  nl, k;

	e = NULL;
	num = strtol(sp->names.v[0], NULL, 10);
	words = (const char **)(uintptr_t)(sp->names.v + 1);
	src = join(w, words, sp->names.n - 1);
	rule = src;
	/* As it was added: its aliases put in. */
	if (uses_alias(words, sp->names.n - 1)) {
		struct alias	a[ALIAS_MAX];
		const char	**x;
		size_t		 na;

		na = aliases_now(w, a, nitems(a));
		if ((x = expand(w, a, na, words, sp->names.n - 1, &e)) != NULL)
			rule = join(w, x, sp->names.n - 1);
		e = NULL;
	}
	(void)i;
	/* That rule alone: another of its number stays. */
	if (sp->live && (nl = live_rules(w, num, &lv)) > 0 && (k = live_pick(w,
	    num, lv, nl, rule, &e)) >= 0)
		(void)live_redo(w, num, lv, nl, k, 0, NULL, &e);
	if (sp->persist)
		(void)kept_drop_one(w, num, src, false, &e);
	return (e);
}

/*
 * Packets followed by the kernel itself: ipfw:::rule-matched, the
 * probe ipfw fires with the rule that decided each packet, told to
 * dtrace(1).  Only those of one address, for a few seconds or packets:
 * a predicate on the address's own words, as the kernel holds it.
 */
#define	FW_TRACE_SECONDS	10
#define	FW_TRACE_PACKETS	100

static const char *const verdicts[] = { "pass", "deny", "divert", "tee",
    "dummynet", "netgraph", "ngtee", "nat", "reass", "nat64" };

/* "a == x" for the address's 32-bit words at p. */
static void
words_match(FILE *fp, const char *p, const uint32_t *w, int n)
{
	int	i;

	fputc('(', fp);
	for (i = 0; i < n; i++)
		fprintf(fp, "%s((uint32_t *)%s)[%d] == %uU", i > 0 ? " && " :
		    "", p, i, w[i]);
	fputc(')', fp);
}

/* The jail's interfaces, but lo0, which every network has its own of. */
static void
trace_ifs(struct work *w, FILE *fp)
{
	static const char *const words[] = { "-", "-" };
	struct execres		 res;
	struct ucl_parser	*p;
	ucl_object_t		*top;
	const ucl_object_t	*i;
	ucl_object_iter_t	 it;
	const char		*name;
	bool			 some;

	some = false;
	top = NULL;
	if (run_exec(w, helper_argv(w, "interfaces", 2, words), &res) == 0 &&
	    res.out != NULL) {
		p = ucl_parser_new(UCL_PARSER_NO_IMPLICIT_ARRAYS);
		if (ucl_parser_add_chunk(p, (const unsigned char *)res.out,
		    res.outlen))
			top = ucl_parser_get_object(p);
		ucl_parser_free(p);
	}
	fputs(" && args[4]->ifp != NULL && (", fp);
	it = NULL;
	while (top != NULL && (i = ucl_object_iterate(ucl_object_lookup(top,
	    "interfaces"), &it, true)) != NULL) {
		name = ucl_object_tostring(ucl_object_lookup(i, "name"));
		if (name == NULL || strcmp(name, "lo0") == 0 ||
		    name[strspn(name, "abcdefghijklmnopqrstuvwxyz"
		    "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-")] != '\0')
			continue;
		fprintf(fp, "%sstringof(args[4]->ifp->if_xname) == \"%s\"",
		    some ? " || " : "", name);
		some = true;
	}
	/* A jail with none of its own sees none. */
	fputs(some ? ")" : "0)", fp);
	if (top != NULL)
		ucl_object_unref(top);
}

int
do_fw_trace(struct work *w, const char *address, uint32_t seconds,
    uint32_t packets, struct arc_fw_trace_rsp *rsp)
{
	struct execres	 res;
	unsigned char	 a[16];
	uint32_t	 wd[4];
	char		*script, *json, *line, *next, *argv[5], *f[12],
			 path[64];
	size_t		 len, n;
	FILE		*fp;
	int		 af, nw, i, sfd, rc;

	rsp->has_ok = true;
	rsp->ok = false;
	if (inet_pton(AF_INET, address, a) == 1) {
		af = AF_INET;
		nw = 1;
	} else if (inet_pton(AF_INET6, address, a) == 1) {
		af = AF_INET6;
		nw = 4;
	} else {
		rsp->error = "the address to follow is an IPv4 or IPv6 address";
		return (0);
	}
	memcpy(wd, a, (size_t)nw * 4);
	if (seconds == 0)
		seconds = FW_TRACE_SECONDS;
	if (packets == 0)
		packets = FW_TRACE_PACKETS;
	script = NULL;
	if ((fp = open_memstream(&script, &len)) == NULL) {
		rsp->error = "out of memory";
		return (0);
	}
	fprintf(fp, "#pragma D option quiet\n"
	    "int n;\nuint64_t start;\n"
	    "ipfw:::rule-matched\n/arg1 == %d && (", af);
	words_match(fp, "arg2", wd, nw);
	fputs(" || ", fp);
	words_match(fp, "arg3", wd, nw);
	fputc(')', fp);
	if (w->jail != NULL)
		trace_ifs(w, fp);
	/* Not one more than asked for: the next would be told before the
	 * clause that ends it. */
	fprintf(fp, " && n < %u/\n{\n\tn++;\n", packets);
	fprintf(fp, "\tprintf(\"P %%d %%d %%s %%s %%d %%d %%d %%d %%s %%d\\n\", "
	    "(timestamp - %s) / 1000000, arg0,\n"
	    "\t    %s((%s *)arg2), %s((%s *)arg3),\n"
	    "\t    args[4]->f_id.proto, args[4]->f_id.src_port,\n"
	    "\t    args[4]->f_id.dst_port, args[5]->rulenum,\n"
	    "\t    args[4]->ifp != NULL ? stringof(args[4]->ifp->if_xname) : "
	    "\"-\",\n\t    (args[4]->flags & 0x00400000) != 0);\n}\n"
	    "ipfw:::rule-matched\n/n >= %u/\n{\n\texit(0);\n}\n"
	    "tick-%us\n{\n\texit(0);\n}\n"
	    "BEGIN\n{\n\tstart = timestamp;\n}\n", "start",
	    af == AF_INET ? "inet_ntoa" : "inet_ntoa6", af == AF_INET ?
	    "in_addr_t" : "struct in6_addr", af == AF_INET ? "inet_ntoa" :
	    "inet_ntoa6", af == AF_INET ? "in_addr_t" : "struct in6_addr",
	    packets, seconds);
	if (fclose(fp) != 0 || script == NULL) {
		free(script);
		rsp->error = "out of memory";
		return (0);
	}
	/* A script with its declarations is read from a file (-s). */
	snprintf(path, sizeof(path), "/tmp/arcana-fw-trace.XXXXXX");
	if ((sfd = mkstemp(path)) == -1 || write(sfd, script, len) !=
	    (ssize_t)len) {
		if (sfd != -1) {
			close(sfd);
			unlink(path);
		}
		free(script);
		rsp->error = "cannot write the script for dtrace";
		return (0);
	}
	close(sfd);
	free(script);
	argv[0] = (char *)(uintptr_t)tool(w, "dtrace");
	argv[1] = (char *)(uintptr_t)"-q";
	argv[2] = (char *)(uintptr_t)"-s";
	argv[3] = path;
	argv[4] = NULL;
	rc = run_exec(w, argv, &res);
	unlink(path);
	if (rc != 0) {
		rsp->error = res.err != NULL && strstr(res.err,
		    "does not match any probes") != NULL ? "the kernel has no "
		    "ipfw:::rule-matched probe here: dtraceall(4) and ipfw(4) "
		    "are to be loaded" : wtext(w, exec_error(w, &res, "dtrace"));
		return (0);
	}
	json = NULL;
	if ((fp = open_memstream(&json, &len)) == NULL) {
		rsp->error = "out of memory";
		return (0);
	}
	fputs("{\"packets\":[", fp);
	n = 0;
	for (line = (char *)(uintptr_t)(res.out != NULL ? res.out : "");
	    line != NULL && *line != '\0'; line = next) {
		if ((next = strchr(line, '\n')) != NULL)
			*next++ = '\0';
		for (i = 0; i < 12 && (f[i] = strsep(&line, " ")) != NULL; i++)
			;
		/* P ms verdict src dst proto sport dport rule if in */
		if (i != 11 || strcmp(f[0], "P") != 0)
			continue;
		fprintf(fp, "%s{\"ms\":%s,\"verdict\":\"%s\",\"family\":\"%s\","
		    "\"source\":\"%s\",\"destination\":\"%s\",\"proto\":%s,"
		    "\"sport\":%s,\"dport\":%s,\"rule\":%s,\"interface\":\"%s\","
		    "\"direction\":\"%s\"}", n++ > 0 ? "," : "", f[1],
		    (size_t)atoi(f[2]) < nitems(verdicts) ? verdicts[atoi(f[2])] :
		    "?", af == AF_INET ? "inet" : "inet6", f[3], f[4], f[5],
		    f[6], f[7], f[8], f[9], strcmp(f[10], "1") == 0 ? "in" :
		    "out");
	}
	fprintf(fp, "],\"seconds\":%u,\"limit\":%u}", seconds, packets);
	if (fclose(fp) != 0 || json == NULL) {
		free(json);
		rsp->error = "out of memory";
		return (0);
	}
	rsp->json = wtext(w, wadopt(w, json));
	rsp->ok = true;
	return (0);
}
