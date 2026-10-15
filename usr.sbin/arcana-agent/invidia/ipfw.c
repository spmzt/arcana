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
	*restp = end + strspn(end, " \t");
	return (true);
}

static bool	alias_name_ok(const char *);
static bool	src_rule(const char *, long *, const char **);
static bool	prefix_ok(const char *);

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
static char *
script_ipfw(char *q)
{
	char	*tok;
	size_t	 n;

	n = strcspn(q, " \t");
	tok = q;
	/* ipfw, a path to it, or a variable: not an assignment. */
	if (memchr(tok, '=', n) != NULL || !((n == 4 && strncmp(tok, "ipfw",
	    4) == 0) || (tok[0] == '/' && n > 5 && strncmp(tok + n - 5,
	    "/ipfw", 5) == 0) || (tok[0] == '$' && n > 1)))
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
	const char		*type, *script, *file;
	size_t			 len, n, o;
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
	for (n = 1, p = text; *p != '\0'; p++)
		if (*p == '\n')
			n++;
	out = wcalloc(w, len + n * sizeof(shnote) + 2, 1);
	o = 0;
	p = text;
	while ((line = strsep(&p, "\n")) != NULL) {
		if (p == NULL && line[0] == '\0')
			break;
		q = line + strspn(line, " \t");
		if (q[0] == '\0' || q[0] == '#') {
			if (sh && q[0] == '#' && q[1] == '!')
				continue;
			q = line;
		} else if (sh && (c = script_ipfw(q)) == NULL) {
			/* The shell's own: kept, as a comment. */
			memcpy(out + o, shnote, sizeof(shnote) - 1);
			o += sizeof(shnote) - 1;
		} else {
			if (sh) {
				q = c;
				q[unshell(q)] = '\0';
			}
			/* ipfw -q add …: the options are applying's. */
			while ((q[0] == '-' && (q[1] == 'q' || q[1] == 'f') &&
			    (q[2] == ' ' || q[2] == '\t')))
				q += 2 + strspn(q + 2, " \t");
			/* Left out: the line as it is written. */
			if (strncmp(q, "flush", 5) == 0 || strncmp(q, "set ",
			    4) == 0 || strncmp(q, "delete ", 7) == 0 ||
			    q[0] == '-') {
				memcpy(out + o, note, sizeof(note) - 1);
				o += sizeof(note) - 1;
				q = line + strspn(line, " \t");
			}
		}
		len = strlen(q);
		memcpy(out + o, q, len);
		o += len;
		out[o++] = '\n';
	}
	out[o] = '\0';
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

/* What is wrong with the job, or NULL. */
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
	} else if (strcmp(verb, "delete") == 0) {
		if (sp->names.n != 1 || !number_ok(sp->names.v[0]))
			return ("name the rule to delete by its number");
		if (!sp->live && !sp->persist)
			return ("say live, persist or both");
		if (sp->safe)
			return ("a rule deleted is not put back by itself: "
			    "apply the kept rules in safe mode instead");
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
		return ("an ipfw job is add, delete, alias, apply, enable, "
		    "disable, zero, or table, nat, nat64lsn, nat64stl, nat64clat, "
		    "nptv6, pipe, queue, sched with their words");
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
	    sp->verb != NULL ? sp->verb : "", "delete") == 0 ? sp->live &&
	    sp->persist ? " (now, and kept)" : sp->persist ? " (kept)" :
	    " (now)" : sp->persist ? " (kept)" : "") == -1)
		t = NULL;
	free(all);
	return (t);
}

/*
 * The kept file with a rule put in at its number, or the rules of a
 * number taken out.  0, or -1 and why.
 */
static int
kept_change_src(struct work *w, long num, const char *rule, const char *src,
    const char **errp);

static int
kept_change(struct work *w, long num, const char *rule, const char **errp)
{

	return (kept_change_src(w, num, rule, NULL, errp));
}

/* The same, the rule's own words with aliases kept before it. */
static int
kept_change_src(struct work *w, long num, const char *rule, const char *src,
    const char **errp)
{
	char		*old, *out, *p, *line;
	const char	*rest;
	size_t		 oldlen, cap, len;
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
	cap = oldlen + (rule != NULL ? strlen(rule) : 0) + (src != NULL ?
	    strlen(src) : 0) + 128;
	out = wcalloc(w, cap, 1);
	len = 0;
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
					len += (size_t)snprintf(out + len,
					    cap - len, "#arcana add %05ld %s\n",
					    num, src);
				len += (size_t)snprintf(out + len, cap - len,
				    "add %05ld %s\n", num, rule);
				done = true;
			}
		}
		len += (size_t)snprintf(out + len, cap - len, "%s\n", line);
	}
	if (!done) {
		if (src != NULL)
			len += (size_t)snprintf(out + len, cap - len,
			    "#arcana add %05ld %s\n", num, src);
		len += (size_t)snprintf(out + len, cap - len, "add %05ld %s\n",
		    num, rule);
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
	const char	*v[IPFW_WORDS], **e, *rest;
	char		*copy, *p, *line, *out;
	size_t		 na, nv, cap, len;
	long		 num, pend = -1;
	int		 ln = 0;

	na = aliases_of(w, text, a, nitems(a));
	cap = strlen(text) * 2 + 1024;
	out = wcalloc(w, cap, 1);
	len = 0;
	copy = wstrdup(w, text);
	for (p = copy; p != NULL && *p != '\0' &&
	    (line = strsep(&p, "\n")) != NULL; ) {
		ln++;
		if (src_rule(line, &num, &rest)) {
			nv = split(w, rest, v, nitems(v));
			if ((e = expand(w, a, na, v, nv, errp)) == NULL) {
				*errp = wfmt(w, "line %d: %s", ln, *errp);
				return (NULL);
			}
			len += (size_t)snprintf(out + len, cap - len, "%s\n"
			    "add %05ld %s\n", line, num, join(w, e, nv));
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
					return (NULL);
				}
				len += (size_t)snprintf(out + len, cap - len,
				    "#arcana add %05ld %s\nadd %05ld %s\n", num,
				    rest, num, join(w, e, nv));
				continue;
			}
		} else
			pend = -1;
		len += (size_t)snprintf(out + len, cap - len, "%s\n", line);
	}
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
	char		*text, *p, *line, *load, *tmp, *argv[4];
	const char	*rest;
	size_t		 len, cap, n;
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
	cap = len * 2 + 256;
	load = wcalloc(w, cap, 1);
	n = 0;
	p = text;
	while ((line = strsep(&p, "\n")) != NULL) {
		line += strspn(line, " \t");
		if (line[0] == '\0' || line[0] == '#')
			continue;
		if (kept_rule(line, &num, &rest))
			n += (size_t)snprintf(load + n, cap - n,
			    "add %05ld set 1 %s\n", num, rest);
		else if (strncmp(line, "table ", 6) == 0 || strncmp(line,
		    "nat64", 5) == 0 || strncmp(line, "nptv6 ", 6) == 0)
			n += (size_t)snprintf(load + n, cap - n, "set 1 %s\n",
			    line);
		else
			n += (size_t)snprintf(load + n, cap - n, "%s\n", line);
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

/* ipfw with argv's words after the ones given, in the jail's scope. */
static int
ipfw_words(struct work *w, const char **errp, const char *const *pre,
    size_t npre, const char *const *words, size_t nwords)
{
	struct execres	 res;
	char		*argv[IPFW_WORDS + 8];
	size_t		 i, n;

	n = 0;
	argv[n++] = (char *)(uintptr_t)opts.ipfw_bin;
	for (i = 0; i < npre && n < nitems(argv) - 1; i++)
		argv[n++] = (char *)(uintptr_t)pre[i];
	for (i = 0; i < nwords && n < nitems(argv) - 1; i++)
		argv[n++] = (char *)(uintptr_t)words[i];
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

/*
 * A rule changed as one: the new one read by ipfw without being done
 * (ipfw -n) before anything is touched; then the rules of the old
 * number deleted and the new one added; and if ipfw does not take it
 * after all, the old ones put back as ipfw listed them.  Kept, the
 * kept file's lines of the old number go and the new one comes.
 */
static int
replace(struct work *w, const struct arc_job_spec *sp, const char **errp)
{
	const char *const	 pre_n[] = { "-q", "-n", "add" };
	const char *const	 pre_add[] = { "-q", "add" };
	struct execres		 res;
	const char		**words, *e;
	char			*argv[5], *text, *p, *line, *rule, *wp, *wd, *src;
	const char		*oldv[IPFW_WORDS + 2];
	size_t			 i, len, nw, no;
	bool			 had;

	words = (const char **)(uintptr_t)(sp->names.v + 1);
	nw = sp->names.n - 1;
	text = NULL;
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
	if (sp->live) {
		if (ipfw_words(w, errp, pre_n, nitems(pre_n), words, nw) != 0) {
			*errp = wfmt(w, "ipfw does not take the new rule, so "
			    "nothing was changed: %s", *errp);
			return (-1);
		}
		/* The old number's rules, as ipfw lists them. */
		argv[0] = (char *)(uintptr_t)opts.ipfw_bin;
		argv[1] = (char *)(uintptr_t)"list";
		argv[2] = (char *)(uintptr_t)sp->names.v[0];
		argv[3] = NULL;
		had = run_exec(w, scope_argv(w, argv), &res) == 0 && res.out !=
		    NULL && res.outlen > 0;
		if (had)
			text = wstrndup(w, res.out, res.outlen);
		if (had && ipfw(w, errp, true, "delete", sp->names.v[0], NULL) !=
		    0)
			return (-1);
		if (ipfw_words(w, errp, pre_add, nitems(pre_add), words, nw) !=
		    0) {
			e = *errp;
			for (p = text; p != NULL && (line = strsep(&p, "\n")) !=
			    NULL;) {
				if (!isdigit((unsigned char)line[0]))
					continue;
				no = 0;
				oldv[no++] = sp->names.v[0];
				wp = line + strcspn(line, " ");
				while ((wd = strsep(&wp, " ")) != NULL && no <
				    nitems(oldv) - 1)
					if (*wd != '\0')
						oldv[no++] = wd;
				(void)ipfw_words(w, NULL, pre_add, nitems(pre_add),
				    oldv, no);
			}
			*errp = wfmt(w, "ipfw did not take the new rule: %s; the "
			    "one before was put back", e);
			return (-1);
		}
	}
	if (sp->persist) {
		rule = join(w, words + 1, nw - 1);
		(void)len;
		if (kept_change(w, strtol(sp->names.v[0], NULL, 10), NULL,
		    errp) != 0 || kept_change_src(w, strtol(sp->names.v[1],
		    NULL, 10), rule, src, errp) != 0)
			return (-1);
	}
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
	const char	*name, *kind, *rest, *v[IPFW_WORDS], **e;
	char		*text, *copy, *p, *line, *out, *val;
	size_t		 len, cap, olen, na, nv, i, k;
	long		 num;
	bool		 del, addr, named;
	struct {
		long	 num;
		char	*rule;
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
	cap = len + 4096 + (sp->names.n * 80);
	out = wcalloc(w, cap, 1);
	olen = 0;
	if (!del) {
		olen += (size_t)snprintf(out + olen, cap - olen, "#arcana alias "
		    "%s %s%s%s\n", name, kind, val != NULL ? " " : "", val !=
		    NULL ? val : "");
		if (addr) {
			olen += (size_t)snprintf(out + olen, cap - olen, "table %s "
			    "create type addr\n", name);
			for (i = 2; i < sp->names.n; i++)
				olen += (size_t)snprintf(out + olen, cap - olen,
				    "table %s add %s\n", name, sp->names.v[i]);
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
		olen += (size_t)snprintf(out + olen, cap - olen, "%s\n", line);
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
		nredo++;
	}
	for (i = 0; i < nredo; i++) {
		const char	*pre[] = { "-q", "add" };
		const char	*wv[IPFW_WORDS + 1];
		char		 nb[16];

		snprintf(nb, sizeof(nb), "%ld", redo[i].num);
		(void)ipfw(w, NULL, true, "delete", nb, NULL);
		wv[0] = wstrdup(w, nb);
		nv = split(w, redo[i].rule, wv + 1, nitems(wv) - 1);
		if (ipfw_words(w, errp, pre, nitems(pre), wv, nv + 1) != 0)
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
	if (strcmp(verb, "delete") == 0) {
		if (sp->live && ipfw(w, errp, true, "delete", sp->names.v[0],
		    NULL) != 0)
			return (-1);
		if (sp->persist && kept_change(w, strtol(sp->names.v[0], NULL,
		    10), NULL, errp) != 0)
			return (-1);
		return (0);
	}
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
	const char	*e;

	e = NULL;
	if (sp->live)
		(void)ipfw(w, &e, true, "delete", sp->names.v[0], NULL);
	if (sp->persist)
		(void)kept_change(w, strtol(sp->names.v[0], NULL, 10), NULL,
		    &e);
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
