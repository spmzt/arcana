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
 */

#include <sys/param.h>
#include <sys/stat.h>
#include <sys/sysctl.h>

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
#define	IPFW_WORDS	120
#define	IPFW_DYN_MAX	3000	/* dynamic rules in a reply, at most */

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

static bool
enabled(void)
{
	int	v;
	size_t	len;

	len = sizeof(v);
	return (sysctlbyname("net.inet.ip.fw.enable", &v, &len, NULL, 0) ==
	    0 && v != 0);
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

/* {"loaded","enabled","rules":[...],"tables","nat","kept","other",...} */
int
do_ipfw(struct work *w, struct arc_network_rsp *rsp)
{
	struct execres	 res;
	ucl_object_t	*top, *rules, *o, *kept, *other, *arr, *rc;
	unsigned char	*json;
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
	ucl_object_insert_key(top, ucl_object_frombool(loaded && (enabled() ||
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
		while ((line = strsep(&p, "\n")) != NULL)
			if (strncmp(line, "--- table(", 10) == 0) {
				line += 10;
				line[strcspn(line, ")")] = '\0';
				ucl_array_append(arr, ucl_object_fromstring(
				    line));
			}
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

	/* What is kept: its rules, and its lines that are not rules. */
	kept = ucl_object_typed_new(UCL_ARRAY);
	other = ucl_object_typed_new(UCL_ARRAY);
	pthread_mutex_lock(&file_lock);
	text = file_read(w, &len);
	pthread_mutex_unlock(&file_lock);
	p = text;
	while (p != NULL && (line = strsep(&p, "\n")) != NULL) {
		line += strspn(line, " \t");
		if (line[0] == '\0' || line[0] == '#')
			continue;
		if (kept_rule(line, &num, &rest)) {
			o = ucl_object_typed_new(UCL_OBJECT);
			ucl_object_insert_key(o, ucl_object_fromint(num), "num",
			    0, false);
			put(o, "text", rest);
			ucl_array_append(kept, o);
		} else
			ucl_array_append(other, ucl_object_fromstring(line));
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

/* The kept rules read, or put in place: as fstab is. */
int
do_ipfw_rules(struct work *w, const struct arc_ipfw_rules_req *rq,
    struct arc_ipfw_rules_rsp *rsp)
{
	const char	*sha, *bad, *e;
	char		*old, *copy, *p, *line;
	size_t		 oldlen, len;
	int		 step, n;

	rsp->has_ok = true;
	rsp->ok = false;
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
	/* The sets are the agent's to swap: a line does not name one. */
	copy = wstrdup(w, rq->conf_text);
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
	if ((bad = file_wrong(w, rq->conf_text, len)) != NULL) {
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
	if (file_write(w, rq->conf_text, len, &e) != 0) {
		rsp->error = e;
		step_end(w, step, false, "%s", e);
		goto out;
	}
	step_end(w, step, true, "the one before it is kept as %s.arcana-old",
	    opts.ipfw_rules);
	rsp->conf_text = wtext(w, wstrdup(w, rq->conf_text));
	rsp->sha256 = sha_hex(w, rq->conf_text, len);
	rsp->ok = true;
out:
	pthread_mutex_unlock(&file_lock);
	return (0);
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
	} else if (strcmp(verb, "delete") == 0) {
		if (sp->names.n != 1 || !number_ok(sp->names.v[0]))
			return ("name the rule to delete by its number");
		if (!sp->live && !sp->persist)
			return ("say live, persist or both");
		if (sp->safe)
			return ("a rule deleted is not put back by itself: "
			    "apply the kept rules in safe mode instead");
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
	} else
		return ("an ipfw job is add, delete, apply, enable, disable "
		    "or zero");
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
kept_change(struct work *w, long num, const char *rule, const char **errp)
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
	cap = oldlen + (rule != NULL ? strlen(rule) : 0) + 64;
	out = wcalloc(w, cap, 1);
	len = 0;
	done = rule == NULL;
	p = old;
	while (p != NULL && *p != '\0' && (line = strsep(&p, "\n")) != NULL) {
		if (kept_rule(line, &n, &rest)) {
			/* Deleted: every line of the number goes. */
			if (rule == NULL && n == num)
				continue;
			/* Added: before the first of a higher number. */
			if (!done && n > num) {
				len += (size_t)snprintf(out + len, cap - len,
				    "add %05ld %s\n", num, rule);
				done = true;
			}
		}
		len += (size_t)snprintf(out + len, cap - len, "%s\n", line);
	}
	if (!done)
		len += (size_t)snprintf(out + len, cap - len, "add %05ld %s\n",
		    num, rule);
	rc = file_write(w, out, len, errp);
	pthread_mutex_unlock(&file_lock);
	return (rc);
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
	if (strcmp(verb, "add") == 0) {
		if (sp->live) {
			n = 0;
			argv[n++] = (char *)(uintptr_t)opts.ipfw_bin;
			argv[n++] = (char *)(uintptr_t)"-q";
			argv[n++] = (char *)(uintptr_t)"add";
			for (i = 0; i < sp->names.n; i++)
				argv[n++] = (char *)(uintptr_t)sp->names.v[i];
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
			len = 1;
			for (i = 1; i < sp->names.n; i++)
				len += strlen(sp->names.v[i]) + 1;
			rule = wcalloc(w, len, 1);
			for (i = 1; i < sp->names.n; i++) {
				if (i > 1)
					strlcat(rule, " ", len);
				strlcat(rule, sp->names.v[i], len);
			}
			if (kept_change(w, strtol(sp->names.v[0], NULL, 10),
			    rule, errp) != 0)
				return (-1);
		}
		return (0);
	}
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
