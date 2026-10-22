/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * The kernel's state, sysctl(8).  What it is comes from the kernel
 * itself, sysctl(3), walked as sysctl -a walks it: every name with its
 * value, whether it can be set, and what it is said to be.  One is set
 * with sysctl(8), which knows every kind of value, and kept in
 * sysctl.conf(5), where the line that set it before is replaced.
 */

#include <sys/param.h>
#include <sys/sysctl.h>

#include <ctype.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ucl.h>
#include <unistd.h>

#include "agent.h"

#define	SYSCTL_MAX	4000	/* values in one reply, at most */
#define	SYSCTL_VALUE	1024	/* of one value, and no more is shown */
#define	SYSCTL_CONF_MAX	(256 * 1024)

static pthread_mutex_t	conf_lock = PTHREAD_MUTEX_INITIALIZER;

/* A name as sysctl(8) takes one: letters, digits and . _ - %. */
bool
sysctl_name_ok(const char *name)
{
	size_t	i;

	if (name == NULL || !isalnum((unsigned char)name[0]) ||
	    strlen(name) > 200)
		return (false);
	for (i = 0; name[i] != '\0'; i++)
		if (!isalnum((unsigned char)name[i]) && strchr("._-%",
		    name[i]) == NULL)
			return (false);
	return (true);
}

/* A value: one line, of what can be seen. */
bool
sysctl_value_ok(const char *value)
{
	size_t	i;

	if (value == NULL || strlen(value) > SYSCTL_VALUE)
		return (false);
	for (i = 0; value[i] != '\0'; i++)
		if ((unsigned char)value[i] < 0x20 || value[i] == 0x7f)
			return (false);
	return (true);
}

static void
put(ucl_object_t *o, const char *key, const char *v)
{

	ucl_object_insert_key(o, ucl_object_fromstring(v), key, 0, false);
}

/* The numbers of a value, one after another, as sysctl(8) prints them. */
static const char *
numbers(struct work *w, u_int type, const unsigned char *p, size_t len)
{
	char	*out;
	size_t	 sz, off, cap, n;

	switch (type) {
	case CTLTYPE_S8:
	case CTLTYPE_U8:
		sz = 1;
		break;
	case CTLTYPE_S16:
	case CTLTYPE_U16:
		sz = 2;
		break;
	case CTLTYPE_INT:
	case CTLTYPE_UINT:
	case CTLTYPE_S32:
	case CTLTYPE_U32:
		sz = 4;
		break;
	case CTLTYPE_LONG:
	case CTLTYPE_ULONG:
		sz = sizeof(long);
		break;
	default:
		sz = 8;
		break;
	}
	cap = (len / sz + 1) * 22;
	out = wcalloc(w, cap, 1);
	for (off = 0, n = 0; off + sz <= len && n + 22 < cap; off += sz) {
		int64_t		s = 0;
		uint64_t	u = 0;

		switch (type) {
		case CTLTYPE_S8:
			s = *(const int8_t *)(p + off);
			break;
		case CTLTYPE_U8:
			u = *(const uint8_t *)(p + off);
			break;
		case CTLTYPE_S16:
			memcpy(&s, p + off, 2);
			s = (int16_t)s;
			break;
		case CTLTYPE_U16:
			memcpy(&u, p + off, 2);
			u = (uint16_t)u;
			break;
		case CTLTYPE_INT:
		case CTLTYPE_S32: {
			int32_t	v;

			memcpy(&v, p + off, 4);
			s = v;
			break;
		}
		case CTLTYPE_UINT:
		case CTLTYPE_U32: {
			uint32_t v;

			memcpy(&v, p + off, 4);
			u = v;
			break;
		}
		case CTLTYPE_LONG: {
			long	v;

			memcpy(&v, p + off, sizeof(v));
			s = v;
			break;
		}
		case CTLTYPE_ULONG: {
			u_long	v;

			memcpy(&v, p + off, sizeof(v));
			u = v;
			break;
		}
		case CTLTYPE_S64:
			memcpy(&s, p + off, 8);
			break;
		default:
			memcpy(&u, p + off, 8);
			break;
		}
		switch (type) {
		case CTLTYPE_S8:
		case CTLTYPE_S16:
		case CTLTYPE_INT:
		case CTLTYPE_S32:
		case CTLTYPE_LONG:
		case CTLTYPE_S64:
			n += (size_t)snprintf(out + n, cap - n, "%s%jd",
			    off > 0 ? " " : "", (intmax_t)s);
			break;
		default:
			n += (size_t)snprintf(out + n, cap - n, "%s%ju",
			    off > 0 ? " " : "", (uintmax_t)u);
			break;
		}
	}
	return (out);
}

static const char *
type_name(u_int type)
{

	switch (type) {
	case CTLTYPE_STRING:
		return ("string");
	case CTLTYPE_OPAQUE:
		return ("opaque");
	case CTLTYPE_NODE:
		return ("node");
	case CTLTYPE_S8:
	case CTLTYPE_S16:
	case CTLTYPE_INT:
	case CTLTYPE_S32:
	case CTLTYPE_LONG:
	case CTLTYPE_S64:
		return ("integer");
	default:
		return ("unsigned");
	}
}

/* What sysctl.conf sets at boot: {"name","value"} of each line. */
static ucl_object_t *
kept(struct work *w)
{
	ucl_object_t	*arr, *o;
	char		*text, *p, *line, *eq, *end;
	FILE		*fp;
	size_t		 n;

	arr = ucl_object_typed_new(UCL_ARRAY);
	pthread_mutex_lock(&conf_lock);
	fp = fopen(opts.sysctl_conf, "re");
	text = NULL;
	if (fp != NULL) {
		text = wcalloc(w, SYSCTL_CONF_MAX + 2, 1);
		n = fread(text, 1, SYSCTL_CONF_MAX, fp);
		text[n] = '\0';
		fclose(fp);
	}
	pthread_mutex_unlock(&conf_lock);
	p = text;
	while (p != NULL && (line = strsep(&p, "\n")) != NULL) {
		line += strspn(line, " \t");
		if (line[0] == '#' || (eq = strchr(line, '=')) == NULL)
			continue;
		*eq++ = '\0';
		line[strcspn(line, " \t")] = '\0';
		eq += strspn(eq, " \t");
		if ((end = strchr(eq, '#')) != NULL)
			*end = '\0';
		for (end = eq + strlen(eq); end > eq && (end[-1] == ' ' ||
		    end[-1] == '\t'); end--)
			end[-1] = '\0';
		n = strlen(eq);
		if (n >= 2 && eq[0] == '"' && eq[n - 1] == '"') {
			eq[n - 1] = '\0';
			eq++;
		}
		if (!sysctl_name_ok(line))
			continue;
		o = ucl_object_typed_new(UCL_OBJECT);
		put(o, "name", line);
		put(o, "value", eq);
		ucl_array_append(arr, o);
	}
	return (arr);
}

/*
 * One value, as {"name","value","type","rw","tun","descr"}: NULL for
 * what is a node, is not a number or text, or cannot be read.  oid has
 * two free places before the name's own numbers.
 */
static ucl_object_t *
one(struct work *w, int *oid, size_t nlen, const char *name,
    unsigned char *val)
{
	ucl_object_t	*o;
	char		 descr[512], fmtbuf[128];
	size_t		 len;
	u_int		 kind, type;

	oid[0] = CTL_SYSCTL;
	oid[1] = CTL_SYSCTL_OIDFMT;
	len = sizeof(fmtbuf);
	if (sysctl(oid, (u_int)nlen + 2, fmtbuf, &len, NULL, 0) == -1)
		return (NULL);
	memcpy(&kind, fmtbuf, sizeof(kind));
	type = kind & CTLTYPE;
	if (type == CTLTYPE_NODE || type == CTLTYPE_OPAQUE)
		return (NULL);
	len = SYSCTL_VALUE;
	if (sysctl(oid + 2, (u_int)nlen, val, &len, NULL, 0) == -1 &&
	    errno != ENOMEM)
		return (NULL);
	o = ucl_object_typed_new(UCL_OBJECT);
	put(o, "name", name);
	if (type == CTLTYPE_STRING) {
		val[len < SYSCTL_VALUE ? len : SYSCTL_VALUE] = '\0';
		put(o, "value", wtext(w, (char *)val));
	} else
		put(o, "value", numbers(w, type, val, len));
	put(o, "type", type_name(type));
	ucl_object_insert_key(o, ucl_object_frombool((kind & CTLFLAG_WR) !=
	    0), "rw", 0, false);
	if ((kind & CTLFLAG_TUN) != 0)
		ucl_object_insert_key(o, ucl_object_frombool(true), "tun", 0,
		    false);
	oid[1] = CTL_SYSCTL_OIDDESCR;
	len = sizeof(descr) - 1;
	if (sysctl(oid, (u_int)nlen + 2, descr, &len, NULL, 0) == 0 && len >
	    1) {
		descr[len] = '\0';
		put(o, "descr", wtext(w, descr));
	}
	return (o);
}

/*
 * {"values":[...],"kept":[...]}: the names that begin with prefix, or
 * all of them.  A name the kernel leaves out of its list (an old name
 * for another, say) is still found when it is asked for by itself.
 */
int
do_sysctl(struct work *w, const char *prefix, struct arc_sysctl_rsp *rsp)
{
	ucl_object_t	*top, *vals, *o;
	unsigned char	*json, *val;
	char		 name[256];
	int		 oid[CTL_MAXNAME + 2], next[CTL_MAXNAME + 2];
	size_t		 len, nlen, plen, n, total;
	int		 step;

	rsp->has_ok = true;
	rsp->ok = false;
	if (prefix != NULL && prefix[0] != '\0' && !sysctl_name_ok(prefix)) {
		rsp->error = "a sysctl is named with letters, digits and "
		    ". _ - %";
		return (0);
	}
	plen = prefix != NULL ? strlen(prefix) : 0;
	top = ucl_object_typed_new(UCL_OBJECT);
	vals = ucl_object_typed_new(UCL_ARRAY);
	step = step_begin(w, ARC_STEP_KIND_LIB, "sysctl(3)", plen > 0 ?
	    "the kernel's state under %s" : "the kernel's state%s", plen > 0 ?
	    prefix : "");
	val = wcalloc(w, SYSCTL_VALUE + 1, 1);
	total = n = 0;
	/* From the first: {0, 2} and a name give the name after it. */
	next[0] = CTL_SYSCTL;
	next[1] = CTL_SYSCTL_NEXT;
	next[2] = CTL_KERN;
	nlen = 1;
	for (;;) {
		len = sizeof(oid) - 2 * sizeof(int);
		if (sysctl(next, (u_int)nlen + 2, oid + 2, &len, NULL, 0) ==
		    -1)
			break;
		nlen = len / sizeof(int);
		memcpy(next + 2, oid + 2, len);
		oid[0] = CTL_SYSCTL;
		oid[1] = CTL_SYSCTL_NAME;
		len = sizeof(name);
		if (sysctl(oid, (u_int)nlen + 2, name, &len, NULL, 0) == -1)
			continue;
		if (plen > 0 && strncmp(name, prefix, plen) != 0)
			continue;
		/* Counted beyond what is sent, but not read. */
		if (n == SYSCTL_MAX) {
			total++;
			continue;
		}
		if ((o = one(w, oid, nlen, name, val)) == NULL)
			continue;
		total++;
		n++;
		ucl_array_append(vals, o);
	}
	if (n == 0 && plen > 0) {
		nlen = CTL_MAXNAME;
		if (sysctlnametomib(prefix, oid + 2, &nlen) == 0 && (o = one(w,
		    oid, nlen, prefix, val)) != NULL) {
			total = n = 1;
			ucl_array_append(vals, o);
		}
	}
	step_end(w, step, true, NULL);
	ucl_object_insert_key(top, vals, "values", 0, false);
	ucl_object_insert_key(top, kept(w), "kept", 0, false);
	json = ucl_object_emit(top, UCL_EMIT_JSON_COMPACT);
	ucl_object_unref(top);
	if (json == NULL || strlen((char *)json) > ARC_MAX_JSON) {
		free(json);
		rsp->error = "more of the kernel's state than a reply "
		    "carries: name where in it to begin";
		return (0);
	}
	rsp->json = wtext(w, wadopt(w, json));
	rsp->has_total = true;
	rsp->total = total;
	rsp->truncated = total > n;
	rsp->ok = true;
	return (0);
}

/*
 * sysctl.conf's text, the host's or the jail's own beneath its root (its
 * rc reads it as it starts), NUL-ended, into *np; NULL with *errp set
 * when it cannot be read.  An absent file is empty.  Under conf_lock.
 */
static char *
sysctl_conf_text(struct work *w, size_t *np, const char **errp)
{
	char	*text;
	FILE	*fp;
	size_t	 n;

	text = wcalloc(w, SYSCTL_CONF_MAX + 1, 1);
	n = 0;
	if (w->jail != NULL) {
		char	*j;
		size_t	 jl;

		if ((j = scope_slurp(w, "/etc/sysctl.conf", &jl)) != NULL) {
			if (jl > SYSCTL_CONF_MAX) {
				*errp = wfmt(w, "%s's /etc/sysctl.conf is larger "
				    "than is edited from here", w->jail);
				return (NULL);
			}
			memcpy(text, j, jl);
			n = jl;
		}
	} else if ((fp = fopen(opts.sysctl_conf, "re")) != NULL) {
		n = fread(text, 1, SYSCTL_CONF_MAX + 1, fp);
		if (n > SYSCTL_CONF_MAX) {
			fclose(fp);
			*errp = wfmt(w, "%s is larger than is edited from "
			    "here", opts.sysctl_conf);
			return (NULL);
		}
		fclose(fp);
	} else if (errno != ENOENT) {
		*errp = wfmt(w, "%s: %s", opts.sysctl_conf, strerror(errno));
		return (NULL);
	}
	text[n] = '\0';
	*np = n;
	return (text);
}

/* Is this line of sysctl.conf the one that sets name?  Then the value. */
static const char *
conf_line_sets(const char *line, const char *name, size_t nl)
{
	const char	*s;

	s = line + strspn(line, " \t");
	if (strncmp(s, name, nl) != 0 || (s[nl] != '=' && s[nl] != ' ' &&
	    s[nl] != '\t') || s[nl + strspn(s + nl, " \t")] != '=')
		return (NULL);
	s += nl + strspn(s + nl, " \t") + 1;
	return (s + strspn(s, " \t"));
}

/*
 * The value sysctl.conf sets name to, as written (quotes and a trailing
 * comment taken off), in w's pool; NULL when no line sets it, or the
 * file cannot be read.
 */
const char *
sysctl_conf_get(struct work *w, const char *name)
{
	const char	*e, *v, *found;
	char		*text, *p, *line, *out;
	size_t		 n, nl, vl;

	pthread_mutex_lock(&conf_lock);
	e = NULL;
	found = NULL;
	if ((text = sysctl_conf_text(w, &n, &e)) != NULL) {
		nl = strlen(name);
		p = text;
		while (p != NULL && *p != '\0' && (line = strsep(&p, "\n")) !=
		    NULL)
			if ((v = conf_line_sets(line, name, nl)) != NULL) {
				found = v;
				break;
			}
	}
	pthread_mutex_unlock(&conf_lock);
	if (found == NULL)
		return (NULL);
	out = wstrdup(w, found);
	if (out[0] == '"') {
		memmove(out, out + 1, strlen(out));
		if ((p = strchr(out, '"')) != NULL)
			*p = '\0';
	} else if ((p = strchr(out, '#')) != NULL)
		*p = '\0';
	vl = strlen(out);
	while (vl > 0 && (out[vl - 1] == ' ' || out[vl - 1] == '\t'))
		out[--vl] = '\0';
	return (out);
}

/*
 * name=value in sysctl.conf, in place of the line that set the name
 * before, or as a new last line; with no value, the line goes.  The file
 * is written beside itself and moved into its place.
 */
static int
conf_set(struct work *w, const char *name, const char *value,
    const char **errp)
{
	char	*text, *out, *p, *line, *tmp;
	size_t	 n, cap, len, nl;
	bool	 done, quote;
	int	 fd, rc;

	rc = -1;
	pthread_mutex_lock(&conf_lock);
	if ((text = sysctl_conf_text(w, &n, errp)) == NULL)
		goto out;
	nl = strlen(name);
	quote = value != NULL && strpbrk(value, " \t#") != NULL;
	cap = n + nl + (value != NULL ? strlen(value) : 0) + 16;
	out = wcalloc(w, cap, 1);
	len = 0;
	done = false;
	p = text;
	while (p != NULL && *p != '\0' && (line = strsep(&p, "\n")) != NULL) {
		if (conf_line_sets(line, name, nl) != NULL) {
			/* Once: a second line for the name goes. */
			if (!done && value != NULL)
				len += (size_t)snprintf(out + len, cap - len,
				    "%s=%s%s%s\n", name, quote ? "\"" : "",
				    value, quote ? "\"" : "");
			done = true;
			continue;
		}
		len += (size_t)snprintf(out + len, cap - len, "%s\n", line);
	}
	if (!done && value != NULL)
		len += (size_t)snprintf(out + len, cap - len, "%s=%s%s%s\n",
		    name, quote ? "\"" : "", value, quote ? "\"" : "");
	if (w->jail != NULL) {
		if (scope_replace(w, "/etc/sysctl.conf", out, len, 0644, NULL) !=
		    0) {
			*errp = wfmt(w, "%s's /etc/sysctl.conf: %s", w->jail,
			    strerror(errno));
			goto out;
		}
		rc = 0;
		goto out;
	}
	tmp = wfmt(w, "%s.arcana-new", opts.sysctl_conf);
	if ((fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644)) ==
	    -1 || write(fd, out, len) != (ssize_t)len || fsync(fd) == -1) {
		*errp = wfmt(w, "%s: %s", tmp, strerror(errno));
		if (fd != -1) {
			close(fd);
			(void)unlink(tmp);
		}
		goto out;
	}
	close(fd);
	if (rename(tmp, opts.sysctl_conf) == -1) {
		*errp = wfmt(w, "%s: %s", opts.sysctl_conf, strerror(errno));
		(void)unlink(tmp);
		goto out;
	}
	rc = 0;
out:
	pthread_mutex_unlock(&conf_lock);
	return (rc);
}

/*
 * {"values":[{"name","value"}...],"kept":[]}: a vnet jail's, under
 * prefix, as its own sysctl(8) prints them (w is in the jail's scope,
 * so that sysctl runs there): what its network has is its own.
 */
int
do_sysctl_jail(struct work *w, const char *prefix, struct arc_sysctl_rsp *rsp)
{
	struct execres	 res;
	ucl_object_t	*top, *vals, *o;
	unsigned char	*json;
	char		*argv[5], *text, *line, *eq;
	size_t		 n;

	rsp->has_ok = true;
	rsp->ok = false;
	if (!sysctl_name_ok(prefix)) {
		rsp->error = "a sysctl is named with letters, digits and "
		    ". _ - %";
		return (0);
	}
	argv[0] = (char *)(uintptr_t)opts.sysctl_bin;
	argv[1] = (char *)(uintptr_t)"-e";
	argv[2] = (char *)(uintptr_t)"--";
	argv[3] = (char *)(uintptr_t)prefix;
	argv[4] = NULL;
	/* One it lacks is none (sysctl -e exits 1 then): an empty list, as
	 * the host's has it.  Not run, or killed, is an error. */
	if (run_exec(w, argv, &res) != 0 && (res.status < 0 || res.status >=
	    128)) {
		rsp->error = wtext(w, exec_error(w, &res, "sysctl"));
		return (0);
	}
	top = ucl_object_typed_new(UCL_OBJECT);
	vals = ucl_object_typed_new(UCL_ARRAY);
	text = wcalloc(w, res.outlen + 1, 1);
	if (res.out != NULL)
		memcpy(text, res.out, res.outlen);
	n = 0;
	while ((line = strsep(&text, "\n")) != NULL && n < SYSCTL_MAX) {
		if ((eq = strchr(line, '=')) == NULL || eq == line)
			continue;
		*eq = '\0';
		o = ucl_object_typed_new(UCL_OBJECT);
		ucl_object_insert_key(o, ucl_object_fromstring(line), "name", 0,
		    true);
		ucl_object_insert_key(o, ucl_object_fromstring(eq + 1), "value",
		    0, true);
		ucl_array_append(vals, o);
		n++;
	}
	ucl_object_insert_key(top, vals, "values", 0, false);
	ucl_object_insert_key(top, ucl_object_typed_new(UCL_ARRAY), "kept", 0,
	    false);
	json = ucl_object_emit(top, UCL_EMIT_JSON_COMPACT);
	ucl_object_unref(top);
	if (json == NULL || strlen((char *)json) > ARC_MAX_JSON) {
		free(json);
		rsp->error = "more of the jail's state than a reply carries: "
		    "name where in it to begin";
		return (0);
	}
	rsp->json = wstrdup(w, (char *)json);
	free(json);
	rsp->ok = true;
	return (0);
}

/* Set one, and with persist keep it for the next boot. */
int
do_sysctl_set(struct work *w, const char *name, const char *value,
    bool persist, const char **errp)
{
	struct execres	 res;
	char		*argv[3];
	int		 step;

	if (!sysctl_name_ok(name)) {
		*errp = "a sysctl is named with letters, digits and . _ - %";
		return (-1);
	}
	if (!sysctl_value_ok(value)) {
		*errp = "a sysctl's value is one line";
		return (-1);
	}
	argv[0] = (char *)(uintptr_t)opts.sysctl_bin;
	argv[1] = wfmt(w, "%s=%s", name, value);
	argv[2] = NULL;
	if (run_exec(w, argv, &res) != 0) {
		*errp = wtext(w, exec_error(w, &res, "sysctl"));
		return (-1);
	}
	if (!persist)
		return (0);
	step = step_begin(w, ARC_STEP_KIND_FILE, w->jail != NULL ? wfmt(w,
	    "%s's /etc/sysctl.conf", w->jail) : opts.sysctl_conf, "%s=%s", name,
	    value);
	if (conf_set(w, name, value, errp) != 0) {
		step_end(w, step, false, "%s", *errp);
		return (-1);
	}
	step_end(w, step, true, NULL);
	return (0);
}

/*
 * sysctl.conf as it was before a safe change: the line that set name
 * back, or none.  A step of its own, so the trace says what was put
 * back.
 */
int
sysctl_conf_restore(struct work *w, const char *name, const char *value,
    const char **errp)
{
	int	step;

	step = step_begin(w, ARC_STEP_KIND_FILE, w->jail != NULL ? wfmt(w,
	    "%s's /etc/sysctl.conf", w->jail) : opts.sysctl_conf, value != NULL ?
	    "%s=%s again" : "%s no longer set%s", name, value != NULL ? value :
	    "");
	if (conf_set(w, name, value, errp) != 0) {
		step_end(w, step, false, "%s", *errp);
		return (-1);
	}
	step_end(w, step, true, NULL);
	return (0);
}

/*
 * One sysctl's value as the kernel has it now (a vnet jail's, when w is
 * in its scope), in w's pool; NULL with *errp set when there is no such
 * sysctl, or sysctl(8) could not be run.
 */
const char *
sysctl_get(struct work *w, const char *name, const char **errp)
{
	struct execres	 res;
	char		*argv[4], *v;
	size_t		 n;

	if (!sysctl_name_ok(name)) {
		*errp = "a sysctl is named with letters, digits and . _ - %";
		return (NULL);
	}
	argv[0] = (char *)(uintptr_t)opts.sysctl_bin;
	argv[1] = (char *)(uintptr_t)"-n";
	argv[2] = (char *)(uintptr_t)name;
	argv[3] = NULL;
	if (run_exec(w, argv, &res) != 0) {
		*errp = wtext(w, exec_error(w, &res, "sysctl"));
		return (NULL);
	}
	n = res.outlen;
	v = wcalloc(w, n + 1, 1);
	if (res.out != NULL)
		memcpy(v, res.out, n);
	while (n > 0 && (v[n - 1] == '\n' || v[n - 1] == '\r'))
		v[--n] = '\0';
	if (!sysctl_value_ok(v)) {
		*errp = wfmt(w, "%s's value is not one line: it cannot be put "
		    "back", name);
		return (NULL);
	}
	return (v);
}

/*
 * The tree in parts, for a dump: where the walk is, kept between the
 * parts, which are asked for one at a time as the client takes them.
 */
#define	SYSCTL_PART	120	/* values in one part */

struct walk {
	int	next[CTL_MAXNAME + 2];
	size_t	nlen;
	size_t	sent;
	bool	begun;
};

/*
 * The next part into *jsonp, an array, to be freed; true while there
 * may be more.  st->priv is the walk, made at the first part.
 */
bool
sysctl_part(struct cbl_dump_state *st, const char *prefix, char **jsonp,
    uint64_t *sentp)
{
	struct work	 w;
	struct walk	*k;
	ucl_object_t	*vals, *o;
	unsigned char	*val;
	char		 name[256];
	int		 oid[CTL_MAXNAME + 2];
	size_t		 len, plen, n;
	bool		 more;

	if ((k = st->priv) == NULL) {
		if ((k = calloc(1, sizeof(*k))) == NULL)
			err(1, "calloc");
		k->next[0] = CTL_SYSCTL;
		k->next[1] = CTL_SYSCTL_NEXT;
		k->next[2] = CTL_KERN;
		k->nlen = 1;
		st->priv = k;
		st->priv_free = free;
	}
	plen = prefix != NULL ? strlen(prefix) : 0;
	work_init(&w);
	vals = ucl_object_typed_new(UCL_ARRAY);
	val = wcalloc(&w, SYSCTL_VALUE + 1, 1);
	more = true;
	for (n = 0; n < SYSCTL_PART; ) {
		len = sizeof(oid) - 2 * sizeof(int);
		if (sysctl(k->next, (u_int)k->nlen + 2, oid + 2, &len, NULL,
		    0) == -1) {
			more = false;
			break;
		}
		k->nlen = len / sizeof(int);
		memcpy(k->next + 2, oid + 2, len);
		oid[0] = CTL_SYSCTL;
		oid[1] = CTL_SYSCTL_NAME;
		len = sizeof(name);
		if (sysctl(oid, (u_int)k->nlen + 2, name, &len, NULL, 0) == -1)
			continue;
		if (plen > 0 && strncmp(name, prefix, plen) != 0)
			continue;
		if ((o = one(&w, oid, k->nlen, name, val)) == NULL)
			continue;
		ucl_array_append(vals, o);
		n++;
	}
	/* A name the kernel leaves out of its list, asked for by itself. */
	if (!more && k->sent == 0 && n == 0 && plen > 0) {
		size_t	nlen = CTL_MAXNAME;

		if (sysctlnametomib(prefix, oid + 2, &nlen) == 0 && (o = one(
		    &w, oid, nlen, prefix, val)) != NULL) {
			ucl_array_append(vals, o);
			n = 1;
		}
	}
	k->sent += n;
	*sentp = k->sent;
	*jsonp = (char *)ucl_object_emit(vals, UCL_EMIT_JSON_COMPACT);
	ucl_object_unref(vals);
	work_free(&w);
	return (more);
}

