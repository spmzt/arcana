/*
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Luxuria: OpenSMTPD (mail/opensmtpd), a plugin the host has installed.
 * The read (smtpd operation) says what smtpctl(8) says: its status,
 * counters and queue, with smtpd.conf, the form it was rendered from,
 * and the tables.  A job (kind smtpd) renders smtpd.conf from the form
 * the console sends (so what runs is what was checked, by smtpd -n
 * here), writes a table (a password hashed by OpenSMTPD's encrypt,
 * never kept clear), or does what smtpctl does to the queue.
 */

#include <sys/param.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <ucl.h>

#include "agent.h"

#define	SPEC_MAX	65536
#define	TABLE_MAX	1048576
#define	TABLES		"aliases", "virtuals", "domains", "senders", \
			"credentials", "secrets"

static const char *const tables[] = { TABLES, NULL };
static const char *const protos[] = { "smtp", "smtp+tls", "smtp+notls",
    "smtps", "lmtp", NULL };

static const char *
smtpd_bin(struct work *w)
{
	const char	*p;

	return ((p = tool(w, "smtpd")) != NULL ? p : opts.smtpd_bin);
}

static const char *
smtpctl_bin(struct work *w)
{
	const char	*p;

	return ((p = tool(w, "smtpctl")) != NULL ? p : opts.smtpctl_bin);
}

static const char *
encrypt_bin(struct work *w)
{
	const char	*p;

	return ((p = tool(w, "encrypt")) != NULL ? p :
	    "/usr/local/libexec/opensmtpd/encrypt");
}

/* Is a file there, in the scope (the host's, or the jail's root)? */
static bool
scoped_x(struct work *w, const char *path, int mode)
{
	const char	*base;
	int		 dfd, rc;

	if ((dfd = scope_open_dir(w, path, &base)) == -1)
		return (false);
	rc = faccessat(dfd, base, mode, AT_EACCESS);
	close(dfd);
	return (rc == 0);
}

/* A directory made in the scope, when it is not there. */
static void
scoped_mkdir(struct work *w, const char *path)
{
	const char	*base;
	int		 dfd;

	if ((dfd = scope_open_dir(w, path, &base)) == -1)
		return;
	(void)mkdirat(dfd, base, 0750);
	close(dfd);
}

/* A table's file, under the directory of the agent's own. */
static const char *
table_path(struct work *w, const char *name)
{

	return (wfmt(w, "%s/%s", opts.smtpd_dir, name));
}

static bool
table_name_ok(const char *s)
{
	size_t	i;

	for (i = 0; s != NULL && tables[i] != NULL; i++)
		if (strcmp(s, tables[i]) == 0)
			return (true);
	return (false);
}

/* Its secrets and its users' passwords: root's alone. */
static bool
table_secret(const char *name)
{

	return (strcmp(name, "credentials") == 0 || strcmp(name, "secrets") ==
	    0);
}

static const char *
sstr(const ucl_object_t *o, const char *k)
{
	const ucl_object_t	*v;

	v = ucl_object_lookup(o, k);
	return (v != NULL && ucl_object_type(v) == UCL_STRING ?
	    ucl_object_tostring(v) : NULL);
}

static bool
sbool(const ucl_object_t *o, const char *k)
{
	const ucl_object_t	*v;

	v = ucl_object_lookup(o, k);
	return (v != NULL && ucl_object_type(v) == UCL_BOOLEAN &&
	    ucl_object_toboolean(v));
}

static bool
word_ok(const char *s, const char *more, size_t max)
{
	size_t	i;

	if (s == NULL || s[0] == '\0' || strlen(s) > max)
		return (false);
	for (i = 0; s[i] != '\0'; i++)
		if (!isalnum((unsigned char)s[i]) && strchr(more, s[i]) == NULL)
			return (false);
	return (true);
}

static bool
domain_ok(const char *s)
{

	return (word_ok(s, ".-", 253) && s[0] != '.' && s[0] != '-' &&
	    s[strlen(s) - 1] != '.' && strstr(s, "..") == NULL);
}

/* What a listener listens on: an interface, localhost, or an address. */
static bool
on_ok(const char *s)
{
	unsigned char	buf[16];

	return (s != NULL && (strcmp(s, "localhost") == 0 || strcmp(s, "all")
	    == 0 || inet_pton(AF_INET, s, buf) == 1 || inet_pton(AF_INET6, s,
	    buf) == 1 || (word_ok(s, "._", 15) && !isdigit((unsigned char)s[0]))));
}

/* A quoted string of smtpd.conf: its own quotes and backslashes escaped. */
static void
quoted(FILE *fp, const char *s)
{

	fputc('"', fp);
	for (; *s != '\0'; s++) {
		if (*s == '"' || *s == '\\')
			fputc('\\', fp);
		fputc(*s, fp);
	}
	fputc('"', fp);
}

/*
 * smtpd.conf from the form: what is defined first (pki, the tables,
 * the filters), the listeners, the actions, the match rules, then the
 * admin's own lines.  NULL and why in *errp when the form is not right.
 */
char *
smtpd_render(struct work *w, const ucl_object_t *in, const char **errp)
{
	static const char *const owned[] = { "listen ", "table ", "pki ",
	    "action ", "match ", "include ", "filter " };
	const ucl_object_t	*l, *e, *rel, *pol, *del;
	ucl_object_iter_t	 it, fit;
	FILE			*b;
	char			*buf, hn[MAXHOSTNAMELEN];
	const char		*v, *p, *kind, *own;
	size_t			 len, i, n;
	bool			 tls, any_auth, has_domains, aliases, virt;

	buf = NULL;
	len = 0;
	if ((b = open_memstream(&buf, &len)) == NULL) {
		*errp = strerror(errno);
		return (NULL);
	}
	if (gethostname(hn, sizeof(hn)) != 0)
		snprintf(hn, sizeof(hn), "this host");
	fprintf(b, "# Written by arcana-agent at %s, from the console's form: "
	    "edited there.\n", hn);
	/* The host's own certificate, Arcana's CA's, when a listener says
	 * pki arcana. */
	tls = false;
	it = NULL;
	while ((l = ucl_object_iterate(ucl_object_lookup(in, "listeners"), &it,
	    true)) != NULL)
		if ((v = sstr(l, "pki")) != NULL && strcmp(v, "arcana") == 0)
			tls = true;
	if (tls) {
		if (w->jail != NULL) {
			*errp = "pki arcana: the host's certificate is not a "
			    "jail's to serve with: name a pki of the own lines";
			goto bad;
		}
		if (tls_files_cert() == NULL) {
			*errp = "pki arcana: this agent runs without a "
			    "certificate (-C): no TLS of Arcana's to listen with";
			goto bad;
		}
		fprintf(b, "pki arcana cert ");
		quoted(b, tls_files_cert());
		fprintf(b, "\npki arcana key ");
		quoted(b, tls_files_key());
		fprintf(b, "\n");
	}
	/* The tables: each a file of the agent's, those that are there. */
	del = ucl_object_lookup(in, "delivery");
	aliases = del != NULL && sbool(del, "aliases");
	virt = del != NULL && sbool(del, "virtual");
	has_domains = ucl_array_size(ucl_object_lookup(in, "domains")) > 0;
	any_auth = false;
	it = NULL;
	while ((l = ucl_object_iterate(ucl_object_lookup(in, "listeners"), &it,
	    true)) != NULL)
		if (sbool(l, "auth"))
			any_auth = true;
	rel = ucl_object_lookup(in, "relay");
	if (aliases)
		fprintf(b, "table aliases file:%s\n", table_path(w, "aliases"));
	if (virt)
		fprintf(b, "table virtuals file:%s\n", table_path(w, "virtuals"));
	if (has_domains)
		fprintf(b, "table domains file:%s\n", table_path(w, "domains"));
	if (any_auth)
		fprintf(b, "table credentials file:%s\n", table_path(w,
		    "credentials"));
	if (rel != NULL && sbool(rel, "auth"))
		fprintf(b, "table secrets file:%s\n", table_path(w, "secrets"));
	/* The filters: the ports' programs by name, and smtpd's own checks. */
	it = NULL;
	while ((e = ucl_object_iterate(ucl_object_lookup(in, "filters"), &it,
	    true)) != NULL) {
		if (ucl_object_type(e) != UCL_OBJECT || !word_ok(sstr(e, "name"),
		    "_-", 32)) {
			*errp = "a filter is named: rspamd, dkimsign, "
			    "senderscore, as the port's program filter-NAME";
			goto bad;
		}
		p = wfmt(w, "/usr/local/libexec/opensmtpd/filter-%s", sstr(e,
		    "name"));
		if (!scoped_x(w, p, X_OK)) {
			*errp = wfmt(w, "filter %s is not installed (%s): pkg "
			    "install opensmtpd-filter-%s", sstr(e, "name"), p,
			    sstr(e, "name"));
			goto bad;
		}
		v = sstr(e, "args");
		if (v != NULL && (strlen(v) > 200 || strpbrk(v, "\"\n") != NULL)) {
			*errp = "a filter's arguments are one line, no quotes";
			goto bad;
		}
		fprintf(b, "filter %s proc-exec ", sstr(e, "name"));
		quoted(b, v != NULL && v[0] != '\0' ? wfmt(w, "%s %s", p, v) : p);
		fprintf(b, "\n");
	}
	pol = ucl_object_lookup(in, "policy");
	if (pol != NULL && sbool(pol, "check_rdns"))
		fprintf(b, "filter check_rdns phase connect match !rdns "
		    "disconnect \"550 no rDNS\"\n");
	if (pol != NULL && sbool(pol, "check_fcrdns"))
		fprintf(b, "filter check_fcrdns phase connect match !fcrdns "
		    "disconnect \"550 no FCrDNS\"\n");
	/* The listeners. */
	n = 0;
	it = NULL;
	while ((l = ucl_object_iterate(ucl_object_lookup(in, "listeners"), &it,
	    true)) != NULL) {
		if (ucl_object_type(l) != UCL_OBJECT || !on_ok(sstr(l, "on"))) {
			*errp = "a listener listens on an interface, localhost, "
			    "all, or an address";
			goto bad;
		}
		if (n++ == 16) {
			*errp = "16 listeners at most";
			goto bad;
		}
		fprintf(b, "listen on %s", sstr(l, "on"));
		if (ucl_object_lookup(l, "port") != NULL) {
			if (ucl_object_type(ucl_object_lookup(l, "port")) !=
			    UCL_INT || ucl_object_toint(ucl_object_lookup(l,
			    "port")) < 1 || ucl_object_toint(ucl_object_lookup(l,
			    "port")) > 65535) {
				*errp = "a listener's port is 1 to 65535";
				goto bad;
			}
			fprintf(b, " port %jd", (intmax_t)ucl_object_toint(
			    ucl_object_lookup(l, "port")));
		}
		v = sstr(l, "tls");
		if (v != NULL && v[0] != '\0' && strcmp(v, "none") != 0) {
			if (strcmp(v, "tls") != 0 && strcmp(v, "tls-require") != 0
			    && strcmp(v, "smtps") != 0) {
				*errp = "a listener's tls is none, tls, tls-require "
				    "or smtps";
				goto bad;
			}
			p = sstr(l, "pki");
			if (p == NULL || p[0] == '\0') {
				*errp = "a listener with TLS names its pki: arcana "
				    "(this host's certificate), or one of "
				    "smtpd.conf's own lines";
				goto bad;
			}
			if (strcmp(p, "arcana") != 0 && !word_ok(p, "_-", 32)) {
				*errp = "a pki is a name";
				goto bad;
			}
			fprintf(b, " %s pki %s", v, p);
		}
		if (sbool(l, "auth"))
			fprintf(b, " auth <credentials>");
		fit = NULL;
		i = 0;
		while ((e = ucl_object_iterate(ucl_object_lookup(l, "filters"),
		    &fit, true)) != NULL) {
			if (ucl_object_type(e) != UCL_STRING || !word_ok(
			    ucl_object_tostring(e), "_", 32)) {
				*errp = "a listener's filters are names of the "
				    "filters defined";
				goto bad;
			}
			fprintf(b, "%s%s", i++ == 0 ? " filter { " : ", ",
			    ucl_object_tostring(e));
		}
		if (i > 0)
			fprintf(b, " }");
		if ((v = sstr(l, "hostname")) != NULL && v[0] != '\0') {
			if (!domain_ok(v)) {
				*errp = "a listener's hostname is a domain name";
				goto bad;
			}
			fprintf(b, " hostname %s", v);
		}
		fprintf(b, "\n");
	}
	if (n == 0) {
		*errp = "a listener at least: localhost, for the host's own "
		    "mail";
		goto bad;
	}
	/* Local delivery. */
	kind = del != NULL ? sstr(del, "kind") : NULL;
	if (kind == NULL || kind[0] == '\0')
		kind = "maildir";
	if (strcmp(kind, "maildir") != 0 && strcmp(kind, "mbox") != 0 &&
	    strcmp(kind, "lmtp") != 0) {
		*errp = "delivery is maildir, mbox or lmtp";
		goto bad;
	}
	v = del != NULL ? sstr(del, "path") : NULL;
	if (v != NULL && v[0] != '\0' && (strlen(v) > 200 || strpbrk(v,
	    "\"\n ") != NULL || (strcmp(kind, "lmtp") == 0 ? v[0] != '/' &&
	    strchr(v, ':') == NULL : v[0] != '/' && v[0] != '~'))) {
		*errp = "delivery's path is a directory (maildir), a file (mbox) "
		    "or an LMTP socket or host:port";
		goto bad;
	}
	fprintf(b, "action \"local\" %s", kind);
	if (v != NULL && v[0] != '\0') {
		fputc(' ', b);
		quoted(b, v);
	}
	if (aliases)
		fprintf(b, " alias <aliases>");
	if (virt)
		fprintf(b, " virtual <virtuals>");
	fprintf(b, "\n");
	/* Relay: out by the smart host, or by MX. */
	fprintf(b, "action \"relay\" relay");
	if (rel != NULL && (v = sstr(rel, "host")) != NULL && v[0] != '\0') {
		if (!domain_ok(v) && !on_ok(v)) {
			*errp = "the relay's host is a name or an address";
			goto bad;
		}
		p = sstr(rel, "proto");
		if (p == NULL || p[0] == '\0')
			p = "smtp+tls";
		for (i = 0; protos[i] != NULL && strcmp(protos[i], p) != 0; i++)
			;
		if (protos[i] == NULL) {
			*errp = "the relay's protocol is smtp, smtp+tls, "
			    "smtp+notls, smtps or lmtp";
			goto bad;
		}
		if (ucl_object_lookup(rel, "port") != NULL && (ucl_object_type(
		    ucl_object_lookup(rel, "port")) != UCL_INT ||
		    ucl_object_toint(ucl_object_lookup(rel, "port")) < 1 ||
		    ucl_object_toint(ucl_object_lookup(rel, "port")) > 65535)) {
			*errp = "the relay's port is 1 to 65535";
			goto bad;
		}
		fprintf(b, " host %s://%s%s", p, sbool(rel, "auth") ? "relay@" :
		    "", v);
		if (ucl_object_lookup(rel, "port") != NULL)
			fprintf(b, ":%jd", (intmax_t)ucl_object_toint(
			    ucl_object_lookup(rel, "port")));
		if (sbool(rel, "auth"))
			fprintf(b, " auth <secrets>");
	}
	if (rel != NULL && (v = sstr(rel, "mail_from")) != NULL && v[0] != '\0') {
		if (!word_ok(v, "@.-_+", 253)) {
			*errp = "mail-from is an address, or @domain";
			goto bad;
		}
		fprintf(b, " mail-from ");
		quoted(b, v);
	}
	fprintf(b, "\n");
	/* What goes where. */
	if (has_domains)
		fprintf(b, "match from any for domain <domains> action \"local\"\n");
	fprintf(b, "match for local action \"local\"\n");
	fprintf(b, "match from local for any action \"relay\"\n");
	if (any_auth)
		fprintf(b, "match auth from any for any action \"relay\"\n");
	/* The policy: sizes and times, as smtpd.conf's globals. */
	if (pol != NULL) {
		if ((v = sstr(pol, "max_size")) != NULL && v[0] != '\0') {
			if (!word_ok(v, "", 12) || !isdigit((unsigned char)v[0])) {
				*errp = "the largest message is a size: 35M, 10240K";
				goto bad;
			}
			fprintf(b, "smtp max-message-size %s\n", v);
		}
		if (sbool(pol, "queue_compression"))
			fprintf(b, "queue compression\n");
		if ((v = sstr(pol, "bounce_warn")) != NULL && v[0] != '\0') {
			if (!word_ok(v, ",", 40) || !isdigit((unsigned char)v[0])) {
				*errp = "bounce warnings are times: 4h, or 1h,4h,1d";
				goto bad;
			}
			fprintf(b, "bounce warn-interval %s\n", v);
		}
		if (ucl_object_lookup(pol, "max_rcpt") != NULL) {
			if (ucl_object_type(ucl_object_lookup(pol, "max_rcpt")) !=
			    UCL_INT || ucl_object_toint(ucl_object_lookup(pol,
			    "max_rcpt")) < 1) {
				*errp = "recipients per message is a number";
				goto bad;
			}
			fprintf(b, "smtp max-rcpt %jd\n", (intmax_t)
			    ucl_object_toint(ucl_object_lookup(pol, "max_rcpt")));
		}
	}
	/* The admin's own lines, last: not what the form owns. */
	own = sstr(in, "own");
	if (own != NULL && strlen(own) > 16384) {
		*errp = "the own lines are 16 KB at most";
		goto bad;
	}
	for (p = own; p != NULL && *p != '\0'; p = strchr(p, '\n') != NULL ?
	    strchr(p, '\n') + 1 : NULL)
		for (i = 0; i < nitems(owned); i++)
			if (strncmp(p, owned[i], strlen(owned[i])) == 0) {
				*errp = wfmt(w, "the own lines may not %.*s, which "
				    "the form does", (int)strlen(owned[i]) - 1,
				    owned[i]);
				goto bad;
			}
	if (own != NULL && own[strspn(own, " \t\r\n")] != '\0')
		fprintf(b, "# The admin's own:\n%s%s", own, own[strlen(own) -
		    1] != '\n' ? "\n" : "");
	if (fclose(b) != 0 || buf == NULL) {
		free(buf);
		*errp = "the configuration could not be written";
		return (NULL);
	}
	return (wadopt(w, buf));
bad:
	fclose(b);
	free(buf);
	return (NULL);
}

/* The form kept beside the file, for the page to fill itself from. */
static const char *
spec_path(struct work *w)
{

	return (wfmt(w, "%s/smtpd.json", opts.smtpd_dir));
}

/* smtpctl's answer, its lines; NULL when it does not run. */
static char *
ctl(struct work *w, const char *a, const char *b, const char *c)
{
	struct execres	 res;
	char		*argv[5];

	argv[0] = (char *)(uintptr_t)smtpctl_bin(w);
	argv[1] = (char *)(uintptr_t)a;
	argv[2] = (char *)(uintptr_t)b;
	argv[3] = (char *)(uintptr_t)c;
	argv[4] = NULL;
	if (run_exec(w, argv, &res) != 0 || res.out == NULL)
		return (NULL);
	return (wstrndup(w, res.out, res.outlen));
}

/* "key=value" lines into an object of numbers. */
static ucl_object_t *
stats_json(struct work *w, const char *text)
{
	ucl_object_t	*o;
	char		*copy, *line, *eq;

	o = ucl_object_typed_new(UCL_OBJECT);
	copy = wstrdup(w, text != NULL ? text : "");
	while ((line = strsep(&copy, "\n")) != NULL) {
		if ((eq = strchr(line, '=')) == NULL)
			continue;
		*eq++ = '\0';
		if (eq[strspn(eq, "0123456789")] == '\0' && eq[0] != '\0')
			ucl_object_insert_key(o, ucl_object_fromint(
			    strtoll(eq, NULL, 10)), line, 0, true);
		else
			ucl_object_insert_key(o, ucl_object_fromstring(eq), line,
			    0, true);
	}
	return (o);
}

/* "MDA running" lines into {"mda": "running"}. */
static ucl_object_t *
status_json(struct work *w, const char *text)
{
	ucl_object_t	*o;
	char		*copy, *line, *sp, k[8];
	size_t		 i;

	o = ucl_object_typed_new(UCL_OBJECT);
	copy = wstrdup(w, text != NULL ? text : "");
	while ((line = strsep(&copy, "\n")) != NULL) {
		if ((sp = strchr(line, ' ')) == NULL || sp - line >= (long)sizeof(k))
			continue;
		for (i = 0; line + i < sp; i++)
			k[i] = (char)tolower((unsigned char)line[i]);
		k[i] = '\0';
		ucl_object_insert_key(o, ucl_object_fromstring(sp + 1), k, 0,
		    true);
	}
	return (o);
}

/*
 * The queue as smtpctl show queue prints it, a line an envelope, the
 * fields by |: evpid, source, type, flags, sender, recipient,
 * destination, created, expires, retries, last try, state, next try,
 * and the error, when there was one.
 */
static ucl_object_t *
queue_json(struct work *w, const char *text, int64_t *np)
{
	static const char *const keys[] = { "evpid", "source", "type", "flags",
	    "from", "to", "dest", "created", "expires", "retries", "lasttry",
	    "state", "next", "error" };
	ucl_object_t	*arr, *o;
	char		*copy, *line, *f;
	size_t		 i;

	arr = ucl_object_typed_new(UCL_ARRAY);
	copy = wstrdup(w, text != NULL ? text : "");
	*np = 0;
	while ((line = strsep(&copy, "\n")) != NULL) {
		if (line[0] == '\0')
			continue;
		(*np)++;
		if (*np > 500)
			continue;
		o = ucl_object_typed_new(UCL_OBJECT);
		for (i = 0; i < nitems(keys) && (f = strsep(&line, "|")) != NULL;
		    i++) {
			if (f[0] == '\0')
				continue;
			if (i >= 7 && i <= 10 && f[strspn(f, "-0123456789")] ==
			    '\0')
				ucl_object_insert_key(o, ucl_object_fromint(
				    strtoll(f, NULL, 10)), keys[i], 0, false);
			else if (i == 12 && f[strspn(f, "-0123456789")] == '\0')
				ucl_object_insert_key(o, ucl_object_fromint(
				    strtoll(f, NULL, 10)), keys[i], 0, false);
			else
				ucl_object_insert_key(o, ucl_object_fromstring(f),
				    keys[i], 0, false);
		}
		ucl_array_append(arr, o);
	}
	return (arr);
}

/* A table's text; the secret ones as their first words alone. */
static ucl_object_t *
table_json(struct work *w, const char *name)
{
	ucl_object_t	*arr;
	char		*text, *copy, *line;
	size_t		 len;

	if ((text = scope_slurp(w, table_path(w, name), &len)) == NULL)
		return (NULL);
	if (!table_secret(name))
		return (ucl_object_fromstring(text));
	arr = ucl_object_typed_new(UCL_ARRAY);
	copy = wstrdup(w, text);
	while ((line = strsep(&copy, "\n")) != NULL) {
		line += strspn(line, " \t");
		if (line[0] == '\0' || line[0] == '#')
			continue;
		line[strcspn(line, " \t")] = '\0';
		ucl_array_append(arr, ucl_object_fromstring(line));
	}
	return (arr);
}

void
do_smtpd(struct work *w, struct arc_smtpd_rsp *rsp)
{
	ucl_object_t	*top, *o, *arr;
	struct ucl_parser *p;
	struct dirent	*de;
	DIR		*d;
	char		*json, *text, *line;
	size_t		 len, i;
	int64_t		 n;
	int		 dfd;
	bool		 enabled, running, installed;

	rsp->has_ok = true;
	rsp->ok = false;
	top = ucl_object_typed_new(UCL_OBJECT);
	installed = scoped_x(w, smtpd_bin(w), X_OK);
	ucl_object_insert_key(top, ucl_object_frombool(installed), "installed",
	    0, false);
	enabled = running = false;
	service_state(w, "smtpd", &enabled, &running);
	ucl_object_insert_key(top, ucl_object_frombool(enabled), "enabled", 0,
	    false);
	ucl_object_insert_key(top, ucl_object_frombool(running), "running", 0,
	    false);
	if (installed && running) {
		ucl_object_insert_key(top, status_json(w, ctl(w, "show", "status",
		    NULL)), "status", 0, false);
		ucl_object_insert_key(top, stats_json(w, ctl(w, "show", "stats",
		    NULL)), "stats", 0, false);
		ucl_object_insert_key(top, queue_json(w, ctl(w, "show", "queue",
		    NULL), &n), "queue", 0, false);
		ucl_object_insert_key(top, ucl_object_fromint(n), "queued", 0,
		    false);
	}
	if ((text = scope_slurp(w, opts.smtpd_conf, &len)) != NULL)
		ucl_object_insert_key(top, ucl_object_fromstring(text), "conf", 0,
		    false);
	ucl_object_insert_key(top, ucl_object_fromstring(opts.smtpd_conf),
	    "conf_path", 0, false);
	/* The form it was rendered from, kept beside. */
	if ((text = scope_slurp(w, spec_path(w), &len)) != NULL) {
		p = ucl_parser_new(UCL_PARSER_NO_TIME);
		o = ucl_parser_add_string(p, text, 0) ? ucl_parser_get_object(p) :
		    NULL;
		ucl_parser_free(p);
		if (o != NULL)
			ucl_object_insert_key(top, o, "spec", 0, false);
	}
	o = ucl_object_typed_new(UCL_OBJECT);
	for (i = 0; tables[i] != NULL; i++)
		if (table_json(w, tables[i]) != NULL)
			ucl_object_insert_key(o, table_json(w, tables[i]),
			    tables[i], 0, false);
	ucl_object_insert_key(top, o, "tables", 0, false);
	/* The filters installed, by their ports. */
	arr = ucl_object_typed_new(UCL_ARRAY);
	d = (dfd = scope_dirfd(w, "/usr/local/libexec/opensmtpd")) != -1 ?
	    fdopendir(dfd) : NULL;
	if (d != NULL) {
		while ((de = readdir(d)) != NULL)
			if (strncmp(de->d_name, "filter-", 7) == 0)
				ucl_array_append(arr, ucl_object_fromstring(
				    de->d_name + 7));
		closedir(d);
	}
	ucl_object_insert_key(top, arr, "filters", 0, false);
	/* What sendmail(8) is on this host (mailer.conf(5)). */
	if ((text = scope_slurp(w, "/etc/mail/mailer.conf", &len)) != NULL)
		for (line = text; line != NULL; line = strchr(line, '\n') != NULL
		    ? strchr(line, '\n') + 1 : NULL)
			if (strncmp(line, "sendmail", 8) == 0 && isspace(
			    (unsigned char)line[8])) {
				ucl_object_insert_key(top, ucl_object_fromstring(
				    wstrndup(w, line + 8 + strspn(line + 8, " \t"),
				    strcspn(line + 8 + strspn(line + 8, " \t"),
				    "\n"))), "mailer", 0, false);
				break;
			}
	/* A jail serves with no certificate of the host's. */
	ucl_object_insert_key(top, ucl_object_frombool(w->jail == NULL &&
	    tls_files_cert() != NULL), "pki", 0, false);
	if (w->jail != NULL)
		ucl_object_insert_key(top, ucl_object_fromstring(w->jail), "jail",
		    0, false);
	json = (char *)ucl_object_emit(top, UCL_EMIT_JSON_COMPACT);
	ucl_object_unref(top);
	if (json == NULL) {
		rsp->error = "out of memory";
		return;
	}
	rsp->json = wstrdup(w, json);
	free(json);
	rsp->ok = true;
}

/* The form parsed; NULL when it is not an object. */
static ucl_object_t *
spec_of(const char *text)
{
	struct ucl_parser	*p;
	ucl_object_t		*o;

	if (text == NULL || strlen(text) > SPEC_MAX)
		return (NULL);
	p = ucl_parser_new(UCL_PARSER_NO_TIME);
	o = ucl_parser_add_string(p, text, 0) ? ucl_parser_get_object(p) : NULL;
	ucl_parser_free(p);
	if (o != NULL && ucl_object_type(o) != UCL_OBJECT) {
		ucl_object_unref(o);
		return (NULL);
	}
	return (o);
}

static bool
id_ok(const char *s)
{

	return (s != NULL && (strcmp(s, "all") == 0 || ((strlen(s) == 8 ||
	    strlen(s) == 16) && strspn(s, "0123456789abcdef") == strlen(s))));
}

const char *
smtpd_check(const struct arc_job_spec *sp)
{
	static _Thread_local char errbuf[300];
	struct work	 cw;
	ucl_object_t	*o;
	const char	*e, *v;

	if (sp->safe)
		return ("mail is not undone: not in safe mode");
	if (sp->verb == NULL)
		return ("an smtpd job has a verb: conf, table, enable, pause, "
		    "resume, schedule, remove, update");
	v = sp->names.n > 0 ? sp->names.v[0] : NULL;
	if (strcmp(sp->verb, "conf") == 0) {
		if (sp->names.n != 0 || (o = spec_of(sp->text)) == NULL)
			return ("conf takes the form as JSON, an object, 64 KB "
			    "at most");
		/* Rendered to be checked: its error outlives the arena. */
		work_init(&cw);
		e = NULL;
		if (smtpd_render(&cw, o, &e) == NULL) {
			snprintf(errbuf, sizeof(errbuf), "%s", e);
			e = errbuf;
		}
		work_free(&cw);
		ucl_object_unref(o);
		return (e);
	}
	if (strcmp(sp->verb, "table") == 0) {
		if (sp->names.n != 1 || !table_name_ok(v))
			return ("table takes one of aliases, virtuals, domains, "
			    "senders, credentials, secrets, and its text");
		if (sp->text == NULL || strlen(sp->text) > TABLE_MAX)
			return ("a table is text, 1 MB at most");
		return (NULL);
	}
	if (strcmp(sp->verb, "enable") == 0) {
		if (sp->names.n != 1 || v == NULL || (strcmp(v, "enable=yes") !=
		    0 && strcmp(v, "enable=no") != 0))
			return ("enable takes enable=yes or enable=no");
		return (NULL);
	}
	if (strcmp(sp->verb, "pause") == 0 || strcmp(sp->verb, "resume") == 0) {
		if (sp->names.n != 1 || v == NULL || (strcmp(v, "mta") != 0 &&
		    strcmp(v, "mda") != 0 && strcmp(v, "smtp") != 0))
			return ("pause and resume take mta, mda or smtp");
		return (NULL);
	}
	if (strcmp(sp->verb, "schedule") == 0 || strcmp(sp->verb, "remove") ==
	    0) {
		if (sp->names.n != 1 || !id_ok(v))
			return ("schedule and remove take an envelope's or a "
			    "message's id, or all");
		return (NULL);
	}
	if (strcmp(sp->verb, "update") == 0) {
		if (sp->names.n != 1 || !table_name_ok(v))
			return ("update takes a table's name");
		return (NULL);
	}
	return ("an smtpd job's verb is conf, table, enable, pause, resume, "
	    "schedule, remove or update");
}

char *
smtpd_title(const struct arc_job_spec *sp)
{
	char	*t;

	if (asprintf(&t, "smtpd %s%s%s", sp->verb, sp->names.n > 0 ? " " : "",
	    sp->names.n > 0 ? sp->names.v[0] : "") == -1)
		return (NULL);
	return (t);
}

/* The service told: restarted where it runs, else nothing. */
static int
restart(struct work *w, const char **errp)
{
	struct arc_service_action_rsp	 r;
	bool				 enabled, running;

	enabled = running = false;
	service_state(w, "smtpd", &enabled, &running);
	if (!running)
		return (0);
	memset(&r, 0, sizeof(r));
	if (do_service_action(w, "smtpd", ARC_SERVICE_ACTION_RESTART, &r) != 0
	    || !r.ok) {
		*errp = wfmt(w, "written, but smtpd did not start again: %s",
		    r.error != NULL ? r.error : "restart failed");
		return (-1);
	}
	return (0);
}

/*
 * A credentials table from "user password" lines: each password hashed
 * by OpenSMTPD's encrypt, so the clear one is kept nowhere; a line
 * "user $..." (a hash already) is kept as it is.
 */
static char *
hashed(struct work *w, const char *text, const char **errp)
{
	struct execres	 res;
	char		*out, *copy, *line, *user, *pass, *argv[3];

	out = wstrdup(w, "");
	copy = wstrdup(w, text);
	while ((line = strsep(&copy, "\n")) != NULL) {
		line += strspn(line, " \t");
		if (line[0] == '\0' || line[0] == '#')
			continue;
		user = strsep(&line, " \t");
		pass = line != NULL ? line + strspn(line, " \t") : NULL;
		if (pass == NULL || pass[0] == '\0' || !word_ok(user, "@._-+",
		    128)) {
			*errp = "credentials are lines of user and password";
			return (NULL);
		}
		if (pass[0] == '$') {
			out = wfmt(w, "%s%s\t%s\n", out, user, pass);
			continue;
		}
		/* The password on encrypt's standard input, as it reads one
		 * given no word: in no command line, no trace. */
		argv[0] = (char *)(uintptr_t)encrypt_bin(w);
		argv[1] = NULL;
		exec_set_secret(true);
		exec_set_stdin(wfmt(w, "%s\n", pass), strlen(pass) + 1);
		if (run_exec(w, argv, &res) != 0 || res.out == NULL) {
			exec_set_secret(false);
			*errp = "encrypt (OpenSMTPD's) did not hash the password";
			return (NULL);
		}
		exec_set_secret(false);
		out = wfmt(w, "%s%s\t%.*s\n", out, user, (int)strcspn(res.out,
		    "\n"), res.out);
	}
	return (out);
}

int
do_smtpd_job(struct work *w, const struct arc_job_spec *sp, const char **errp)
{
	struct execres			 res;
	struct arc_service_action_rsp	 r;
	ucl_object_t			*o;
	const char			*v, *conf, *path;
	char				*argv[5], *text;
	int				 step;
	bool				 enabled, running;

	if ((*errp = smtpd_check(sp)) != NULL)
		return (-1);
	v = sp->names.n > 0 ? sp->names.v[0] : NULL;
	if (strcmp(sp->verb, "conf") == 0) {
		if ((o = spec_of(sp->text)) == NULL || (conf = smtpd_render(w, o,
		    errp)) == NULL)
			return (-1);
		scoped_mkdir(w, opts.smtpd_dir);
		/* Checked by smtpd itself before it is put in place. */
		path = wfmt(w, "%s.arcana-new", opts.smtpd_conf);
		if (scope_replace(w, path, conf, strlen(conf), 0644, NULL) != 0) {
			*errp = wfmt(w, "%s: %s", path, strerror(errno));
			return (-1);
		}
		step = step_begin(w, ARC_STEP_KIND_EXEC, "smtpd -n", "the "
		    "configuration checked");
		argv[0] = (char *)(uintptr_t)smtpd_bin(w);
		argv[1] = (char *)(uintptr_t)"-n";
		argv[2] = (char *)(uintptr_t)"-f";
		argv[3] = (char *)(uintptr_t)path;
		argv[4] = NULL;
		if (run_exec(w, argv, &res) != 0) {
			(void)scope_unlink(w, path);
			*errp = wfmt(w, "smtpd does not take it: %s", exec_error(w,
			    &res, "smtpd -n"));
			step_end(w, step, false, "%s", *errp);
			ucl_object_unref(o);
			return (-1);
		}
		step_end(w, step, true, NULL);
		if (scope_replace(w, opts.smtpd_conf, conf, strlen(conf), 0644,
		    NULL) != 0) {
			*errp = wfmt(w, "%s: %s", opts.smtpd_conf, strerror(errno));
			ucl_object_unref(o);
			return (-1);
		}
		(void)scope_unlink(w, path);
		text = (char *)ucl_object_emit(o, UCL_EMIT_JSON_COMPACT);
		ucl_object_unref(o);
		if (text != NULL) {
			(void)scope_replace(w, spec_path(w), text, strlen(text),
			    0600, NULL);
			free(text);
		}
		return (restart(w, errp));
	}
	if (strcmp(sp->verb, "table") == 0) {
		scoped_mkdir(w, opts.smtpd_dir);
		text = strcmp(v, "credentials") == 0 ? hashed(w, sp->text, errp) :
		    (char *)(uintptr_t)sp->text;
		if (text == NULL)
			return (-1);
		if (scope_replace(w, table_path(w, v), text, strlen(text),
		    table_secret(v) ? 0600 : 0644, NULL) != 0) {
			*errp = wfmt(w, "%s: %s", table_path(w, v), strerror(errno));
			return (-1);
		}
		enabled = running = false;
		service_state(w, "smtpd", &enabled, &running);
		if (!running)
			return (0);
		argv[0] = (char *)(uintptr_t)smtpctl_bin(w);
		argv[1] = (char *)(uintptr_t)"update";
		argv[2] = (char *)(uintptr_t)"table";
		argv[3] = (char *)(uintptr_t)v;
		argv[4] = NULL;
		/* A table smtpd.conf does not name is not its to update. */
		(void)run_exec(w, argv, &res);
		return (0);
	}
	if (strcmp(sp->verb, "enable") == 0) {
		memset(&r, 0, sizeof(r));
		if (strcmp(v, "enable=yes") == 0) {
			if (rc_set(w, "smtpd_enable", "=", "YES", errp) != 0 ||
			    do_service_action(w, "smtpd", ARC_SERVICE_ACTION_START,
			    &r) != 0 || !r.ok) {
				*errp = r.error != NULL ? r.error : *errp != NULL ?
				    *errp : "smtpd did not start";
				return (-1);
			}
			return (0);
		}
		if (do_service_action(w, "smtpd", ARC_SERVICE_ACTION_STOP, &r) !=
		    0)
			return (-1);
		return (rc_set(w, "smtpd_enable", "=", "NO", errp));
	}
	/* smtpctl's own: pause, resume, schedule, remove, update. */
	argv[0] = (char *)(uintptr_t)smtpctl_bin(w);
	argv[1] = (char *)(uintptr_t)sp->verb;
	argv[2] = (char *)(uintptr_t)(strcmp(sp->verb, "update") == 0 ? "table"
	    : v);
	argv[3] = (char *)(uintptr_t)(strcmp(sp->verb, "update") == 0 ? v :
	    NULL);
	argv[4] = NULL;
	if (run_exec(w, argv, &res) != 0) {
		*errp = wtext(w, exec_error(w, &res, "smtpctl"));
		return (-1);
	}
	return (0);
}
