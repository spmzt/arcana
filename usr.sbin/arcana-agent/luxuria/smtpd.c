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
 *
 * Watched every --smtpd-watch seconds (60 unless said, never with 0),
 * on the host and in each jail that has it: smtpctl's counters kept, a
 * day of them, for the read's graphs; a mail fault when smtpd is
 * enabled and not running (Major), or when more are queued than the
 * limit the tab set (watch.json beside the tables; Minor).
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
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
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

/*
 * smtpd's service, of the host or of the jail the work is in: there,
 * service(8) is run by jexec and its rc.conf read by sysrc -R (rc_get
 * does).
 */
static void
svc_state(struct work *w, bool *enabled, bool *running)
{
	struct execres	 res;
	const char	*v;
	char		*argv[4];

	if (w->jail == NULL) {
		service_state(w, "smtpd", running, enabled);
		return;
	}
	v = rc_get(w, "smtpd_enable");
	*enabled = v != NULL && strcasecmp(v, "yes") == 0;
	argv[0] = (char *)(uintptr_t)opts.service_bin;
	argv[1] = (char *)(uintptr_t)"smtpd";
	argv[2] = (char *)(uintptr_t)"onestatus";
	argv[3] = NULL;
	*running = run_exec(w, scope_jexec(w, argv), &res) == 0 && res.status ==
	    0;
}

/* start, stop or restart it; 0, or -1 with why. */
static int
svc_do(struct work *w, const char *verb, const char **errp)
{
	struct service_action_rsp	 r;
	struct execres			 res;
	char				*argv[4];

	if (w->jail == NULL) {
		memset(&r, 0, sizeof(r));
		if (do_service_action(w, "smtpd", strcmp(verb, "start") == 0 ?
		    ARC_SERVICE_ACTION_START : strcmp(verb, "stop") == 0 ?
		    ARC_SERVICE_ACTION_STOP : ARC_SERVICE_ACTION_RESTART, &r) != 0
		    || !r.ok) {
			*errp = r.error != NULL ? r.error : wfmt(w, "smtpd: %s "
			    "failed", verb);
			return (-1);
		}
		return (0);
	}
	argv[0] = (char *)(uintptr_t)opts.service_bin;
	argv[1] = (char *)(uintptr_t)"smtpd";
	argv[2] = wfmt(w, "one%s", verb);
	argv[3] = NULL;
	if (run_exec(w, scope_jexec(w, argv), &res) != 0) {
		*errp = wtext(w, exec_error(w, &res, wfmt(w, "service smtpd "
		    "one%s", verb)));
		return (-1);
	}
	return (0);
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
	if (run_exec(w, scope_jexec(w, argv), &res) != 0 || res.out == NULL)
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

/*
 * A table as smtpd.conf declares it, "table NAME [BACKEND:]PATH" (a
 * path alone is a file:), or one of the agent's own when the file
 * declares none of that name.  kind: "auth" for a table a listener
 * signs users in by (its passwords hashed), "relay" for a smart host's
 * sign-in (kept as given), "" else.
 */
struct ctable {
	const char	*name;
	const char	*backend;
	const char	*path;
	const char	*kind;
	bool		 declared;
};

static bool
tname_ok(const char *s)
{
	size_t	i, n;

	n = s != NULL ? strlen(s) : 0;
	if (n == 0 || n > 64)
		return (false);
	for (i = 0; i < n; i++)
		if (!isalnum((unsigned char)s[i]) && s[i] != '_' && s[i] != '-')
			return (false);
	return (true);
}

/* How smtpd.conf uses a table: by listeners' auth, by a relay's. */
static const char *
table_kind(const char *conf, const char *name)
{
	char		 ref[80];
	const char	*p, *bol;

	snprintf(ref, sizeof(ref), "auth <%s>", name);
	for (p = conf; p != NULL && (p = strstr(p, ref)) != NULL; p++) {
		for (bol = p; bol > conf && bol[-1] != '\n'; bol--)
			;
		bol += strspn(bol, " \t");
		if (strncmp(bol, "listen", 6) == 0)
			return ("auth");
		if (strncmp(bol, "action", 6) == 0)
			return ("relay");
	}
	return ("");
}

/* The tables smtpd.conf declares; how many. */
static int
conf_tables(struct work *w, const char *conf, struct ctable *v, int max)
{
	char		*copy, *line, *name, *src, *colon;
	int		 n;

	n = 0;
	if (conf == NULL)
		return (0);
	copy = wstrdup(w, conf);
	while ((line = strsep(&copy, "\n")) != NULL && n < max) {
		line += strspn(line, " \t");
		if (strncmp(line, "table", 5) != 0 || (line[5] != ' ' &&
		    line[5] != '\t'))
			continue;
		line += 5 + strspn(line + 5, " \t");
		name = strsep(&line, " \t");
		if (name == NULL || !tname_ok(name) || line == NULL)
			continue;
		src = line + strspn(line, " \t");
		src[strcspn(src, " \t\r#")] = '\0';
		if (src[0] == '{' || src[0] == '\0')
			continue;	/* inline: smtpd.conf's own words */
		v[n].name = wstrdup(w, name);
		if (src[0] == '/') {
			v[n].backend = "file";
			v[n].path = wstrdup(w, src);
		} else if ((colon = strchr(src, ':')) != NULL) {
			v[n].backend = wstrndup(w, src, (size_t)(colon - src));
			v[n].path = wstrdup(w, colon + 1);
		} else
			continue;
		v[n].kind = table_kind(conf, name);
		v[n].declared = true;
		n++;
	}
	return (n);
}

/*
 * The table of that name: smtpd.conf's, else the agent's own of that
 * name.  False when there is none.
 */
static bool
ctable_find(struct work *w, const char *name, struct ctable *ct)
{
	struct ctable	 v[32];
	char		*conf;
	size_t		 len;
	int		 n, i;

	conf = scope_slurp(w, opts.smtpd_conf, &len);
	n = conf_tables(w, conf, v, (int)nitems(v));
	for (i = 0; i < n; i++)
		if (strcmp(v[i].name, name) == 0) {
			*ct = v[i];
			return (true);
		}
	if (!table_name_ok(name))
		return (false);
	ct->name = name;
	ct->backend = "file";
	ct->path = table_path(w, name);
	ct->kind = strcmp(name, "credentials") == 0 ? "auth" : strcmp(name,
	    "secrets") == 0 ? "relay" : "";
	ct->declared = false;
	return (true);
}

/* A line's key in a table of that backend: passwd(5)'s name before its
 * colon; else its first word, an alias's without its colon. */
static char *
line_key(struct work *w, const char *backend, const char *line)
{
	size_t	n;

	line += strspn(line, " \t");
	if (strcmp(backend, "passwd") == 0)
		return (wstrndup(w, line, strcspn(line, ":")));
	n = strcspn(line, " \t");
	if (n > 0 && line[n - 1] == ':')
		n--;
	return (wstrndup(w, line, n));
}

/*
 * The entries of a table smtpd.conf declares, as JSON: each its key,
 * and its value unless the table holds passwords or a sign-in.
 */
static const char *
makemap_bin(struct work *w)
{
	const char	*p;

	return ((p = tool(w, "makemap")) != NULL ? p :
	    "/usr/local/sbin/makemap");
}

static bool
is_db(const struct ctable *ct)
{

	return (strcmp(ct->backend, "db") == 0);
}

/* A db: table's text, as makemap makes the database of: its path
 * without .db, the way makemap names the one by the other. */
static const char *
db_source(struct work *w, const char *path)
{
	size_t	n = strlen(path);

	if (n > 3 && strcmp(path + n - 3, ".db") == 0)
		return (wstrndup(w, path, n - 3));
	return (wfmt(w, "%s.txt", path));
}

/* A db: table's lines: its text, else what makemap -U dumps of it. */
static char *
db_text(struct work *w, const struct ctable *ct, size_t *lenp)
{
	struct execres	 res;
	char		*text, *argv[4];

	if ((text = scope_slurp(w, db_source(w, ct->path), lenp)) != NULL)
		return (text);
	argv[0] = (char *)(uintptr_t)makemap_bin(w);
	argv[1] = (char *)(uintptr_t)"-U";
	argv[2] = (char *)(uintptr_t)ct->path;
	argv[3] = NULL;
	if (run_exec(w, scope_jexec(w, argv), &res) != 0 || res.out == NULL)
		return (NULL);
	*lenp = res.outlen;
	return (wstrndup(w, res.out, res.outlen));
}

/*
 * The kind of map smtpd.conf uses a table as, for makemap -t: aliases
 * where it is an action's alias table, set where it is a list matched
 * against (domain, mail-from, rcpt-to, src, helo-src), a map else.
 */
static const char *
db_type(const char *conf, const char *name)
{
	static const char *const sets[] = { "domain", "mail-from", "rcpt-to",
	    "src", "helo-src", "for", "from" };
	const char	*p, *b, *e;
	char		 tok[80], prev[32];
	size_t		 n, i;

	snprintf(tok, sizeof(tok), "<%s>", name);
	for (p = conf; p != NULL && (p = strstr(p, tok)) != NULL; p++) {
		/* The word before it, a "!" passed over. */
		for (e = p; e > conf && (e[-1] == ' ' || e[-1] == '\t' ||
		    e[-1] == '!'); e--)
			;
		for (b = e; b > conf && !isspace((unsigned char)b[-1]); b--)
			;
		n = (size_t)(e - b) < sizeof(prev) - 1 ? (size_t)(e - b) :
		    sizeof(prev) - 1;
		memcpy(prev, b, n);
		prev[n] = '\0';
		if (strcmp(prev, "alias") == 0)
			return ("aliases");
		for (i = 0; i < nitems(sets); i++)
			if (strcmp(prev, sets[i]) == 0)
				return ("set");
	}
	return (NULL);
}

/* A db: table made again from its text by makemap(8). */
static int
db_make(struct work *w, const struct ctable *ct, const char **errp)
{
	struct execres	 res;
	const char	*type;
	char		*argv[8], *conf;
	size_t		 len;
	int		 n = 0;

	conf = scope_slurp(w, opts.smtpd_conf, &len);
	type = conf != NULL ? db_type(conf, ct->name) : NULL;
	argv[n++] = (char *)(uintptr_t)makemap_bin(w);
	if (type != NULL) {
		argv[n++] = (char *)(uintptr_t)"-t";
		argv[n++] = (char *)(uintptr_t)type;
	}
	argv[n++] = (char *)(uintptr_t)"-o";
	argv[n++] = (char *)(uintptr_t)ct->path;
	argv[n++] = (char *)(uintptr_t)db_source(w, ct->path);
	argv[n] = NULL;
	if (run_exec(w, scope_jexec(w, argv), &res) != 0) {
		*errp = wtext(w, exec_error(w, &res, "makemap"));
		return (-1);
	}
	return (0);
}

static ucl_object_t *
ctable_json(struct work *w, const struct ctable *ct)
{
	ucl_object_t	*o, *arr, *e;
	char		*text, *copy, *line, *key;
	const char	*val;
	size_t		 len;
	bool		 secret;
	int		 n;

	o = ucl_object_typed_new(UCL_OBJECT);
	ucl_object_insert_key(o, ucl_object_fromstring(ct->name), "name", 0,
	    false);
	ucl_object_insert_key(o, ucl_object_fromstring(ct->backend), "backend",
	    0, false);
	ucl_object_insert_key(o, ucl_object_fromstring(ct->path), "path", 0,
	    false);
	ucl_object_insert_key(o, ucl_object_fromstring(ct->kind), "kind", 0,
	    false);
	secret = ct->kind[0] != '\0' || strcmp(ct->backend, "passwd") == 0;
	ucl_object_insert_key(o, ucl_object_frombool(secret), "secret", 0,
	    false);
	if (strcmp(ct->backend, "file") != 0 && strcmp(ct->backend,
	    "passwd") != 0 && !is_db(ct)) {
		/* What no file holds (a database's server, a socket): its
		 * own. */
		ucl_object_insert_key(o, ucl_object_frombool(false), "editable",
		    0, false);
		return (o);
	}
	ucl_object_insert_key(o, ucl_object_frombool(true), "editable", 0,
	    false);
	if (is_db(ct))
		ucl_object_insert_key(o, ucl_object_fromstring(db_source(w,
		    ct->path)), "source", 0, false);
	arr = ucl_object_typed_new(UCL_ARRAY);
	n = 0;
	if ((text = is_db(ct) ? db_text(w, ct, &len) : scope_slurp(w, ct->path,
	    &len)) != NULL) {
		copy = wstrdup(w, text);
		while ((line = strsep(&copy, "\n")) != NULL && n < 5000) {
			line += strspn(line, " \t");
			if (line[0] == '\0' || line[0] == '#')
				continue;
			key = line_key(w, ct->backend, line);
			e = ucl_object_typed_new(UCL_OBJECT);
			ucl_object_insert_key(e, ucl_object_fromstring(key), "key",
			    0, false);
			if (!secret) {
				val = line + strlen(key);
				val += strspn(val, ": \t");
				ucl_object_insert_key(e, ucl_object_fromstring(val),
				    "value", 0, false);
			}
			ucl_array_append(arr, e);
			n++;
		}
	} else
		ucl_object_insert_key(o, ucl_object_fromstring(strerror(errno)),
		    "error", 0, false);
	ucl_object_insert_key(o, arr, "entries", 0, false);
	return (o);
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

#define	WATCH_PLACES	16
#define	WATCH_KEPT	1440		/* samples a place, a day of minutes */

/* A sample of smtpctl show stats: what is queued, deliveries so far. */
struct msample {
	time_t		t;
	int64_t		queued, ok, tempfail, permfail, sessions;
};

static struct {
	char		 place[MAXHOSTNAMELEN];	/* the jail, "" the host */
	struct msample	*v;
	int		 first, n;
} rings[WATCH_PLACES];
static pthread_mutex_t	rings_lock = PTHREAD_MUTEX_INITIALIZER;

static int64_t
stat_num(const ucl_object_t *o, const char *key)
{
	const ucl_object_t	*v;

	return ((v = ucl_object_lookup(o, key)) != NULL &&
	    ucl_object_type(v) == UCL_INT ? ucl_object_toint(v) : 0);
}

/* A place's ring, made when asked to; NULL, none.  The lock is held. */
static int
ring_of(const char *place, bool make)
{
	int	i, free_at = -1;

	for (i = 0; i < WATCH_PLACES; i++) {
		if (rings[i].v != NULL && strcmp(rings[i].place, place) == 0)
			return (i);
		if (rings[i].v == NULL && free_at == -1)
			free_at = i;
	}
	if (!make || free_at == -1 || (rings[free_at].v = calloc(WATCH_KEPT,
	    sizeof(struct msample))) == NULL)
		return (-1);
	snprintf(rings[free_at].place, sizeof(rings[0].place), "%s", place);
	rings[free_at].first = rings[free_at].n = 0;
	return (free_at);
}

static void
ring_add(const char *place, const struct msample *m)
{
	int	i;

	pthread_mutex_lock(&rings_lock);
	if ((i = ring_of(place, true)) != -1) {
		if (rings[i].n < WATCH_KEPT)
			rings[i].v[(rings[i].first + rings[i].n++) % WATCH_KEPT] =
			    *m;
		else {
			rings[i].v[rings[i].first] = *m;
			rings[i].first = (rings[i].first + 1) % WATCH_KEPT;
		}
	}
	pthread_mutex_unlock(&rings_lock);
}

/* A place's samples, oldest first, as [t, queued, ok, tempfail,
 * permfail, sessions] each. */
static ucl_object_t *
ring_json(const char *place)
{
	const struct msample	*m;
	ucl_object_t		*arr, *e;
	int			 i, k;

	arr = ucl_object_typed_new(UCL_ARRAY);
	pthread_mutex_lock(&rings_lock);
	if ((i = ring_of(place, false)) != -1)
		for (k = 0; k < rings[i].n; k++) {
			m = &rings[i].v[(rings[i].first + k) % WATCH_KEPT];
			e = ucl_object_typed_new(UCL_ARRAY);
			ucl_array_append(e, ucl_object_fromint(m->t));
			ucl_array_append(e, ucl_object_fromint(m->queued));
			ucl_array_append(e, ucl_object_fromint(m->ok));
			ucl_array_append(e, ucl_object_fromint(m->tempfail));
			ucl_array_append(e, ucl_object_fromint(m->permfail));
			ucl_array_append(e, ucl_object_fromint(m->sessions));
			ucl_array_append(arr, e);
		}
	pthread_mutex_unlock(&rings_lock);
	return (arr);
}

static const char *
watch_path(struct work *w)
{

	return (wfmt(w, "%s/watch.json", opts.smtpd_dir));
}

/* The queue's limit the tab set where the work is; 0, none. */
static int64_t
watch_limit(struct work *w)
{
	struct ucl_parser	*p;
	ucl_object_t		*o;
	int64_t			 n = 0;
	size_t			 len;
	char			*text;

	if ((text = scope_slurp(w, watch_path(w), &len)) == NULL)
		return (0);
	p = ucl_parser_new(UCL_PARSER_NO_TIME);
	if (ucl_parser_add_string(p, text, 0) && (o = ucl_parser_get_object(p))
	    != NULL) {
		n = stat_num(o, "queue_max");
		ucl_object_unref(o);
	}
	ucl_parser_free(p);
	return (n > 0 ? n : 0);
}

/* One place, the host ("") or a jail the work is in: sampled, judged. */
static void
place_watch(struct work *w, const char *place)
{
	struct msample	 m;
	ucl_object_t	*st;
	const char	*text;
	char		 obj[MAXHOSTNAMELEN + 16], where[MAXHOSTNAMELEN + 8];
	int64_t		 limit;
	bool		 enabled, running;

	snprintf(obj, sizeof(obj), "%s%s%ssmtpd", place[0] != '\0' ? "jail:" :
	    "host:", place, place[0] != '\0' ? "/" : "");
	snprintf(where, sizeof(where), "%s%s", place[0] != '\0' ? " in " : "",
	    place);
	enabled = running = false;
	svc_state(w, &enabled, &running);
	if (!running) {
		if (enabled)
			fault_set("mail", "Major", obj, "smtpd", "smtpd%s is "
			    "enabled and not running", where);
		else
			fault_clear("mail", obj, "smtpd%s is turned off", where);
		return;
	}
	if ((text = ctl(w, "show", "stats", NULL)) == NULL)
		return;
	st = stats_json(w, text);
	memset(&m, 0, sizeof(m));
	m.t = time(NULL);
	m.queued = stat_num(st, "scheduler.envelope");
	m.ok = stat_num(st, "scheduler.delivery.ok");
	m.tempfail = stat_num(st, "scheduler.delivery.tempfail");
	m.permfail = stat_num(st, "scheduler.delivery.permfail");
	m.sessions = stat_num(st, "smtp.session");
	ucl_object_unref(st);
	ring_add(place, &m);
	if ((limit = watch_limit(w)) > 0 && m.queued > limit)
		fault_set("mail", "Minor", obj, "smtpd", "%jd messages queued%s, "
		    "over %jd", (intmax_t)m.queued, where, (intmax_t)limit);
	else
		fault_clear("mail", obj, "smtpd%s runs, %jd queued", where,
		    (intmax_t)m.queued);
}

static bool
has_smtpd(struct work *w, int jid, const char *path)
{
	const char *const	*pl;
	size_t			 np, k;

	plugins_there(w, jid, path, &pl, &np);
	for (k = 0; k < np; k++)
		if (strcmp(pl[k], "smtpd") == 0)
			return (true);
	return (false);
}

static void *
watch(void *arg __unused)
{
	struct work	 w;
	struct jinfo	*list;
	const char	*e;
	size_t		 n, i;
	int		 k;
	bool		 listed;

	for (;;) {
		sleep((unsigned int)opts.smtpd_watch_s);
		work_init(&w);
		if (has_smtpd(&w, 0, NULL))
			place_watch(&w, "");
		list = NULL;
		n = 0;
		if ((listed = jails_running(&w, &list, &n, &e) == 0))
			for (i = 0; i < n; i++) {
				if (list[i].dying || !has_smtpd(&w, list[i].jid,
				    list[i].path) || scope_enter(&w,
				    list[i].name, &e) != 0)
					continue;
				place_watch(&w, list[i].name);
				(void)scope_enter(&w, NULL, &e);
			}
		/* The rings of the places gone (a jail stopped) let go;
		 * none when the jails could not be listed. */
		pthread_mutex_lock(&rings_lock);
		for (k = 0; listed && k < WATCH_PLACES; k++) {
			if (rings[k].v == NULL || rings[k].place[0] == '\0')
				continue;
			for (i = 0; i < n; i++)
				if (!list[i].dying && strcmp(list[i].name,
				    rings[k].place) == 0)
					break;
			if (i == n) {
				free(rings[k].v);
				rings[k].v = NULL;
			}
		}
		pthread_mutex_unlock(&rings_lock);
		work_free(&w);
	}
	return (NULL);
}

void
smtpd_watch_start(void)
{
	pthread_t	tid;
	int		error;

	if (opts.smtpd_watch_s <= 0)
		return;
	if ((error = pthread_create(&tid, NULL, watch, NULL)) != 0) {
		logmsg(LOG_ERR, "smtpd watch: %s", strerror(error));
		return;
	}
	(void)pthread_detach(tid);
}

static int	restart(struct work *, const char **);

/* The host's smtpd.conf serves with the agent's own certificate. */
static bool
uses_host_cert(const char *conf)
{
	const char	*cert;

	return (conf != NULL && (cert = tls_files_cert()) != NULL &&
	    strstr(conf, cert) != NULL);
}

/*
 * The agent's certificate renewed (tls install): the host's smtpd, when
 * a pki of its is that certificate, started again to read it.
 */
void
smtpd_cert_renewed(struct work *w)
{
	const char	*e;
	size_t		 len;
	int		 step;
	char		*conf;

	if (w->jail != NULL || (conf = scope_slurp(w, opts.smtpd_conf, &len))
	    == NULL || !uses_host_cert(conf))
		return;
	step = step_begin(w, ARC_STEP_KIND_DAEMON, "smtpd", "serves with the "
	    "certificate renewed: started again");
	e = NULL;
	step_end(w, step, restart(w, &e) == 0, e != NULL ? "%s" : NULL, e);
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
	svc_state(w, &enabled, &running);
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
	if ((text = scope_slurp(w, opts.smtpd_conf, &len)) != NULL) {
		struct ctable	 ct[32];
		int		 nt, k;

		ucl_object_insert_key(top, ucl_object_fromstring(text), "conf", 0,
		    false);
		/* Arcana's own when its form wrote it; the admin's else. */
		ucl_object_insert_key(top, ucl_object_frombool(strstr(text,
		    "# Written by arcana-agent") == text), "conf_arcana", 0,
		    false);
		nt = conf_tables(w, text, ct, (int)nitems(ct));
		arr = ucl_object_typed_new(UCL_ARRAY);
		for (k = 0; k < nt; k++)
			ucl_array_append(arr, ctable_json(w, &ct[k]));
		ucl_object_insert_key(top, arr, "conf_tables", 0, false);
	}
	ucl_object_insert_key(top, ucl_object_fromstring(opts.smtpd_conf),
	    "conf_path", 0, false);
	/* The watcher's samples of this place, and the tab's limit. */
	ucl_object_insert_key(top, ring_json(w->jail != NULL ? w->jail : ""),
	    "series", 0, false);
	ucl_object_insert_key(top, ucl_object_fromint(watch_limit(w)),
	    "queue_max", 0, false);
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
	/* The host's certificate, when smtpd serves with it: its dates. */
	if (w->jail == NULL && (text = scope_slurp(w, opts.smtpd_conf, &len)) !=
	    NULL && uses_host_cert(text)) {
		time_t	nb, na;

		if (tls_cert_dates(w, &nb, &na)) {
			o = ucl_object_typed_new(UCL_OBJECT);
			ucl_object_insert_key(o, ucl_object_fromint(nb),
			    "not_before", 0, false);
			ucl_object_insert_key(o, ucl_object_fromint(na),
			    "not_after", 0, false);
			ucl_object_insert_key(top, o, "pki_cert", 0, false);
		}
	}
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
		    "resume, schedule, remove, update, watch");
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
		if (sp->names.n != 1 || !tname_ok(v))
			return ("table takes one of aliases, virtuals, domains, "
			    "senders, credentials, secrets, and its text");
		if (sp->text == NULL || strlen(sp->text) > TABLE_MAX)
			return ("a table is text, 1 MB at most");
		return (NULL);
	}
	if (strcmp(sp->verb, "conf-text") == 0) {
		if (sp->names.n > 1 || (v != NULL && strcmp(v, "check") != 0) ||
		    sp->text == NULL || sp->text[0] == '\0' || strlen(sp->text) >
		    256 * 1024 || strchr(sp->text, '\0') != sp->text +
		    strlen(sp->text))
			return ("conf-text takes smtpd.conf's text, 256 KB at most, "
			    "and check to only check it");
		return (NULL);
	}
	if (strcmp(sp->verb, "entry") == 0) {
		if (sp->names.n != 1 || !tname_ok(v))
			return ("entry takes a table's name, and lines to put in");
		if (sp->text == NULL || sp->text[strspn(sp->text, " \t\n")] ==
		    '\0' || strlen(sp->text) > TABLE_MAX)
			return ("entry takes the lines to put in, 1 MB at most");
		return (NULL);
	}
	if (strcmp(sp->verb, "unentry") == 0) {
		if (sp->names.n != 2 || !tname_ok(v) ||
		    !word_ok(sp->names.v[1], "@._-+", 255))
			return ("unentry takes a table's name and an entry's key");
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
	if (strcmp(sp->verb, "watch") == 0) {
		if (sp->names.n != 1 || v == NULL || v[0] == '\0' ||
		    v[strspn(v, "0123456789")] != '\0' || strlen(v) > 9)
			return ("watch takes how many may be queued before it is "
			    "a fault, 0 for no limit");
		return (NULL);
	}
	return ("an smtpd job's verb is conf, conf-text, table, entry, "
	    "unentry, enable, pause, resume, schedule, remove, update or "
	    "watch");
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
	const char	*e;
	bool		 enabled, running;

	enabled = running = false;
	svc_state(w, &enabled, &running);
	if (!running)
		return (0);
	if (svc_do(w, "restart", &e) != 0) {
		*errp = wfmt(w, "written, but smtpd did not start again: %s", e);
		return (-1);
	}
	return (0);
}

/*
 * A password hashed by OpenSMTPD's encrypt, read on its standard input
 * as it reads one given no word: in no command line, no trace.
 */
static char *
hash_one(struct work *w, const char *pass, const char **errp)
{
	struct execres	 res;
	char		*argv[2];

	argv[0] = (char *)(uintptr_t)encrypt_bin(w);
	argv[1] = NULL;
	exec_set_secret(true);
	exec_set_stdin(wfmt(w, "%s\n", pass), strlen(pass) + 1);
	if (run_exec(w, scope_jexec(w, argv), &res) != 0 || res.out == NULL ||
	    res.out[0] == '\0') {
		exec_set_secret(false);
		*errp = "encrypt (OpenSMTPD's) did not hash the password";
		return (NULL);
	}
	exec_set_secret(false);
	return (wstrndup(w, res.out, strcspn(res.out, "\n")));
}

/*
 * A credentials table from "user password" lines: each password hashed
 * by OpenSMTPD's encrypt, so the clear one is kept nowhere; a line
 * "user $..." (a hash already) is kept as it is.
 */
static char *
hashed(struct work *w, const char *text, const char **errp)
{
	char		*out, *copy, *line, *user, *pass;

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
		if ((pass = hash_one(w, pass, errp)) == NULL)
			return (NULL);
		out = wfmt(w, "%s%s\t%s\n", out, user, pass);
	}
	return (out);
}

/* A file's mode in the scope, or dflt when it is not there. */
static mode_t
scoped_mode(struct work *w, const char *path, mode_t dflt)
{
	struct stat	 sb;
	const char	*base;
	int		 dfd, rc;

	if ((dfd = scope_open_dir(w, path, &base)) == -1)
		return (dflt);
	rc = fstatat(dfd, base, &sb, 0);
	close(dfd);
	return (rc == 0 ? sb.st_mode & ALLPERMS : dflt);
}

/* The table written whole, its mode kept, and smtpd told where it runs. */
static int
ctable_put(struct work *w, const struct ctable *ct, const char *text,
    const char **errp)
{
	struct execres	 res;
	const char	*file;
	char		*argv[5];
	bool		 enabled, running, secret;

	secret = ct->kind[0] != '\0' || strcmp(ct->backend, "passwd") == 0;
	if (!ct->declared)
		scoped_mkdir(w, opts.smtpd_dir);
	/* A db: table's text written, the database made from it. */
	file = is_db(ct) ? db_source(w, ct->path) : ct->path;
	if (scope_replace(w, file, text, strlen(text), scoped_mode(w,
	    is_db(ct) ? ct->path : file, secret ? 0600 : 0644), NULL) != 0) {
		*errp = wfmt(w, "%s: %s", file, strerror(errno));
		return (-1);
	}
	if (is_db(ct) && db_make(w, ct, errp) != 0)
		return (-1);
	enabled = running = false;
	svc_state(w, &enabled, &running);
	if (!running)
		return (0);
	argv[0] = (char *)(uintptr_t)smtpctl_bin(w);
	argv[1] = (char *)(uintptr_t)"update";
	argv[2] = (char *)(uintptr_t)"table";
	argv[3] = (char *)(uintptr_t)ct->name;
	argv[4] = NULL;
	/* A table smtpd.conf does not name is not its to update. */
	(void)run_exec(w, scope_jexec(w, argv), &res);
	return (0);
}

static int
table_put(struct work *w, const char *name, const char *text,
    const char **errp)
{
	struct ctable	ct;

	if (!ctable_find(w, name, &ct)) {
		*errp = wfmt(w, "smtpd.conf declares no table %s", name);
		return (-1);
	}
	return (ctable_put(w, &ct, text, errp));
}

/* A passwd(5) line's fields after the password ("uid:gid:gecos:home:
 * shell"), or NULL. */
static const char *
pw_tail(const char *line)
{
	const char	*p;

	if ((p = strchr(line, ':')) == NULL || (p = strchr(p + 1, ':')) ==
	    NULL)
		return (NULL);
	return (p + 1);
}

/*
 * passwd(5) lines for a passwd: table: "user password" hashed by
 * encrypt; a user there already keeps the rest of their line, their
 * hash's {SCHEME} written as before; a new one gets the fields every
 * other line has alike, or empty ones.  A whole line (with colons) is
 * taken as it is.
 */
static char *
pw_lines(struct work *w, const char *old, const char *text,
    const char **errp)
{
	char		*out, *copy, *line, *user, *pass, *hash, *ocopy, *ol;
	const char	*tail, *same_tail, *scheme, *t, *ohash;
	bool		 alike, prefixed;
	int		 n;

	/* What the other lines have alike: their tail, a {SCHEME}. */
	same_tail = NULL;
	alike = true;
	prefixed = false;
	n = 0;
	ocopy = wstrdup(w, old);
	while ((ol = strsep(&ocopy, "\n")) != NULL) {
		ol += strspn(ol, " \t");
		if (ol[0] == '\0' || ol[0] == '#' || (t = pw_tail(ol)) == NULL)
			continue;
		ohash = strchr(ol, ':') + 1;
		if (n == 0)
			prefixed = ohash[0] == '{';
		else if (prefixed != (ohash[0] == '{'))
			prefixed = false;
		if (n++ == 0)
			same_tail = t;
		else if (same_tail != NULL && strcmp(same_tail, t) != 0)
			alike = false;
	}
	out = wstrdup(w, "");
	copy = wstrdup(w, text);
	while ((line = strsep(&copy, "\n")) != NULL) {
		line += strspn(line, " \t");
		if (line[0] == '\0' || line[0] == '#')
			continue;
		user = strsep(&line, " \t");
		if (strchr(user, ':') != NULL) {
			/* A whole passwd(5) line. */
			out = wfmt(w, "%s%s%s%s\n", out, user, line != NULL ? " " :
			    "", line != NULL ? line : "");
			continue;
		}
		pass = line != NULL ? line + strspn(line, " \t") : NULL;
		if (pass == NULL || pass[0] == '\0' || !word_ok(user, "@._-+",
		    128)) {
			*errp = "a passwd table takes lines of user and password, "
			    "or whole passwd(5) lines";
			return (NULL);
		}
		if ((hash = hash_one(w, pass, errp)) == NULL)
			return (NULL);
		scheme = !prefixed ? "" : strncmp(hash, "$6$", 3) == 0 ?
		    "{SHA512-CRYPT}" : strncmp(hash, "$5$", 3) == 0 ?
		    "{SHA256-CRYPT}" : strncmp(hash, "$2", 2) == 0 ?
		    "{BLF-CRYPT}" : "{CRYPT}";
		/* Theirs, kept: the rest of their line. */
		tail = NULL;
		ocopy = wstrdup(w, old);
		while ((ol = strsep(&ocopy, "\n")) != NULL && tail == NULL) {
			ol += strspn(ol, " \t");
			if (strncmp(ol, user, strlen(user)) == 0 &&
			    ol[strlen(user)] == ':')
				tail = pw_tail(ol);
		}
		if (tail == NULL)
			/* uid:gid:gecos:home:shell, empty: four colons. */
			tail = alike && same_tail != NULL ? same_tail : "::::";
		out = wfmt(w, "%s%s:%s%s:%s\n", out, user, scheme, hash, tail);
	}
	return (out);
}

/*
 * Entries put in a table, the others kept: each line of text replaces
 * the lines of its key (a user's new password, an alias's new
 * address), or is added; a password hashed first where the table
 * signs users in.  With drop, the lines of that key taken out
 * instead, refused when none is.  The table is smtpd.conf's, at its
 * own path, or the agent's own of that name.
 */
static int
table_entries(struct work *w, const char *name, const char *text,
    const char *drop, const char **errp)
{
	struct ctable	 ct;
	char		*old, *copy, *line, *out, *add, *k;
	const char	*l;
	size_t		 len;
	int		 n;

	if (!ctable_find(w, name, &ct)) {
		*errp = wfmt(w, "smtpd.conf declares no table %s", name);
		return (-1);
	}
	if (strcmp(ct.backend, "file") != 0 && strcmp(ct.backend, "passwd") !=
	    0 && !is_db(&ct)) {
		*errp = wfmt(w, "table %s is %s:%s, kept where no file is: not "
		    "written here", name, ct.backend, ct.path);
		return (-1);
	}
	if ((old = is_db(&ct) ? db_text(w, &ct, &len) : scope_slurp(w, ct.path,
	    &len)) == NULL)
		old = wstrdup(w, "");
	add = NULL;
	if (drop == NULL) {
		add = strcmp(ct.backend, "passwd") == 0 ? pw_lines(w, old, text,
		    errp) : strcmp(ct.kind, "auth") == 0 ? hashed(w, text, errp) :
		    wstrdup(w, text);
		if (add == NULL)
			return (-1);
	}
	out = wstrdup(w, "");
	n = 0;
	copy = wstrdup(w, old);
	while ((line = strsep(&copy, "\n")) != NULL) {
		l = line + strspn(line, " \t");
		if (l[0] != '\0' && l[0] != '#') {
			k = line_key(w, ct.backend, l);
			if (drop != NULL && strcmp(k, drop) == 0) {
				n++;
				continue;
			}
			/* Replaced by a line of the same key given. */
			if (add != NULL) {
				char	*a, *al;
				bool	 same = false;

				a = wstrdup(w, add);
				while (!same && (al = strsep(&a, "\n")) != NULL)
					if (al[strspn(al, " \t")] != '\0' &&
					    strcmp(line_key(w, ct.backend, al), k) ==
					    0)
						same = true;
				if (same)
					continue;
			}
		}
		if (line[0] != '\0' || copy != NULL)
			out = wfmt(w, "%s%s\n", out, line);
	}
	if (drop != NULL && n == 0) {
		*errp = wfmt(w, "%s has no entry %s", name, drop);
		return (-1);
	}
	if (add != NULL) {
		copy = add;
		while ((line = strsep(&copy, "\n")) != NULL)
			if (line[strspn(line, " \t")] != '\0')
				out = wfmt(w, "%s%s\n", out, line);
	}
	/* Blank lines the file ended with are not kept growing. */
	len = strlen(out);
	while (len >= 2 && out[len - 1] == '\n' && out[len - 2] == '\n')
		out[--len] = '\0';
	return (ctable_put(w, &ct, out, errp));
}

/*
 * smtpd.conf put in place once smtpd -n has read it, the one before
 * kept beside (smtpd.conf.arcana-old): the admin's file is never lost.
 */
static int
conf_put(struct work *w, const char *conf, bool check_only,
    const char **errp)
{
	struct execres	 res;
	const char	*path, *base;
	char		*argv[5];
	int		 step;

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
	if (run_exec(w, scope_jexec(w, argv), &res) != 0) {
		(void)scope_unlink(w, path);
		*errp = wfmt(w, "smtpd does not take it: %s", exec_error(w, &res,
		    "smtpd -n"));
		step_end(w, step, false, "%s", *errp);
		return (-1);
	}
	step_end(w, step, true, NULL);
	if (check_only) {
		(void)scope_unlink(w, path);
		return (0);
	}
	base = strrchr(opts.smtpd_conf, '/') != NULL ? strrchr(opts.smtpd_conf,
	    '/') + 1 : opts.smtpd_conf;
	if (scope_replace(w, opts.smtpd_conf, conf, strlen(conf), scoped_mode(w,
	    opts.smtpd_conf, 0644), wfmt(w, "%s.arcana-old", base)) != 0) {
		*errp = wfmt(w, "%s: %s", opts.smtpd_conf, strerror(errno));
		(void)scope_unlink(w, path);
		return (-1);
	}
	(void)scope_unlink(w, path);
	return (0);
}

int
do_smtpd_job(struct work *w, const struct arc_job_spec *sp, const char **errp)
{
	struct execres			 res;
	ucl_object_t			*o;
	const char			*v, *conf;
	char				*argv[5], *text;

	if ((*errp = smtpd_check(sp)) != NULL)
		return (-1);
	v = sp->names.n > 0 ? sp->names.v[0] : NULL;
	if (strcmp(sp->verb, "conf-text") == 0) {
		/* The admin's own smtpd.conf, as text: checked, put in place,
		 * the one before kept; the form no longer what it is. */
		if (conf_put(w, sp->text, v != NULL && strcmp(v, "check") == 0,
		    errp) != 0)
			return (-1);
		if (v != NULL && strcmp(v, "check") == 0)
			return (0);
		(void)scope_unlink(w, spec_path(w));
		return (restart(w, errp));
	}
	if (strcmp(sp->verb, "conf") == 0) {
		size_t	 clen;
		char	*cur;

		if ((o = spec_of(sp->text)) == NULL || (conf = smtpd_render(w, o,
		    errp)) == NULL)
			return (-1);
		/* The admin's own file is not replaced by the form unless
		 * that is asked for (force). */
		if ((cur = scope_slurp(w, opts.smtpd_conf, &clen)) != NULL &&
		    strstr(cur, "# Written by arcana-agent") != cur &&
		    !sp->force) {
			ucl_object_unref(o);
			*errp = wfmt(w, "%s is not Arcana's (its form did not write "
			    "it): its own lines would be replaced; edit it as text, "
			    "or replace it with the form on purpose", opts.smtpd_conf);
			return (-1);
		}
		scoped_mkdir(w, opts.smtpd_dir);
		if (conf_put(w, conf, false, errp) != 0) {
			ucl_object_unref(o);
			return (-1);
		}
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
		text = strcmp(v, "credentials") == 0 ? hashed(w, sp->text, errp) :
		    (char *)(uintptr_t)sp->text;
		if (text == NULL)
			return (-1);
		return (table_put(w, v, text, errp));
	}
	if (strcmp(sp->verb, "entry") == 0)
		return (table_entries(w, v, sp->text, NULL, errp));
	if (strcmp(sp->verb, "unentry") == 0)
		return (table_entries(w, v, NULL, sp->names.v[1], errp));
	if (strcmp(sp->verb, "watch") == 0) {
		text = wfmt(w, "{\"queue_max\":%s}\n", v);
		scoped_mkdir(w, opts.smtpd_dir);
		if (scope_replace(w, watch_path(w), text, strlen(text), 0644,
		    NULL) != 0) {
			*errp = wfmt(w, "%s: %s", watch_path(w), strerror(errno));
			return (-1);
		}
		return (0);
	}
	if (strcmp(sp->verb, "enable") == 0) {
		if (strcmp(v, "enable=yes") == 0)
			return (rc_set(w, "smtpd_enable", "=", "YES", errp) != 0 ||
			    svc_do(w, "start", errp) != 0 ? -1 : 0);
		if (svc_do(w, "stop", errp) != 0)
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
	if (run_exec(w, scope_jexec(w, argv), &res) != 0) {
		*errp = wtext(w, exec_error(w, &res, "smtpctl"));
		return (-1);
	}
	return (0);
}
