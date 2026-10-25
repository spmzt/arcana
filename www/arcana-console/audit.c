/*-
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * The audit trail (SASE-5, MEF 118.1 §13.1): an Audit Event for each
 * Policy Action the console applies or sees applied, and for each
 * change to the Policies, kept in the data directory one a line, oldest
 * first.  Each carries what [R65] lists: the Policy applied, how, where,
 * who or what triggered it, the Event that did, the Policy Action, why,
 * and when.  [R66] asks it to be tamper-proof, hard or costly to alter:
 * each line carries an HMAC-SHA256, under a key of the console's own
 * that no reader is given, of the one before's and its own, so a line
 * changed, taken away or put in breaks the chain from there on, and
 * the read says where.  Workers append under flock(2).
 */

#include <sys/param.h>
#include <sys/file.h>
#include <sys/stat.h>

#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <openssl/evp.h>
#include <openssl/hmac.h>

#include <ucl.h>

#include "console.h"

#define	AUDIT_FILE	"sdwan-audit.jsonl"
#define	AUDIT_KEY	"sdwan-audit.key"
#define	AUDIT_READ	500		/* events in a read, newest */
#define	AUDIT_LINE	4096

/* The key, made once, readable by the console's user alone. */
static int
audit_key(uint8_t key[32])
{
	char	path[MAXPATHLEN];
	int	fd;
	ssize_t	n;

	snprintf(path, sizeof(path), "%s/%s", cfg.datadir, AUDIT_KEY);
	if ((fd = open(path, O_RDONLY | O_CLOEXEC)) != -1) {
		n = read(fd, key, 32);
		close(fd);
		return (n == 32 ? 0 : -1);
	}
	if (errno != ENOENT)
		return (-1);
	arc4random_buf(key, 32);
	if ((fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600)) ==
	    -1) {
		/* Another worker made it first: its, then. */
		if (errno == EEXIST && (fd = open(path, O_RDONLY | O_CLOEXEC)) !=
		    -1) {
			n = read(fd, key, 32);
			close(fd);
			return (n == 32 ? 0 : -1);
		}
		return (-1);
	}
	n = write(fd, key, 32);
	(void)fsync(fd);
	close(fd);
	return (n == 32 ? 0 : -1);
}

/* HMAC-SHA256 of the one before's and a line's text, in hex. */
static void
mac(const uint8_t key[32], const char *prev, const char *body, char out[65])
{
	uint8_t		 md[EVP_MAX_MD_SIZE];
	unsigned int	 len;
	char		*both;
	int		 i;

	if (asprintf(&both, "%s\n%s", prev, body) == -1) {
		out[0] = '\0';
		return;
	}
	len = 0;
	(void)HMAC(EVP_sha256(), key, 32, (const uint8_t *)both, strlen(both),
	    md, &len);
	free(both);
	for (i = 0; i < 32 && (unsigned int)i < len; i++)
		snprintf(out + 2 * i, 3, "%02x", md[i]);
	out[64] = '\0';
}

/* A string as a JSON string's inside: quotes, backslashes and controls
 * escaped. */
static void
jesc(struct buf *b, const char *s)
{

	for (; s != NULL && *s != '\0'; s++) {
		if (*s == '"' || *s == '\\')
			buf_appendf(b, "\\%c", *s);
		else if ((unsigned char)*s < 0x20)
			buf_appendf(b, "\\u%04x", (unsigned char)*s);
		else
			buf_append(b, s, 1);
	}
}

/* The last line's seq and hash, read from the open file's end. */
static void
last_of(int fd, int64_t *seqp, char hash[65])
{
	char		 buf[AUDIT_LINE + 1], *p, *h;
	off_t		 end, from;
	ssize_t		 n;

	*seqp = 0;
	snprintf(hash, 65, "%s", "");
	if ((end = lseek(fd, 0, SEEK_END)) <= 0)
		return;
	from = end > AUDIT_LINE ? end - AUDIT_LINE : 0;
	if ((n = pread(fd, buf, (size_t)(end - from), from)) <= 0)
		return;
	buf[n] = '\0';
	while (n > 0 && buf[n - 1] == '\n')
		buf[--n] = '\0';
	p = (p = strrchr(buf, '\n')) != NULL ? p + 1 : buf;
	if (strncmp(p, "{\"seq\":", 7) == 0)
		*seqp = strtoll(p + 7, NULL, 10);
	if ((h = strstr(p, ",\"hash\":\"")) != NULL && strlen(h + 9) >= 64)
		snprintf(hash, 65, "%.64s", h + 9);
}

/*
 * An Audit Event: event names what happened (identity-issued,
 * identity-revoked, reauthorisation-due, policies-changed,
 * policies-applied); action the Policy Action (Allow, Block) or, for
 * what the System Administrator changes, Administer; policy, how,
 * where, who and why as [R65] has them.
 */
void
audit_add(const char *event, const char *action, const char *policy,
    const char *how, const char *where, const char *who, const char *fmt, ...)
{
	struct buf	*b;
	va_list		 ap;
	uint8_t		 key[32];
	char		 path[MAXPATHLEN], prev[65], hash[65], *why, *body;
	char		 when[32];
	int64_t		 seq;
	time_t		 now;
	int		 fd;

	if (audit_key(key) == -1) {
		log_msg(LOG_ERR, "audit: no key: %s", strerror(errno));
		return;
	}
	va_start(ap, fmt);
	if (vasprintf(&why, fmt, ap) == -1)
		why = NULL;
	va_end(ap);
	snprintf(path, sizeof(path), "%s/%s", cfg.datadir, AUDIT_FILE);
	if ((fd = open(path, O_RDWR | O_CREAT | O_APPEND | O_CLOEXEC, 0600)) ==
	    -1) {
		log_msg(LOG_ERR, "audit: %s: %s", path, strerror(errno));
		free(why);
		explicit_bzero(key, sizeof(key));
		return;
	}
	(void)flock(fd, LOCK_EX);
	last_of(fd, &seq, prev);
	now = time(NULL);
	strftime(when, sizeof(when), "%Y-%m-%dT%H:%M:%SZ", gmtime(&now));
	b = buf_alloc(512);
	buf_appendf(b, "{\"seq\":%jd,\"t\":%jd,\"when\":\"%s\",\"event\":\"",
	    (intmax_t)seq + 1, (intmax_t)now, when);
	jesc(b, event);
	buf_appendf(b, "\",\"action\":\"");
	jesc(b, action);
	buf_appendf(b, "\",\"policy\":\"");
	jesc(b, policy);
	buf_appendf(b, "\",\"how\":\"");
	jesc(b, how);
	buf_appendf(b, "\",\"where\":\"");
	jesc(b, where);
	buf_appendf(b, "\",\"who\":\"");
	jesc(b, who);
	buf_appendf(b, "\",\"why\":\"");
	jesc(b, why);
	buf_appendf(b, "\",\"prev\":\"%s\"", prev);
	/* What the hash covers, then the line with it. */
	if ((body = strndup((char *)b->data, b->offset)) == NULL) {
		log_msg(LOG_ERR, "audit: out of memory");
		goto out;
	}
	mac(key, prev, body, hash);
	free(body);
	buf_appendf(b, ",\"hash\":\"%s\"}\n", hash);
	if (write(fd, b->data, b->offset) != (ssize_t)b->offset)
		log_msg(LOG_ERR, "audit: %s: %s", path, strerror(errno));
	(void)fsync(fd);
out:
	(void)flock(fd, LOCK_UN);
	close(fd);
	buf_free(b);
	free(why);
	explicit_bzero(key, sizeof(key));
}

/*
 * The trail read and its chain checked: the newest events first (at
 * most AUDIT_READ, those the filter keeps), whether the whole is
 * intact, and the first line where it is not.
 */
static ucl_object_t *
audit_read(const char *filter, bool *intactp, int64_t *brokenp,
    int64_t *countp)
{
	struct ucl_parser	*p;
	ucl_object_t		*all, *o, *out;
	FILE			*fp;
	uint8_t			 key[32];
	char			 path[MAXPATHLEN], prev[65], want[65], *line;
	char			*h, *body;
	size_t			 cap;
	ssize_t			 n;
	int64_t			 seq, k;

	*intactp = true;
	*brokenp = 0;
	*countp = 0;
	all = ucl_object_typed_new(UCL_ARRAY);
	snprintf(path, sizeof(path), "%s/%s", cfg.datadir, AUDIT_FILE);
	if ((fp = fopen(path, "r")) == NULL || audit_key(key) == -1) {
		if (fp != NULL)
			fclose(fp);
		return (all);
	}
	(void)flock(fileno(fp), LOCK_SH);
	snprintf(prev, sizeof(prev), "%s", "");
	line = NULL;
	cap = 0;
	seq = 0;
	while ((n = getline(&line, &cap, fp)) > 0) {
		if (line[n - 1] == '\n')
			line[--n] = '\0';
		seq++;
		(*countp)++;
		/* Its own hash, of the one before's and of what is
		 * before its hash; its seq the next. */
		h = strstr(line, ",\"hash\":\"");
		if (*intactp && (h == NULL || strncmp(line, "{\"seq\":", 7) != 0 ||
		    strtoll(line + 7, NULL, 10) != seq || strlen(h + 9) < 66 ||
		    strncmp(strstr(line, ",\"prev\":\"") != NULL ? strstr(line,
		    ",\"prev\":\"") + 9 : "", prev, strlen(prev)) != 0)) {
			*intactp = false;
			*brokenp = seq;
		}
		if (*intactp) {
			body = strndup(line, (size_t)(h - line));
			mac(key, prev, body, want);
			free(body);
			if (strncmp(h + 9, want, 64) != 0) {
				*intactp = false;
				*brokenp = seq;
			}
		}
		if (h != NULL && strlen(h + 9) >= 64)
			snprintf(prev, sizeof(prev), "%.64s", h + 9);
		if (filter != NULL && filter[0] != '\0' && strcasestr(line,
		    filter) == NULL)
			continue;
		p = ucl_parser_new(UCL_PARSER_NO_IMPLICIT_ARRAYS |
		    UCL_PARSER_DISABLE_MACRO | UCL_PARSER_NO_TIME);
		if (ucl_parser_add_string(p, line, 0) && (o =
		    ucl_parser_get_object(p)) != NULL) {
			ucl_object_delete_key(o, "prev");
			ucl_object_delete_key(o, "hash");
			ucl_array_append(all, o);
		}
		ucl_parser_free(p);
	}
	free(line);
	(void)flock(fileno(fp), LOCK_UN);
	fclose(fp);
	explicit_bzero(key, sizeof(key));
	/* Newest first, the last AUDIT_READ. */
	out = ucl_object_typed_new(UCL_ARRAY);
	for (k = (int64_t)ucl_array_size(all) - 1; k >= 0 && (int64_t)
	    ucl_array_size(out) < AUDIT_READ; k--)
		ucl_array_append(out, ucl_object_copy(ucl_array_find_index(all,
		    (unsigned int)k)));
	ucl_object_unref(all);
	return (out);
}

/*
 * GET /api/sdwan/audit[.csv]?q=: the audit trail, newest first, with
 * whether its chain is intact and where it broke; q keeps the events
 * with it anywhere in them.  As CSV with .csv.
 */
int
api_sdwan_audit(struct http_request *req)
{
	ucl_object_t		*events, *out;
	const ucl_object_t	*e;
	ucl_object_iter_t	 it;
	struct buf		*b;
	char			*q;
	int64_t			 broken, count;
	bool			 intact, csv;

	if (!guard(req, false))
		return (WEB_OK);
	csv = strstr(req->path, ".csv") != NULL;
	q = NULL;
	(void)http_argument_get_string(req, "q", &q);
	events = audit_read(q, &intact, &broken, &count);
	if (!csv) {
		out = ucl_object_typed_new(UCL_OBJECT);
		ucl_object_insert_key(out, ucl_object_frombool(intact), "intact", 0,
		    false);
		ucl_object_insert_key(out, broken > 0 ? ucl_object_fromint(broken) :
		    ucl_object_typed_new(UCL_NULL), "broken_at", 0, false);
		ucl_object_insert_key(out, ucl_object_fromint(count), "count", 0,
		    false);
		ucl_object_insert_key(out, events, "events", 0, false);
		return (reply_json(req, 200, out));
	}
	b = buf_alloc(4096);
	buf_appendf(b, "seq,when,event,action,policy,how,where,who,why\n");
	it = NULL;
	while ((e = ucl_object_iterate(events, &it, true)) != NULL) {
		static const char *const k[] = { "when", "event", "action",
		    "policy", "how", "where", "who", "why" };
		const char	*v;
		size_t		 i, j;

		buf_appendf(b, "%jd", (intmax_t)ucl_object_toint(
		    ucl_object_lookup(e, "seq")));
		for (i = 0; i < nitems(k); i++) {
			v = ucl_object_lookup(e, k[i]) != NULL ?
			    ucl_object_tostring_forced(ucl_object_lookup(e, k[i])) :
			    "";
			buf_appendf(b, ",\"");
			for (j = 0; v[j] != '\0'; j++) {
				if (v[j] == '"')
					buf_appendf(b, "\"\"");
				else
					buf_append(b, &v[j], 1);
			}
			buf_appendf(b, "\"");
		}
		buf_appendf(b, "\n");
	}
	ucl_object_unref(events);
	http_response_header(req, "content-type", "text/csv; charset=utf-8");
	http_response_header(req, "content-disposition", "attachment; "
	    "filename=\"sdwan-audit.csv\"");
	http_response(req, 200, b->data, b->offset);
	buf_free(b);
	return (WEB_OK);
}
