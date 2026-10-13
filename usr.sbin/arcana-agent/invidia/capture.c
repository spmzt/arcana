/*-
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Invidia: packets taken off the wire, or off a tap, with tcpdump(1),
 * of the host or of a jail's own network.  A source is an interface, a
 * bridge's span port, or a bpf(4) tap: since FreeBSD 16, each ipfw rule
 * with log (logdst bpf) has one of its own, ipfw and the rule's number
 * (ipfw100), on which what the rule matches is mirrored.  Without an
 * interface, the sources tcpdump -D lists.
 *
 * A capture is a few packets or seconds, whichever ends first: tcpdump
 * writes a pcap in a directory of /tmp only root reads (the jail's own
 * /tmp, in a jail), reads it back as lines, and the pcap goes with them,
 * to be saved; then both are taken away.
 */

#include <sys/param.h>
#include <sys/socket.h>
#include <sys/stat.h>

#include <net/if.h>

#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/evp.h>

#include <ucl.h>

#include "agent.h"

#define	CAPTURE_PACKETS	500	/* at most */
#define	CAPTURE_SECONDS	60

static bool
source_ok(const char *s)
{
	size_t	i;

	if (s == NULL || s[0] == '\0' || s[0] == '-' || strlen(s) >= IFNAMSIZ)
		return (false);
	for (i = 0; s[i] != '\0'; i++)
		if (!(s[i] >= 'a' && s[i] <= 'z') && !(s[i] >= 'A' && s[i] <=
		    'Z') && !(s[i] >= '0' && s[i] <= '9') && strchr("._-",
		    s[i]) == NULL)
			return (false);
	return (true);
}

/* tcpdump -D: "2.ipfw100 [Up, Connection status unknown]". */
static ucl_object_t *
sources(struct work *w, const char *prog)
{
	struct execres	 res;
	ucl_object_t	*arr;
	char		*argv[3], *text, *p, *line, *name;

	arr = ucl_object_typed_new(UCL_ARRAY);
	argv[0] = (char *)(uintptr_t)prog;
	argv[1] = (char *)(uintptr_t)"-D";
	argv[2] = NULL;
	if (run_exec(w, scope_jexec(w, argv), &res) != 0 || res.out == NULL)
		return (arr);
	text = wstrndup(w, res.out, res.outlen);
	p = text;
	while ((line = strsep(&p, "\n")) != NULL) {
		if ((name = strchr(line, '.')) == NULL)
			continue;
		name++;
		name[strcspn(name, " ")] = '\0';
		if (source_ok(name))
			ucl_array_append(arr, ucl_object_fromstring(name));
	}
	return (arr);
}

void
do_capture(struct work *w, const struct arc_capture_req *rq,
    struct arc_capture_rsp *rsp)
{
	struct execres	 res;
	ucl_object_t	*top, *lines;
	const char	*prog, *tmo, *path, *base, *f, *e, *tdir, *dname;
	char		*argv[64], *text, *p, *line, *pcap, *b64, *json;
	size_t		 len;
	int		 n, i, packets, seconds, got, tfd;
	bool		 timed;

	if ((prog = tool(w, "tcpdump")) == NULL) {
		rsp->error = "there is no tcpdump(1) here";
		return;
	}
	top = ucl_object_typed_new(UCL_OBJECT);
	if (rq->interface == NULL || rq->interface[0] == '\0') {
		ucl_object_insert_key(top, sources(w, prog), "sources", 0,
		    false);
		goto out;
	}
	if (!source_ok(rq->interface)) {
		ucl_object_unref(top);
		rsp->error = "a source is an interface or a tap's name";
		return;
	}
	if (rq->net_filter != NULL && strpbrk(rq->net_filter, "\r\n") != NULL) {
		ucl_object_unref(top);
		rsp->error = "a filter is one line of pcap-filter(7)";
		return;
	}
	if ((tmo = tool(w, "timeout")) == NULL) {
		ucl_object_unref(top);
		rsp->error = "there is no timeout(1) here";
		return;
	}
	packets = rq->has_packets && rq->packets > 0 ? (int)MIN(rq->packets,
	    CAPTURE_PACKETS) : 50;
	seconds = rq->has_seconds && rq->seconds > 0 ? (int)MIN(rq->seconds,
	    CAPTURE_SECONDS) : 10;
	/* A directory of its own, root's alone: what was on the wire is
	 * nobody else's to read while it is there. */
	tdir = wfmt(w, "%s/tmp", w->jail == NULL && opts.tools_dir != NULL ?
	    opts.tools_dir : "");
	dname = wfmt(w, ".arcana-capture.%08x", arc4random());
	if ((tfd = scope_dirfd(w, tdir)) == -1 || mkdirat(tfd, dname, 0700) ==
	    -1) {
		if (tfd != -1)
			close(tfd);
		ucl_object_unref(top);
		rsp->error = wfmt(w, "%s: %s", tdir, strerror(errno));
		return;
	}
	base = "c.pcap";
	path = wfmt(w, "%s/%s/%s", tdir, dname, base);
	n = 0;
	argv[n++] = (char *)(uintptr_t)tmo;
	argv[n++] = wfmt(w, "%d", seconds);
	argv[n++] = (char *)(uintptr_t)prog;
	argv[n++] = (char *)(uintptr_t)"-n";
	argv[n++] = (char *)(uintptr_t)"-U";
	argv[n++] = (char *)(uintptr_t)"-i";
	argv[n++] = (char *)(uintptr_t)rq->interface;
	argv[n++] = (char *)(uintptr_t)"-c";
	argv[n++] = wfmt(w, "%d", packets);
	argv[n++] = (char *)(uintptr_t)"-w";
	argv[n++] = (char *)(uintptr_t)path;
	/*
	 * The filter's words, each an argument, no shell between; and after
	 * "--", so that none of them is taken for an option of tcpdump's
	 * (-w a file, -z a command), which runs as root.
	 */
	argv[n++] = (char *)(uintptr_t)"--";
	for (f = rq->net_filter != NULL ? rq->net_filter : ""; *f != '\0' &&
	    n < 60; f = e) {
		f += strspn(f, " \t");
		if (*f == '\0')
			break;
		e = f + strcspn(f, " \t");
		argv[n++] = wstrndup(w, f, (size_t)(e - f));
	}
	argv[n] = NULL;
	timed = false;
	if (run_exec(w, scope_jexec(w, argv), &res) != 0) {
		/* timeout(1) ends it at the time asked for: 124. */
		if (res.status == 124)
			timed = true;
		else {
			(void)scope_rename(w, path, base, NULL);
			(void)unlinkat(tfd, dname, AT_REMOVEDIR);
			close(tfd);
			ucl_object_unref(top);
			rsp->error = res.errlen > 0 ? wtext(w, wstrndup(w,
			    res.err, strcspn(res.err, "\n"))) : wtext(w,
			    exec_error(w, &res, "tcpdump"));
			return;
		}
	}
	/* Read back, as lines. */
	lines = ucl_object_typed_new(UCL_ARRAY);
	argv[0] = (char *)(uintptr_t)prog;
	argv[1] = (char *)(uintptr_t)"-n";
	argv[2] = (char *)(uintptr_t)"-tttt";
	argv[3] = (char *)(uintptr_t)"-r";
	argv[4] = (char *)(uintptr_t)path;
	argv[5] = NULL;
	got = 0;
	if (run_exec(w, scope_jexec(w, argv), &res) == 0 && res.out != NULL) {
		text = wstrndup(w, res.out, res.outlen);
		p = text;
		while ((line = strsep(&p, "\n")) != NULL && got <
		    CAPTURE_PACKETS)
			if (line[0] != '\0') {
				ucl_array_append(lines, ucl_object_fromstring(
				    line));
				got++;
			}
	}
	/* And the pcap itself, to be saved. */
	if ((pcap = scope_slurp(w, path, &len)) != NULL) {
		b64 = wmalloc(w, 4 * ((len + 2) / 3) + 1);
		i = EVP_EncodeBlock((unsigned char *)b64, (unsigned char *)pcap,
		    (int)len);
		if (i >= 0) {
			b64[i] = '\0';
			ucl_object_insert_key(top, ucl_object_fromstring(b64),
			    "pcap", 0, false);
		}
		ucl_object_insert_key(top, ucl_object_fromint((int64_t)len),
		    "bytes", 0, false);
	}
	(void)scope_rename(w, path, base, NULL);
	(void)unlinkat(tfd, dname, AT_REMOVEDIR);
	close(tfd);
	ucl_object_insert_key(top, ucl_object_fromstring(rq->interface),
	    "source", 0, false);
	ucl_object_insert_key(top, ucl_object_fromstring(rq->net_filter !=
	    NULL ? rq->net_filter : ""), "filter", 0, false);
	ucl_object_insert_key(top, ucl_object_fromint(got), "packets", 0,
	    false);
	ucl_object_insert_key(top, ucl_object_fromint(packets), "limit", 0,
	    false);
	ucl_object_insert_key(top, ucl_object_fromint(seconds), "seconds", 0,
	    false);
	ucl_object_insert_key(top, ucl_object_frombool(timed), "timed_out", 0,
	    false);
	ucl_object_insert_key(top, lines, "lines", 0, false);
out:
	json = (char *)ucl_object_emit(top, UCL_EMIT_JSON_COMPACT);
	rsp->json = json != NULL ? wtext(w, wstrdup(w, json)) : NULL;
	free(json);
	ucl_object_unref(top);
	rsp->ok = rsp->json != NULL;
}
