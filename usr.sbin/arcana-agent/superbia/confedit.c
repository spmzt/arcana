/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Superbia: what a jail is configured to be, changed in its jail.conf
 * with libjailconf.  The file before the change is kept beside it, and
 * jail(8) reads the result back before it is believed.
 */

#include <sys/param.h>
#include <sys/ioctl.h>
#include <sys/jail.h>
#include <sys/socket.h>
#include <sys/sockio.h>

#include <net/if.h>
#include <netinet/in.h>
#include <netinet/in_var.h>
#include <netinet6/in6_var.h>
#include <netinet6/nd6.h>
#include <arpa/inet.h>

#include <err.h>
#include <errno.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <jail.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "jailconf.h"
#include "agent.h"

/* list ("a,b") with addr added or removed. */
const char *
list_edit(struct work *w, const char *key, const char *list, const char *addr,
    bool add)
{
	char		*copy, *p, *tok;
	const char	*out;

	out = "";
	if (list != NULL && *list != '\0') {
		if ((copy = strdup(list)) == NULL)
			err(1, "strdup");
		for (p = copy; (tok = strsep(&p, ",")) != NULL; ) {
			if (!add && jc_value_equal(key, tok, addr))
				continue;
			out = *out == '\0' ? wstrdup(w, tok) :
			    wfmt(w, "%s,%s", out, tok);
		}
		free(copy);
	}
	if (add)
		out = *out == '\0' ? wstrdup(w, addr) :
		    wfmt(w, "%s,%s", out, addr);
	return (out);
}

bool
list_has(const char *key, const char *list, const char *addr)
{
	char	*copy, *p, *tok;
	bool	 found;

	if (list == NULL || *list == '\0')
		return (false);
	if ((copy = strdup(list)) == NULL)
		err(1, "strdup");
	found = false;
	for (p = copy; (tok = strsep(&p, ",")) != NULL; )
		if (jc_value_equal(key, tok, addr))
			found = true;
	free(copy);
	return (found);
}

/* Keep the previous configuration next to the file, mode 0600. */
int
write_backup(struct work *w, const char *path, const char *buf, size_t len,
    const char **errp)
{
	const char	*bak;
	ssize_t		 n;
	size_t		 off;
	int		 fd, step;

	bak = wfmt(w, "%s.arcana.bak", path);
	step = step_begin(w, ARC_STEP_KIND_FILE, "write",
	    "previous version to %s", bak);
	if ((fd = open(bak, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC,
	    0600)) == -1)
		goto fail;
	for (off = 0; off < len; off += (size_t)n)
		if ((n = write(fd, buf + off, len - off)) <= 0) {
			close(fd);
			goto fail;
		}
	if (fsync(fd) == -1) {
		close(fd);
		goto fail;
	}
	close(fd);
	step_end(w, step, true, NULL);
	return (0);
fail:
	*errp = wfmt(w, "%s: %s", bak, strerror(errno));
	step_end(w, step, false, "%s", *errp);
	return (-1);
}

/*
 * After writing: let jail(8) read the scope again; does the jail's
 * resolved key now hold (add) or lack (remove) the value?
 */
bool
verify_jail8(struct work *w, const char *scope, const char *name,
    const char *key, const char *value, bool add)
{
	const struct arc_param	*p;
	struct cjail		*js;
	const char		*e;
	size_t			 n, i, v;
	bool			 found;

	if (conf_scope_read(w, scope, &js, &n, &e) == -1)
		return (false);
	for (i = 0; i < n; i++) {
		if (strcmp(js[i].name, name) != 0)
			continue;
		p = cjail_param(&js[i], key);
		found = false;
		for (v = 0; p != NULL && v < p->values.n; v++)
			if (jc_value_equal(key, p->values.v[v], value))
				found = true;
		return (found == add);
	}
	return (false);
}

/*
 * A file's text without arcana's block, the lines from begin to end
 * (each a whole line); what was between them in *innerp, "" when
 * there was no block.  The text is a copy: the caller's stays.
 */
char *
block_cut(struct work *w, const char *old, const char *begin, const char *end,
    char **innerp)
{
	char	*out, *b, *e;

	out = wstrdup(w, old);
	if (innerp != NULL)
		*innerp = wstrdup(w, "");
	if ((b = strstr(out, begin)) == NULL || (e = strstr(b, end)) == NULL)
		return (out);
	if (innerp != NULL)
		*innerp = wstrndup(w, b + strlen(begin), (size_t)(e - b -
		    strlen(begin)));
	memmove(b, e + strlen(end), strlen(e + strlen(end)) + 1);
	return (out);
}

/*
 * The text with arcana's block at its end: begin, the body, end; on a
 * line of its own.  A body NULL or empty adds no block.
 */
char *
block_add(struct work *w, const char *text, const char *begin, const char *end,
    const char *body)
{
	size_t	len;

	if (body == NULL || body[0] == '\0')
		return ((char *)(uintptr_t)text);
	len = strlen(text);
	return (wfmt(w, "%s%s%s%s%s", text, len > 0 && text[len - 1] != '\n' ?
	    "\n" : "", begin, body, end));
}

/*
 * A file written whole: a new file beside it, its mode set, synced,
 * closed once, then moved over the old; no symlink followed.  0, or -1
 * and why in *errp.
 */
int
file_put(struct work *w, const char *path, const char *text, mode_t mode,
    const char **errp)
{
	const char	*tmp;
	size_t		 len;
	int		 fd;

	tmp = wfmt(w, "%s.arcana-new", path);
	len = strlen(text);
	if ((fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC |
	    O_NOFOLLOW, mode)) == -1 || fchmod(fd, mode) != 0 || write(fd, text,
	    len) != (ssize_t)len || fsync(fd) != 0) {
		*errp = wfmt(w, "%s: %s", path, strerror(errno));
		if (fd != -1)
			(void)close(fd);
		(void)unlink(tmp);
		return (-1);
	}
	if (close(fd) != 0 || rename(tmp, path) != 0) {
		*errp = wfmt(w, "%s: %s", path, strerror(errno));
		(void)unlink(tmp);
		return (-1);
	}
	return (0);
}
