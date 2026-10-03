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
