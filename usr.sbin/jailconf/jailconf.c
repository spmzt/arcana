/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * jailconf: add or remove one value of a jail's parameter in jail.conf(5)
 * in place, leaving the rest of the file as it was.  What the jail is
 * configured with is jail(8)'s to say ("jail -f file -e sep").
 */

#include <sys/param.h>
#include <sys/capsicum.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include <capsicum_helpers.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "jailconf.h"

#define	PATH_JAIL		"/usr/sbin/jail"
#define	PATH_JAIL_CONF		"/etc/jail.conf"
#define	PATH_JAIL_CONF_D	"/etc/jail.conf.d"
/* jail -e separator: ASCII unit separator, never in a jail.conf value. */
#define	JAIL_E_SEP		'\037'

extern char	**environ;

static void	usage(void) __dead2;
static void	field_values(const char *, const char *, char ***, size_t *);
static int	jail_values(const char *, const char *, const char *,
		    char ***, size_t *);

static void
usage(void)
{

	fprintf(stderr, "usage: jailconf [-nv] [-f file] jail "
	    "parameter+=value\n"
	    "       jailconf [-nv] [-f file] jail parameter-=value\n");
	exit(2);
}

/*
 * The values of one field of jail(8) -e, "key=value,value" from s to
 * end, as quoted_print() in usr.sbin/jail/jail.c writes them: a value
 * quoted with " or ' when it holds blanks or quotes, '\\' escaping
 * '\\' and the quote.  None for a field without '=', a flag.
 */
static void
field_values(const char *s, const char *end, char ***vp, size_t *np)
{
	char	*cur;
	size_t	 len;
	char	 quote;

	*vp = NULL;
	*np = 0;
	if ((s = memchr(s, '=', (size_t)(end - s))) == NULL)
		return;
	if ((cur = malloc((size_t)(end - s))) == NULL)
		err(1, "malloc");
	len = 0;
	quote = 0;
	for (s++; ; s++) {
		if (s == end || (*s == ',' && quote == 0)) {
			if ((*vp = reallocarray(*vp, *np + 1,
			    sizeof(**vp))) == NULL ||
			    ((*vp)[*np] = strndup(cur, len)) == NULL)
				err(1, "malloc");
			(*np)++;
			len = 0;
			if (s == end)
				break;
		} else if (*s == '\\' && s + 1 < end)
			cur[len++] = *++s;
		else if (quote != 0 && *s == quote)
			quote = 0;
		else if (quote == 0 && (*s == '"' || *s == '\''))
			quote = *s;
		else
			cur[len++] = *s;
	}
	free(cur);
}

/*
 * What jail(8) reads in file: "jail -f file -e sep" prints each jail
 * the file configures on a line of its own, its name first, then its
 * parameters, globals, "*" blocks, variables and includes resolved.
 * The jail's values of key in *havep, *nhavep of them, and 1; 0 when
 * jail(8) has no such jail, -1 when it does not read the file (it says
 * why on the standard error).
 */
static int
jail_values(const char *file, const char *jail, const char *key,
    char ***havep, size_t *nhavep)
{
	posix_spawn_file_actions_t	 fa;
	char				*argv[6], sep[2], *buf, **v;
	const char			*line, *eol, *p, *q;
	size_t				 len, cap, n, i, klen;
	ssize_t				 r;
	pid_t				 pid;
	bool				 found;
	int				 fd[2], status;

	sep[0] = JAIL_E_SEP;
	sep[1] = '\0';
	argv[0] = (char *)(uintptr_t)PATH_JAIL;
	argv[1] = (char *)(uintptr_t)"-f";
	argv[2] = (char *)(uintptr_t)file;
	argv[3] = (char *)(uintptr_t)"-e";
	argv[4] = sep;
	argv[5] = NULL;
	if (pipe2(fd, O_CLOEXEC) == -1)
		err(1, "pipe");
	if (posix_spawn_file_actions_init(&fa) != 0 ||
	    posix_spawn_file_actions_adddup2(&fa, fd[1], STDOUT_FILENO) != 0)
		err(1, "posix_spawn_file_actions");
	if ((errno = posix_spawn(&pid, argv[0], &fa, NULL, argv,
	    environ)) != 0)
		err(1, "%s", argv[0]);
	posix_spawn_file_actions_destroy(&fa);
	close(fd[1]);
	buf = NULL;
	len = cap = 0;
	for (;;) {
		if (len + 4096 > cap) {
			cap = MAX(cap * 2, len + 4096);
			if ((buf = realloc(buf, cap)) == NULL)
				err(1, "realloc");
		}
		if ((r = read(fd[0], buf + len, cap - len)) == -1 &&
		    errno == EINTR)
			continue;
		if (r <= 0)
			break;
		len += (size_t)r;
	}
	close(fd[0]);
	while (waitpid(pid, &status, 0) == -1)
		if (errno != EINTR)
			err(1, "waitpid");
	if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
		free(buf);
		return (-1);
	}

	*havep = NULL;
	*nhavep = 0;
	found = false;
	klen = strlen(key);
	for (line = buf; !found && line < buf + len; line = eol + 1) {
		if ((eol = memchr(line, '\n', (size_t)(buf + len - line))) ==
		    NULL)
			eol = buf + len;
		/* name=jail, first. */
		if ((p = memchr(line, JAIL_E_SEP, (size_t)(eol - line))) ==
		    NULL)
			p = eol;
		if ((size_t)(p - line) < 5 || strncmp(line, "name=", 5) != 0)
			continue;
		field_values(line, p, &v, &n);
		found = n == 1 && strcmp(v[0], jail) == 0;
		for (i = 0; i < n; i++)
			free(v[i]);
		free(v);
		for (; found && p < eol; p = q) {
			p++;
			if ((q = memchr(p, JAIL_E_SEP, (size_t)(eol - p))) ==
			    NULL)
				q = eol;
			if ((size_t)(q - p) >= klen && strncmp(p, key, klen) ==
			    0 && (p + klen == q || p[klen] == '='))
				field_values(p, q, havep, nhavep);
		}
	}
	free(buf);
	return (found ? 1 : 0);
}

int
main(int argc, char *argv[])
{
	struct jc_conf	 conf;
	struct jc_block	*b;
	struct jc_file	*f;
	struct stat	 sb;
	const char	*file, *jail;
	char		*key, *value, *op, *out, *diff, def[MAXPATHLEN];
	char		 errbuf[1024], **have;
	size_t		 outlen, nhave, i;
	unsigned char	 addr[16];
	bool		 add, dryrun, verbose;
	int		 ch, af, plen, dfd, rc;

	file = NULL;
	dryrun = verbose = false;
	while ((ch = getopt(argc, argv, "f:nv")) != -1) {
		switch (ch) {
		case 'f':
			file = optarg;
			break;
		case 'n':
			dryrun = true;
			break;
		case 'v':
			verbose = true;
			break;
		default:
			usage();
		}
	}
	argc -= optind;
	argv += optind;
	if (argc != 2)
		usage();
	jail = argv[0];

	/* parameter+=value or parameter-=value */
	if ((key = strdup(argv[1])) == NULL)
		err(1, "strdup");
	if ((op = strchr(key, '=')) == NULL || op == key ||
	    (op[-1] != '+' && op[-1] != '-') || op - 1 == key)
		usage();
	add = op[-1] == '+';
	op[-1] = '\0';
	value = op + 1;
	if (*value == '\0')
		errx(1, "empty value");
	if ((strcmp(key, "ip4.addr") == 0 || strcmp(key, "ip6.addr") == 0) &&
	    (!jc_addr_split(value, &af, addr, &plen) ||
	    (af == AF_INET) != (strcmp(key, "ip4.addr") == 0)))
		errx(1, "%s: not a valid %s value", value, key);

	/* As rc.d/jail does: jail.conf.d/<jail>.conf, then jail.conf. */
	if (file == NULL) {
		snprintf(def, sizeof(def), "%s/%s.conf", PATH_JAIL_CONF_D,
		    jail);
		file = stat(def, &sb) == 0 ? def : PATH_JAIL_CONF;
	}

	/*
	 * jail(8) says what the jail is configured with, what it inherits
	 * included; the files are parsed here only to find the jail's
	 * block, in file or in what it includes, and the bytes to change.
	 */
	if ((rc = jail_values(file, jail, key, &have, &nhave)) == -1)
		errx(1, "%s: jail(8) does not read it", file);
	if (rc == 0)
		errx(1, "%s: jail(8) reads no jail '%s' there", file, jail);
	if (jc_load(&conf, file) == -1)
		errx(1, "%s", conf.error);
	if ((b = jc_find(&conf, jail, &f)) == NULL)
		errx(1, "%s: no block of jail '%s' in it or what it includes",
		    file, jail);
	/*
	 * The files are read, includes and all; the one to change is
	 * written in its directory, opened here.  Capability mode
	 * (capsicum(4)) from now: the edit, its check and the write
	 * reach nothing else.
	 */
	if (strrchr(f->path, '/') == NULL)
		snprintf(def, sizeof(def), ".");
	else
		snprintf(def, sizeof(def), "%.*s", strrchr(f->path, '/') ==
		    f->path ? 1 : (int)(strrchr(f->path, '/') - f->path),
		    f->path);
	if ((dfd = open(def, O_RDONLY | O_DIRECTORY | O_CLOEXEC)) == -1)
		err(1, "%s", def);
	caph_cache_catpages();
	if (caph_enter() == -1)
		err(1, "cap_enter");
	if (jc_edit(f, b, key, value, add, (const char *const *)have, nhave,
	    &out, &outlen, errbuf, sizeof(errbuf)) == -1)
		errx(1, "%s", errbuf);
	if (!jc_verify(f->path, out, outlen, jail, key, value, add))
		errx(1, "%s: the edited text does not check out; not written",
		    f->path);
	if (dryrun || verbose) {
		diff = jc_diff(f->path, f->buf, f->len, out, outlen);
		fputs(diff, stdout);
		free(diff);
	}
	if (!dryrun && jc_write_at(dfd, f->path, out, outlen, errbuf,
	    sizeof(errbuf)) == -1)
		errx(1, "%s", errbuf);
	close(dfd);
	free(out);
	for (i = 0; i < nhave; i++)
		free(have[i]);
	free(have);
	jc_free(&conf);
	free(key);
	return (0);
}
