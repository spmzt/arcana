/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * jailconf: add or remove one value of a jail's parameter in jail.conf(5)
 * in place, leaving the rest of the file as it was.
 */

#include <sys/param.h>
#include <sys/socket.h>
#include <sys/stat.h>

#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "jailconf.h"

#define	PATH_JAIL_CONF		"/etc/jail.conf"
#define	PATH_JAIL_CONF_D	"/etc/jail.conf.d"

static void	usage(void) __dead2;

static void
usage(void)
{

	fprintf(stderr, "usage: jailconf [-nv] [-f file] jail "
	    "parameter+=value\n"
	    "       jailconf [-nv] [-f file] jail parameter-=value\n");
	exit(2);
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
	char		 errbuf[1024];
	size_t		 outlen;
	unsigned char	 addr[16];
	bool		 add, dryrun, verbose;
	int		 ch, af, plen;

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

	if (jc_load(&conf, file) == -1)
		errx(1, "%s", conf.error);
	if ((b = jc_find(&conf, jail, &f)) == NULL)
		errx(1, "%s: no jail '%s'", file, jail);
	if (jc_edit(&conf, f, b, key, value, add, &out, &outlen, errbuf,
	    sizeof(errbuf)) == -1)
		errx(1, "%s", errbuf);
	if (!jc_verify(f->path, out, outlen, jail, key, value, add))
		errx(1, "%s: the edited text does not check out; not written",
		    f->path);
	if (dryrun || verbose) {
		diff = jc_diff(f->path, f->buf, f->len, out, outlen);
		fputs(diff, stdout);
		free(diff);
	}
	if (!dryrun && jc_write(f->path, out, outlen, errbuf,
	    sizeof(errbuf)) == -1)
		errx(1, "%s", errbuf);
	free(out);
	jc_free(&conf);
	free(key);
	return (0);
}
