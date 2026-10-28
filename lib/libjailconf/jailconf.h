/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * libjailconf: change values in jail.conf(5) in place.
 *
 * Reading configuration is jail(8)'s job: "jail -f file -e sep" says
 * what each jail is configured with, globals, "*" blocks, variables and
 * includes resolved, and libjail(3) what a running jail has.  This
 * library exists for the one thing jail(8) cannot do: add or remove a
 * single value of one jail's parameter while leaving every other byte
 * of the file, comments and layout included, as it was.  It parses
 * with the lexical rules of usr.sbin/jail/jaillex.l and keeps byte
 * offsets of the jails' blocks; includes are followed only to find the
 * file a jail's block is in, and global statements are not kept.  What
 * a jail inherits comes from the caller, as jail(8) reads it.
 */

#ifndef _JAILCONF_H_
#define _JAILCONF_H_

#include <sys/types.h>

#include <stdbool.h>

struct jc_part {
	bool		 isvar;		/* $name or ${name} */
	char		*s;
};

struct jc_value {
	struct jc_part	*parts;
	size_t		 nparts;
	size_t		 off;		/* raw span in the file */
	size_t		 end;
	char		 quote;		/* quote of the first piece, or 0 */
};

enum jc_op {
	JC_FLAG,			/* "persist;" */
	JC_SET,				/* "a = b;" */
	JC_APPEND,			/* "a += b;" */
	JC_NAMEVAL,			/* ".include x;" */
};

struct jc_stmt {
	char		*key;
	bool		 keyvar;	/* "$var = ..." */
	enum jc_op	 op;
	struct jc_value	*vals;
	size_t		 nvals;
	size_t		 off;		/* start of key */
	size_t		 end;		/* just past ';' */
	int		 line;
};

struct jc_block {
	char		*name;		/* hierarchical: "a.b" */
	size_t		 open;		/* offset of '{' */
	size_t		 close;		/* offset of '}' */
	int		 line;
	struct jc_stmt	*stmts;
	size_t		 nstmts;
};

struct jc_file {
	char		*path;
	char		*buf;
	size_t		 len;
	struct jc_block	*blocks;
	size_t		 nblocks;
};

struct jc_conf {
	struct jc_file	**files;	/* the file and what it includes */
	size_t		 nfiles;
	char		*error;		/* first error, "file line N: msg" */
};

__BEGIN_DECLS
int		 jc_load(struct jc_conf *, const char *);
int		 jc_load_buf(struct jc_conf *, const char *, const char *,
		    size_t);
void		 jc_free(struct jc_conf *);
struct jc_block	*jc_find(const struct jc_conf *, const char *,
		    struct jc_file **);
int		 jc_edit(struct jc_file *, struct jc_block *, const char *,
		    const char *, bool, const char *const *, size_t, char **,
		    size_t *, char *, size_t);
int		 jc_replace(struct jc_file *, const struct jc_block *,
		    const char *, const char *, char **, size_t *);
bool		 jc_verify(const char *, const char *, size_t, const char *,
		    const char *, const char *, bool);
char		*jc_diff(const char *, const char *, size_t, const char *,
		    size_t);
int		 jc_write(const char *, const char *, size_t, char *, size_t);
int		 jc_write_at(int, const char *, const char *, size_t, char *,
		    size_t);
bool		 jc_addr_split(const char *, int *, void *, int *);
bool		 jc_value_equal(const char *, const char *, const char *);
__END_DECLS

#endif /* !_JAILCONF_H_ */
