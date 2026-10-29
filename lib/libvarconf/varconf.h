/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * libvarconf: files of variable assignments read and changed in place,
 * every other byte, comments and layout included, left as it was:
 * rc.conf and rc.conf.d (sh(1)), loader.conf (the loader's), sysctl.conf
 * (sysctl(8)'s), each read as what reads it reads it.
 * rc.conf(5) and the rc.conf.d fragments rc(8) reads are sh(1) itself:
 * a variable's value is what sh(1) would give it, read with its
 * quoting rules, and what sh(1) would not settle by reading alone (an
 * expansion, an assignment inside an "if" or a function, one before a
 * command) is said so, never guessed.
 */

#ifndef _VARCONF_H_
#define _VARCONF_H_

#include <sys/types.h>

#include <stdbool.h>

enum vc_dialect {
	VC_SH,				/* rc.conf, rc.conf.d */
	VC_LOADER,			/* loader.conf, loader.conf.d */
	VC_SYSCTL,			/* sysctl.conf, sysctl.conf.local */
};

/* An assignment's value is not a literal: an expansion in it. */
#define	VC_COMPUTED	0x01
/* It may not run, or not when the file is read: in an "if", a loop, a
 * function, after "&&" or "||", or in a line sh(1) runs as a command. */
#define	VC_COND		0x02
/* Not one sh(1) runs as an assignment of the file's, as far as the
 * line can be read: an environment of a command, a word of one. */
#define	VC_OPAQUE	0x04

struct vc_assign {
	char		*name;
	char		*value;		/* literal; NULL if computed, opaque */
	unsigned	 flags;		/* VC_* */
	int		 line;		/* its name's, from 1 */
	size_t		 off;		/* its name's first byte */
	size_t		 voff, vend;	/* its value's bytes */
	size_t		 soff, send;	/* its line, the newline included */
	size_t		 nstmt;		/* assignments on that line */
};

struct vc_file {
	enum vc_dialect	 dialect;
	char		*text;
	size_t		 len;
	struct vc_assign *a;
	size_t		 na;
};

/*
 * rtadvd.conf(5): records of capabilities, as rtadvd(8)'s advcap.c reads
 * them (capconf.c).
 */
struct vc_cap {
	char		*name;
	char		 type;		/* '#', '=', '@', or 0: a flag */
	char		*value;		/* a number in decimal, a string */
	size_t		 off, end;	/* the field's bytes, its ":" not */
	/* Inside a string before it: tskip() splits one at each ":", so
	 * rtadvd(8) looks in it for a field, but it is no field to edit. */
	bool		 inner;
};

struct vc_record {
	char		**names;
	size_t		 nnames;
	struct vc_cap	*caps;
	size_t		 ncaps;
	char		*tc;		/* a last tc=: the record it brings */
	int		 line;
	size_t		 off, end;	/* its lines, the last newline in */
};

struct vc_capfile {
	char		*text;
	size_t		 len;
	struct vc_record *r;
	size_t		 nr;
};

__BEGIN_DECLS
int		 vc_parse(struct vc_file *, enum vc_dialect, const char *,
		    size_t, char *, size_t);
int		 vc_read(struct vc_file *, enum vc_dialect, const char *,
		    char *, size_t);
void		 vc_free(struct vc_file *);
bool		 vc_name_ok(enum vc_dialect, const char *);
const struct vc_assign *vc_get(const struct vc_file *, const char *);
bool		 vc_settled(const struct vc_file *, const char *);
int		 vc_set(struct vc_file *, const char *, const char *, char *,
		    size_t);
int		 vc_unset(struct vc_file *, const char *, char *, size_t);
int		 vc_comment(struct vc_file *, const char *, const char *,
		    char *, size_t);
int		 vc_uncomment(struct vc_file *, const char *, const char *,
		    char *, size_t);
int		 vc_write(const struct vc_file *, const char *, mode_t, char *,
		    size_t);
int		 vc_rcd_path(const char *, const char *, const char *, char *,
		    size_t, char *, size_t);
int		 vc_rc_files(const char *, const char *, const char *,
		    const char *, char ***, size_t *, char *, size_t);
void		 vc_rc_files_free(char **, size_t);
int		 vc_cap_parse(struct vc_capfile *, const char *, size_t, char *,
		    size_t);
int		 vc_cap_read(struct vc_capfile *, const char *, char *, size_t);
void		 vc_cap_free(struct vc_capfile *);
const struct vc_record *vc_cap_record(const struct vc_capfile *,
		    const char *);
const struct vc_cap *vc_cap_get(const struct vc_capfile *, const char *,
		    const char *, char);
int		 vc_cap_set(struct vc_capfile *, const char *, const char *,
		    char, const char *, char *, size_t);
int		 vc_cap_unset(struct vc_capfile *, const char *, const char *,
		    char *, size_t);
int		 vc_cap_add_record(struct vc_capfile *, const char *,
		    const char *const *, size_t, char *, size_t);
int		 vc_cap_set_record(struct vc_capfile *, const char *,
		    const char *const *, size_t, char *, size_t);
char		*vc_cap_field(const char *, char, const char *);
int		 vc_cap_remove_record(struct vc_capfile *, const char *,
		    char *, size_t);
int		 vc_cap_write(const struct vc_capfile *, const char *, mode_t,
		    char *, size_t);
int		 vc_conflict(char *const *, size_t, const char *, char *,
		    size_t);
__END_DECLS

#endif /* !_VARCONF_H_ */
