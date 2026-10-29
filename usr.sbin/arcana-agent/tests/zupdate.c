/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * zupdate: arcana-agent's update action with the bytes of a file as
 * they are, said to inflate to size bytes (0: sent as it is) and to
 * have the SHA-256 given, for agent_test.sh: what a sender that lies
 * about them sends, which arcanactl never does.  The agent's error, or
 * "ok"; exit 1 when it refused.
 *
 *	zupdate uri file size sha256
 */

#include <sys/stat.h>

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <cblink.h>
#include <cbl_schema.h>

#include "ymodel.h"

/* n's child name; NULL where it has none. */
static const struct cbl_ynode *
child(const struct cbl_ynode *n, const char *name)
{

	for (uint32_t i = 0; n != NULL && i < n->nchild; i++)
		if (strcmp(n->child[i]->name, name) == 0)
			return (n->child[i]);
	return (NULL);
}

int
main(int argc, char **argv)
{
	struct arcana_agent_agent_update_input	 in;
	struct cbl_ybuf				 t = { NULL, 0, 0 };
	const struct cbl_ymodule		*m;
	const struct cbl_ynode			*agent, *act, *input;
	struct stat				 sb;
	cbl_ctx					*ctx;
	cbl_conn				*c;
	cbl_msg					*req, *rep = NULL;
	const char				*errstr;
	uint8_t					*data;
	int					 error, fd;

	if (argc != 5)
		errx(2, "usage: zupdate uri file size sha256");
	if ((fd = open(argv[2], O_RDONLY)) == -1 || fstat(fd, &sb) == -1)
		err(1, "%s", argv[2]);
	if ((data = malloc((size_t)sb.st_size)) == NULL)
		err(1, NULL);
	if (read(fd, data, (size_t)sb.st_size) != sb.st_size)
		err(1, "%s", argv[2]);
	close(fd);
	memset(&in, 0, sizeof(in));
	in.binary.p = data;
	in.binary.len = (size_t)sb.st_size;
	in.sha256 = argv[4];
	in.program_size = (uint32_t)strtonum(argv[3], 0, UINT32_MAX, &errstr);
	if (errstr != NULL)
		errx(2, "size %s: %s", argv[3], errstr);
	in.has_program_size = in.program_size != 0;
	agent = NULL;
	for (uint32_t i = 0; agent == NULL && i < ymodel_schema.nmod; i++) {
		m = ymodel_schema.mod[i];
		for (uint32_t k = 0; strcmp(m->name, "arcana-agent") == 0 &&
		    k < m->ntop; k++)
			if (strcmp(m->top[k]->name, "agent") == 0)
				agent = m->top[k];
	}
	if ((act = child(agent, "update")) == NULL ||
	    (input = child(act, "input")) == NULL)
		errx(1, "arcana-agent's update is not in the tables");
	if ((error = cbl_ctx_new(&ctx)) != 0 ||
	    (error = cbl_ctx_set_limit(ctx, CBL_LIM_MAX_FRAME,
	    8 * 1024 * 1024)) != 0 ||
	    (error = cbl_conn_new(ctx, argv[1], 0, &c)) != 0 ||
	    (error = cbl_conn_connect(c)) != 0)
		errc(1, error, "%s", argv[1]);
	/* The action of the agent container, its target none of a list. */
	if ((error = cbl_msg_new(ctx, CBL_YANG_FAMILY, CBL_YCMD_RPC, 0,
	    &req)) != 0 || (error = cbl_msg_put_ynode(req, input, &in)) != 0 ||
	    (error = cbl_yiid_write(agent, NULL, 0, &t)) != 0 ||
	    (error = cbl_msg_put_yaction(req, t.p, t.len)) != 0)
		errc(1, error, "update");
	cbl_ybuf_free(&t);
	if ((error = cbl_request(c, req, &rep, 60000)) != 0) {
		printf("%s\n", rep != NULL && cbl_msg_err_str(rep) != NULL ?
		    cbl_msg_err_str(rep) : strerror(error));
		return (1);
	}
	printf("ok\n");
	cbl_msg_free(rep);
	cbl_conn_free(c);
	cbl_ctx_free(ctx);
	free(data);
	return (0);
}
