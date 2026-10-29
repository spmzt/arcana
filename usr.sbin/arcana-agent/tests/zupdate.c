/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * zupdate: agent-update with the bytes of a file as they are, said to
 * inflate to size bytes and to have the SHA-256 given, for
 * agent_test.sh: what a sender that lies about them sends, which
 * arcanactl never does.  The agent's error, or "ok"; exit 1 when it
 * refused.
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

#include <arcana.h>

int
main(int argc, char **argv)
{
	struct arcana_agent_update_input	 in;
	struct arcana_agent_update_output	 out;
	struct stat				 sb;
	cbl_family_info				*info;
	cbl_ctx					*ctx;
	cbl_conn				*c;
	cbl_msg					*req, *rep = NULL;
	cbl_yarena				*a;
	const char				*errstr;
	uint8_t					*data;
	char					 why[256];
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
	if ((error = cbl_ctx_new(&ctx)) != 0 ||
	    (error = cbl_ctx_set_limit(ctx, CBL_LIM_MAX_FRAME,
	    8 * 1024 * 1024)) != 0 ||
	    (error = cbl_conn_new(ctx, argv[1], 0, &c)) != 0 ||
	    (error = cbl_conn_connect(c)) != 0 ||
	    (error = cbl_resolve(c, ARC_FAMILY_NAME, &info)) != 0)
		errc(1, error, "%s", argv[1]);
	if ((error = cbl_msg_new(ctx, cbl_family_info_id(info),
	    ARC_CMD_AGENT_UPDATE, 0, &req)) != 0 ||
	    (error = arcana_agent_update_input_put(req, &in)) != 0)
		errc(1, error, "agent-update");
	if ((error = cbl_request(c, req, &rep, 60000)) != 0) {
		printf("%s\n", rep != NULL && cbl_msg_err_str(rep) != NULL ?
		    cbl_msg_err_str(rep) : strerror(error));
		return (1);
	}
	if ((a = cbl_yarena_new()) == NULL)
		err(1, NULL);
	memset(&out, 0, sizeof(out));
	if (arcana_agent_update_output_parse(rep, &out, a, CBL_YD_STRICT, why,
	    sizeof(why)) != 0)
		errx(1, "the reply: %s", why);
	printf("%s\n", out.ok ? "ok" : out.error != NULL ? out.error :
	    "failed");
	error = out.ok ? 0 : 1;
	cbl_yarena_free(a);
	cbl_msg_free(rep);
	cbl_family_info_free(info);
	cbl_conn_free(c);
	cbl_ctx_free(ctx);
	free(data);
	return (error);
}
