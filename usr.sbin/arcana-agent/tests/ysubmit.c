/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * ysubmit: arcana-jobs' submit rpc over cblink's YANG family, for
 * agent_test.sh: one if-state change per interface named, each brought
 * up, to the agent at uri; the jobs' ids, one a line, or the agent's
 * refusal and exit 1.
 *
 *	ysubmit uri interface ...
 */

#include <err.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <cblink.h>
#include <cbl_schema.h>

#include "ymodel.h"

typedef struct arcana_jobs_submit_input_change ychange;

/* The rpc's node, and its input's and output's. */
static const struct cbl_ynode *
rpc_node(const char *name, const struct cbl_ynode **in,
    const struct cbl_ynode **out)
{
	const struct cbl_ymodule	*m;
	const struct cbl_ynode		*n;
	uint32_t			 i, k;

	for (i = 0; i < ymodel_schema.nmod; i++) {
		m = ymodel_schema.mod[i];
		if (strcmp(m->name, "arcana-jobs") != 0)
			continue;
		for (k = 0; k < m->ntop; k++) {
			if (strcmp((n = m->top[k])->name, name) != 0)
				continue;
			*in = *out = NULL;
			for (i = 0; i < n->nchild; i++)
				if (n->child[i]->kind == CBL_YN_INPUT)
					*in = n->child[i];
				else if (n->child[i]->kind == CBL_YN_OUTPUT)
					*out = n->child[i];
			return (n);
		}
	}
	return (NULL);
}

int
main(int argc, char **argv)
{
	struct arcana_jobs_submit_input_change_if_state *st;
	struct arcana_jobs_submit_input	 in;
	struct arcana_jobs_submit_output out;
	const struct cbl_ynode		*n, *nin, *nout;
	cbl_ctx				*ctx;
	cbl_conn			*c;
	cbl_msg				*req, *rep = NULL;
	cbl_yarena			*a;
	ychange				*v;
	char				 why[256];
	int				 i, error;

	if (argc < 3)
		errx(2, "usage: ysubmit uri interface ...");
	if ((n = rpc_node("submit", &nin, &nout)) == NULL || nin == NULL ||
	    nout == NULL)
		errx(1, "no arcana-jobs:submit in the tables");
	if ((v = calloc((size_t)argc - 2, sizeof(*v))) == NULL ||
	    (st = calloc((size_t)argc - 2, sizeof(*st))) == NULL)
		err(1, NULL);
	for (i = 2; i < argc; i++) {
		st[i - 2].interface = argv[i];
		st[i - 2].has_up = true;
		st[i - 2].up = true;
		v[i - 2].kind = ARCANA_JOBS_SUBMIT_INPUT_CHANGE_KIND_IF_STATE;
		v[i - 2].if_state = &st[i - 2];
	}
	memset(&in, 0, sizeof(in));
	in.change.n = (size_t)argc - 2;
	in.change.v = v;
	if ((error = cbl_ctx_new(&ctx)) != 0 ||
	    (error = cbl_conn_new(ctx, argv[1], 0, &c)) != 0 ||
	    (error = cbl_conn_connect(c)) != 0)
		errc(1, error, "%s", argv[1]);
	if ((error = cbl_msg_new(ctx, CBL_YANG_FAMILY, CBL_YCMD_RPC, 0,
	    &req)) != 0 || (error = cbl_msg_put_ynode(req, nin, &in)) != 0)
		errc(1, error, "submit");
	if ((error = cbl_request(c, req, &rep, 5000)) != 0) {
		fprintf(stderr, "ysubmit: %s\n", rep != NULL &&
		    cbl_msg_err_str(rep) != NULL ? cbl_msg_err_str(rep) :
		    strerror(error));
		return (1);
	}
	if ((a = cbl_yarena_new()) == NULL)
		err(1, NULL);
	memset(&out, 0, sizeof(out));
	if ((error = cbl_msg_ydecode(rep, nout, &out, a, CBL_YD_STRICT, why,
	    sizeof(why))) != 0)
		errx(1, "the output: %s", why);
	for (size_t k = 0; k < out.id.n; k++)
		printf("%ju\n", (uintmax_t)out.id.v[k]);
	cbl_yarena_free(a);
	cbl_msg_free(rep);
	cbl_conn_free(c);
	cbl_ctx_free(ctx);
	free(st);
	free(v);
	return (0);
}
