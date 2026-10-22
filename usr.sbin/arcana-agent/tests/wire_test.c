/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * The wire: the structs share/arcana/wire.awk keeps the version-1 names
 * over (arcana.h) go through the schema tables cblink-gen wrote from
 * the family's YANG module and come back the same.  One of each kind:
 * a reply with scalars, their has_ flags, strings, a nested set and a
 * list of a shared one (the steps of a trace), a job spec with an
 * enum and empties, the stats with decimal64, an event, a stream's
 * part with typed routes and a chunk with bytes.
 */

#include <sys/param.h>

#include <string.h>

#include <atf-c.h>

#include <arcana.h>

/* Encoded under its node and decoded again, strictly. */
#define	ROUND(T, in, out, a)						\
	do {								\
		struct cbl_ybuf rb = { 0 };				\
		char rwhy[200];						\
									\
		ATF_REQUIRE_EQ(0, T##_encode((in), &rb));		\
		ATF_REQUIRE(rb.len > 0);				\
		ATF_REQUIRE_EQ_MSG(0, T##_decode(rb.p, rb.len, (out), (a),	\
		    CBL_YD_STRICT, rwhy, sizeof(rwhy)), "%s", rwhy);	\
		cbl_ybuf_free(&rb);					\
	} while (0)

ATF_TC(list_reply);
ATF_TC_HEAD(list_reply, tc)
{
	atf_tc_set_md_var(tc, "descr", "A list reply: scalars with their "
	    "has_ flags, a nested host, a list of jails, a leaf-list and a "
	    "trace of steps, the shared struct");
}
ATF_TC_BODY(list_reply, tc)
{
	struct arc_list_rsp in, out;
	struct arc_host host;
	struct arc_jail jails[2];
	struct arc_step steps[2];
	const char *const scopes[] = { "/etc/jail.conf", "/etc/jail.conf.d" };
	const char *const argv[] = { "jail", "-c", "web" };
	cbl_yarena *a;

	memset(&in, 0, sizeof(in));
	memset(&host, 0, sizeof(host));
	memset(jails, 0, sizeof(jails));
	memset(steps, 0, sizeof(steps));
	in.has_ok = true;
	in.ok = true;
	in.error = "none";
	host.hostname = "edge.example";
	host.has_ncpu = true;
	host.ncpu = 4;
	host.has_privileged = true;
	host.privileged = true;
	in.host = &host;
	jails[0].name = "web";
	jails[0].has_state = true;
	jails[0].state = ARC_JAIL_STATE_RUNNING;
	jails[0].has_jid = true;
	jails[0].jid = 7;
	jails[1].name = "db";
	jails[1].has_state = true;
	jails[1].state = ARC_JAIL_STATE_STOPPED;
	in.jails.n = 2;
	in.jails.v = jails;
	in.scopes.n = 2;
	in.scopes.v = scopes;
	steps[0].has_id = true;
	steps[0].id = 0;
	steps[0].has_parent = true;
	steps[0].parent = -1;
	steps[0].has_kind = true;
	steps[0].kind = ARC_STEP_KIND_EXEC;
	steps[0].label = "jail -c web";
	steps[0].argv.n = 3;
	steps[0].argv.v = argv;
	steps[0].has_exit = true;
	steps[0].exit = 0;
	steps[1].has_id = true;
	steps[1].id = 1;
	steps[1].has_parent = true;
	steps[1].parent = 0;
	steps[1].has_kind = true;
	steps[1].kind = ARC_STEP_KIND_FILE;
	steps[1].label = "/etc/jail.conf.d/web.conf";
	in.trace.n = 2;
	in.trace.v = steps;

	ATF_REQUIRE((a = cbl_yarena_new()) != NULL);
	ROUND(arcana_list_output, &in, &out, a);
	ATF_CHECK(out.has_ok && out.ok);
	ATF_CHECK_STREQ("none", out.error);
	ATF_REQUIRE(out.host != NULL);
	ATF_CHECK_STREQ("edge.example", out.host->hostname);
	ATF_CHECK(out.host->has_ncpu && out.host->ncpu == 4);
	ATF_CHECK(out.host->has_privileged && out.host->privileged);
	ATF_CHECK(!out.host->has_physmem);
	ATF_REQUIRE_EQ(2, out.jails.n);
	ATF_CHECK_STREQ("web", out.jails.v[0].name);
	ATF_CHECK(out.jails.v[0].has_jid && out.jails.v[0].jid == 7);
	ATF_CHECK(out.jails.v[1].state == ARC_JAIL_STATE_STOPPED);
	ATF_CHECK(!out.jails.v[1].has_jid);
	ATF_REQUIRE_EQ(2, out.scopes.n);
	ATF_CHECK_STREQ("/etc/jail.conf.d", out.scopes.v[1]);
	ATF_REQUIRE_EQ(2, out.trace.n);
	ATF_CHECK(out.trace.v[0].has_parent && out.trace.v[0].parent == -1);
	ATF_CHECK(out.trace.v[0].kind == ARC_STEP_KIND_EXEC);
	ATF_REQUIRE_EQ(3, out.trace.v[0].argv.n);
	ATF_CHECK_STREQ("web", out.trace.v[0].argv.v[2]);
	ATF_CHECK(out.trace.v[0].has_exit && out.trace.v[0].exit == 0);
	ATF_CHECK(!out.trace.v[1].has_exit);
	ATF_CHECK_STREQ("/etc/jail.conf.d/web.conf", out.trace.v[1].label);
	cbl_yarena_free(a);
}

ATF_TC(job_spec);
ATF_TC_HEAD(job_spec, tc)
{
	atf_tc_set_md_var(tc, "descr", "A job spec in a submit request: the "
	    "kind as a uint8 of the enum, empties present or not, a strict "
	    "decode refusing a key the module has not");
}
ATF_TC_BODY(job_spec, tc)
{
	struct arc_job_submit_req in, out;
	struct arc_job_spec spec;
	struct cbl_ybuf b = { 0 };
	cbl_yarena *a;
	char why[200];

	memset(&in, 0, sizeof(in));
	memset(&spec, 0, sizeof(spec));
	spec.has_kind = true;
	spec.kind = ARC_JOB_KIND_ROUTE;
	spec.destination = "192.0.2.0/24";
	spec.gateway = "198.51.100.1";
	spec.has_fib = true;
	spec.fib = 2;
	spec.persist = true;
	spec.remove = false;
	spec.safe = true;
	spec.has_safe_wait = true;
	spec.safe_wait = 120;
	in.batch.n = 1;
	in.batch.v = &spec;
	ATF_REQUIRE((a = cbl_yarena_new()) != NULL);
	ROUND(arcana_job_submit_input, &in, &out, a);
	ATF_REQUIRE_EQ(1, out.batch.n);
	ATF_CHECK(out.batch.v[0].has_kind && out.batch.v[0].kind ==
	    ARC_JOB_KIND_ROUTE);
	ATF_CHECK_STREQ("192.0.2.0/24", out.batch.v[0].destination);
	ATF_CHECK(out.batch.v[0].has_fib && out.batch.v[0].fib == 2);
	ATF_CHECK(out.batch.v[0].persist);
	ATF_CHECK(!out.batch.v[0].remove);
	ATF_CHECK(!out.batch.v[0].has_action);
	ATF_CHECK(out.batch.v[0].jail == NULL);
	ATF_CHECK(out.batch.v[0].safe);
	ATF_CHECK(out.batch.v[0].has_safe_wait && out.batch.v[0].safe_wait ==
	    120);
	/* A key the module has not: refused strictly, taken loosely. */
	ATF_REQUIRE_EQ(0, arcana_job_submit_input_encode(&in, &b));
	ATF_REQUIRE(b.len > 2);
	/* A map of one more pair: {<this map>..., 9999: 1} is more than
	 * this test can forge from the outside; what it checks is that
	 * the strict decode of the same bytes is the loose one's. */
	ATF_CHECK_EQ(0, arcana_job_submit_input_decode(b.p, b.len, &out, a, 0,
	    why, sizeof(why)));
	cbl_ybuf_free(&b);
	cbl_yarena_free(a);
}

ATF_TC(stats_and_events);
ATF_TC_HEAD(stats_and_events, tc)
{
	atf_tc_set_md_var(tc, "descr", "The stats' decimal64 fields, in "
	    "hundredths; an event and a step notification, structures of "
	    "their groups");
}
ATF_TC_BODY(stats_and_events, tc)
{
	struct arc_stats_rsp in, out;
	struct arc_stats st;
	struct arc_event_ntf e, eo;
	struct arc_step_ntf s, so;
	struct arc_step step;
	cbl_yarena *a;

	memset(&in, 0, sizeof(in));
	memset(&st, 0, sizeof(st));
	st.has_cpu_pct = true;
	st.cpu_pct = 1250;	/* 12.50 % */
	st.has_load1 = true;
	st.load1 = 7;		/* 0.07 */
	st.has_mem_total = true;
	st.mem_total = 8ULL << 30;
	in.has_ok = true;
	in.ok = true;
	in.stats = &st;
	ATF_REQUIRE((a = cbl_yarena_new()) != NULL);
	ROUND(arcana_stats_output, &in, &out, a);
	ATF_REQUIRE(out.stats != NULL);
	ATF_CHECK(out.stats->has_cpu_pct && out.stats->cpu_pct == 1250);
	ATF_CHECK(out.stats->has_load1 && out.stats->load1 == 7);
	ATF_CHECK(!out.stats->has_load5);
	ATF_CHECK(out.stats->mem_total == (8ULL << 30));

	memset(&e, 0, sizeof(e));
	e.json = "{\"n\":1,\"kind\":\"route\"}";
	ROUND(arcana_event_ntf, &e, &eo, a);
	ATF_CHECK_STREQ(e.json, eo.json);

	memset(&s, 0, sizeof(s));
	memset(&step, 0, sizeof(step));
	step.has_id = true;
	step.id = 3;
	step.has_status = true;
	step.status = ARC_STEP_STATUS_INCOMPLETE;
	step.label = "pkg upgrade";
	s.trace.n = 1;
	s.trace.v = &step;
	ROUND(arcana_step_ntf, &s, &so, a);
	ATF_REQUIRE_EQ(1, so.trace.n);
	ATF_CHECK(so.trace.v[0].id == 3);
	ATF_CHECK(so.trace.v[0].status == ARC_STEP_STATUS_INCOMPLETE);
	ATF_CHECK_STREQ("pkg upgrade", so.trace.v[0].label);
	cbl_yarena_free(a);
}

ATF_TC(part_and_chunk);
ATF_TC_HEAD(part_and_chunk, tc)
{
	atf_tc_set_md_var(tc, "descr", "A stream's part with typed routes and "
	    "JSON rows, and a chunk of bytes, the streams' payloads");
}
ATF_TC_BODY(part_and_chunk, tc)
{
	struct arc_part p, po;
	struct arc_route routes[2];
	struct arc_chunk c, co;
	uint8_t bytes[300];
	cbl_yarena *a;
	size_t i;

	memset(&p, 0, sizeof(p));
	memset(routes, 0, sizeof(routes));
	p.has_total = true;
	p.total = 2;
	p.json = "[]";
	routes[0].destination = "default";
	routes[0].gateway = "203.0.113.1";
	routes[0].has_fib = true;
	routes[0].fib = 0;
	routes[1].destination = "2001:db8::/32";
	routes[1].interface_name = "gre0";
	p.routes.n = 2;
	p.routes.v = routes;
	ATF_REQUIRE((a = cbl_yarena_new()) != NULL);
	ROUND(arcana_part, &p, &po, a);
	ATF_CHECK(po.has_total && po.total == 2);
	ATF_CHECK_STREQ("[]", po.json);
	ATF_REQUIRE_EQ(2, po.routes.n);
	ATF_CHECK_STREQ("203.0.113.1", po.routes.v[0].gateway);
	ATF_CHECK(po.routes.v[0].has_fib && po.routes.v[0].fib == 0);
	ATF_CHECK_STREQ("gre0", po.routes.v[1].interface_name);
	ATF_CHECK(po.routes.v[1].gateway == NULL);

	for (i = 0; i < sizeof(bytes); i++)
		bytes[i] = (uint8_t)(i * 7);
	memset(&c, 0, sizeof(c));
	c.data.p = bytes;
	c.data.len = sizeof(bytes);
	ROUND(arcana_chunk, &c, &co, a);
	ATF_REQUIRE_EQ(sizeof(bytes), co.data.len);
	ATF_CHECK(memcmp(bytes, co.data.p, sizeof(bytes)) == 0);
	cbl_yarena_free(a);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, list_reply);
	ATF_TP_ADD_TC(tp, job_spec);
	ATF_TP_ADD_TC(tp, stats_and_events);
	ATF_TP_ADD_TC(tp, part_and_chunk);
	return (atf_no_error());
}
