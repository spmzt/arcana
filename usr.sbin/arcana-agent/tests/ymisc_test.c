/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * ymisc: the host, the agent and the jails' files as arcana-host,
 * arcana-agent and arcana-jail-files have them (yhost.c, yagent.c,
 * yjf.c), for agent_test.sh.
 *
 *	ymisc host certs.json		the host made up, with those certs
 *	ymisc transport reply.json	the transport operation's JSON
 *	ymisc tls status.json		the tls operation's status
 *	ymisc bundle bundle.json	config-export's bundle
 *	ymisc apply report.json		config-apply's report
 *	ymisc log head log.json tags.json
 *					source-log's commits and tags
 *	ymisc jail-files reply.json	the jail-files operation's JSON
 *	ymisc sshd reply.json		the ssh operation's JSON
 *	ymisc builder reply.json	the builder operation's JSON
 *	ymisc builder-options reply.json	a port's options
 *	ymisc notify token chat text	the notify request
 *
 * Through YANG-CBOR and back, the same bytes.
 */

#include "ycommon.h"

static const char *
ident(bool has, uint64_t sid)
{

	if (!has)
		return ("-");
	for (uint32_t i = 0; i < ymodel_schema.nident; i++)
		if (ymodel_schema.ident[i].sid == sid)
			return (ymodel_schema.ident[i].name);
	return ("?");
}

static void
cert(const char *what, const struct arcana_host_host_certificates_trusted *c)
{

	printf("%s %s cn=%s org=%s country=%s issuer=%s from=%s until=%s "
	    "sha256=%s key=%s ca=%s self=%s local=%s\n", what, c->file, str(
	    c->common_name), str(c->organization), str(c->country), str(
	    c->issuer), str(c->not_before), str(c->not_after), str(c->sha256),
	    str(c->key), c->ca ? "yes" : "no", c->self_signed ? "yes" : "no",
	    str(c->local));
}

int
main(int argc, char **argv)
{
	cbl_yarena *a;
	int error;

	if (argc < 3)
		errx(2, "usage: ymisc host|transport|tls|bundle|apply|jail-files "
		    "file.json | log head log.json tags.json");
	if ((a = cbl_yarena_new()) == NULL)
		err(1, "cbl_yarena_new");
	if (strcmp(argv[1], "host") == 0) {
		static const char *const plugins[] = { "bird", "wireguard",
		    "nothing" };
		struct arc_host hh = { .hostname = "labvm", .sysname = "FreeBSD",
		    .release = "16.0-CURRENT", .machine = "amd64",
		    .has_osreldate = true, .osreldate = 1600000, .has_ncpu = true,
		    .ncpu = 12, .has_physmem = true, .physmem = 25769803776,
		    .has_boottime = true, .boottime = 1791990000, .has_time =
		    true, .time = 1791995110, .has_securelevel = true,
		    .securelevel = -1, .has_privileged = true, .privileged =
		    false, .version = "0.123.0", .build = "0123456789abcdef"
		    "0123456789abcdef0123456789abcdef0123456789abcdef",
		    .plugins = { 3, plugins } };
		struct arc_pool pools[] = { { .name = "zroot", .has_size = true,
		    .size = 107374182400, .has_alloc = true, .alloc = 10737418240,
		    .has_free = true, .free = 96636764160, .health = "ONLINE" } };
		/* The decimals in hundredths, as the wire has them. */
		struct arc_stats st = { .has_cpu_pct = true, .cpu_pct = 1234,
		    .has_load1 = true, .load1 = 42, .has_load5 = true, .load5 =
		    50, .has_load15 = true, .load15 = 55, .has_mem_total =
		    true, .mem_total = 25769803776, .has_mem_used = true,
		    .mem_used = 8589934592, .has_mem_inactive = true,
		    .mem_inactive = 1073741824, .has_mem_free = true, .mem_free =
		    16106127360, .has_swap_total = true, .swap_total =
		    4294967296, .has_swap_used = true, .swap_used = 0, .pools =
		    { 1, pools } };
		struct arcana_host_host_certificates c;
		struct arcana_host_host h, back;

		if ((error = yhost_certs_from_json(slurp(argv[2]), a, &c)) != 0)
			errc(1, error, "yhost_certs_from_json");
		if ((error = yhost_from(&hh, &st, &c, a, &h)) != 0)
			errc(1, error, "yhost_from");
		printf("host %s %s %s %s osreldate=%u ncpu=%u physmem=%ju boot=%s "
		    "time=%s securelevel=%d privileged=%s\n", h.hostname,
		    h.sysname, h.release, h.machine, h.osreldate, h.ncpu,
		    (uintmax_t)h.physmem, str(h.boot_time), str(h.time),
		    h.securelevel, h.privileged ? "yes" : "no");
		printf("agent %s %s\n", str(h.agent->version), str(h.agent->build));
		for (size_t i = 0; i < h.plugin.n; i++)
			printf("plugin %s\n", ident(true, h.plugin.v[i]));
		printf("stats cpu=%jd load=%jd/%jd/%jd memory=%ju/%ju/%ju/%ju "
		    "swap=%ju/%ju\n", (intmax_t)h.stats->cpu, (intmax_t)
		    h.stats->load1, (intmax_t)h.stats->load5, (intmax_t)
		    h.stats->load15, (uintmax_t)h.stats->memory_total,
		    (uintmax_t)h.stats->memory_used, (uintmax_t)
		    h.stats->memory_inactive, (uintmax_t)h.stats->memory_free,
		    (uintmax_t)h.stats->swap_total, (uintmax_t)
		    h.stats->swap_used);
		for (size_t i = 0; i < h.stats->pool.n; i++)
			printf("pool %s size=%ju allocated=%ju free=%ju %s\n",
			    h.stats->pool.v[i].name, (uintmax_t)
			    h.stats->pool.v[i].size, (uintmax_t)
			    h.stats->pool.v[i].allocated, (uintmax_t)
			    h.stats->pool.v[i].free, str(
			    h.stats->pool.v[i].health));
		printf("certificates localbase=%s added=%s distrusted=%s "
		    "certctl=%s now=%s\n", str(c.localbase), str(c.added_dir),
		    str(c.distrusted_dir), c.certctl ? "yes" : "no", str(c.now));
		for (size_t i = 0; i < c.trusted.n; i++)
			cert("trusted", &c.trusted.v[i]);
		for (size_t i = 0; i < c.untrusted.n; i++)
			cert("untrusted", (const void *)&c.untrusted.v[i]);
		same((void *)arcana_host_host_encode, (void *)
		    arcana_host_host_decode, &h, &back, a);
	} else if (strcmp(argv[1], "transport") == 0) {
		struct arcana_agent_agent_transport t, back;

		if ((error = yagent_transport_from_json(slurp(argv[2]), a, &t))
		    != 0)
			errc(1, error, "yagent_transport_from_json");
		printf("transport sctp=%s\n", t.sctp ? "yes" : "no");
		for (size_t i = 0; i < t.listener.n; i++)
			printf("listener %s %s up=%s why=%s\n", t.listener.v[i].uri,
			    t.listener.v[i].has_transport ? (const char *[]){
			    "tcp", "sctp", "unix" }[t.listener.v[i].transport] :
			    "-", t.listener.v[i].up ? "yes" : "no", str(
			    t.listener.v[i].why));
		for (size_t i = 0; i < t.session.n; i++)
			printf("session %s %s %s since=%s\n", str(
			    t.session.v[i].transport), str(t.session.v[i].address),
			    str(t.session.v[i].name), str(t.session.v[i].since));
		same((void *)arcana_agent_agent_transport_encode, (void *)
		    arcana_agent_agent_transport_decode, &t, &back, a);
	} else if (strcmp(argv[1], "tls") == 0) {
		struct arcana_agent_agent_tls t, back;

		if ((error = yagent_tls_from_json(slurp(argv[2]), a, &t)) != 0)
			errc(1, error, "yagent_tls_from_json");
		if (t.certificate != NULL) {
			printf("certificate %s issuer=%s from=%s until=%s sha256=%s "
			    "chain=", str(t.certificate->subject), str(
			    t.certificate->issuer), str(t.certificate->not_before),
			    str(t.certificate->not_after), str(
			    t.certificate->sha256));
			for (size_t i = 0; i < t.certificate->chain.n; i++)
				printf("%s%s", i > 0 ? "," : "",
				    t.certificate->chain.v[i]);
			printf("\n");
		}
		for (size_t i = 0; i < t.ca.n; i++)
			printf("ca %s issuer=%s sha256=%s\n", str(t.ca.v[i].subject),
			    str(t.ca.v[i].issuer), str(t.ca.v[i].sha256));
		printf("pending=%s\n", t.pending ? "yes" : "no");
		same((void *)arcana_agent_agent_tls_encode, (void *)
		    arcana_agent_agent_tls_decode, &t, &back, a);
	} else if (strcmp(argv[1], "bundle") == 0) {
		struct arcana_agent_agent_config_export_output b, back;

		if ((error = yagent_bundle_from_json(slurp(argv[2]), a, &b)) != 0)
			errc(1, error, "yagent_bundle_from_json");
		printf("bundle host=%s agent=%s taken=%s\n", str(b.host), str(
		    b.agent), str(b.taken));
		if (b.facts != NULL) {
			printf("facts %s %s cpu=%s ncpu=%u memory=%ju\n", str(
			    b.facts->arch), str(b.facts->release), str(
			    b.facts->cpu), b.facts->ncpu, (uintmax_t)
			    b.facts->memory);
			for (size_t i = 0; i < b.facts->interface.n; i++)
				printf("interface %s %s %s\n",
				    b.facts->interface.v[i].name, str(
				    b.facts->interface.v[i].driver), str(
				    b.facts->interface.v[i].mac));
			for (size_t i = 0; i < b.facts->disk.n; i++)
				printf("disk %s %ju\n", b.facts->disk.v[i].name,
				    (uintmax_t)b.facts->disk.v[i].size);
		}
		for (size_t i = 0; i < b.package.n; i++)
			printf("package %s %s %s\n", b.package.v[i].name, str(
			    b.package.v[i].origin), str(b.package.v[i].version));
		for (size_t i = 0; i < b.file.n; i++)
			printf("file %s mode=%s %s:%s text=%zu secret=%s\n",
			    b.file.v[i].path, str(b.file.v[i].mode), str(
			    b.file.v[i].owner), str(b.file.v[i].group),
			    b.file.v[i].text != NULL ? strlen(b.file.v[i].text) :
			    0, b.file.v[i].secret ? "yes" : "no");
		same((void *)arcana_agent_agent_config_export_output_encode,
		    (void *)arcana_agent_agent_config_export_output_decode, &b,
		    &back, a);
	} else if (strcmp(argv[1], "apply") == 0) {
		static const char *const states[] = { "same", "changed", "new",
		    "withheld" };
		struct arcana_agent_agent_config_apply_output r, back;

		if ((error = yagent_apply_from_json(slurp(argv[2]), a, &r)) != 0)
			errc(1, error, "yagent_apply_from_json");
		for (size_t i = 0; i < r.mismatch.n; i++)
			printf("mismatch %s\n", r.mismatch.v[i]);
		for (size_t i = 0; i < r.file.n; i++)
			printf("file %s %s diff=%zu\n", r.file.v[i].path,
			    r.file.v[i].has_state ? states[r.file.v[i].state] :
			    "-", r.file.v[i].diff != NULL ? strlen(
			    r.file.v[i].diff) : 0);
		for (size_t i = 0; i < r.package.n; i++)
			printf("package %s\n", r.package.v[i]);
		printf("backup=%s applied=%s reboot=%s\n", str(r.backup),
		    r.applied ? "yes" : "no", r.reboot ? "yes" : "no");
		same((void *)arcana_agent_agent_config_apply_output_encode,
		    (void *)arcana_agent_agent_config_apply_output_decode, &r,
		    &back, a);
	} else if (strcmp(argv[1], "log") == 0) {
		struct arcana_agent_agent_source_log_output l, back;

		if (argc != 5)
			errx(2, "log head log.json tags.json");
		if ((error = yagent_log_from_json(argv[2], slurp(argv[3]), slurp(
		    argv[4]), a, &l)) != 0)
			errc(1, error, "yagent_log_from_json");
		printf("head %s\n", str(l.commit));
		for (size_t i = 0; i < l.commit_log.n; i++)
			printf("commit %s %s %s body=%zu\n", l.commit_log.v[i].hash,
			    str(l.commit_log.v[i].time), str(
			    l.commit_log.v[i].subject), l.commit_log.v[i].body !=
			    NULL ? strlen(l.commit_log.v[i].body) : 0);
		for (size_t i = 0; i < l.tag.n; i++)
			printf("tag %s %s\n", l.tag.v[i].name, str(
			    l.tag.v[i].message));
		same((void *)arcana_agent_agent_source_log_output_encode, (void *)
		    arcana_agent_agent_source_log_output_decode, &l, &back, a);
	} else if (strcmp(argv[1], "jail-files") == 0) {
		struct arcana_jails_jails_arcjf_files f, back;

		if ((error = yjf_from_json(slurp(argv[2]), a, &f)) != 0)
			errc(1, error, "yjf_from_json");
		printf("files %s defaults=%s text=%zu\n", str(f.directory),
		    f.defaults != NULL ? str(f.defaults->path) : "-",
		    f.defaults != NULL && f.defaults->text != NULL ? strlen(
		    f.defaults->text) : 0);
		for (size_t i = 0; i < f.template.n; i++)
			printf("template %s text=%zu\n", f.template.v[i].name,
			    f.template.v[i].text != NULL ? strlen(
			    f.template.v[i].text) : 0);
		for (size_t i = 0; i < f.jail.n; i++)
			printf("jail %s text=%zu\n", f.jail.v[i].name,
			    f.jail.v[i].text != NULL ? strlen(f.jail.v[i].text) :
			    0);
		same((void *)arcana_jails_jails_arcjf_files_encode, (void *)
		    arcana_jails_jails_arcjf_files_decode, &f, &back, a);
	} else if (strcmp(argv[1], "sshd") == 0) {
		struct arcana_sshd_sshd d, back;

		if ((error = ysshd_from_json(slurp(argv[2]), a, &d)) != 0)
			errc(1, error, "ysshd_from_json");
		for (size_t i = 0; i < d.setting.n; i++) {
			printf("setting %s =", d.setting.v[i].name);
			for (size_t k = 0; k < d.setting.v[i].value.n; k++)
				printf(" %s", d.setting.v[i].value.v[k]);
			printf("\n");
		}
		printf("from-file=%s banner=%zu before-kept=%s\n", str(
		    d.settings_from_file), d.banner != NULL ? strlen(d.banner) :
		    0, d.before_kept ? "yes" : "no");
		for (size_t i = 0; i < d.host_key.n; i++) {
			const struct arcana_sshd_sshd_host_key *h =
			    &d.host_key.v[i];

			printf("host-key %s %s %u %s %s used=%s", h->path, str(
			    h->type), h->bits, str(h->fingerprint), str(
			    h->comment), h->certificate_used ? "yes" : "no");
			if (h->certificate != NULL) {
				printf(" cert %s id=%s after=%s before=%s ca=%s "
				    "principals=", str(h->certificate->kind), str(
				    h->certificate->id), str(
				    h->certificate->valid_after), str(
				    h->certificate->valid_before), str(
				    h->certificate->ca));
				for (size_t k = 0; k < h->certificate->principal.n;
				    k++)
					printf("%s%s", k > 0 ? "," : "",
					    h->certificate->principal.v[k]);
			}
			printf("\n");
		}
		for (size_t i = 0; i < d.user.n; i++) {
			printf("user %s uid=%u home=%s shell=%s keys=%s\n",
			    d.user.v[i].name, d.user.v[i].uid, str(
			    d.user.v[i].home), str(d.user.v[i].shell), str(
			    d.user.v[i].keys_file));
			for (size_t k = 0; k < d.user.v[i].key.n; k++)
				printf("  key %s %s %u %s options=%s\n",
				    d.user.v[i].key.v[k].fingerprint, str(
				    d.user.v[i].key.v[k].type),
				    d.user.v[i].key.v[k].bits, str(
				    d.user.v[i].key.v[k].comment), str(
				    d.user.v[i].key.v[k].options));
		}
		for (size_t i = 0; i < d.user_ca.n; i++)
			printf("user-ca %s\n", d.user_ca.v[i]);
		same((void *)arcana_sshd_sshd_encode, (void *)
		    arcana_sshd_sshd_decode, &d, &back, a);
	} else if (strcmp(argv[1], "builder") == 0) {
		struct arcana_builder_builder d, back;

		if ((error = ybuilder_from_json(slurp(argv[2]), a, &d)) != 0)
			errc(1, error, "ybuilder_from_json");
		printf("installed=%s configured=%s conf=%zu basefs=%s\n",
		    d.installed ? "yes" : "no", d.configured ? "yes" : "no",
		    d.conf.n, str(d.basefs));
		for (size_t i = 0; i < d.jail.n; i++)
			printf("jail %s version=%s method=%s updated=%s\n",
			    d.jail.v[i].name, str(d.jail.v[i].version), str(
			    d.jail.v[i].method), str(d.jail.v[i].timestamp));
		for (size_t i = 0; i < d.ports.n; i++)
			printf("ports %s\n", d.ports.v[i].name);
		for (size_t i = 0; i < d.options.n; i++)
			for (size_t k = 0; k < d.options.v[i].port.n; k++)
				printf("options %s %s set=%zu unset=%zu\n",
				    d.options.v[i].name, d.options.v[i].port.v[k].name,
				    d.options.v[i].port.v[k].set.n,
				    d.options.v[i].port.v[k].unset.n);
		for (size_t i = 0; i < d.build.n; i++) {
			const struct arcana_builder_builder_build *b =
			    &d.build.v[i];

			printf("build %s/%s/%s %s built=%u failed=%u\n", b->jail,
			    b->ports, b->set, str(b->status), b->built,
			    b->failed);
			for (size_t k = 0; k < b->failed_port.n; k++)
				printf("  failed %s %s %s after=%u\n",
				    b->failed_port.v[k].package, str(
				    b->failed_port.v[k].origin), str(
				    b->failed_port.v[k].phase),
				    b->failed_port.v[k].elapsed);
			for (size_t k = 0; k < b->skipped_port.n; k++)
				printf("  skipped %s because=%s\n",
				    b->skipped_port.v[k].package, str(
				    b->skipped_port.v[k].because));
		}
		for (size_t i = 0; i < d.run.n; i++)
			printf("run %u state=%d exit=%s%u argv=%zu\n",
			    d.run.v[i].id, d.run.v[i].has_state ?
			    (int)d.run.v[i].state : -1, d.run.v[i].has_exit ? "" :
			    "-", d.run.v[i].exit, d.run.v[i].argv.n);
		same((void *)arcana_builder_builder_encode, (void *)
		    arcana_builder_builder_decode, &d, &back, a);
	} else if (strcmp(argv[1], "builder-options") == 0) {
		struct arcana_builder_builder_port_options_output d, back;

		if ((error = ybuilder_options_from_json(slurp(argv[2]), a,
		    &d)) != 0)
			errc(1, error, "ybuilder_options_from_json");
		printf("%s dir-exists=%s configured=%s\n", str(d.pkgname),
		    d.options_dir_exists ? "yes" : "no", d.configured ? "yes" :
		    "no");
		for (size_t i = 0; i < d.section.n; i++) {
			printf("section %u %s:", d.section.v[i].index, str(
			    d.section.v[i].title));
			for (size_t k = 0; k < d.section.v[i].option.n; k++)
				printf(" %s=%s", d.section.v[i].option.v[k].name,
				    d.section.v[i].option.v[k].on ? "on" : "off");
			printf("\n");
		}
		same((void *)arcana_builder_builder_port_options_output_encode,
		    (void *)arcana_builder_builder_port_options_output_decode,
		    &d, &back, a);
	} else if (strcmp(argv[1], "notify") == 0) {
		/* The request, as arcanactl or the console gives it. */
		struct arcana_notify_notify_input d, back;

		if (argc != 5)
			errx(2, "notify token chat text");
		memset(&d, 0, sizeof(d));
		d.token = argv[2];
		d.chat = argv[3];
		d.text = argv[4];
		printf("notify chat=%s text=%zu\n", d.chat, strlen(d.text));
		same((void *)arcana_notify_notify_input_encode, (void *)
		    arcana_notify_notify_input_decode, &d, &back, a);
	} else
		errx(2, "%s: host, transport, tls, bundle, apply, log, "
		    "jail-files, sshd, builder, builder-options or notify",
		    argv[1]);
	return (0);
}
