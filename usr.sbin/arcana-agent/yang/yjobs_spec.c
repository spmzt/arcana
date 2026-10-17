/*
 * Made from share/arcana/jobs.yaml by share/arcana/jobs.awk
 * (out=yspec): not to be edited.  A change of arcana-jobs's submit
 * (its struct, as cblink-gen makes it from arcana-jobs-kinds) made
 * the job-spec the agent's queue takes, field by field as jobs.yaml
 * names them.
 */

#include <errno.h>
#include <string.h>

#include <arcana.h>

#include "collect.h"

static const char *const netgraph_verb[] = {
	"mkpeer", "connect", "rmhook", "shutdown", "name",
};
static const char *const wireguard_verb[] = {
	"init", "peer", "unpeer",
};
static const char *const bird_verb[] = {
	"enable", "disable", "restart", "reload", "configure",
};
static const char *const kmod_verb[] = {
	"load", "unload", "keep", "forget",
};
static const char *const ipsec_sa_verb[] = {
	"key", "set", "derive", "commit", "clear",
};
static const char *const process_verb[] = {
	"signal", "renice",
};
static const char *const ipsec_verb[] = {
	"init", "start", "conn", "unconn", "child", "unchild", "up", "down",
};
static const char *const ipsec_ipsec_mode[] = {
	"tunnel", "transport",
};
static const char *const ipsec_start_action[] = {
	"start", "trap", "none",
};
static const char *const jail_conf_verb[] = {
	"make", "remove", "defaults", "template", "untemplate", "edit",
};
static const char *const jail_conf_copy[] = {
	"clone", "send",
};
static const char *const carp_verb[] = {
	"add", "set", "remove",
};
static const char *const neighbour_verb[] = {
	"add", "delete",
};
static const char *const cert_verb[] = {
	"add", "remove", "trust", "untrust", "rehash",
};
static const char *const ssh_verb[] = {
	"banner", "set", "authorize", "unauthorize", "options", "sign",
	"user-cas",
};
static const char *const poudriere_verb[] = {
	"jail-create", "jail-update", "jail-delete", "ports-create",
	"ports-update", "ports-delete", "bulk", "stop", "make-conf", "conf",
	"options",
};

/*
 * Change c made job-spec sp, its arrays a's.  0, or EINVAL: no kind,
 * or one not given.
 */
int
yjobs_spec(const struct arcana_jobs_submit_input_change *in,
    cbl_yarena *a, struct arc_job_spec *sp)
{
	struct arc_variable *vars = NULL;
	size_t nv = 0;

	memset(sp, 0, sizeof(*sp));
	sp->has_kind = true;
	switch (in->kind) {
	case ARCANA_JOBS_SUBMIT_INPUT_CHANGE_KIND_JAIL_ACTION: {
		const struct arcana_jobs_submit_input_change_jail_action *c =
		    in->jail_action;

		if (c == NULL)
			return (EINVAL);
		sp->kind = ARC_JOB_KIND_JAIL_ACTION;
		sp->jail = c->jail;
		if ((sp->has_action = c->has_action))
			sp->action = (uint8_t)c->action;
		return (0);
	}
	case ARCANA_JOBS_SUBMIT_INPUT_CHANGE_KIND_ADDRESS: {
		const struct arcana_jobs_submit_input_change_address *c =
		    in->address;

		if (c == NULL)
			return (EINVAL);
		sp->kind = ARC_JOB_KIND_ADDRESS;
		sp->jail = c->jail;
		sp->address = c->address;
		sp->interface = c->interface;
		sp->remove = c->has_remove && c->remove;
		sp->live = c->has_live && c->live;
		sp->persist = c->has_persist && c->persist;
		return (0);
	}
	case ARCANA_JOBS_SUBMIT_INPUT_CHANGE_KIND_SERVICE_ACTION: {
		const struct arcana_jobs_submit_input_change_service_action *c =
		    in->service_action;

		if (c == NULL)
			return (EINVAL);
		sp->kind = ARC_JOB_KIND_SERVICE_ACTION;
		sp->service = c->service;
		if ((sp->has_service_action = c->has_action))
			sp->service_action = (uint8_t)c->action;
		return (0);
	}
	case ARCANA_JOBS_SUBMIT_INPUT_CHANGE_KIND_SERVICE_CONFIG: {
		const struct arcana_jobs_submit_input_change_service_config *c =
		    in->service_config;

		if (c == NULL)
			return (EINVAL);
		sp->kind = ARC_JOB_KIND_SERVICE_CONFIG;
		if ((vars = cbl_yarena_alloc(a, (c->set.n + c->unset.n +
		    1) * sizeof(*vars))) == NULL)
			return (ENOMEM);
		memset(vars, 0, (c->set.n + c->unset.n + 1) *
		    sizeof(*vars));
		sp->service = c->service;
		for (size_t i = 0; i < c->set.n; i++) {
			vars[nv].key = c->set.v[i].name;
			vars[nv++].value = c->set.v[i].value;
		}
		for (size_t i = 0; i < c->unset.n; i++) {
			vars[nv].key = c->unset.v[i];
			vars[nv++].remove = true;
		}
		sp->variables.n = nv;
		sp->variables.v = vars;
		return (0);
	}
	case ARCANA_JOBS_SUBMIT_INPUT_CHANGE_KIND_PKG_UPGRADE: {
		const struct arcana_jobs_submit_input_change_pkg_upgrade *c =
		    in->pkg_upgrade;

		if (c == NULL)
			return (EINVAL);
		sp->kind = ARC_JOB_KIND_PKG_UPGRADE;
		sp->jail = c->jail;
		sp->names.n = c->packages.n;
		sp->names.v = c->packages.v;
		sp->force = c->has_force && c->force;
		if ((sp->has_pkg_ip = c->has_pkg_ip))
			sp->pkg_ip = c->pkg_ip;
		sp->pkg_repo = c->pkg_repo;
		return (0);
	}
	case ARCANA_JOBS_SUBMIT_INPUT_CHANGE_KIND_IF_ADDRESS: {
		const struct arcana_jobs_submit_input_change_if_address *c =
		    in->if_address;

		if (c == NULL)
			return (EINVAL);
		sp->kind = ARC_JOB_KIND_IF_ADDRESS;
		sp->interface = c->interface;
		sp->address = c->address;
		sp->jail = c->jail;
		sp->remove = c->has_remove && c->remove;
		sp->live = c->has_live && c->live;
		sp->persist = c->has_persist && c->persist;
		sp->safe = c->has_safe && c->safe;
		return (0);
	}
	case ARCANA_JOBS_SUBMIT_INPUT_CHANGE_KIND_IF_STATE: {
		const struct arcana_jobs_submit_input_change_if_state *c =
		    in->if_state;

		if (c == NULL)
			return (EINVAL);
		sp->kind = ARC_JOB_KIND_IF_STATE;
		sp->interface = c->interface;
		if ((sp->has_up = c->has_up))
			sp->up = c->up;
		sp->jail = c->jail;
		sp->persist = c->has_persist && c->persist;
		sp->safe = c->has_safe && c->safe;
		return (0);
	}
	case ARCANA_JOBS_SUBMIT_INPUT_CHANGE_KIND_ROUTE: {
		const struct arcana_jobs_submit_input_change_route *c =
		    in->route;

		if (c == NULL)
			return (EINVAL);
		sp->kind = ARC_JOB_KIND_ROUTE;
		sp->destination = c->destination;
		sp->jail = c->jail;
		sp->gateway = c->gateway;
		sp->remove = c->has_remove && c->remove;
		if ((sp->has_fib = c->has_fib))
			sp->fib = c->fib;
		if ((sp->has_metric = c->has_metric))
			sp->metric = c->metric;
		if ((sp->has_weight = c->has_weight))
			sp->weight = c->weight;
		sp->source = c->source;
		sp->persist = c->has_persist && c->persist;
		sp->safe = c->has_safe && c->safe;
		return (0);
	}
	case ARCANA_JOBS_SUBMIT_INPUT_CHANGE_KIND_IF_SET: {
		const struct arcana_jobs_submit_input_change_if_set *c =
		    in->if_set;

		if (c == NULL)
			return (EINVAL);
		sp->kind = ARC_JOB_KIND_IF_SET;
		sp->interface = c->interface;
		sp->jail = c->jail;
		if ((sp->has_mtu = c->has_mtu))
			sp->mtu = c->mtu;
		sp->description = c->description;
		if ((sp->has_fib = c->has_fib))
			sp->fib = c->fib;
		if ((sp->has_tunnelfib = c->has_tunnelfib))
			sp->tunnelfib = c->tunnelfib;
		sp->persist = c->has_persist && c->persist;
		sp->safe = c->has_safe && c->safe;
		return (0);
	}
	case ARCANA_JOBS_SUBMIT_INPUT_CHANGE_KIND_IF_CREATE: {
		const struct arcana_jobs_submit_input_change_if_create *c =
		    in->if_create;

		if (c == NULL)
			return (EINVAL);
		sp->kind = ARC_JOB_KIND_IF_CREATE;
		sp->interface = c->interface;
		sp->jail = c->jail;
		sp->tunnel_local = c->tunnel_local;
		sp->tunnel_remote = c->tunnel_remote;
		sp->address = c->address;
		sp->destination = c->destination;
		sp->description = c->description;
		if ((sp->has_mtu = c->has_mtu))
			sp->mtu = c->mtu;
		if ((sp->has_fib = c->has_fib))
			sp->fib = c->fib;
		if ((sp->has_tunnelfib = c->has_tunnelfib))
			sp->tunnelfib = c->tunnelfib;
		if ((sp->has_id = c->has_id))
			sp->id = c->id;
		sp->parent = c->parent;
		if ((sp->has_reqid = c->has_reqid))
			sp->reqid = c->reqid;
		sp->persist = c->has_persist && c->persist;
		return (0);
	}
	case ARCANA_JOBS_SUBMIT_INPUT_CHANGE_KIND_IF_DESTROY: {
		const struct arcana_jobs_submit_input_change_if_destroy *c =
		    in->if_destroy;

		if (c == NULL)
			return (EINVAL);
		sp->kind = ARC_JOB_KIND_IF_DESTROY;
		sp->interface = c->interface;
		sp->jail = c->jail;
		sp->persist = c->has_persist && c->persist;
		return (0);
	}
	case ARCANA_JOBS_SUBMIT_INPUT_CHANGE_KIND_NETGRAPH: {
		const struct arcana_jobs_submit_input_change_netgraph *c =
		    in->netgraph;

		if (c == NULL)
			return (EINVAL);
		sp->kind = ARC_JOB_KIND_NETGRAPH;
		if (c->has_verb)
			sp->verb = netgraph_verb[c->verb];
		sp->names.n = c->args.n;
		sp->names.v = c->args.v;
		sp->jail = c->jail;
		return (0);
	}
	case ARCANA_JOBS_SUBMIT_INPUT_CHANGE_KIND_WIREGUARD: {
		const struct arcana_jobs_submit_input_change_wireguard *c =
		    in->wireguard;

		if (c == NULL)
			return (EINVAL);
		sp->kind = ARC_JOB_KIND_WIREGUARD;
		sp->interface = c->interface;
		if (c->has_verb)
			sp->verb = wireguard_verb[c->verb];
		sp->jail = c->jail;
		sp->peer = c->peer;
		sp->endpoint = c->endpoint;
		sp->allowed_ips = c->allowed_ips;
		if ((sp->has_keepalive = c->has_keepalive))
			sp->keepalive = c->keepalive;
		if ((sp->has_listen_port = c->has_listen_port))
			sp->listen_port = c->listen_port;
		sp->persist = c->has_persist && c->persist;
		sp->preshared_key = c->preshared_key;
		return (0);
	}
	case ARCANA_JOBS_SUBMIT_INPUT_CHANGE_KIND_BIRD: {
		const struct arcana_jobs_submit_input_change_bird *c =
		    in->bird;

		if (c == NULL)
			return (EINVAL);
		sp->kind = ARC_JOB_KIND_BIRD;
		if (c->has_verb)
			sp->verb = bird_verb[c->verb];
		sp->jail = c->jail;
		sp->names.n = c->args.n;
		sp->names.v = c->args.v;
		return (0);
	}
	case ARCANA_JOBS_SUBMIT_INPUT_CHANGE_KIND_IF_VNET: {
		const struct arcana_jobs_submit_input_change_if_vnet *c =
		    in->if_vnet;

		if (c == NULL)
			return (EINVAL);
		sp->kind = ARC_JOB_KIND_IF_VNET;
		sp->interface = c->interface;
		sp->jail = c->jail;
		sp->remove = c->has_remove && c->remove;
		sp->parent = c->parent;
		sp->persist = c->has_persist && c->persist;
		return (0);
	}
	case ARCANA_JOBS_SUBMIT_INPUT_CHANGE_KIND_KMOD: {
		const struct arcana_jobs_submit_input_change_kmod *c =
		    in->kmod;

		if (c == NULL)
			return (EINVAL);
		sp->kind = ARC_JOB_KIND_KMOD;
		if (c->has_verb)
			sp->verb = kmod_verb[c->verb];
		sp->names.n = c->args.n;
		sp->names.v = c->args.v;
		sp->persist = c->has_persist && c->persist;
		return (0);
	}
	case ARCANA_JOBS_SUBMIT_INPUT_CHANGE_KIND_NTP: {
		const struct arcana_jobs_submit_input_change_ntp *c =
		    in->ntp;

		if (c == NULL)
			return (EINVAL);
		sp->kind = ARC_JOB_KIND_NTP;
		sp->names.n = c->args.n;
		sp->names.v = c->args.v;
		sp->remove = c->has_remove && c->remove;
		sp->persist = c->has_persist && c->persist;
		return (0);
	}
	case ARCANA_JOBS_SUBMIT_INPUT_CHANGE_KIND_RTADVD: {
		const struct arcana_jobs_submit_input_change_rtadvd *c =
		    in->rtadvd;

		if (c == NULL)
			return (EINVAL);
		sp->kind = ARC_JOB_KIND_RTADVD;
		sp->interface = c->interface;
		sp->names.n = c->args.n;
		sp->names.v = c->args.v;
		sp->remove = c->has_remove && c->remove;
		sp->persist = c->has_persist && c->persist;
		return (0);
	}
	case ARCANA_JOBS_SUBMIT_INPUT_CHANGE_KIND_IPSEC_SA: {
		const struct arcana_jobs_submit_input_change_ipsec_sa *c =
		    in->ipsec_sa;

		if (c == NULL)
			return (EINVAL);
		sp->kind = ARC_JOB_KIND_IPSEC_SA;
		if (c->has_verb)
			sp->verb = ipsec_sa_verb[c->verb];
		sp->interface = c->interface;
		if ((sp->has_reqid = c->has_reqid))
			sp->reqid = c->reqid;
		sp->tunnel_local = c->tunnel_local;
		sp->tunnel_remote = c->tunnel_remote;
		sp->names.n = c->args.n;
		sp->names.v = c->args.v;
		return (0);
	}
	case ARCANA_JOBS_SUBMIT_INPUT_CHANGE_KIND_ZFS: {
		const struct arcana_jobs_submit_input_change_zfs *c =
		    in->zfs;

		if (c == NULL)
			return (EINVAL);
		sp->kind = ARC_JOB_KIND_ZFS;
		sp->verb = c->verb;
		sp->names.n = c->args.n;
		sp->names.v = c->args.v;
		sp->recursive = c->has_recursive && c->recursive;
		sp->force = c->has_force && c->force;
		return (0);
	}
	case ARCANA_JOBS_SUBMIT_INPUT_CHANGE_KIND_ZPOOL: {
		const struct arcana_jobs_submit_input_change_zpool *c =
		    in->zpool;

		if (c == NULL)
			return (EINVAL);
		sp->kind = ARC_JOB_KIND_ZPOOL;
		sp->verb = c->verb;
		sp->names.n = c->args.n;
		sp->names.v = c->args.v;
		sp->force = c->has_force && c->force;
		return (0);
	}
	case ARCANA_JOBS_SUBMIT_INPUT_CHANGE_KIND_MOUNT: {
		const struct arcana_jobs_submit_input_change_mount *c =
		    in->mount;

		if (c == NULL)
			return (EINVAL);
		sp->kind = ARC_JOB_KIND_MOUNT;
		sp->verb = c->verb;
		sp->names.n = c->args.n;
		sp->names.v = c->args.v;
		sp->force = c->has_force && c->force;
		return (0);
	}
	case ARCANA_JOBS_SUBMIT_INPUT_CHANGE_KIND_GPART: {
		const struct arcana_jobs_submit_input_change_gpart *c =
		    in->gpart;

		if (c == NULL)
			return (EINVAL);
		sp->kind = ARC_JOB_KIND_GPART;
		sp->verb = c->verb;
		sp->names.n = c->args.n;
		sp->names.v = c->args.v;
		sp->force = c->has_force && c->force;
		return (0);
	}
	case ARCANA_JOBS_SUBMIT_INPUT_CHANGE_KIND_CAM: {
		const struct arcana_jobs_submit_input_change_cam *c =
		    in->cam;

		if (c == NULL)
			return (EINVAL);
		sp->kind = ARC_JOB_KIND_CAM;
		sp->verb = c->verb;
		sp->names.n = c->args.n;
		sp->names.v = c->args.v;
		return (0);
	}
	case ARCANA_JOBS_SUBMIT_INPUT_CHANGE_KIND_SYSCTL: {
		const struct arcana_jobs_submit_input_change_sysctl *c =
		    in->sysctl;

		if (c == NULL)
			return (EINVAL);
		sp->kind = ARC_JOB_KIND_SYSCTL;
		sp->names.n = c->args.n;
		sp->names.v = c->args.v;
		sp->persist = c->has_persist && c->persist;
		return (0);
	}
	case ARCANA_JOBS_SUBMIT_INPUT_CHANGE_KIND_IPFW: {
		const struct arcana_jobs_submit_input_change_ipfw *c =
		    in->ipfw;

		if (c == NULL)
			return (EINVAL);
		sp->kind = ARC_JOB_KIND_IPFW;
		sp->verb = c->verb;
		sp->names.n = c->args.n;
		sp->names.v = c->args.v;
		sp->jail = c->jail;
		sp->persist = c->has_persist && c->persist;
		sp->safe = c->has_safe && c->safe;
		return (0);
	}
	case ARCANA_JOBS_SUBMIT_INPUT_CHANGE_KIND_BRIDGE: {
		const struct arcana_jobs_submit_input_change_bridge *c =
		    in->bridge;

		if (c == NULL)
			return (EINVAL);
		sp->kind = ARC_JOB_KIND_BRIDGE;
		sp->verb = c->verb;
		sp->names.n = c->args.n;
		sp->names.v = c->args.v;
		sp->jail = c->jail;
		sp->persist = c->has_persist && c->persist;
		return (0);
	}
	case ARCANA_JOBS_SUBMIT_INPUT_CHANGE_KIND_GENEVE: {
		const struct arcana_jobs_submit_input_change_geneve *c =
		    in->geneve;

		if (c == NULL)
			return (EINVAL);
		sp->kind = ARC_JOB_KIND_GENEVE;
		sp->verb = c->verb;
		sp->names.n = c->args.n;
		sp->names.v = c->args.v;
		sp->jail = c->jail;
		sp->persist = c->has_persist && c->persist;
		return (0);
	}
	case ARCANA_JOBS_SUBMIT_INPUT_CHANGE_KIND_PROCESS: {
		const struct arcana_jobs_submit_input_change_process *c =
		    in->process;

		if (c == NULL)
			return (EINVAL);
		sp->kind = ARC_JOB_KIND_PROCESS;
		if (c->has_verb)
			sp->verb = process_verb[c->verb];
		sp->names.n = c->args.n;
		sp->names.v = c->args.v;
		return (0);
	}
	case ARCANA_JOBS_SUBMIT_INPUT_CHANGE_KIND_PKG_CLEAN: {
		const struct arcana_jobs_submit_input_change_pkg_clean *c =
		    in->pkg_clean;

		if (c == NULL)
			return (EINVAL);
		sp->kind = ARC_JOB_KIND_PKG_CLEAN;
		sp->jail = c->jail;
		sp->force = c->has_force && c->force;
		return (0);
	}
	case ARCANA_JOBS_SUBMIT_INPUT_CHANGE_KIND_IPSEC: {
		const struct arcana_jobs_submit_input_change_ipsec *c =
		    in->ipsec;

		if (c == NULL)
			return (EINVAL);
		sp->kind = ARC_JOB_KIND_IPSEC;
		if (c->has_verb)
			sp->verb = ipsec_verb[c->verb];
		sp->jail = c->jail;
		sp->conn = c->conn;
		sp->child = c->child;
		sp->tunnel_local = c->tunnel_local;
		sp->tunnel_remote = c->tunnel_remote;
		if (c->has_ipsec_mode)
			sp->ipsec_mode = ipsec_ipsec_mode[c->ipsec_mode];
		sp->pubkey = c->pubkey;
		sp->local_cert = c->local_cert;
		sp->remote_cert = c->remote_cert;
		sp->remote_ca = c->remote_ca;
		sp->local_ts = c->local_ts;
		sp->remote_ts = c->remote_ts;
		if ((sp->has_reqid = c->has_reqid))
			sp->reqid = c->reqid;
		if (c->has_start_action)
			sp->start_action = ipsec_start_action[c->start_action];
		sp->local_id = c->local_id;
		sp->remote_id = c->remote_id;
		sp->persist = c->has_persist && c->persist;
		return (0);
	}
	case ARCANA_JOBS_SUBMIT_INPUT_CHANGE_KIND_PKG_INSTALL: {
		const struct arcana_jobs_submit_input_change_pkg_install *c =
		    in->pkg_install;

		if (c == NULL)
			return (EINVAL);
		sp->kind = ARC_JOB_KIND_PKG_INSTALL;
		sp->names.n = c->packages.n;
		sp->names.v = c->packages.v;
		sp->jail = c->jail;
		sp->force = c->has_force && c->force;
		if ((sp->has_pkg_ip = c->has_pkg_ip))
			sp->pkg_ip = c->pkg_ip;
		sp->pkg_repo = c->pkg_repo;
		return (0);
	}
	case ARCANA_JOBS_SUBMIT_INPUT_CHANGE_KIND_JAIL_CONF: {
		const struct arcana_jobs_submit_input_change_jail_conf *c =
		    in->jail_conf;

		if (c == NULL)
			return (EINVAL);
		sp->kind = ARC_JOB_KIND_JAIL_CONF;
		if (c->has_verb)
			sp->verb = jail_conf_verb[c->verb];
		sp->jail = c->jail;
		sp->dataset = c->dataset;
		sp->snapshot = c->snapshot;
		if (c->has_copy)
			sp->copy = jail_conf_copy[c->copy];
		sp->path = c->path;
		sp->text = c->text;
		sp->start = c->has_start && c->start;
		sp->names.n = c->args.n;
		sp->names.v = c->args.v;
		return (0);
	}
	case ARCANA_JOBS_SUBMIT_INPUT_CHANGE_KIND_CARP: {
		const struct arcana_jobs_submit_input_change_carp *c =
		    in->carp;

		if (c == NULL)
			return (EINVAL);
		sp->kind = ARC_JOB_KIND_CARP;
		if (c->has_verb)
			sp->verb = carp_verb[c->verb];
		sp->interface = c->interface;
		sp->jail = c->jail;
		sp->address = c->address;
		sp->names.n = c->args.n;
		sp->names.v = c->args.v;
		sp->preshared_key = c->preshared_key;
		sp->persist = c->has_persist && c->persist;
		sp->safe = c->has_safe && c->safe;
		return (0);
	}
	case ARCANA_JOBS_SUBMIT_INPUT_CHANGE_KIND_NEIGHBOUR: {
		const struct arcana_jobs_submit_input_change_neighbour *c =
		    in->neighbour;

		if (c == NULL)
			return (EINVAL);
		sp->kind = ARC_JOB_KIND_NEIGHBOUR;
		if (c->has_verb)
			sp->verb = neighbour_verb[c->verb];
		sp->address = c->address;
		sp->jail = c->jail;
		sp->lladdr = c->lladdr;
		sp->temporary = c->has_temporary && c->temporary;
		sp->live = c->has_live && c->live;
		sp->persist = c->has_persist && c->persist;
		return (0);
	}
	case ARCANA_JOBS_SUBMIT_INPUT_CHANGE_KIND_CERT: {
		const struct arcana_jobs_submit_input_change_cert *c =
		    in->cert;

		if (c == NULL)
			return (EINVAL);
		sp->kind = ARC_JOB_KIND_CERT;
		if (c->has_verb)
			sp->verb = cert_verb[c->verb];
		sp->jail = c->jail;
		sp->path = c->path;
		sp->text = c->text;
		return (0);
	}
	case ARCANA_JOBS_SUBMIT_INPUT_CHANGE_KIND_SSH: {
		const struct arcana_jobs_submit_input_change_ssh *c =
		    in->ssh;

		if (c == NULL)
			return (EINVAL);
		sp->kind = ARC_JOB_KIND_SSH;
		if (c->has_verb)
			sp->verb = ssh_verb[c->verb];
		sp->jail = c->jail;
		sp->path = c->path;
		sp->names.n = c->args.n;
		sp->names.v = c->args.v;
		sp->text = c->text;
		sp->user = c->user;
		sp->safe = c->has_safe && c->safe;
		return (0);
	}
	case ARCANA_JOBS_SUBMIT_INPUT_CHANGE_KIND_POUDRIERE: {
		const struct arcana_jobs_submit_input_change_poudriere *c =
		    in->poudriere;

		if (c == NULL)
			return (EINVAL);
		sp->kind = ARC_JOB_KIND_POUDRIERE;
		if (c->has_verb)
			sp->verb = poudriere_verb[c->verb];
		sp->names.n = c->args.n;
		sp->names.v = c->args.v;
		sp->text = c->text;
		return (0);
	}
	default:
		return (EINVAL);
	}
}
