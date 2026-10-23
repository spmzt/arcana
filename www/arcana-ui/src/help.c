/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * Help: the page shown, in the book.  Each section, each tab of a host
 * and each kind of its network has a part of the book that says what
 * it does and through which of FreeBSD's facilities; the top bar's ?
 * opens it.
 */

#include <stdio.h>
#include <string.h>

#include "app.h"

#define	BOOK	"https://spmzt.github.io/arcana-docs/"

static const char *
net_help(void)
{

	switch (app.net.kind) {
	case NET_ROUTES:
		return ("sections/network.html#routes");
	case NET_NEXTHOPS:
	case NET_NHGROUPS:
		return ("sections/network.html#nexthops-and-their-groups");
	case NET_INTERFACES:
		return ("sections/network.html#interfaces");
	case NET_NETGRAPH:
		return ("sections/network.html#netgraph");
	case NET_BRIDGES:
		return ("sections/network.html#bridges");
	case NET_GENEVE:
		return ("sections/network.html#geneve");
	case NET_CONNECTIONS:
	case NET_SOCKETS:
	case NET_NEIGHBOURS:
		return ("sections/network.html#connections-sockets-and-"
		    "neighbours");
	case NET_SPAN:
		return ("sections/network.html#span-traffic-mirrored-and-taken");
	case NET_CARP:
		return ("sections/network.html#carp-an-address-shared-between-"
		    "hosts");
	case NET_WIREGUARD:
		return ("sections/network.html#wireguard");
	case NET_BIRD:
		return ("sections/plugins.html#bird");
	case NET_IPSEC:
		return ("sections/plugins.html#ipsec");
	default:
		return ("sections/network.html");
	}
}

static const char *
tab_help(void)
{

	switch (app.tab) {
	case TAB_SUMMARY:
		return ("sections/host.html#summary");
	case TAB_JAILS:
		return ("sections/host.html#jails");
	case TAB_SERVICES:
		return ("sections/host.html#services");
	case TAB_NETWORK:
		return (net_help());
	case TAB_FIREWALL:
		return ("sections/firewall.html");
	case TAB_PACKAGES:
		return ("sections/packages-jobs.html#packages");
	case TAB_STORAGE:
		return ("sections/storage.html");
	case TAB_KERNEL:
		return ("sections/kernel.html#kernel");
	case TAB_SYSCTL:
		return ("sections/kernel.html#sysctl");
	case TAB_CERTS:
		return ("sections/certificates.html");
	case TAB_SSH:
		return ("sections/ssh.html");
	case TAB_PROCESSES:
		return ("sections/kernel.html#processes");
	case TAB_LOG:
		return ("sections/log.html");
	case TAB_JOBS:
		return ("sections/packages-jobs.html#jobs");
	default:
		return ("sections/host.html");
	}
}

/* The book's page, and its part, of what is shown. */
const char *
help_path(void)
{

	switch (app.node) {
	case NODE_FLEET:
		return ("sections/panel.html#all-hosts");
	case NODE_DEVICES:
		return ("sections/panel.html#devices");
	case NODE_NETWORK:
		return (app.netsect == NETSECT_GROUPS ?
		    "sections/network.html#nexthops-and-their-groups" :
		    app.netsect == NETSECT_TRACE ? "sections/map.html#traceroute" :
		    app.netsect == NETSECT_OVERLAY ? "sections/map.html" :
		    app.netsect >= NETSECT_BGP ? "sections/map.html#bgp-ospf-and-bfd" :
		    "sections/map.html");
	case NODE_USAGE:
		return ("sections/utilization.html");
	case NODE_WORKFLOWS:
		return ("sections/workflows.html");
	case NODE_SDWAN:
		return ("sdwan/index.html");
	case NODE_SECURITY:
		return ("sections/security.html");
	case NODE_STORAGE:
		return ("sections/storage-services.html");
	case NODE_BUILDER:
		return ("sections/builder.html");
	case NODE_TROUBLE:
		return ("sections/troubleshoot.html");
	case NODE_SETTINGS:
		return ("sections/settings.html");
	case NODE_API:
		return ("reference/api.html");
	case NODE_HOST:
	case NODE_JAIL:
		return (tab_help());
	default:
		return ("");
	}
}

/* The top bar's ?: this page in the book, in a tab of its own. */
void
help_button(struct html *h)
{

	h_fmt(h, "<a class=\"button ghost help\" href=\"" BOOK "%s\" target="
	    "\"_blank\" rel=\"noopener\" title=\"This page in Arcana's book: "
	    "what it does, and how\" aria-label=\"Help\">?</a>", help_path());
}
