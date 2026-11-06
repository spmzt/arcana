/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * The sections of a host's tabs that hold several: Network (the base
 * system's, BIRD, IPsec, the FEC relay), Monitoring (utilization,
 * alerts, the tunnels measured), System (with sysctl, the kernel, the
 * processes) and Security (with SSH and the certificates).  Each is a
 * tab of before (enum tab, and for the Network tab's plugins and
 * tunnels its kind), read and drawn as it was; a row under the tabs
 * goes between them.  The address is #/hosts/<id>/<tab>/<section>; a
 * tab of before's name leads to its section, and a tab alone to its
 * first, as the tabs themselves are not kept for each host.
 */

#include <stdio.h>
#include <string.h>

#include "app.h"

static const struct hsect {
	const char	*group, *sect, *title;
	const char	*leaf;		/* main.c's "tab" word for it */
	int		 tab;
	int		 kind;		/* the Network tab's, -1 any other */
	const char	*plugin;	/* its package's, drawn as a plugin */
	const char	*tip;
} hs[] = {
	{ "network", "base", "Base system", "network", TAB_NETWORK, -1, NULL,
	    "Routes, interfaces, sockets: the base system's" },
	{ "network", "bird", "BIRD", "bird", TAB_NETWORK, NET_BIRD, "bird",
	    NULL },
	{ "network", "ipsec", "IPsec", "ipsec", TAB_NETWORK, NET_IPSEC,
	    "strongswan", NULL },
	{ "network", "relay", "FEC relay", "relay", TAB_RELAY, -1,
	    "speederv2", NULL },
	{ "monitoring", "utilization", "Utilization", "monitoring",
	    TAB_MONITORING, -1, NULL, "How busy the host has been, how it is "
	    "sampled, and its limits" },
	{ "monitoring", "alerts", "Alerts", "alerts", TAB_ALERTS, -1, NULL,
	    "What of the host the mail and Telegram alerts leave out" },
	{ "monitoring", "tunnels", "Tunnel quality", "monitors", TAB_NETWORK,
	    NET_MONITORS, NULL, "Each tunnel's delay, delay variation and "
	    "loss, measured" },
	{ "system", "general", "General", "system", TAB_SYSTEM, -1, NULL,
	    NULL },
	{ "system", "sysctl", "Sysctl", "sysctl", TAB_SYSCTL, -1, NULL, NULL },
	{ "system", "kernel", "Kernel", "kernel", TAB_KERNEL, -1, NULL, NULL },
	{ "system", "processes", "Processes", "processes", TAB_PROCESSES, -1,
	    NULL, NULL },
	{ "security", "general", "General", "security", TAB_SECURITY, -1, NULL,
	    NULL },
	{ "security", "ssh", "SSH", "ssh", TAB_SSH, -1, NULL, NULL },
	{ "security", "certificates", "Certificates", "certificates",
	    TAB_CERTS, -1, NULL, NULL },
};

static size_t
first_of(size_t i)
{

	while (i > 0 && strcmp(hs[i - 1].group, hs[i].group) == 0)
		i--;
	return (i);
}

/* The section shown, or -1 for a tab without sections. */
static int
cur(void)
{
	size_t	i;

	if (app.node != NODE_HOST)
		return (-1);
	for (i = 0; i < nitems(hs); i++) {
		if (hs[i].tab != (int)app.tab)
			continue;
		if (hs[i].tab != TAB_NETWORK || hs[i].kind == (int)app.net.kind)
			return ((int)i);
	}
	/* The Network tab's base system: any kind but those above. */
	return (app.tab == TAB_NETWORK ? 0 : -1);
}

bool
hosttab_sectioned(void)
{

	return (cur() >= 0);
}

/*
 * The "tab" word main.c knows for arg: a tab and its section
 * ("system/kernel"), a tab alone (its first section), or a tab of
 * before ("kernel").  Anything else is arg itself.
 */
const char *
hosttab_resolve(const char *arg, char *buf, size_t len)
{
	const char	*sl;
	size_t		 gl, i, f;

	sl = strchr(arg, '/');
	gl = sl != NULL ? (size_t)(sl - arg) : strlen(arg);
	for (i = 0; i < nitems(hs); i++) {
		if (strlen(hs[i].group) != gl || strncmp(arg, hs[i].group,
		    gl) != 0)
			continue;
		f = first_of(i);
		if (sl == NULL)
			break;
		while (i < nitems(hs) && strcmp(hs[i].group, hs[f].group) ==
		    0 && strcmp(hs[i].sect, sl + 1) != 0)
			i++;
		/* A section not known: the tab's first. */
		if (i == nitems(hs) || strcmp(hs[i].group, hs[f].group) != 0)
			i = f;
		break;
	}
	if (i == nitems(hs) && sl == NULL)
		for (i = 0; i < nitems(hs); i++)
			if (strcmp(arg, hs[i].leaf) == 0)
				break;
	if (i == nitems(hs)) {
		snprintf(buf, len, "%s", arg);
		return (buf);
	}
	snprintf(buf, len, "%s", hs[i].leaf);
	return (buf);
}

/* The address's <tab>/<section>, when the tab shown has sections. */
bool
hosttab_loc(char *buf, size_t len)
{
	int	i;

	if ((i = cur()) < 0)
		return (false);
	snprintf(buf, len, "%s/%s", hs[i].group, hs[i].sect);
	return (true);
}

/* The row of the tab's sections, under the tabs. */
void
hosttab_nav(struct html *h, struct server *s)
{
	const char	*at;
	size_t		 i, f;
	int		 c;

	if ((c = cur()) < 0)
		return;
	f = first_of((size_t)c);
	h_raw(h, "<nav class=\"tabs sub hsects\" aria-label=\"Sections\">");
	for (i = f; i < nitems(hs) && strcmp(hs[i].group, hs[f].group) == 0;
	    i++) {
		at = NULL;
		if (hs[i].plugin != NULL)
			at = hs[i].kind >= 0 ? plugin_where(s,
			    kind_plugin(hs[i].kind)) : plugin_anywhere(s,
			    hs[i].plugin);
		h_fmt(h, "<button class=\"tab%s%s%s\" data-act=\"tab\" "
		    "data-arg=\"%s/%s\"", hs[i].plugin != NULL ? " plugin" : "",
		    hs[i].plugin != NULL && s->list != NULL && at == NULL ?
		    " missing" : "", (int)i == c ? " on" : "", hs[i].group,
		    hs[i].sect);
		if (hs[i].plugin != NULL && at == NULL && s->list != NULL)
			h_raw(h, " title=\"A plugin, not installed here: open it "
			    "to install its package\"");
		else if (at != NULL) {
			h_raw(h, " title=\"A plugin, on ");
			h_txt(h, at[0] != '\0' ? at : "the host");
			h_raw(h, "\"");
		} else if (hs[i].tip != NULL)
			h_fmt(h, " title=\"%s\"", hs[i].tip);
		h_fmt(h, ">%s</button>", hs[i].title);
	}
	h_raw(h, "</nav>");
}
